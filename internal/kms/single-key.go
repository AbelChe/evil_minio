// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/minio/kes-go"
	"github.com/minio/minio/internal/hash/sha256"
)

// Parse parses s as single-key KMS. The given string
// is expected to have the following format:
//
//	<key-id>:<base64-key>
//
// The returned KMS implementation uses the parsed
// key ID and key to derive new DEKs and decrypt ciphertext.
func Parse(s string) (KMS, error) {
	v := strings.SplitN(s, ":", 2)
	if len(v) != 2 {
		return nil, errors.New("kms: invalid master key format")
	}

	keyID, b64Key := v[0], v[1]
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	return New(keyID, key)
}

// New returns a single-key KMS that derives new DEKs from the
// given key.
func New(keyID string, key []byte) (KMS, error) {
	if len(key) != 32 {
		return nil, errors.New("kms: invalid key length " + strconv.Itoa(len(key)))
	}
	return secretKey{
		keyID: keyID,
		key:   key,
	}, nil
}

// secretKey is a KMS implementation that derives new DEKs
// from a single key.
type secretKey struct {
	keyID string
	key   []byte
}

var _ KMS = secretKey{} // compiler check

const ( // algorithms used to derive and encrypt DEKs
	algorithmAESGCM           = "AES-256-GCM-HMAC-SHA-256"
	algorithmChaCha20Poly1305 = "ChaCha20Poly1305"
)

func (kms secretKey) Stat(context.Context) (Status, error) {
	return Status{
		Name:       "SecretKey",
		DefaultKey: kms.keyID,
	}, nil
}

// IsLocal returns true if the KMS is a local implementation
func (kms secretKey) IsLocal() bool {
	return true
}

// List returns an array of local KMS Names
func (kms secretKey) List() []kes.KeyInfo {
	kmsSecret := []kes.KeyInfo{
		{
			Name: kms.keyID,
		},
	}
	return kmsSecret
}

func (secretKey) Metrics(ctx context.Context) (kes.Metric, error) {
	return kes.Metric{}, Error{
		HTTPStatusCode: http.StatusNotImplemented,
		APICode:        "KMS.NotImplemented",
		Err:            errors.New("metrics are not supported"),
	}
}

func (kms secretKey) CreateKey(_ context.Context, keyID string) error {
	if keyID == kms.keyID {
		return nil
	}
	return Error{
		HTTPStatusCode: http.StatusNotImplemented,
		APICode:        "KMS.NotImplemented",
		Err:            fmt.Errorf("creating custom key %q is not supported", keyID),
	}
}

func (kms secretKey) GenerateKey(_ context.Context, keyID string, context Context) (DEK, error) {
	if keyID == "" {
		keyID = kms.keyID
	}
	if keyID != kms.keyID {
		return DEK{}, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.NotFoundException",
			Err:            fmt.Errorf("key %q does not exist", keyID),
		}
	}
	iv, err := sioutil.Random(16)
	if err != nil {
		return DEK{}, err
	}

	var algorithm string
	if sioutil.NativeAES() {
		algorithm = algorithmAESGCM
	} else {
		algorithm = algorithmChaCha20Poly1305
	}

	var aead cipher.AEAD
	switch algorithm {
	case algorithmAESGCM:
		mac := hmac.New(sha256.New, kms.key)
		mac.Write(iv)
		sealingKey := mac.Sum(nil)

		var block cipher.Block
		block, err = aes.NewCipher(sealingKey)
		if err != nil {
			return DEK{}, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return DEK{}, err
		}
	case algorithmChaCha20Poly1305:
		var sealingKey []byte
		sealingKey, err = chacha20.HChaCha20(kms.key, iv)
		if err != nil {
			return DEK{}, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return DEK{}, err
		}
	default:
		return DEK{}, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            errors.New("invalid algorithm: " + algorithm),
		}
	}

	nonce, err := sioutil.Random(aead.NonceSize())
	if err != nil {
		return DEK{}, err
	}

	plaintext, err := sioutil.Random(32)
	if err != nil {
		return DEK{}, err
	}
	associatedData, _ := context.MarshalText()
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

	json := jsoniter.ConfigCompatibleWithStandardLibrary
	ciphertext, err = json.Marshal(encryptedKey{
		Algorithm: algorithm,
		IV:        iv,
		Nonce:     nonce,
		Bytes:     ciphertext,
	})
	if err != nil {
		return DEK{}, err
	}
	return DEK{
		KeyID:      keyID,
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
	}, nil
}

func (kms secretKey) DecryptKey(keyID string, ciphertext []byte, context Context) ([]byte, error) {
	if keyID != kms.keyID {
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.NotFoundException",
			Err:            fmt.Errorf("key %q does not exist", keyID),
		}
	}

	var encryptedKey encryptedKey
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if err := json.Unmarshal(ciphertext, &encryptedKey); err != nil {
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            err,
		}
	}

	if n := len(encryptedKey.IV); n != 16 {
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            fmt.Errorf("invalid iv size: %d", n),
		}
	}

	var aead cipher.AEAD
	switch encryptedKey.Algorithm {
	case algorithmAESGCM:
		mac := hmac.New(sha256.New, kms.key)
		mac.Write(encryptedKey.IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case algorithmChaCha20Poly1305:
		sealingKey, err := chacha20.HChaCha20(kms.key, encryptedKey.IV)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            fmt.Errorf("invalid algorithm: %q", encryptedKey.Algorithm),
		}
	}

	if n := len(encryptedKey.Nonce); n != aead.NonceSize() {
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            fmt.Errorf("invalid nonce size %d", n),
		}
	}

	associatedData, _ := context.MarshalText()
	plaintext, err := aead.Open(nil, encryptedKey.Nonce, encryptedKey.Bytes, associatedData)
	if err != nil {
		return nil, Error{
			HTTPStatusCode: http.StatusBadRequest,
			APICode:        "KMS.InternalException",
			Err:            fmt.Errorf("encrypted key is not authentic"),
		}
	}
	return plaintext, nil
}

func (kms secretKey) DecryptAll(_ context.Context, keyID string, ciphertexts [][]byte, contexts []Context) ([][]byte, error) {
	plaintexts := make([][]byte, 0, len(ciphertexts))
	for i := range ciphertexts {
		plaintext, err := kms.DecryptKey(keyID, ciphertexts[i], contexts[i])
		if err != nil {
			return nil, err
		}
		plaintexts = append(plaintexts, plaintext)
	}
	return plaintexts, nil
}

type encryptedKey struct {
	Algorithm string `json:"aead"`
	IV        []byte `json:"iv"`
	Nonce     []byte `json:"nonce"`
	Bytes     []byte `json:"bytes"`
}
