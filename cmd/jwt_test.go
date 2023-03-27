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

package cmd

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	"github.com/minio/minio/internal/auth"
	xjwt "github.com/minio/minio/internal/jwt"
)

func testAuthenticate(authType string, t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		t.Fatal(err)
	}

	cred, err := auth.GetNewCredentials()
	if err != nil {
		t.Fatalf("Error getting new credentials: %s", err)
	}

	globalActiveCred = cred

	// Define test cases.
	testCases := []struct {
		accessKey   string
		secretKey   string
		expectedErr error
	}{
		// Access key (less than 3 chrs) too small.
		{"u1", cred.SecretKey, auth.ErrInvalidAccessKeyLength},
		// Secret key (less than 8 chrs) too small.
		{cred.AccessKey, "pass", auth.ErrInvalidSecretKeyLength},
		// Authentication error.
		{"myuser", "mypassword", errInvalidAccessKeyID},
		// Authentication error.
		{cred.AccessKey, "mypassword", errAuthentication},
		// Success.
		{cred.AccessKey, cred.SecretKey, nil},
	}

	// Run tests.
	for _, testCase := range testCases {
		var err error
		if authType == "web" {
			_, err = authenticateWeb(testCase.accessKey, testCase.secretKey)
		} else if authType == "url" {
			_, err = authenticateURL(testCase.accessKey, testCase.secretKey)
		}

		if testCase.expectedErr != nil {
			if err == nil {
				t.Fatalf("%+v: expected: %s, got: <nil>", testCase, testCase.expectedErr)
			}
			if testCase.expectedErr.Error() != err.Error() {
				t.Fatalf("%+v: expected: %s, got: %s", testCase, testCase.expectedErr, err)
			}
		} else if err != nil {
			t.Fatalf("%+v: expected: <nil>, got: %s", testCase, err)
		}
	}
}

func TestAuthenticateWeb(t *testing.T) {
	testAuthenticate("web", t)
}

func TestAuthenticateURL(t *testing.T) {
	testAuthenticate("url", t)
}

func getTokenString(accessKey, secretKey string) (string, error) {
	claims := xjwt.NewMapClaims()
	claims.SetExpiry(UTCNow().Add(defaultJWTExpiry))
	claims.SetAccessKey(accessKey)
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, claims)
	return token.SignedString([]byte(secretKey))
}

// Tests web request authenticator.
func TestWebRequestAuthenticate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		t.Fatal(err)
	}

	creds := globalActiveCred
	token, err := getTokenString(creds.AccessKey, creds.SecretKey)
	if err != nil {
		t.Fatalf("unable get token %s", err)
	}
	testCases := []struct {
		req         *http.Request
		expectedErr error
	}{
		// Set valid authorization header.
		{
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{token},
				},
			},
			expectedErr: nil,
		},
		// No authorization header.
		{
			req: &http.Request{
				Header: http.Header{},
			},
			expectedErr: errNoAuthToken,
		},
		// Invalid authorization token.
		{
			req: &http.Request{
				Header: http.Header{
					"Authorization": []string{"invalid-token"},
				},
			},
			expectedErr: errAuthentication,
		},
	}

	for i, testCase := range testCases {
		_, _, _, gotErr := metricsRequestAuthenticate(testCase.req)
		if testCase.expectedErr != gotErr {
			t.Errorf("Test %d, expected err %s, got %s", i+1, testCase.expectedErr, gotErr)
		}
	}
}

func BenchmarkParseJWTStandardClaims(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		b.Fatal(err)
	}

	creds := globalActiveCred
	token, err := authenticateNode(creds.AccessKey, creds.SecretKey, "")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err = xjwt.ParseWithStandardClaims(token, xjwt.NewStandardClaims(), []byte(creds.SecretKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkParseJWTMapClaims(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		b.Fatal(err)
	}

	creds := globalActiveCred
	token, err := authenticateNode(creds.AccessKey, creds.SecretKey, "")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err = xjwt.ParseWithClaims(token, xjwt.NewMapClaims(), func(*xjwt.MapClaims) ([]byte, error) {
				return []byte(creds.SecretKey), nil
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkAuthenticateNode(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		b.Fatal(err)
	}

	creds := globalActiveCred
	b.Run("uncached", func(b *testing.B) {
		fn := authenticateNode
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fn(creds.AccessKey, creds.SecretKey, "aud")
		}
	})
	b.Run("cached", func(b *testing.B) {
		fn := cachedAuthenticateNode(time.Second)
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			fn(creds.AccessKey, creds.SecretKey, "aud")
		}
	})
}

func BenchmarkAuthenticateWeb(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	obj, fsDir, err := prepareFS(ctx)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(fsDir)
	if err = newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		b.Fatal(err)
	}

	creds := globalActiveCred
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		authenticateWeb(creds.AccessKey, creds.SecretKey)
	}
}
