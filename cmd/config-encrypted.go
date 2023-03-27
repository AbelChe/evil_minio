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
	"bytes"
	"context"
	"fmt"
	"path"
	"time"
	"unicode/utf8"

	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/kms"
	"github.com/minio/minio/internal/logger"
	etcd "go.etcd.io/etcd/client/v3"
)

func handleEncryptedConfigBackend(objAPI ObjectLayer) error {
	encrypted, err := checkBackendEncrypted(objAPI)
	if err != nil {
		return fmt.Errorf("Unable to encrypt config %w", err)
	}
	if !encrypted {
		return nil
	}
	if err = migrateConfigPrefixToEncrypted(objAPI); err != nil {
		return fmt.Errorf("Unable to migrate all config at .minio.sys/config/: %w", err)
	}
	return nil
}

const backendEncryptedFile = "backend-encrypted"

var backendEncryptedMigrationComplete = []byte("encrypted")

func checkBackendEtcdEncrypted(ctx context.Context, client *etcd.Client) (bool, error) {
	bootstrapTrace("check if etcd backend is encrypted")
	data, err := readKeyEtcd(ctx, client, backendEncryptedFile)
	if err != nil && err != errConfigNotFound {
		return false, err
	}
	return err == nil && bytes.Equal(data, backendEncryptedMigrationComplete), nil
}

func checkBackendEncrypted(objAPI ObjectLayer) (bool, error) {
	bootstrapTrace("check if the config backend is encrypted")
	data, err := readConfig(GlobalContext, objAPI, backendEncryptedFile)
	if err != nil && err != errConfigNotFound {
		return false, err
	}
	return err == nil && bytes.Equal(data, backendEncryptedMigrationComplete), nil
}

func migrateIAMConfigsEtcdToEncrypted(ctx context.Context, client *etcd.Client) error {
	encrypted, err := checkBackendEtcdEncrypted(ctx, client)
	if err != nil {
		return err
	}

	// If backend doesn't have this file means we have already
	// attempted then migration
	if !encrypted {
		return nil
	}

	bootstrapTrace("encrypt etcd config")

	if GlobalKMS != nil {
		stat, err := GlobalKMS.Stat(ctx)
		if err != nil {
			return err
		}
		logger.Info(fmt.Sprintf("Attempting to re-encrypt IAM users and policies on etcd with %q (%s)", stat.DefaultKey, stat.Name))
	}

	listCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	r, err := client.Get(listCtx, minioConfigPrefix, etcd.WithPrefix(), etcd.WithKeysOnly())
	if err != nil {
		return err
	}

	for _, kv := range r.Kvs {
		data, err := readKeyEtcd(ctx, client, string(kv.Key))
		if err == errConfigNotFound { // Perhaps not present or someone deleted it.
			continue
		}
		if err != nil {
			return err
		}

		if !utf8.Valid(data) {
			pdata, err := madmin.DecryptData(globalActiveCred.String(), bytes.NewReader(data))
			if err != nil {
				if GlobalKMS != nil {
					pdata, err = config.DecryptBytes(GlobalKMS, data, kms.Context{
						minioMetaBucket: path.Join(minioMetaBucket, string(kv.Key)),
					})
					if err != nil {
						pdata, err = config.DecryptBytes(GlobalKMS, data, kms.Context{
							minioMetaBucket: string(kv.Key),
						})
						if err != nil {
							return fmt.Errorf("Decrypting IAM config failed %w, possibly credentials are incorrect", err)
						}
					}
				} else {
					return fmt.Errorf("Decrypting IAM config failed %w, possibly credentials are incorrect", err)
				}
			}
			data = pdata
		}

		if GlobalKMS != nil {
			data, err = config.EncryptBytes(GlobalKMS, data, kms.Context{
				minioMetaBucket: path.Join(minioMetaBucket, string(kv.Key)),
			})
			if err != nil {
				return err
			}
		}

		if err = saveKeyEtcd(ctx, client, string(kv.Key), data); err != nil {
			return err
		}
	}

	if GlobalKMS != nil {
		logger.Info("Migration of encrypted IAM config data completed. All data is now encrypted on etcd.")
	}

	return deleteKeyEtcd(ctx, client, backendEncryptedFile)
}

func migrateConfigPrefixToEncrypted(objAPI ObjectLayer) error {
	bootstrapTrace("migrating config prefix to encrypted")
	if GlobalKMS != nil {
		stat, err := GlobalKMS.Stat(context.Background())
		if err != nil {
			return err
		}
		logger.Info(fmt.Sprintf("Attempting to re-encrypt config, IAM users and policies on MinIO with %q (%s)", stat.DefaultKey, stat.Name))
	}

	results := make(chan ObjectInfo)
	if err := objAPI.Walk(GlobalContext, minioMetaBucket, minioConfigPrefix, results, ObjectOptions{}); err != nil {
		return err
	}

	for obj := range results {
		data, err := readConfig(GlobalContext, objAPI, obj.Name)
		if err != nil {
			return err
		}

		if !utf8.Valid(data) {
			pdata, err := madmin.DecryptData(globalActiveCred.String(), bytes.NewReader(data))
			if err != nil {
				if GlobalKMS != nil {
					pdata, err = config.DecryptBytes(GlobalKMS, data, kms.Context{
						minioMetaBucket: path.Join(minioMetaBucket, obj.Name),
					})
					if err != nil {
						pdata, err = config.DecryptBytes(GlobalKMS, data, kms.Context{
							minioMetaBucket: obj.Name,
						})
						if err != nil {
							return fmt.Errorf("Decrypting IAM config failed %w, possibly credentials are incorrect", err)
						}
					}
				} else {
					return fmt.Errorf("Decrypting IAM config failed %w, possibly credentials are incorrect", err)
				}
			}
			data = pdata
		}

		if GlobalKMS != nil {
			data, err = config.EncryptBytes(GlobalKMS, data, kms.Context{
				obj.Bucket: path.Join(obj.Bucket, obj.Name),
			})
			if err != nil {
				return err
			}
		}

		if err = saveConfig(GlobalContext, objAPI, obj.Name, data); err != nil {
			return err
		}
	}

	if GlobalKMS != nil {
		logger.Info("Migration of encrypted config data completed. All config data is now encrypted.")
	}

	return deleteConfig(GlobalContext, objAPI, backendEncryptedFile)
}
