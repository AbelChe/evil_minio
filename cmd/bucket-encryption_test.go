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
	"testing"
)

func TestValidateBucketSSEConfig(t *testing.T) {
	testCases := []struct {
		inputXML    string
		expectedErr error
		shouldPass  bool
	}{
		// MinIO supported XML
		{
			inputXML: `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			<Rule>
			<ApplyServerSideEncryptionByDefault>
			<SSEAlgorithm>AES256</SSEAlgorithm>
			</ApplyServerSideEncryptionByDefault>
			</Rule>
			</ServerSideEncryptionConfiguration>`,
			expectedErr: nil,
			shouldPass:  true,
		},
		// Unsupported XML
		{
			inputXML: `<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			<Rule>
			<ApplyServerSideEncryptionByDefault>
                        <SSEAlgorithm>aws:kms</SSEAlgorithm>
                        <KMSMasterKeyID>my-key</KMSMasterKeyID>
			</ApplyServerSideEncryptionByDefault>
			</Rule>
			</ServerSideEncryptionConfiguration>`,
			expectedErr: nil,
			shouldPass:  true,
		},
	}

	for i, tc := range testCases {
		_, err := validateBucketSSEConfig(bytes.NewReader([]byte(tc.inputXML)))
		if tc.shouldPass && err != nil {
			t.Fatalf("Test case %d: Expected to succeed but got %s", i+1, err)
		}

		if !tc.shouldPass {
			if err == nil || err != nil && err.Error() != tc.expectedErr.Error() {
				t.Fatalf("Test case %d: Expected %s but got %s", i+1, tc.expectedErr, err)
			}
		}
	}
}
