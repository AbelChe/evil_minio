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

package arn

import (
	"fmt"
	"regexp"
	"strings"
)

// ARN structure:
//
// arn:partition:service:region:account-id:resource-type/resource-id
//
// In this implementation, account-id is empty.
//
// Reference: https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html

type arnPartition string

const (
	arnPartitionMinio arnPartition = "minio"
)

type arnService string

const (
	arnServiceIAM arnService = "iam"
)

type arnResourceType string

const (
	arnResourceTypeRole arnResourceType = "role"
)

// ARN - representation of resources based on AWS ARNs.
type ARN struct {
	Partition    arnPartition
	Service      arnService
	Region       string
	ResourceType arnResourceType
	ResourceID   string
}

// Allows english letters, numbers, '.', '-', '_' and '/'. Starts with a
// letter or digit. At least 1 character long.
var validResourceIDRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_/\.-]*$`)

// NewIAMRoleARN - returns an ARN for a role in MinIO.
func NewIAMRoleARN(resourceID, serverRegion string) (ARN, error) {
	if !validResourceIDRegex.MatchString(resourceID) {
		return ARN{}, fmt.Errorf("Invalid resource ID: %s", resourceID)
	}
	return ARN{
		Partition:    arnPartitionMinio,
		Service:      arnServiceIAM,
		Region:       serverRegion,
		ResourceType: arnResourceTypeRole,
		ResourceID:   resourceID,
	}, nil
}

// String - returns string representation of the ARN.
func (arn ARN) String() string {
	return strings.Join(
		[]string{
			"arn",
			string(arn.Partition),
			string(arn.Service),
			arn.Region,
			"", // account-id is always empty in this implementation
			string(arn.ResourceType) + "/" + arn.ResourceID,
		},
		":",
	)
}

// Parse - parses an ARN string into a type.
func Parse(arnStr string) (arn ARN, err error) {
	ps := strings.Split(arnStr, ":")
	if len(ps) != 6 ||
		ps[0] != "arn" {
		err = fmt.Errorf("Invalid ARN string format")
		return
	}

	if ps[1] != string(arnPartitionMinio) {
		err = fmt.Errorf("Invalid ARN - bad partition field")
		return
	}

	if ps[2] != string(arnServiceIAM) {
		err = fmt.Errorf("Invalid ARN - bad service field")
		return
	}

	// ps[3] is region and is not validated here. If the region is invalid,
	// the ARN would not match any configured ARNs in the server.

	if ps[4] != "" {
		err = fmt.Errorf("Invalid ARN - unsupported account-id field")
		return
	}

	res := strings.SplitN(ps[5], "/", 2)
	if len(res) != 2 {
		err = fmt.Errorf("Invalid ARN - resource does not contain a \"/\"")
		return
	}

	if res[0] != string(arnResourceTypeRole) {
		err = fmt.Errorf("Invalid ARN: resource type is invalid.")
		return
	}

	if !validResourceIDRegex.MatchString(res[1]) {
		err = fmt.Errorf("Invalid resource ID: %s", res[1])
		return
	}

	arn = ARN{
		Partition:    arnPartitionMinio,
		Service:      arnServiceIAM,
		Region:       ps[3],
		ResourceType: arnResourceTypeRole,
		ResourceID:   res[1],
	}
	return
}
