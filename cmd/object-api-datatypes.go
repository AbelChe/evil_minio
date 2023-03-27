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
	"io"
	"math"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/hash"
	"github.com/minio/minio/internal/logger"
)

// BackendType - represents different backend types.
type BackendType int

// Enum for different backend types.
const (
	Unknown = BackendType(madmin.Unknown)
	// Filesystem backend.
	BackendFS = BackendType(madmin.FS)
	// Multi disk BackendErasure (single, distributed) backend.
	BackendErasure = BackendType(madmin.Erasure)
	// Add your own backend.
)

// StorageInfo - represents total capacity of underlying storage.
type StorageInfo = madmin.StorageInfo

// objectHistogramInterval is an interval that will be
// used to report the histogram of objects data sizes
type objectHistogramInterval struct {
	name       string
	start, end int64
}

const (
	// dataUsageBucketLen must be length of ObjectsHistogramIntervals
	dataUsageBucketLen  = 7
	dataUsageVersionLen = 7
)

// ObjectsHistogramIntervals is the list of all intervals
// of object sizes to be included in objects histogram.
var ObjectsHistogramIntervals = [dataUsageBucketLen]objectHistogramInterval{
	{"LESS_THAN_1024_B", 0, humanize.KiByte - 1},
	{"BETWEEN_1024_B_AND_1_MB", humanize.KiByte, humanize.MiByte - 1},
	{"BETWEEN_1_MB_AND_10_MB", humanize.MiByte, humanize.MiByte*10 - 1},
	{"BETWEEN_10_MB_AND_64_MB", humanize.MiByte * 10, humanize.MiByte*64 - 1},
	{"BETWEEN_64_MB_AND_128_MB", humanize.MiByte * 64, humanize.MiByte*128 - 1},
	{"BETWEEN_128_MB_AND_512_MB", humanize.MiByte * 128, humanize.MiByte*512 - 1},
	{"GREATER_THAN_512_MB", humanize.MiByte * 512, math.MaxInt64},
}

// ObjectsVersionCountIntervals is the list of all intervals
// of object version count to be included in objects histogram.
var ObjectsVersionCountIntervals = [dataUsageVersionLen]objectHistogramInterval{
	{"UNVERSIONED", 0, 0},
	{"SINGLE_VERSION", 1, 1},
	{"BETWEEN_2_AND_10", 2, 9},
	{"BETWEEN_10_AND_100", 10, 99},
	{"BETWEEN_100_AND_1000", 100, 999},
	{"BETWEEN_1000_AND_10000", 1000, 9999},
	{"GREATER_THAN_10000", 10000, math.MaxInt64},
}

// BucketInfo - represents bucket metadata.
type BucketInfo struct {
	// Name of the bucket.
	Name string

	// Date and time when the bucket was created.
	Created time.Time
	Deleted time.Time

	// Bucket features enabled
	Versioning, ObjectLocking bool
}

// ObjectInfo - represents object metadata.
type ObjectInfo struct {
	// Name of the bucket.
	Bucket string

	// Name of the object.
	Name string

	// Date and time when the object was last modified.
	ModTime time.Time

	// Total object size.
	Size int64

	// IsDir indicates if the object is prefix.
	IsDir bool

	// Hex encoded unique entity tag of the object.
	ETag string

	// Version ID of this object.
	VersionID string

	// IsLatest indicates if this is the latest current version
	// latest can be true for delete marker or a version.
	IsLatest bool

	// DeleteMarker indicates if the versionId corresponds
	// to a delete marker on an object.
	DeleteMarker bool

	// Transitioned object information
	TransitionedObject TransitionedObject

	// RestoreExpires indicates date a restored object expires
	RestoreExpires time.Time

	// RestoreOngoing indicates if a restore is in progress
	RestoreOngoing bool

	// A standard MIME type describing the format of the object.
	ContentType string

	// Specifies what content encodings have been applied to the object and thus
	// what decoding mechanisms must be applied to obtain the object referenced
	// by the Content-Type header field.
	ContentEncoding string

	// Date and time at which the object is no longer able to be cached
	Expires time.Time

	// CacheStatus sets status of whether this is a cache hit/miss
	CacheStatus CacheStatusType
	// CacheLookupStatus sets whether a cacheable response is present in the cache
	CacheLookupStatus CacheStatusType

	// Specify object storage class
	StorageClass string

	ReplicationStatusInternal string
	ReplicationStatus         replication.StatusType
	// User-Defined metadata
	UserDefined map[string]string

	// User-Defined object tags
	UserTags string

	// List of individual parts, maximum size of upto 10,000
	Parts []ObjectPartInfo `json:"-"`

	// Implements writer and reader used by CopyObject API
	Writer       io.WriteCloser `json:"-"`
	Reader       *hash.Reader   `json:"-"`
	PutObjReader *PutObjReader  `json:"-"`

	metadataOnly bool
	versionOnly  bool // adds a new version, only used by CopyObject
	keyRotation  bool

	// Date and time when the object was last accessed.
	AccTime time.Time

	Legacy bool // indicates object on disk is in legacy data format

	// backendType indicates which backend filled this structure
	backendType BackendType
	// internal representation of version purge status
	VersionPurgeStatusInternal string
	VersionPurgeStatus         VersionPurgeStatusType

	// The total count of all versions of this object
	NumVersions int
	//  The modtime of the successor object version if any
	SuccessorModTime time.Time

	// Checksums added on upload.
	// Encoded, maybe encrypted.
	Checksum []byte
}

// ArchiveInfo returns any saved zip archive meta information.
// It will be decrypted if needed.
func (o *ObjectInfo) ArchiveInfo() []byte {
	if len(o.UserDefined) == 0 {
		return nil
	}
	z, ok := o.UserDefined[archiveInfoMetadataKey]
	if !ok {
		return nil
	}
	data := []byte(z)
	if v, ok := o.UserDefined[archiveTypeMetadataKey]; ok && v == archiveTypeEnc {
		decrypted, err := o.metadataDecrypter()(archiveTypeEnc, data)
		if err != nil {
			logger.LogIf(GlobalContext, err)
			return nil
		}
		data = decrypted
	}
	return data
}

// Clone - Returns a cloned copy of current objectInfo
func (o *ObjectInfo) Clone() (cinfo ObjectInfo) {
	cinfo = ObjectInfo{
		Bucket:                     o.Bucket,
		Name:                       o.Name,
		ModTime:                    o.ModTime,
		Size:                       o.Size,
		IsDir:                      o.IsDir,
		ETag:                       o.ETag,
		VersionID:                  o.VersionID,
		IsLatest:                   o.IsLatest,
		DeleteMarker:               o.DeleteMarker,
		TransitionedObject:         o.TransitionedObject,
		RestoreExpires:             o.RestoreExpires,
		RestoreOngoing:             o.RestoreOngoing,
		ContentType:                o.ContentType,
		ContentEncoding:            o.ContentEncoding,
		Expires:                    o.Expires,
		CacheStatus:                o.CacheStatus,
		CacheLookupStatus:          o.CacheLookupStatus,
		StorageClass:               o.StorageClass,
		ReplicationStatus:          o.ReplicationStatus,
		UserTags:                   o.UserTags,
		Parts:                      o.Parts,
		Writer:                     o.Writer,
		Reader:                     o.Reader,
		PutObjReader:               o.PutObjReader,
		metadataOnly:               o.metadataOnly,
		versionOnly:                o.versionOnly,
		keyRotation:                o.keyRotation,
		backendType:                o.backendType,
		AccTime:                    o.AccTime,
		Legacy:                     o.Legacy,
		VersionPurgeStatus:         o.VersionPurgeStatus,
		NumVersions:                o.NumVersions,
		SuccessorModTime:           o.SuccessorModTime,
		ReplicationStatusInternal:  o.ReplicationStatusInternal,
		VersionPurgeStatusInternal: o.VersionPurgeStatusInternal,
	}
	cinfo.UserDefined = make(map[string]string, len(o.UserDefined))
	for k, v := range o.UserDefined {
		cinfo.UserDefined[k] = v
	}
	return cinfo
}

func (o ObjectInfo) tierStats() tierStats {
	ts := tierStats{
		TotalSize:   uint64(o.Size),
		NumVersions: 1,
	}
	// the current version of an object is accounted towards objects count
	if o.IsLatest {
		ts.NumObjects = 1
	}
	return ts
}

// ReplicateObjectInfo represents object info to be replicated
type ReplicateObjectInfo struct {
	ObjectInfo
	OpType               replication.Type
	EventType            string
	RetryCount           uint32
	ResetID              string
	Dsc                  ReplicateDecision
	ExistingObjResync    ResyncDecision
	TargetArn            string
	TargetStatuses       map[string]replication.StatusType
	TargetPurgeStatuses  map[string]VersionPurgeStatusType
	ReplicationTimestamp time.Time
}

// MultipartInfo captures metadata information about the uploadId
// this data structure is used primarily for some internal purposes
// for verifying upload type such as was the upload
// - encrypted
// - compressed
type MultipartInfo struct {
	// Name of the bucket.
	Bucket string

	// Name of the object.
	Object string

	// Upload ID identifying the multipart upload whose parts are being listed.
	UploadID string

	// Date and time at which the multipart upload was initiated.
	Initiated time.Time

	// Any metadata set during InitMultipartUpload, including encryption headers.
	UserDefined map[string]string
}

// ListPartsInfo - represents list of all parts.
type ListPartsInfo struct {
	// Name of the bucket.
	Bucket string

	// Name of the object.
	Object string

	// Upload ID identifying the multipart upload whose parts are being listed.
	UploadID string

	// The class of storage used to store the object.
	StorageClass string

	// Part number after which listing begins.
	PartNumberMarker int

	// When a list is truncated, this element specifies the last part in the list,
	// as well as the value to use for the part-number-marker request parameter
	// in a subsequent request.
	NextPartNumberMarker int

	// Maximum number of parts that were allowed in the response.
	MaxParts int

	// Indicates whether the returned list of parts is truncated.
	IsTruncated bool

	// List of all parts.
	Parts []PartInfo

	// Any metadata set during InitMultipartUpload, including encryption headers.
	UserDefined map[string]string

	// ChecksumAlgorithm if set
	ChecksumAlgorithm string
}

// Lookup - returns if uploadID is valid
func (lm ListMultipartsInfo) Lookup(uploadID string) bool {
	for _, upload := range lm.Uploads {
		if upload.UploadID == uploadID {
			return true
		}
	}
	return false
}

// ListMultipartsInfo - represnets bucket resources for incomplete multipart uploads.
type ListMultipartsInfo struct {
	// Together with upload-id-marker, this parameter specifies the multipart upload
	// after which listing should begin.
	KeyMarker string

	// Together with key-marker, specifies the multipart upload after which listing
	// should begin. If key-marker is not specified, the upload-id-marker parameter
	// is ignored.
	UploadIDMarker string

	// When a list is truncated, this element specifies the value that should be
	// used for the key-marker request parameter in a subsequent request.
	NextKeyMarker string

	// When a list is truncated, this element specifies the value that should be
	// used for the upload-id-marker request parameter in a subsequent request.
	NextUploadIDMarker string

	// Maximum number of multipart uploads that could have been included in the
	// response.
	MaxUploads int

	// Indicates whether the returned list of multipart uploads is truncated. A
	// value of true indicates that the list was truncated. The list can be truncated
	// if the number of multipart uploads exceeds the limit allowed or specified
	// by max uploads.
	IsTruncated bool

	// List of all pending uploads.
	Uploads []MultipartInfo

	// When a prefix is provided in the request, The result contains only keys
	// starting with the specified prefix.
	Prefix string

	// A character used to truncate the object prefixes.
	// NOTE: only supported delimiter is '/'.
	Delimiter string

	// CommonPrefixes contains all (if there are any) keys between Prefix and the
	// next occurrence of the string specified by delimiter.
	CommonPrefixes []string

	EncodingType string // Not supported yet.
}

// TransitionedObject transitioned object tier and status.
type TransitionedObject struct {
	Name        string
	VersionID   string
	Tier        string
	FreeVersion bool
	Status      string
}

// DeletedObjectInfo - container for list objects versions deleted objects.
type DeletedObjectInfo struct {
	// Name of the bucket.
	Bucket string

	// Name of the object.
	Name string

	// Date and time when the object was last modified.
	ModTime time.Time

	// Version ID of this object.
	VersionID string

	// Indicates the deleted marker is latest
	IsLatest bool
}

// ListObjectVersionsInfo - container for list objects versions.
type ListObjectVersionsInfo struct {
	// Indicates whether the returned list objects response is truncated. A
	// value of true indicates that the list was truncated. The list can be truncated
	// if the number of objects exceeds the limit allowed or specified
	// by max keys.
	IsTruncated bool

	// When response is truncated (the IsTruncated element value in the response is true),
	// you can use the key name in this field as marker in the subsequent
	// request to get next set of objects.
	//
	// NOTE: AWS S3 returns NextMarker only if you have delimiter request parameter specified,
	//       MinIO always returns NextMarker.
	NextMarker string

	// NextVersionIDMarker may be set of IsTruncated is true
	NextVersionIDMarker string

	// List of objects info for this request.
	Objects []ObjectInfo

	// List of prefixes for this request.
	Prefixes []string
}

// ListObjectsInfo - container for list objects.
type ListObjectsInfo struct {
	// Indicates whether the returned list objects response is truncated. A
	// value of true indicates that the list was truncated. The list can be truncated
	// if the number of objects exceeds the limit allowed or specified
	// by max keys.
	IsTruncated bool

	// When response is truncated (the IsTruncated element value in the response is true),
	// you can use the key name in this field as marker in the subsequent
	// request to get next set of objects.
	//
	// NOTE: AWS S3 returns NextMarker only if you have delimiter request parameter specified,
	//       MinIO always returns NextMarker.
	NextMarker string

	// List of objects info for this request.
	Objects []ObjectInfo

	// List of prefixes for this request.
	Prefixes []string
}

// ListObjectsV2Info - container for list objects version 2.
type ListObjectsV2Info struct {
	// Indicates whether the returned list objects response is truncated. A
	// value of true indicates that the list was truncated. The list can be truncated
	// if the number of objects exceeds the limit allowed or specified
	// by max keys.
	IsTruncated bool

	// When response is truncated (the IsTruncated element value in the response
	// is true), you can use the key name in this field as marker in the subsequent
	// request to get next set of objects.
	//
	// NOTE: This element is returned only if you have delimiter request parameter
	// specified.
	ContinuationToken     string
	NextContinuationToken string

	// List of objects info for this request.
	Objects []ObjectInfo

	// List of prefixes for this request.
	Prefixes []string
}

// PartInfo - represents individual part metadata.
type PartInfo struct {
	// Part number that identifies the part. This is a positive integer between
	// 1 and 10,000.
	PartNumber int

	// Date and time at which the part was uploaded.
	LastModified time.Time

	// Entity tag returned when the part was initially uploaded.
	ETag string

	// Size in bytes of the part.
	Size int64

	// Decompressed Size.
	ActualSize int64

	// Checksum values
	ChecksumCRC32  string
	ChecksumCRC32C string
	ChecksumSHA1   string
	ChecksumSHA256 string
}

// CompletePart - represents the part that was completed, this is sent by the client
// during CompleteMultipartUpload request.
type CompletePart struct {
	// Part number identifying the part. This is a positive integer between 1 and
	// 10,000
	PartNumber int

	// Entity tag returned when the part was uploaded.
	ETag string

	// Checksum values. Optional.
	ChecksumCRC32  string
	ChecksumCRC32C string
	ChecksumSHA1   string
	ChecksumSHA256 string
}

// CompletedParts - is a collection satisfying sort.Interface.
type CompletedParts []CompletePart

func (a CompletedParts) Len() int           { return len(a) }
func (a CompletedParts) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a CompletedParts) Less(i, j int) bool { return a[i].PartNumber < a[j].PartNumber }

// CompleteMultipartUpload - represents list of parts which are completed, this is sent by the
// client during CompleteMultipartUpload request.
type CompleteMultipartUpload struct {
	Parts []CompletePart `xml:"Part"`
}

// NewMultipartUploadResult contains information about a newly created multipart upload.
type NewMultipartUploadResult struct {
	UploadID     string
	ChecksumAlgo string
}
