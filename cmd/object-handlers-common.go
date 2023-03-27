// Copyright (c) 2015-2023 MinIO, Inc.
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
	"regexp"
	"strconv"
	"time"

	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
)

var etagRegex = regexp.MustCompile("\"*?([^\"]*?)\"*?$")

// Validates the preconditions for CopyObjectPart, returns true if CopyObjectPart
// operation should not proceed. Preconditions supported are:
//
//	x-amz-copy-source-if-modified-since
//	x-amz-copy-source-if-unmodified-since
//	x-amz-copy-source-if-match
//	x-amz-copy-source-if-none-match
func checkCopyObjectPartPreconditions(ctx context.Context, w http.ResponseWriter, r *http.Request, objInfo ObjectInfo) bool {
	return checkCopyObjectPreconditions(ctx, w, r, objInfo)
}

// Validates the preconditions for CopyObject, returns true if CopyObject operation should not proceed.
// Preconditions supported are:
//
//	x-amz-copy-source-if-modified-since
//	x-amz-copy-source-if-unmodified-since
//	x-amz-copy-source-if-match
//	x-amz-copy-source-if-none-match
func checkCopyObjectPreconditions(ctx context.Context, w http.ResponseWriter, r *http.Request, objInfo ObjectInfo) bool {
	// Return false for methods other than GET and HEAD.
	if r.Method != http.MethodPut {
		return false
	}
	// If the object doesn't have a modtime (IsZero), or the modtime
	// is obviously garbage (Unix time == 0), then ignore modtimes
	// and don't process the If-Modified-Since header.
	if objInfo.ModTime.IsZero() || objInfo.ModTime.Equal(time.Unix(0, 0)) {
		return false
	}

	// Headers to be set of object content is not going to be written to the client.
	writeHeaders := func() {
		// set common headers
		setCommonHeaders(w)

		// set object-related metadata headers
		w.Header().Set(xhttp.LastModified, objInfo.ModTime.UTC().Format(http.TimeFormat))

		if objInfo.ETag != "" {
			w.Header()[xhttp.ETag] = []string{"\"" + objInfo.ETag + "\""}
		}
	}
	// x-amz-copy-source-if-modified-since: Return the object only if it has been modified
	// since the specified time otherwise return 412 (precondition failed).
	ifModifiedSinceHeader := r.Header.Get(xhttp.AmzCopySourceIfModifiedSince)
	if ifModifiedSinceHeader != "" {
		if givenTime, err := amztime.ParseHeader(ifModifiedSinceHeader); err == nil {
			if !ifModifiedSince(objInfo.ModTime, givenTime) {
				// If the object is not modified since the specified time.
				writeHeaders()
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
				return true
			}
		}
	}

	// x-amz-copy-source-if-unmodified-since : Return the object only if it has not been
	// modified since the specified time, otherwise return a 412 (precondition failed).
	ifUnmodifiedSinceHeader := r.Header.Get(xhttp.AmzCopySourceIfUnmodifiedSince)
	if ifUnmodifiedSinceHeader != "" {
		if givenTime, err := amztime.ParseHeader(ifUnmodifiedSinceHeader); err == nil {
			if ifModifiedSince(objInfo.ModTime, givenTime) {
				// If the object is modified since the specified time.
				writeHeaders()
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
				return true
			}
		}
	}

	// x-amz-copy-source-if-match : Return the object only if its entity tag (ETag) is the
	// same as the one specified; otherwise return a 412 (precondition failed).
	ifMatchETagHeader := r.Header.Get(xhttp.AmzCopySourceIfMatch)
	if ifMatchETagHeader != "" {
		if !isETagEqual(objInfo.ETag, ifMatchETagHeader) {
			// If the object ETag does not match with the specified ETag.
			writeHeaders()
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
			return true
		}
	}

	// If-None-Match : Return the object only if its entity tag (ETag) is different from the
	// one specified otherwise, return a 304 (not modified).
	ifNoneMatchETagHeader := r.Header.Get(xhttp.AmzCopySourceIfNoneMatch)
	if ifNoneMatchETagHeader != "" {
		if isETagEqual(objInfo.ETag, ifNoneMatchETagHeader) {
			// If the object ETag matches with the specified ETag.
			writeHeaders()
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
			return true
		}
	}
	// Object content should be written to http.ResponseWriter
	return false
}

// Validates the preconditions. Returns true if PUT operation should not proceed.
// Preconditions supported are:
//
//	x-minio-source-mtime
//	x-minio-source-etag
func checkPreconditionsPUT(ctx context.Context, w http.ResponseWriter, r *http.Request, objInfo ObjectInfo, opts ObjectOptions) bool {
	// Return false for methods other than PUT.
	if r.Method != http.MethodPut {
		return false
	}
	// If the object doesn't have a modtime (IsZero), or the modtime
	// is obviously garbage (Unix time == 0), then ignore modtimes
	// and don't process the If-Modified-Since header.
	if objInfo.ModTime.IsZero() || objInfo.ModTime.Equal(time.Unix(0, 0)) {
		return false
	}

	// If top level is a delete marker proceed to upload.
	if objInfo.DeleteMarker {
		return false
	}

	// Headers to be set of object content is not going to be written to the client.
	writeHeaders := func() {
		// set common headers
		setCommonHeaders(w)

		// set object-related metadata headers
		w.Header().Set(xhttp.LastModified, objInfo.ModTime.UTC().Format(http.TimeFormat))

		if objInfo.ETag != "" {
			w.Header()[xhttp.ETag] = []string{"\"" + objInfo.ETag + "\""}
		}
	}

	// If-Match : Return the object only if its entity tag (ETag) is the same as the one specified;
	// otherwise return a 412 (precondition failed).
	ifMatchETagHeader := r.Header.Get(xhttp.IfMatch)
	if ifMatchETagHeader != "" {
		if !isETagEqual(objInfo.ETag, ifMatchETagHeader) {
			// If the object ETag does not match with the specified ETag.
			writeHeaders()
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
			return true
		}
	}

	// If-None-Match : Return the object only if its entity tag (ETag) is different from the
	// one specified otherwise, return a 304 (not modified).
	ifNoneMatchETagHeader := r.Header.Get(xhttp.IfNoneMatch)
	if ifNoneMatchETagHeader != "" {
		if isETagEqual(objInfo.ETag, ifNoneMatchETagHeader) {
			// If the object ETag matches with the specified ETag.
			writeHeaders()
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}

	etagMatch := opts.PreserveETag != "" && isETagEqual(objInfo.ETag, opts.PreserveETag)
	vidMatch := opts.VersionID != "" && opts.VersionID == objInfo.VersionID
	mtimeMatch := !opts.MTime.IsZero() && objInfo.ModTime.Unix() >= opts.MTime.Unix()
	if etagMatch && vidMatch && mtimeMatch {
		writeHeaders()
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
		return true
	}

	// Object content should be persisted.
	return false
}

// Validates the preconditions. Returns true if GET/HEAD operation should not proceed.
// Preconditions supported are:
//
//	If-Modified-Since
//	If-Unmodified-Since
//	If-Match
//	If-None-Match
func checkPreconditions(ctx context.Context, w http.ResponseWriter, r *http.Request, objInfo ObjectInfo, opts ObjectOptions) bool {
	// Return false for methods other than GET and HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	// If the object doesn't have a modtime (IsZero), or the modtime
	// is obviously garbage (Unix time == 0), then ignore modtimes
	// and don't process the If-Modified-Since header.
	if objInfo.ModTime.IsZero() || objInfo.ModTime.Equal(time.Unix(0, 0)) {
		return false
	}

	// Headers to be set of object content is not going to be written to the client.
	writeHeaders := func() {
		// set common headers
		setCommonHeaders(w)

		// set object-related metadata headers
		w.Header().Set(xhttp.LastModified, objInfo.ModTime.UTC().Format(http.TimeFormat))

		if objInfo.ETag != "" {
			w.Header()[xhttp.ETag] = []string{"\"" + objInfo.ETag + "\""}
		}
	}

	// Check if the part number is correct.
	if opts.PartNumber > 1 && opts.PartNumber > len(objInfo.Parts) {
		// According to S3 we don't need to set any object information here.
		writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrInvalidPartNumber), r.URL)
		return true
	}

	// If-Modified-Since : Return the object only if it has been modified since the specified time,
	// otherwise return a 304 (not modified).
	ifModifiedSinceHeader := r.Header.Get(xhttp.IfModifiedSince)
	if ifModifiedSinceHeader != "" {
		if givenTime, err := amztime.ParseHeader(ifModifiedSinceHeader); err == nil {
			if !ifModifiedSince(objInfo.ModTime, givenTime) {
				// If the object is not modified since the specified time.
				writeHeaders()
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}

	// If-Unmodified-Since : Return the object only if it has not been modified since the specified
	// time, otherwise return a 412 (precondition failed).
	ifUnmodifiedSinceHeader := r.Header.Get(xhttp.IfUnmodifiedSince)
	if ifUnmodifiedSinceHeader != "" {
		if givenTime, err := amztime.ParseHeader(ifUnmodifiedSinceHeader); err == nil {
			if ifModifiedSince(objInfo.ModTime, givenTime) {
				// If the object is modified since the specified time.
				writeHeaders()
				writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
				return true
			}
		}
	}

	// If-Match : Return the object only if its entity tag (ETag) is the same as the one specified;
	// otherwise return a 412 (precondition failed).
	ifMatchETagHeader := r.Header.Get(xhttp.IfMatch)
	if ifMatchETagHeader != "" {
		if !isETagEqual(objInfo.ETag, ifMatchETagHeader) {
			// If the object ETag does not match with the specified ETag.
			writeHeaders()
			writeErrorResponse(ctx, w, errorCodes.ToAPIErr(ErrPreconditionFailed), r.URL)
			return true
		}
	}

	// If-None-Match : Return the object only if its entity tag (ETag) is different from the
	// one specified otherwise, return a 304 (not modified).
	ifNoneMatchETagHeader := r.Header.Get(xhttp.IfNoneMatch)
	if ifNoneMatchETagHeader != "" {
		if isETagEqual(objInfo.ETag, ifNoneMatchETagHeader) {
			// If the object ETag matches with the specified ETag.
			writeHeaders()
			w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	// Object content should be written to http.ResponseWriter
	return false
}

// returns true if object was modified after givenTime.
func ifModifiedSince(objTime time.Time, givenTime time.Time) bool {
	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	return objTime.After(givenTime.Add(1 * time.Second))
}

// canonicalizeETag returns ETag with leading and trailing double-quotes removed,
// if any present
func canonicalizeETag(etag string) string {
	return etagRegex.ReplaceAllString(etag, "$1")
}

// isETagEqual return true if the canonical representations of two ETag strings
// are equal, false otherwise
func isETagEqual(left, right string) bool {
	return canonicalizeETag(left) == canonicalizeETag(right)
}

// setPutObjHeaders sets all the necessary headers returned back
// upon a success Put/Copy/CompleteMultipart/Delete requests
// to activate delete only headers set delete as true
func setPutObjHeaders(w http.ResponseWriter, objInfo ObjectInfo, delete bool) {
	// We must not use the http.Header().Set method here because some (broken)
	// clients expect the ETag header key to be literally "ETag" - not "Etag" (case-sensitive).
	// Therefore, we have to set the ETag directly as map entry.
	if objInfo.ETag != "" && !delete {
		w.Header()[xhttp.ETag] = []string{`"` + objInfo.ETag + `"`}
	}

	// Set the relevant version ID as part of the response header.
	if objInfo.VersionID != "" {
		w.Header()[xhttp.AmzVersionID] = []string{objInfo.VersionID}
		// If version is a deleted marker, set this header as well
		if objInfo.DeleteMarker && delete { // only returned during delete object
			w.Header()[xhttp.AmzDeleteMarker] = []string{strconv.FormatBool(objInfo.DeleteMarker)}
		}
	}

	if objInfo.Bucket != "" && objInfo.Name != "" {
		if lc, err := globalLifecycleSys.Get(objInfo.Bucket); err == nil && !delete {
			lc.SetPredictionHeaders(w, objInfo.ToLifecycleOpts())
		}
	}
	hash.AddChecksumHeader(w, objInfo.decryptChecksums())
}

func deleteObjectVersions(ctx context.Context, o ObjectLayer, bucket string, toDel []ObjectToDelete) {
	for remaining := toDel; len(remaining) > 0; toDel = remaining {
		if len(toDel) > maxDeleteList {
			remaining = toDel[maxDeleteList:]
			toDel = toDel[:maxDeleteList]
		} else {
			remaining = nil
		}
		vc, _ := globalBucketVersioningSys.Get(bucket)
		deletedObjs, errs := o.DeleteObjects(ctx, bucket, toDel, ObjectOptions{
			PrefixEnabledFn:  vc.PrefixEnabled,
			VersionSuspended: vc.Suspended(),
		})
		var logged bool
		for i, err := range errs {
			if err != nil {
				if !logged {
					// log the first error
					logger.LogIf(ctx, err)
					logged = true
				}
				continue
			}
			dobj := deletedObjs[i]
			sendEvent(eventArgs{
				EventName:  event.ObjectRemovedDelete,
				BucketName: bucket,
				Object: ObjectInfo{
					Name:      dobj.ObjectName,
					VersionID: dobj.VersionID,
				},
				Host: "Internal: [ILM-Expiry]",
			})
		}
	}
}
