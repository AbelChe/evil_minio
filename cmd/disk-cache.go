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
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/color"
	"github.com/minio/minio/internal/config/cache"
	"github.com/minio/minio/internal/disk"
	"github.com/minio/minio/internal/hash"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/sync/errgroup"
	xnet "github.com/minio/pkg/net"
	"github.com/minio/pkg/wildcard"
)

const (
	cacheBlkSize          = 1 << 20
	cacheGCInterval       = time.Minute * 30
	writeBackStatusHeader = ReservedMetadataPrefixLower + "write-back-status"
	writeBackRetryHeader  = ReservedMetadataPrefixLower + "write-back-retry"
)

type cacheCommitStatus string

const (
	// CommitPending - cache writeback with backend is pending.
	CommitPending cacheCommitStatus = "pending"

	// CommitComplete - cache writeback completed ok.
	CommitComplete cacheCommitStatus = "complete"

	// CommitFailed - cache writeback needs a retry.
	CommitFailed cacheCommitStatus = "failed"
)

const (
	// CommitWriteBack allows staging and write back of cached content for single object uploads
	CommitWriteBack string = "writeback"
	// CommitWriteThrough allows caching multipart uploads to disk synchronously
	CommitWriteThrough string = "writethrough"
)

// String returns string representation of status
func (s cacheCommitStatus) String() string {
	return string(s)
}

// CacheStorageInfo - represents total, free capacity of
// underlying cache storage.
type CacheStorageInfo struct {
	Total uint64 // Total cache disk space.
	Free  uint64 // Free cache available space.
}

// CacheObjectLayer implements primitives for cache object API layer.
type CacheObjectLayer interface {
	// Object operations.
	GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (gr *GetObjectReader, err error)
	GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error)
	DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error)
	DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error)
	PutObject(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error)
	CopyObject(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error)
	// Multipart operations.
	NewMultipartUpload(ctx context.Context, bucket, object string, opts ObjectOptions) (res *NewMultipartUploadResult, err error)
	PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error)
	AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error
	CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (objInfo ObjectInfo, err error)
	CopyObjectPart(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject, uploadID string, partID int, startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (pi PartInfo, e error)

	// Storage operations.
	StorageInfo(ctx context.Context) CacheStorageInfo
	CacheStats() *CacheStats
}

// Abstracts disk caching - used by the S3 layer
type cacheObjects struct {
	// slice of cache drives
	cache []*diskCache
	// file path patterns to exclude from cache
	exclude []string
	// number of accesses after which to cache an object
	after int
	// commit objects in async manner
	commitWriteback    bool
	commitWritethrough bool

	// if true migration is in progress from v1 to v2
	migrating bool
	// retry queue for writeback cache mode to reattempt upload to backend
	wbRetryCh chan ObjectInfo
	// Cache stats
	cacheStats *CacheStats

	InnerGetObjectNInfoFn          func(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (gr *GetObjectReader, err error)
	InnerGetObjectInfoFn           func(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error)
	InnerDeleteObjectFn            func(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error)
	InnerPutObjectFn               func(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error)
	InnerCopyObjectFn              func(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error)
	InnerNewMultipartUploadFn      func(ctx context.Context, bucket, object string, opts ObjectOptions) (res *NewMultipartUploadResult, err error)
	InnerPutObjectPartFn           func(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error)
	InnerAbortMultipartUploadFn    func(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error
	InnerCompleteMultipartUploadFn func(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (objInfo ObjectInfo, err error)
	InnerCopyObjectPartFn          func(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject, uploadID string, partID int, startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (pi PartInfo, e error)
}

func (c *cacheObjects) incHitsToMeta(ctx context.Context, dcache *diskCache, bucket, object string, size int64, eTag string, rs *HTTPRangeSpec) error {
	metadata := map[string]string{"etag": eTag}
	return dcache.SaveMetadata(ctx, bucket, object, metadata, size, rs, "", true, false)
}

// Backend metadata could have changed through server side copy - reset cache metadata if that is the case
func (c *cacheObjects) updateMetadataIfChanged(ctx context.Context, dcache *diskCache, bucket, object string, bkObjectInfo, cacheObjInfo ObjectInfo, rs *HTTPRangeSpec) error {
	bkMeta := make(map[string]string, len(bkObjectInfo.UserDefined))
	cacheMeta := make(map[string]string, len(cacheObjInfo.UserDefined))
	for k, v := range bkObjectInfo.UserDefined {
		if strings.HasPrefix(strings.ToLower(k), ReservedMetadataPrefixLower) {
			// Do not need to send any internal metadata
			continue
		}
		bkMeta[http.CanonicalHeaderKey(k)] = v
	}
	for k, v := range cacheObjInfo.UserDefined {
		if strings.HasPrefix(strings.ToLower(k), ReservedMetadataPrefixLower) {
			// Do not need to send any internal metadata
			continue
		}
		cacheMeta[http.CanonicalHeaderKey(k)] = v
	}

	if !isMetadataSame(bkMeta, cacheMeta) ||
		bkObjectInfo.ETag != cacheObjInfo.ETag ||
		bkObjectInfo.ContentType != cacheObjInfo.ContentType ||
		!bkObjectInfo.Expires.Equal(cacheObjInfo.Expires) {
		return dcache.SaveMetadata(ctx, bucket, object, getMetadata(bkObjectInfo), bkObjectInfo.Size, nil, "", false, false)
	}
	return c.incHitsToMeta(ctx, dcache, bucket, object, cacheObjInfo.Size, cacheObjInfo.ETag, rs)
}

// DeleteObject clears cache entry if backend delete operation succeeds
func (c *cacheObjects) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	if objInfo, err = c.InnerDeleteObjectFn(ctx, bucket, object, opts); err != nil {
		return
	}
	if c.isCacheExclude(bucket, object) || c.skipCache() {
		return
	}

	dcache, cerr := c.getCacheLoc(bucket, object)
	if cerr != nil {
		return objInfo, cerr
	}
	dcache.Delete(ctx, bucket, object)
	return
}

// DeleteObjects batch deletes objects in slice, and clears any cached entries
func (c *cacheObjects) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	errs := make([]error, len(objects))
	objInfos := make([]ObjectInfo, len(objects))
	for idx, object := range objects {
		opts.VersionID = object.VersionID
		objInfos[idx], errs[idx] = c.DeleteObject(ctx, bucket, object.ObjectName, opts)
	}
	deletedObjects := make([]DeletedObject, len(objInfos))
	for idx := range errs {
		if errs[idx] != nil {
			continue
		}
		if objInfos[idx].DeleteMarker {
			deletedObjects[idx] = DeletedObject{
				DeleteMarker:          objInfos[idx].DeleteMarker,
				DeleteMarkerVersionID: objInfos[idx].VersionID,
			}
			continue
		}
		deletedObjects[idx] = DeletedObject{
			ObjectName: objInfos[idx].Name,
			VersionID:  objInfos[idx].VersionID,
		}
	}
	return deletedObjects, errs
}

// construct a metadata k-v map
func getMetadata(objInfo ObjectInfo) map[string]string {
	metadata := make(map[string]string, len(objInfo.UserDefined)+4)
	metadata["etag"] = objInfo.ETag
	metadata["content-type"] = objInfo.ContentType
	if objInfo.ContentEncoding != "" {
		metadata["content-encoding"] = objInfo.ContentEncoding
	}
	if !objInfo.Expires.Equal(timeSentinel) {
		metadata["expires"] = objInfo.Expires.Format(http.TimeFormat)
	}
	metadata["last-modified"] = objInfo.ModTime.Format(http.TimeFormat)
	for k, v := range objInfo.UserDefined {
		metadata[k] = v
	}
	return metadata
}

// marks cache hit
func (c *cacheObjects) incCacheStats(size int64) {
	c.cacheStats.incHit()
	c.cacheStats.incBytesServed(size)
}

func (c *cacheObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (gr *GetObjectReader, err error) {
	if c.isCacheExclude(bucket, object) || c.skipCache() {
		return c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)
	}
	var cc *cacheControl
	var cacheObjSize int64
	// fetch diskCache if object is currently cached or nearest available cache drive
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		return c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)
	}

	cacheReader, numCacheHits, cacheErr := dcache.Get(ctx, bucket, object, rs, h, opts)
	if cacheErr == nil {
		cacheObjSize = cacheReader.ObjInfo.Size
		if rs != nil {
			if _, len, err := rs.GetOffsetLength(cacheObjSize); err == nil {
				cacheObjSize = len
			}
		}
		cc = cacheControlOpts(cacheReader.ObjInfo)
		if cc != nil && (!cc.isStale(cacheReader.ObjInfo.ModTime) ||
			cc.onlyIfCached) {
			// This is a cache hit, mark it so
			bytesServed := cacheReader.ObjInfo.Size
			if rs != nil {
				if _, len, err := rs.GetOffsetLength(bytesServed); err == nil {
					bytesServed = len
				}
			}
			c.cacheStats.incHit()
			c.cacheStats.incBytesServed(bytesServed)
			c.incHitsToMeta(ctx, dcache, bucket, object, cacheReader.ObjInfo.Size, cacheReader.ObjInfo.ETag, rs)
			return cacheReader, nil
		}
		if cc != nil && cc.noStore {
			cacheReader.Close()
			c.cacheStats.incMiss()
			bReader, err := c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)
			bReader.ObjInfo.CacheLookupStatus = CacheHit
			bReader.ObjInfo.CacheStatus = CacheMiss
			return bReader, err
		}
		// serve cached content without ETag verification if writeback commit is not yet complete
		if writebackInProgress(cacheReader.ObjInfo.UserDefined) {
			return cacheReader, nil
		}
	}

	objInfo, err := c.InnerGetObjectInfoFn(ctx, bucket, object, opts)
	if backendDownError(err) && cacheErr == nil {
		c.incCacheStats(cacheObjSize)
		return cacheReader, nil
	} else if err != nil {
		if cacheErr == nil {
			cacheReader.Close()
		}
		if _, ok := err.(ObjectNotFound); ok {
			if cacheErr == nil {
				// Delete cached entry if backend object
				// was deleted.
				dcache.Delete(ctx, bucket, object)
			}
		}
		c.cacheStats.incMiss()
		return nil, err
	}

	if !objInfo.IsCacheable() {
		if cacheErr == nil {
			cacheReader.Close()
		}
		c.cacheStats.incMiss()
		return c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)
	}
	// skip cache for objects with locks
	objRetention := objectlock.GetObjectRetentionMeta(objInfo.UserDefined)
	legalHold := objectlock.GetObjectLegalHoldMeta(objInfo.UserDefined)
	if objRetention.Mode.Valid() || legalHold.Status.Valid() {
		if cacheErr == nil {
			cacheReader.Close()
		}
		c.cacheStats.incMiss()
		return c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)
	}
	if cacheErr == nil {
		// if ETag matches for stale cache entry, serve from cache
		if cacheReader.ObjInfo.ETag == objInfo.ETag {
			// Update metadata in case server-side copy might have changed object metadata
			c.updateMetadataIfChanged(ctx, dcache, bucket, object, objInfo, cacheReader.ObjInfo, rs)
			c.incCacheStats(cacheObjSize)
			return cacheReader, nil
		}
		cacheReader.Close()
		// Object is stale, so delete from cache
		dcache.Delete(ctx, bucket, object)
	}

	// Reaching here implies cache miss
	c.cacheStats.incMiss()

	bkReader, bkErr := c.InnerGetObjectNInfoFn(ctx, bucket, object, rs, h, lockType, opts)

	if bkErr != nil {
		return bkReader, bkErr
	}
	// If object has less hits than configured cache after, just increment the hit counter
	// but do not cache it.
	if numCacheHits < c.after {
		c.incHitsToMeta(ctx, dcache, bucket, object, objInfo.Size, objInfo.ETag, rs)
		return bkReader, bkErr
	}

	// Record if cache has a hit that was invalidated by ETag verification
	if cacheErr == nil {
		bkReader.ObjInfo.CacheLookupStatus = CacheHit
	}

	// Check if we can add it without exceeding total cache size.
	if !dcache.diskSpaceAvailable(objInfo.Size) {
		return bkReader, bkErr
	}

	if rs != nil && !dcache.enableRange {
		go func() {
			// if range caching is disabled, download entire object.
			rs = nil
			// fill cache in the background for range GET requests
			bReader, bErr := c.InnerGetObjectNInfoFn(GlobalContext, bucket, object, rs, h, lockType, opts)
			if bErr != nil {
				return
			}
			defer bReader.Close()
			oi, _, _, err := dcache.statRange(GlobalContext, bucket, object, rs)
			// avoid cache overwrite if another background routine filled cache
			if err != nil || oi.ETag != bReader.ObjInfo.ETag {
				// use a new context to avoid locker prematurely timing out operation when the GetObjectNInfo returns.
				dcache.Put(GlobalContext, bucket, object, bReader, bReader.ObjInfo.Size, rs, ObjectOptions{
					UserDefined: getMetadata(bReader.ObjInfo),
				}, false, false)
				return
			}
		}()
		return bkReader, bkErr
	}

	// Initialize pipe.
	pr, pw := io.Pipe()
	var wg sync.WaitGroup
	teeReader := io.TeeReader(bkReader, pw)
	userDefined := getMetadata(bkReader.ObjInfo)
	wg.Add(1)
	go func() {
		_, putErr := dcache.Put(ctx, bucket, object,
			io.LimitReader(pr, bkReader.ObjInfo.Size),
			bkReader.ObjInfo.Size, rs, ObjectOptions{
				UserDefined: userDefined,
			}, false, false)
		// close the read end of the pipe, so the error gets
		// propagated to teeReader
		pr.CloseWithError(putErr)
		wg.Done()
	}()
	cleanupBackend := func() {
		pw.CloseWithError(bkReader.Close())
		wg.Wait()
	}
	return NewGetObjectReaderFromReader(teeReader, bkReader.ObjInfo, opts, cleanupBackend)
}

// Returns ObjectInfo from cache if available.
func (c *cacheObjects) GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	getObjectInfoFn := c.InnerGetObjectInfoFn

	if c.isCacheExclude(bucket, object) || c.skipCache() {
		return getObjectInfoFn(ctx, bucket, object, opts)
	}

	// fetch diskCache if object is currently cached or nearest available cache drive
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		return getObjectInfoFn(ctx, bucket, object, opts)
	}
	var cc *cacheControl
	// if cache control setting is valid, avoid HEAD operation to backend
	cachedObjInfo, _, cerr := dcache.Stat(ctx, bucket, object)
	if cerr == nil {
		cc = cacheControlOpts(cachedObjInfo)
		if cc == nil || (cc != nil && !cc.isStale(cachedObjInfo.ModTime)) {
			// This is a cache hit, mark it so
			c.cacheStats.incHit()
			return cachedObjInfo, nil
		}
		// serve cache metadata without ETag verification if writeback commit is not yet complete
		if writebackInProgress(cachedObjInfo.UserDefined) {
			return cachedObjInfo, nil
		}
	}

	objInfo, err := getObjectInfoFn(ctx, bucket, object, opts)
	if err != nil {
		if _, ok := err.(ObjectNotFound); ok {
			// Delete the cached entry if backend object was deleted.
			dcache.Delete(ctx, bucket, object)
			c.cacheStats.incMiss()
			return ObjectInfo{}, err
		}
		if !backendDownError(err) {
			c.cacheStats.incMiss()
			return ObjectInfo{}, err
		}
		if cerr == nil {
			// This is a cache hit, mark it so
			c.cacheStats.incHit()
			return cachedObjInfo, nil
		}
		c.cacheStats.incMiss()
		if xnet.IsNetworkOrHostDown(err, false) {
			return ObjectInfo{}, BackendDown{Err: err.Error()}
		}
		return ObjectInfo{}, err
	}
	// Reaching here implies cache miss
	c.cacheStats.incMiss()
	// when backend is up, do a sanity check on cached object
	if cerr != nil {
		return objInfo, nil
	}
	if cachedObjInfo.ETag != objInfo.ETag {
		// Delete the cached entry if the backend object was replaced.
		dcache.Delete(ctx, bucket, object)
	}
	return objInfo, nil
}

// CopyObject reverts to backend after evicting any stale cache entries
func (c *cacheObjects) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error) {
	copyObjectFn := c.InnerCopyObjectFn
	if c.isCacheExclude(srcBucket, srcObject) || c.skipCache() {
		return copyObjectFn(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
	}
	if srcBucket != dstBucket || srcObject != dstObject {
		return copyObjectFn(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
	}
	// fetch diskCache if object is currently cached or nearest available cache drive
	dcache, err := c.getCacheToLoc(ctx, srcBucket, srcObject)
	if err != nil {
		return copyObjectFn(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
	}
	// if currently cached, evict old entry and revert to backend.
	if cachedObjInfo, _, cerr := dcache.Stat(ctx, srcBucket, srcObject); cerr == nil {
		cc := cacheControlOpts(cachedObjInfo)
		if cc == nil || !cc.isStale(cachedObjInfo.ModTime) {
			dcache.Delete(ctx, srcBucket, srcObject)
		}
	}
	return copyObjectFn(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
}

// StorageInfo - returns underlying storage statistics.
func (c *cacheObjects) StorageInfo(ctx context.Context) (cInfo CacheStorageInfo) {
	var total, free uint64
	for _, cache := range c.cache {
		if cache == nil {
			continue
		}
		info, err := getDiskInfo(cache.dir)
		logger.GetReqInfo(ctx).AppendTags("cachePath", cache.dir)
		logger.LogIf(ctx, err)
		total += info.Total
		free += info.Free
	}
	return CacheStorageInfo{
		Total: total,
		Free:  free,
	}
}

// CacheStats - returns underlying storage statistics.
func (c *cacheObjects) CacheStats() (cs *CacheStats) {
	return c.cacheStats
}

// skipCache() returns true if cache migration is in progress
func (c *cacheObjects) skipCache() bool {
	return c.migrating
}

// Returns true if object should be excluded from cache
func (c *cacheObjects) isCacheExclude(bucket, object string) bool {
	// exclude directories from cache
	if strings.HasSuffix(object, SlashSeparator) {
		return true
	}
	for _, pattern := range c.exclude {
		matchStr := fmt.Sprintf("%s/%s", bucket, object)
		if ok := wildcard.MatchSimple(pattern, matchStr); ok {
			return true
		}
	}
	return false
}

// choose a cache deterministically based on hash of bucket,object. The hash index is treated as
// a hint. In the event that the cache drive at hash index is offline, treat the list of cache drives
// as a circular buffer and walk through them starting at hash index until an online drive is found.
func (c *cacheObjects) getCacheLoc(bucket, object string) (*diskCache, error) {
	index := c.hashIndex(bucket, object)
	numDisks := len(c.cache)
	for k := 0; k < numDisks; k++ {
		i := (index + k) % numDisks
		if c.cache[i] == nil {
			continue
		}
		if c.cache[i].IsOnline() {
			return c.cache[i], nil
		}
	}
	return nil, errDiskNotFound
}

// get cache disk where object is currently cached for a GET operation. If object does not exist at that location,
// treat the list of cache drives as a circular buffer and walk through them starting at hash index
// until an online drive is found.If object is not found, fall back to the first online cache drive
// closest to the hash index, so that object can be re-cached.
func (c *cacheObjects) getCacheToLoc(ctx context.Context, bucket, object string) (*diskCache, error) {
	index := c.hashIndex(bucket, object)

	numDisks := len(c.cache)
	// save first online cache disk closest to the hint index
	var firstOnlineDisk *diskCache
	for k := 0; k < numDisks; k++ {
		i := (index + k) % numDisks
		if c.cache[i] == nil {
			continue
		}
		if c.cache[i].IsOnline() {
			if firstOnlineDisk == nil {
				firstOnlineDisk = c.cache[i]
			}
			if c.cache[i].Exists(ctx, bucket, object) {
				return c.cache[i], nil
			}
		}
	}

	if firstOnlineDisk != nil {
		return firstOnlineDisk, nil
	}
	return nil, errDiskNotFound
}

// Compute a unique hash sum for bucket and object
func (c *cacheObjects) hashIndex(bucket, object string) int {
	return crcHashMod(pathJoin(bucket, object), len(c.cache))
}

// newCache initializes the cacheFSObjects for the "drives" specified in config.json
// or the global env overrides.
func newCache(config cache.Config) ([]*diskCache, bool, error) {
	var caches []*diskCache
	ctx := logger.SetReqInfo(GlobalContext, &logger.ReqInfo{})
	formats, migrating, err := loadAndValidateCacheFormat(ctx, config.Drives)
	if err != nil {
		return nil, false, err
	}
	var warningMsg string
	for i, dir := range config.Drives {
		// skip diskCache creation for cache drives missing a format.json
		if formats[i] == nil {
			caches = append(caches, nil)
			continue
		}
		if !globalIsCICD && len(warningMsg) == 0 {
			rootDsk, err := disk.IsRootDisk(dir, "/")
			if err != nil {
				warningMsg = fmt.Sprintf("Invalid cache dir %s err : %s", dir, err.Error())
			}
			if rootDsk {
				warningMsg = fmt.Sprintf("cache dir cannot be part of root drive: %s", dir)
			}
		}

		if err := checkAtimeSupport(dir); err != nil {
			return nil, false, fmt.Errorf("Atime support required for drive caching, atime check failed with %w", err)
		}

		cache, err := newDiskCache(ctx, dir, config)
		if err != nil {
			return nil, false, err
		}
		caches = append(caches, cache)
	}
	if warningMsg != "" {
		logger.Info(color.Yellow(fmt.Sprintf("WARNING: Usage of root drive for drive caching is deprecated: %s", warningMsg)))
	}
	return caches, migrating, nil
}

func (c *cacheObjects) migrateCacheFromV1toV2(ctx context.Context) {
	logger.Info(color.Blue("Cache migration initiated ...."))

	g := errgroup.WithNErrs(len(c.cache))
	for index, dc := range c.cache {
		if dc == nil {
			continue
		}
		index := index
		g.Go(func() error {
			// start migration from V1 to V2
			return migrateOldCache(ctx, c.cache[index])
		}, index)
	}

	errCnt := 0
	for _, err := range g.Wait() {
		if err != nil {
			errCnt++
			logger.LogIf(ctx, err)
			continue
		}
	}

	if errCnt > 0 {
		return
	}

	// update migration status
	c.migrating = false
	logger.Info(color.Blue("Cache migration completed successfully."))
}

// PutObject - caches the uploaded object for single Put operations
func (c *cacheObjects) PutObject(ctx context.Context, bucket, object string, r *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	putObjectFn := c.InnerPutObjectFn
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return putObjectFn(ctx, bucket, object, r, opts)
	}
	size := r.Size()
	if c.skipCache() {
		return putObjectFn(ctx, bucket, object, r, opts)
	}

	// fetch from backend if there is no space on cache drive
	if !dcache.diskSpaceAvailable(size) {
		return putObjectFn(ctx, bucket, object, r, opts)
	}

	if opts.ServerSideEncryption != nil {
		dcache.Delete(ctx, bucket, object)
		return putObjectFn(ctx, bucket, object, r, opts)
	}

	// skip cache for objects with locks
	objRetention := objectlock.GetObjectRetentionMeta(opts.UserDefined)
	legalHold := objectlock.GetObjectLegalHoldMeta(opts.UserDefined)
	if objRetention.Mode.Valid() || legalHold.Status.Valid() {
		dcache.Delete(ctx, bucket, object)
		return putObjectFn(ctx, bucket, object, r, opts)
	}

	// fetch from backend if cache exclude pattern or cache-control
	// directive set to exclude
	if c.isCacheExclude(bucket, object) {
		dcache.Delete(ctx, bucket, object)
		return putObjectFn(ctx, bucket, object, r, opts)
	}
	if c.commitWriteback {
		oi, err := dcache.Put(ctx, bucket, object, r, r.Size(), nil, opts, false, true)
		if err != nil {
			return ObjectInfo{}, err
		}
		go c.uploadObject(GlobalContext, oi)
		return oi, nil
	}
	if !c.commitWritethrough {
		objInfo, err = putObjectFn(ctx, bucket, object, r, opts)
		if err == nil {
			go func() {
				// fill cache in the background
				bReader, bErr := c.InnerGetObjectNInfoFn(GlobalContext, bucket, object, nil, http.Header{}, readLock, ObjectOptions{})
				if bErr != nil {
					return
				}
				defer bReader.Close()
				oi, _, err := dcache.Stat(GlobalContext, bucket, object)
				// avoid cache overwrite if another background routine filled cache
				if err != nil || oi.ETag != bReader.ObjInfo.ETag {
					dcache.Put(GlobalContext, bucket, object, bReader, bReader.ObjInfo.Size, nil, ObjectOptions{UserDefined: getMetadata(bReader.ObjInfo)}, false, false)
				}
			}()
		}
		return objInfo, err
	}
	cLock, lkctx, cerr := dcache.GetLockContext(GlobalContext, bucket, object)
	if cerr != nil {
		return putObjectFn(ctx, bucket, object, r, opts)
	}
	defer cLock.Unlock(lkctx)
	// Initialize pipe to stream data to backend
	pipeReader, pipeWriter := io.Pipe()
	hashReader, err := hash.NewReader(pipeReader, size, "", "", r.ActualSize())
	if err != nil {
		return
	}
	// Initialize pipe to stream data to cache
	rPipe, wPipe := io.Pipe()
	infoCh := make(chan ObjectInfo)
	go func() {
		defer close(infoCh)
		info, err := putObjectFn(ctx, bucket, object, NewPutObjReader(hashReader), opts)
		pipeReader.CloseWithError(err)
		rPipe.CloseWithError(err)
		if err == nil {
			infoCh <- info
		}
	}()

	go func() {
		_, err := dcache.put(lkctx.Context(), bucket, object, rPipe, r.Size(), nil, opts, false, false)
		if err != nil {
			logger.LogIf(lkctx.Context(), err)
		}
		// We do not care about errors to cached backend.
		rPipe.Close()
	}()

	mwriter := cacheMultiWriter(pipeWriter, wPipe)
	_, err = io.Copy(mwriter, r)
	pipeWriter.Close()
	wPipe.Close()
	if err != nil {
		return ObjectInfo{}, err
	}
	info := <-infoCh
	if cerr = dcache.updateMetadata(lkctx.Context(), bucket, object, info.ETag, info.ModTime, info.Size); cerr != nil {
		dcache.delete(bucket, object)
	}
	return info, err
}

// upload cached object to backend in async commit mode.
func (c *cacheObjects) uploadObject(ctx context.Context, oi ObjectInfo) {
	dcache, err := c.getCacheToLoc(ctx, oi.Bucket, oi.Name)
	if err != nil {
		// disk cache could not be located.
		logger.LogIf(ctx, fmt.Errorf("Could not upload %s/%s to backend: %w", oi.Bucket, oi.Name, err))
		return
	}
	cReader, _, bErr := dcache.Get(ctx, oi.Bucket, oi.Name, nil, http.Header{}, ObjectOptions{})
	if bErr != nil {
		return
	}
	defer cReader.Close()

	if cReader.ObjInfo.ETag != oi.ETag {
		return
	}
	st := cacheCommitStatus(oi.UserDefined[writeBackStatusHeader])
	if st == CommitComplete || st.String() == "" {
		return
	}
	hashReader, err := hash.NewReader(cReader, oi.Size, "", "", oi.Size)
	if err != nil {
		return
	}
	var opts ObjectOptions
	opts.UserDefined = cloneMSS(oi.UserDefined)
	objInfo, err := c.InnerPutObjectFn(ctx, oi.Bucket, oi.Name, NewPutObjReader(hashReader), opts)
	wbCommitStatus := CommitComplete
	size := objInfo.Size
	if err != nil {
		wbCommitStatus = CommitFailed
	}

	meta := cloneMSS(cReader.ObjInfo.UserDefined)
	retryCnt := 0
	if wbCommitStatus == CommitFailed {
		retryCnt, _ = strconv.Atoi(meta[writeBackRetryHeader])
		retryCnt++
		meta[writeBackRetryHeader] = strconv.Itoa(retryCnt)
		size = cReader.ObjInfo.Size
	} else {
		delete(meta, writeBackRetryHeader)
	}
	meta[writeBackStatusHeader] = wbCommitStatus.String()
	meta["etag"] = oi.ETag
	dcache.SaveMetadata(ctx, oi.Bucket, oi.Name, meta, size, nil, "", false, wbCommitStatus == CommitComplete)
	if retryCnt > 0 {
		// slow down retries
		time.Sleep(time.Second * time.Duration(retryCnt%10+1))
		c.queueWritebackRetry(oi)
	}
}

func (c *cacheObjects) queueWritebackRetry(oi ObjectInfo) {
	select {
	case <-GlobalContext.Done():
		return
	case c.wbRetryCh <- oi:
		c.uploadObject(GlobalContext, oi)
	default:
	}
}

// Returns cacheObjects for use by Server.
func newServerCacheObjects(ctx context.Context, config cache.Config) (CacheObjectLayer, error) {
	// list of disk caches for cache "drives" specified in config.json or MINIO_CACHE_DRIVES env var.
	cache, migrateSw, err := newCache(config)
	if err != nil {
		return nil, err
	}
	c := &cacheObjects{
		cache:              cache,
		exclude:            config.Exclude,
		after:              config.After,
		migrating:          migrateSw,
		commitWriteback:    config.CacheCommitMode == CommitWriteBack,
		commitWritethrough: config.CacheCommitMode == CommitWriteThrough,

		cacheStats: newCacheStats(),
		InnerGetObjectInfoFn: func(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
			return newObjectLayerFn().GetObjectInfo(ctx, bucket, object, opts)
		},
		InnerGetObjectNInfoFn: func(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (gr *GetObjectReader, err error) {
			return newObjectLayerFn().GetObjectNInfo(ctx, bucket, object, rs, h, lockType, opts)
		},
		InnerDeleteObjectFn: func(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
			return newObjectLayerFn().DeleteObject(ctx, bucket, object, opts)
		},
		InnerPutObjectFn: func(ctx context.Context, bucket, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
			return newObjectLayerFn().PutObject(ctx, bucket, object, data, opts)
		},
		InnerCopyObjectFn: func(ctx context.Context, srcBucket, srcObject, destBucket, destObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (objInfo ObjectInfo, err error) {
			return newObjectLayerFn().CopyObject(ctx, srcBucket, srcObject, destBucket, destObject, srcInfo, srcOpts, dstOpts)
		},
		InnerNewMultipartUploadFn: func(ctx context.Context, bucket, object string, opts ObjectOptions) (res *NewMultipartUploadResult, err error) {
			return newObjectLayerFn().NewMultipartUpload(ctx, bucket, object, opts)
		},
		InnerPutObjectPartFn: func(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error) {
			return newObjectLayerFn().PutObjectPart(ctx, bucket, object, uploadID, partID, data, opts)
		},
		InnerAbortMultipartUploadFn: func(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error {
			return newObjectLayerFn().AbortMultipartUpload(ctx, bucket, object, uploadID, opts)
		},
		InnerCompleteMultipartUploadFn: func(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (objInfo ObjectInfo, err error) {
			return newObjectLayerFn().CompleteMultipartUpload(ctx, bucket, object, uploadID, uploadedParts, opts)
		},
		InnerCopyObjectPartFn: func(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject, uploadID string, partID int, startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (pi PartInfo, e error) {
			return newObjectLayerFn().CopyObjectPart(ctx, srcBucket, srcObject, dstBucket, dstObject, uploadID, partID, startOffset, length, srcInfo, srcOpts, dstOpts)
		},
	}
	c.cacheStats.GetDiskStats = func() []CacheDiskStats {
		cacheDiskStats := make([]CacheDiskStats, len(c.cache))
		for i := range c.cache {
			dcache := c.cache[i]
			cacheDiskStats[i] = CacheDiskStats{}
			if dcache != nil {
				info, err := getDiskInfo(dcache.dir)
				logger.LogIf(ctx, err)
				cacheDiskStats[i].UsageSize = info.Used
				cacheDiskStats[i].TotalCapacity = info.Total
				cacheDiskStats[i].Dir = dcache.stats.Dir
				if info.Total != 0 {
					// UsageState
					gcTriggerPct := dcache.quotaPct * dcache.highWatermark / 100
					usedPercent := float64(info.Used) * 100 / float64(info.Total)
					if usedPercent >= float64(gcTriggerPct) {
						cacheDiskStats[i].UsageState = 1
					}
					// UsagePercent
					cacheDiskStats[i].UsagePercent = uint64(usedPercent)
				}
			}
		}
		return cacheDiskStats
	}
	if migrateSw {
		go c.migrateCacheFromV1toV2(ctx)
	}
	go c.gc(ctx)
	if c.commitWriteback {
		c.wbRetryCh = make(chan ObjectInfo, 10000)
		go func() {
			<-GlobalContext.Done()
			close(c.wbRetryCh)
		}()
		go c.queuePendingWriteback(ctx)
	}

	return c, nil
}

func (c *cacheObjects) gc(ctx context.Context) {
	ticker := time.NewTicker(cacheGCInterval)

	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.migrating {
				continue
			}
			for _, dcache := range c.cache {
				if dcache != nil {
					// Check if there is disk.
					// Will queue a GC scan if at high watermark.
					dcache.diskSpaceAvailable(0)
				}
			}
		}
	}
}

// queues any pending or failed async commits when server restarts
func (c *cacheObjects) queuePendingWriteback(ctx context.Context) {
	for _, dcache := range c.cache {
		if dcache != nil {
			for {
				select {
				case <-ctx.Done():
					return
				case oi, ok := <-dcache.retryWritebackCh:
					if !ok {
						goto next
					}
					c.queueWritebackRetry(oi)
				default:
					time.Sleep(time.Second * 1)
				}
			}
		next:
		}
	}
}

// NewMultipartUpload - Starts a new multipart upload operation to backend - if writethrough mode is enabled, starts caching the multipart.
func (c *cacheObjects) NewMultipartUpload(ctx context.Context, bucket, object string, opts ObjectOptions) (res *NewMultipartUploadResult, err error) {
	newMultipartUploadFn := c.InnerNewMultipartUploadFn
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}
	if c.skipCache() {
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}

	if opts.ServerSideEncryption != nil { // avoid caching encrypted objects
		dcache.Delete(ctx, bucket, object)
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}

	// skip cache for objects with locks
	objRetention := objectlock.GetObjectRetentionMeta(opts.UserDefined)
	legalHold := objectlock.GetObjectLegalHoldMeta(opts.UserDefined)
	if objRetention.Mode.Valid() || legalHold.Status.Valid() {
		dcache.Delete(ctx, bucket, object)
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}

	// fetch from backend if cache exclude pattern or cache-control
	// directive set to exclude
	if c.isCacheExclude(bucket, object) {
		dcache.Delete(ctx, bucket, object)
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}
	if !c.commitWritethrough && !c.commitWriteback {
		return newMultipartUploadFn(ctx, bucket, object, opts)
	}

	// perform multipart upload on backend and cache simultaneously
	res, err = newMultipartUploadFn(ctx, bucket, object, opts)
	if err == nil {
		dcache.NewMultipartUpload(GlobalContext, bucket, object, res.UploadID, opts)
	}
	return res, err
}

// PutObjectPart streams part to cache concurrently if writethrough mode is enabled. Otherwise redirects the call to remote
func (c *cacheObjects) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, data *PutObjReader, opts ObjectOptions) (info PartInfo, err error) {
	putObjectPartFn := c.InnerPutObjectPartFn
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}

	if !c.commitWritethrough && !c.commitWriteback {
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}
	if c.skipCache() {
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}
	size := data.Size()

	// avoid caching part if space unavailable
	if !dcache.diskSpaceAvailable(size) {
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}

	if opts.ServerSideEncryption != nil {
		dcache.Delete(ctx, bucket, object)
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}

	// skip cache for objects with locks
	objRetention := objectlock.GetObjectRetentionMeta(opts.UserDefined)
	legalHold := objectlock.GetObjectLegalHoldMeta(opts.UserDefined)
	if objRetention.Mode.Valid() || legalHold.Status.Valid() {
		dcache.Delete(ctx, bucket, object)
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}

	// fetch from backend if cache exclude pattern or cache-control
	// directive set to exclude
	if c.isCacheExclude(bucket, object) {
		dcache.Delete(ctx, bucket, object)
		return putObjectPartFn(ctx, bucket, object, uploadID, partID, data, opts)
	}

	info = PartInfo{}
	// Initialize pipe to stream data to backend
	pipeReader, pipeWriter := io.Pipe()
	hashReader, err := hash.NewReader(pipeReader, size, "", "", data.ActualSize())
	if err != nil {
		return
	}
	// Initialize pipe to stream data to cache
	rPipe, wPipe := io.Pipe()
	pinfoCh := make(chan PartInfo)
	cinfoCh := make(chan PartInfo)

	errorCh := make(chan error)
	go func() {
		info, err = putObjectPartFn(ctx, bucket, object, uploadID, partID, NewPutObjReader(hashReader), opts)
		if err != nil {
			close(pinfoCh)
			pipeReader.CloseWithError(err)
			rPipe.CloseWithError(err)
			errorCh <- err
			return
		}
		close(errorCh)
		pinfoCh <- info
	}()
	go func() {
		pinfo, perr := dcache.PutObjectPart(GlobalContext, bucket, object, uploadID, partID, rPipe, data.Size(), opts)
		if perr != nil {
			rPipe.CloseWithError(perr)
			close(cinfoCh)
			// clean up upload
			dcache.AbortUpload(bucket, object, uploadID)
			return
		}
		cinfoCh <- pinfo
	}()

	mwriter := cacheMultiWriter(pipeWriter, wPipe)
	_, err = io.Copy(mwriter, data)
	pipeWriter.Close()
	wPipe.Close()

	if err != nil {
		err = <-errorCh
		return PartInfo{}, err
	}
	info = <-pinfoCh
	cachedInfo := <-cinfoCh
	if info.PartNumber == cachedInfo.PartNumber {
		cachedInfo.ETag = info.ETag
		cachedInfo.LastModified = info.LastModified
		dcache.SavePartMetadata(GlobalContext, bucket, object, uploadID, partID, cachedInfo)
	}
	return info, err
}

// CopyObjectPart behaves similar to PutObjectPart - caches part to upload dir if writethrough mode is enabled.
func (c *cacheObjects) CopyObjectPart(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject, uploadID string, partID int, startOffset int64, length int64, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (pi PartInfo, e error) {
	copyObjectPartFn := c.InnerCopyObjectPartFn
	dcache, err := c.getCacheToLoc(ctx, dstBucket, dstObject)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return copyObjectPartFn(ctx, srcBucket, srcObject, dstBucket, dstObject, uploadID, partID, startOffset, length, srcInfo, srcOpts, dstOpts)
	}

	if !c.commitWritethrough && !c.commitWriteback {
		return copyObjectPartFn(ctx, srcBucket, srcObject, dstBucket, dstObject, uploadID, partID, startOffset, length, srcInfo, srcOpts, dstOpts)
	}
	if err := dcache.uploadIDExists(dstBucket, dstObject, uploadID); err != nil {
		return copyObjectPartFn(ctx, srcBucket, srcObject, dstBucket, dstObject, uploadID, partID, startOffset, length, srcInfo, srcOpts, dstOpts)
	}
	partInfo, err := copyObjectPartFn(ctx, srcBucket, srcObject, dstBucket, dstObject, uploadID, partID, startOffset, length, srcInfo, srcOpts, dstOpts)
	if err != nil {
		return pi, toObjectErr(err, dstBucket, dstObject)
	}
	go func() {
		isSuffixLength := false
		if startOffset < 0 {
			isSuffixLength = true
		}

		rs := &HTTPRangeSpec{
			IsSuffixLength: isSuffixLength,
			Start:          startOffset,
			End:            startOffset + length,
		}
		// fill cache in the background
		bReader, bErr := c.InnerGetObjectNInfoFn(GlobalContext, srcBucket, srcObject, rs, http.Header{}, readLock, ObjectOptions{})
		if bErr != nil {
			return
		}
		defer bReader.Close()
		// avoid cache overwrite if another background routine filled cache
		dcache.PutObjectPart(GlobalContext, dstBucket, dstObject, uploadID, partID, bReader, length, ObjectOptions{UserDefined: getMetadata(bReader.ObjInfo)})
	}()
	// Success.
	return partInfo, nil
}

// CompleteMultipartUpload - completes multipart upload operation on the backend. If writethrough mode is enabled, this also
// finalizes the upload saved in cache multipart dir.
func (c *cacheObjects) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []CompletePart, opts ObjectOptions) (oi ObjectInfo, err error) {
	completeMultipartUploadFn := c.InnerCompleteMultipartUploadFn
	if !c.commitWritethrough && !c.commitWriteback {
		return completeMultipartUploadFn(ctx, bucket, object, uploadID, uploadedParts, opts)
	}
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return completeMultipartUploadFn(ctx, bucket, object, uploadID, uploadedParts, opts)
	}

	// perform multipart upload on backend and cache simultaneously
	oi, err = completeMultipartUploadFn(ctx, bucket, object, uploadID, uploadedParts, opts)
	if err == nil {
		// fill cache in the background
		go func() {
			_, err := dcache.CompleteMultipartUpload(bgContext(ctx), bucket, object, uploadID, uploadedParts, oi, opts)
			if err != nil {
				// fill cache in the background
				bReader, bErr := c.InnerGetObjectNInfoFn(GlobalContext, bucket, object, nil, http.Header{}, readLock, ObjectOptions{})
				if bErr != nil {
					return
				}
				defer bReader.Close()
				oi, _, err := dcache.Stat(GlobalContext, bucket, object)
				// avoid cache overwrite if another background routine filled cache
				if err != nil || oi.ETag != bReader.ObjInfo.ETag {
					dcache.Put(GlobalContext, bucket, object, bReader, bReader.ObjInfo.Size, nil, ObjectOptions{UserDefined: getMetadata(bReader.ObjInfo)}, false, false)
				}
			}
		}()
	}
	return
}

// AbortMultipartUpload - aborts multipart upload on backend and cache.
func (c *cacheObjects) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string, opts ObjectOptions) error {
	abortMultipartUploadFn := c.InnerAbortMultipartUploadFn
	if !c.commitWritethrough && !c.commitWriteback {
		return abortMultipartUploadFn(ctx, bucket, object, uploadID, opts)
	}
	dcache, err := c.getCacheToLoc(ctx, bucket, object)
	if err != nil {
		// disk cache could not be located,execute backend call.
		return abortMultipartUploadFn(ctx, bucket, object, uploadID, opts)
	}
	if err = dcache.uploadIDExists(bucket, object, uploadID); err != nil {
		return toObjectErr(err, bucket, object, uploadID)
	}

	// execute backend operation
	err = abortMultipartUploadFn(ctx, bucket, object, uploadID, opts)
	if err != nil {
		return err
	}
	// abort multipart upload on cache
	go dcache.AbortUpload(bucket, object, uploadID)
	return nil
}
