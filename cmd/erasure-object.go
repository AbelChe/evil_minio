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
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/readahead"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	xioutil "github.com/minio/minio/internal/ioutil"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/sync/errgroup"
	"github.com/minio/pkg/mimedb"
	"github.com/minio/pkg/wildcard"
	uatomic "go.uber.org/atomic"
)

// list all errors which can be ignored in object operations.
var objectOpIgnoredErrs = append(baseIgnoredErrs, errDiskAccessDenied, errUnformattedDisk)

// Object Operations

func countOnlineDisks(onlineDisks []StorageAPI) (online int) {
	for _, onlineDisk := range onlineDisks {
		if onlineDisk != nil && onlineDisk.IsOnline() {
			online++
		}
	}
	return online
}

// CopyObject - copy object source object to destination object.
// if source object and destination object are same we only
// update metadata.
func (er erasureObjects) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (oi ObjectInfo, err error) {
	auditObjectErasureSet(ctx, dstObject, &er)

	// This call shouldn't be used for anything other than metadata updates or adding self referential versions.
	if !srcInfo.metadataOnly {
		return oi, NotImplemented{}
	}

	if !dstOpts.NoLock {
		lk := er.NewNSLock(dstBucket, dstObject)
		lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return oi, err
		}
		ctx = lkctx.Context()
		defer lk.Unlock(lkctx)
	}
	// Read metadata associated with the object from all disks.
	storageDisks := er.getDisks()

	var metaArr []FileInfo
	var errs []error

	// Read metadata associated with the object from all disks.
	if srcOpts.VersionID != "" {
		metaArr, errs = readAllFileInfo(ctx, storageDisks, srcBucket, srcObject, srcOpts.VersionID, true)
	} else {
		metaArr, errs = readAllXL(ctx, storageDisks, srcBucket, srcObject, true, false)
	}

	readQuorum, writeQuorum, err := objectQuorumFromMeta(ctx, metaArr, errs, er.defaultParityCount)
	if err != nil {
		if errors.Is(err, errErasureReadQuorum) && !strings.HasPrefix(srcBucket, minioMetaBucket) {
			_, derr := er.deleteIfDangling(ctx, srcBucket, srcObject, metaArr, errs, nil, srcOpts)
			if derr != nil {
				err = derr
			}
		}
		return ObjectInfo{}, toObjectErr(err, srcBucket, srcObject)
	}

	// List all online disks.
	onlineDisks, modTime := listOnlineDisks(storageDisks, metaArr, errs)

	// Pick latest valid metadata.
	fi, err := pickValidFileInfo(ctx, metaArr, modTime, readQuorum)
	if err != nil {
		return oi, toObjectErr(err, srcBucket, srcObject)
	}
	if fi.Deleted {
		if srcOpts.VersionID == "" {
			return oi, toObjectErr(errFileNotFound, srcBucket, srcObject)
		}
		return fi.ToObjectInfo(srcBucket, srcObject, srcOpts.Versioned || srcOpts.VersionSuspended), toObjectErr(errMethodNotAllowed, srcBucket, srcObject)
	}

	filterOnlineDisksInplace(fi, metaArr, onlineDisks)

	versionID := srcInfo.VersionID
	if srcInfo.versionOnly {
		versionID = dstOpts.VersionID
		// preserve destination versionId if specified.
		if versionID == "" {
			versionID = mustGetUUID()
			fi.IsLatest = true // we are creating a new version so this is latest.
		}
		modTime = UTCNow()
	}

	fi.VersionID = versionID // set any new versionID we might have created
	fi.ModTime = modTime     // set modTime for the new versionID
	if !dstOpts.MTime.IsZero() {
		modTime = dstOpts.MTime
		fi.ModTime = dstOpts.MTime
	}
	fi.Metadata = srcInfo.UserDefined
	srcInfo.UserDefined["etag"] = srcInfo.ETag

	inlineData := fi.InlineData()
	freeVersionID := fi.TierFreeVersionID()
	freeVersionMarker := fi.TierFreeVersion()

	// Update `xl.meta` content on each disks.
	for index := range metaArr {
		if metaArr[index].IsValid() {
			metaArr[index].ModTime = modTime
			metaArr[index].VersionID = versionID
			if !metaArr[index].InlineData() {
				// If the data is not inlined, we may end up incorrectly
				// inlining the data here, that leads to an inconsistent
				// situation where some objects are were not inlined
				// were now inlined, make sure to `nil` the Data such
				// that xl.meta is written as expected.
				metaArr[index].Data = nil
			}
			metaArr[index].Metadata = srcInfo.UserDefined
			// Preserve existing values
			if inlineData {
				metaArr[index].SetInlineData()
			}
			if freeVersionID != "" {
				metaArr[index].SetTierFreeVersionID(freeVersionID)
			}
			if freeVersionMarker {
				metaArr[index].SetTierFreeVersion()
			}
		}
	}

	// Write unique `xl.meta` for each disk.
	if _, err = writeUniqueFileInfo(ctx, onlineDisks, srcBucket, srcObject, metaArr, writeQuorum); err != nil {
		return oi, toObjectErr(err, srcBucket, srcObject)
	}

	return fi.ToObjectInfo(srcBucket, srcObject, srcOpts.Versioned || srcOpts.VersionSuspended), nil
}

// GetObjectNInfo - returns object info and an object
// Read(Closer). When err != nil, the returned reader is always nil.
func (er erasureObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *HTTPRangeSpec, h http.Header, lockType LockType, opts ObjectOptions) (gr *GetObjectReader, err error) {
	auditObjectErasureSet(ctx, object, &er)

	// This is a special call attempted first to check for SOS-API calls.
	gr, err = veeamSOSAPIGetObject(ctx, bucket, object, rs, opts)
	if err == nil {
		return gr, nil
	}
	// reset any error to 'nil'
	err = nil

	var unlockOnDefer bool
	nsUnlocker := func() {}
	defer func() {
		if unlockOnDefer {
			nsUnlocker()
		}
	}()

	// Acquire lock
	if lockType != noLock {
		lock := er.NewNSLock(bucket, object)
		switch lockType {
		case writeLock:
			lkctx, err := lock.GetLock(ctx, globalOperationTimeout)
			if err != nil {
				return nil, err
			}
			ctx = lkctx.Context()
			nsUnlocker = func() { lock.Unlock(lkctx) }
		case readLock:
			lkctx, err := lock.GetRLock(ctx, globalOperationTimeout)
			if err != nil {
				return nil, err
			}
			ctx = lkctx.Context()
			nsUnlocker = func() { lock.RUnlock(lkctx) }
		}
		unlockOnDefer = true
	}

	fi, metaArr, onlineDisks, err := er.getObjectFileInfo(ctx, bucket, object, opts, true)
	if err != nil {
		return nil, toObjectErr(err, bucket, object)
	}

	if !fi.DataShardFixed() {
		diskMTime := pickValidDiskTimeWithQuorum(metaArr, fi.Erasure.DataBlocks)
		if !diskMTime.Equal(timeSentinel) && !diskMTime.IsZero() {
			for index := range onlineDisks {
				if onlineDisks[index] == OfflineDisk {
					continue
				}
				if !metaArr[index].IsValid() {
					continue
				}
				if !metaArr[index].AcceptableDelta(diskMTime, shardDiskTimeDelta) {
					// If disk mTime mismatches it is considered outdated
					// https://github.com/minio/minio/pull/13803
					//
					// This check only is active if we could find maximally
					// occurring disk mtimes that are somewhat same across
					// the quorum. Allowing to skip those shards which we
					// might think are wrong.
					onlineDisks[index] = OfflineDisk
				}
			}
		}
	}

	objInfo := fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	if objInfo.DeleteMarker {
		if opts.VersionID == "" {
			return &GetObjectReader{
				ObjInfo: objInfo,
			}, toObjectErr(errFileNotFound, bucket, object)
		}
		// Make sure to return object info to provide extra information.
		return &GetObjectReader{
			ObjInfo: objInfo,
		}, toObjectErr(errMethodNotAllowed, bucket, object)
	}
	if objInfo.IsRemote() {
		gr, err := getTransitionedObjectReader(ctx, bucket, object, rs, h, objInfo, opts)
		if err != nil {
			return nil, err
		}
		unlockOnDefer = false
		return gr.WithCleanupFuncs(nsUnlocker), nil
	}

	fn, off, length, err := NewGetObjectReader(rs, objInfo, opts)
	if err != nil {
		return nil, err
	}
	unlockOnDefer = false

	pr, pw := xioutil.WaitPipe()
	go func() {
		pw.CloseWithError(er.getObjectWithFileInfo(ctx, bucket, object, off, length, pw, fi, metaArr, onlineDisks))
	}()

	// Cleanup function to cause the go routine above to exit, in
	// case of incomplete read.
	pipeCloser := func() {
		pr.CloseWithError(nil)
	}

	return fn(pr, h, pipeCloser, nsUnlocker)
}

func (er erasureObjects) getObjectWithFileInfo(ctx context.Context, bucket, object string, startOffset int64, length int64, writer io.Writer, fi FileInfo, metaArr []FileInfo, onlineDisks []StorageAPI) error {
	// Reorder online disks based on erasure distribution order.
	// Reorder parts metadata based on erasure distribution order.
	onlineDisks, metaArr = shuffleDisksAndPartsMetadataByIndex(onlineDisks, metaArr, fi)

	// For negative length read everything.
	if length < 0 {
		length = fi.Size - startOffset
	}

	// Reply back invalid range if the input offset and length fall out of range.
	if startOffset > fi.Size || startOffset+length > fi.Size {
		logger.LogIf(ctx, InvalidRange{startOffset, length, fi.Size}, logger.Application)
		return InvalidRange{startOffset, length, fi.Size}
	}

	// Get start part index and offset.
	partIndex, partOffset, err := fi.ObjectToPartOffset(ctx, startOffset)
	if err != nil {
		return InvalidRange{startOffset, length, fi.Size}
	}

	// Calculate endOffset according to length
	endOffset := startOffset
	if length > 0 {
		endOffset += length - 1
	}

	// Get last part index to read given length.
	lastPartIndex, _, err := fi.ObjectToPartOffset(ctx, endOffset)
	if err != nil {
		return InvalidRange{startOffset, length, fi.Size}
	}

	var totalBytesRead int64
	erasure, err := NewErasure(ctx, fi.Erasure.DataBlocks, fi.Erasure.ParityBlocks, fi.Erasure.BlockSize)
	if err != nil {
		return toObjectErr(err, bucket, object)
	}

	var healOnce sync.Once

	// once we have obtained a common FileInfo i.e latest, we should stick
	// to single dataDir to read the content to avoid reading from some other
	// dataDir that has stale FileInfo{} to ensure that we fail appropriately
	// during reads and expect the same dataDir everywhere.
	dataDir := fi.DataDir
	for ; partIndex <= lastPartIndex; partIndex++ {
		if length == totalBytesRead {
			break
		}

		partNumber := fi.Parts[partIndex].Number

		// Save the current part name and size.
		partSize := fi.Parts[partIndex].Size

		partLength := partSize - partOffset
		// partLength should be adjusted so that we don't write more data than what was requested.
		if partLength > (length - totalBytesRead) {
			partLength = length - totalBytesRead
		}

		tillOffset := erasure.ShardFileOffset(partOffset, partLength, partSize)
		// Get the checksums of the current part.
		readers := make([]io.ReaderAt, len(onlineDisks))
		prefer := make([]bool, len(onlineDisks))
		for index, disk := range onlineDisks {
			if disk == OfflineDisk {
				continue
			}
			if !metaArr[index].IsValid() {
				continue
			}
			checksumInfo := metaArr[index].Erasure.GetChecksumInfo(partNumber)
			partPath := pathJoin(object, dataDir, fmt.Sprintf("part.%d", partNumber))
			readers[index] = newBitrotReader(disk, metaArr[index].Data, bucket, partPath, tillOffset,
				checksumInfo.Algorithm, checksumInfo.Hash, erasure.ShardSize())

			// Prefer local disks
			prefer[index] = disk.Hostname() == ""
		}

		written, err := erasure.Decode(ctx, writer, readers, partOffset, partLength, partSize, prefer)
		// Note: we should not be defer'ing the following closeBitrotReaders() call as
		// we are inside a for loop i.e if we use defer, we would accumulate a lot of open files by the time
		// we return from this function.
		closeBitrotReaders(readers)
		if err != nil {
			// If we have successfully written all the content that was asked
			// by the client, but we still see an error - this would mean
			// that we have some parts or data blocks missing or corrupted
			// - attempt a heal to successfully heal them for future calls.
			if written == partLength {
				var scan madmin.HealScanMode
				switch {
				case errors.Is(err, errFileNotFound):
					scan = madmin.HealNormalScan
				case errors.Is(err, errFileCorrupt):
					scan = madmin.HealDeepScan
				}
				switch scan {
				case madmin.HealNormalScan, madmin.HealDeepScan:
					healOnce.Do(func() {
						if _, healing := er.getOnlineDisksWithHealing(); !healing {
							go healObject(bucket, object, fi.VersionID, scan)
						}
					})
					// Healing is triggered and we have written
					// successfully the content to client for
					// the specific part, we should `nil` this error
					// and proceed forward, instead of throwing errors.
					err = nil
				}
			}
			if err != nil {
				return toObjectErr(err, bucket, object)
			}
		}
		for i, r := range readers {
			if r == nil {
				onlineDisks[i] = OfflineDisk
			}
		}
		// Track total bytes read from disk and written to the client.
		totalBytesRead += partLength
		// partOffset will be valid only for the first part, hence reset it to 0 for
		// the remaining parts.
		partOffset = 0
	} // End of read all parts loop.
	// Return success.
	return nil
}

// GetObjectInfo - reads object metadata and replies back ObjectInfo.
func (er erasureObjects) GetObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (info ObjectInfo, err error) {
	auditObjectErasureSet(ctx, object, &er)

	if !opts.NoLock {
		// Lock the object before reading.
		lk := er.NewNSLock(bucket, object)
		lkctx, err := lk.GetRLock(ctx, globalOperationTimeout)
		if err != nil {
			return ObjectInfo{}, err
		}
		ctx = lkctx.Context()
		defer lk.RUnlock(lkctx)
	}

	return er.getObjectInfo(ctx, bucket, object, opts)
}

func auditDanglingObjectDeletion(ctx context.Context, bucket, object, versionID string, tags map[string]interface{}) {
	if len(logger.AuditTargets()) == 0 {
		return
	}

	opts := AuditLogOptions{
		Event:     "DeleteDanglingObject",
		Bucket:    bucket,
		Object:    object,
		VersionID: versionID,
		Tags:      tags,
	}

	auditLogInternal(ctx, opts)
}

func (er erasureObjects) deleteIfDangling(ctx context.Context, bucket, object string, metaArr []FileInfo, errs []error, dataErrs []error, opts ObjectOptions) (FileInfo, error) {
	_, file, line, cok := runtime.Caller(1)
	var err error
	m, ok := isObjectDangling(metaArr, errs, dataErrs)
	if ok {
		tags := make(map[string]interface{}, 4)
		tags["set"] = er.setIndex
		tags["pool"] = er.poolIndex
		tags["parity"] = m.Erasure.ParityBlocks
		if cok {
			tags["caller"] = fmt.Sprintf("%s:%d", file, line)
		}

		defer auditDanglingObjectDeletion(ctx, bucket, object, m.VersionID, tags)

		err = errFileNotFound
		if opts.VersionID != "" {
			err = errFileVersionNotFound
		}

		fi := FileInfo{
			VersionID: m.VersionID,
		}
		if opts.VersionID != "" {
			fi.VersionID = opts.VersionID
		}
		fi.SetTierFreeVersionID(mustGetUUID())
		disks := er.getDisks()
		g := errgroup.WithNErrs(len(disks))
		for index := range disks {
			index := index
			g.Go(func() error {
				if disks[index] == nil {
					return errDiskNotFound
				}
				return disks[index].DeleteVersion(ctx, bucket, object, fi, false)
			}, index)
		}

		g.Wait()
	}
	return m, err
}

func readAllXL(ctx context.Context, disks []StorageAPI, bucket, object string, readData, inclFreeVers bool) ([]FileInfo, []error) {
	metadataArray := make([]*xlMetaV2, len(disks))
	metaFileInfos := make([]FileInfo, len(metadataArray))
	metadataShallowVersions := make([][]xlMetaV2ShallowVersion, len(disks))

	g := errgroup.WithNErrs(len(disks))
	// Read `xl.meta` in parallel across disks.
	for index := range disks {
		index := index
		g.Go(func() (err error) {
			if disks[index] == nil {
				return errDiskNotFound
			}
			rf, err := disks[index].ReadXL(ctx, bucket, object, readData)
			if err != nil {
				return err
			}

			var xl xlMetaV2
			if err = xl.LoadOrConvert(rf.Buf); err != nil {
				return err
			}
			metadataArray[index] = &xl
			metaFileInfos[index] = FileInfo{
				DiskMTime: rf.DiskMTime,
			}
			return nil
		}, index)
	}

	ignoredErrs := []error{
		errFileNotFound,
		errFileNameTooLong,
		errVolumeNotFound,
		errFileVersionNotFound,
		errDiskNotFound,
	}

	errs := g.Wait()
	for index, err := range errs {
		if err == nil {
			continue
		}
		if bucket == minioMetaBucket {
			// minioMetaBucket "reads" for .metacache are not written with O_SYNC
			// so there is a potential for them to not fully committed to stable
			// storage leading to unexpected EOFs. Allow these failures to
			// be ignored since the caller already ignores them in streamMetadataParts()
			ignoredErrs = append(ignoredErrs, io.ErrUnexpectedEOF, io.EOF)
		}
		if !IsErr(err, ignoredErrs...) {
			logger.LogOnceIf(ctx, fmt.Errorf("Drive %s, path (%s/%s) returned an error (%w)",
				disks[index], bucket, object, err),
				disks[index].String())
		}
	}

	for index := range metadataArray {
		if metadataArray[index] != nil {
			metadataShallowVersions[index] = metadataArray[index].versions
		}
	}

	readQuorum := (len(disks) + 1) / 2
	meta := &xlMetaV2{versions: mergeXLV2Versions(readQuorum, false, 1, metadataShallowVersions...)}
	lfi, err := meta.ToFileInfo(bucket, object, "", inclFreeVers)
	if err != nil {
		for i := range errs {
			if errs[i] == nil {
				errs[i] = err
			}
		}
		return metaFileInfos, errs
	}
	if !lfi.IsValid() {
		for i := range errs {
			if errs[i] == nil {
				errs[i] = errCorruptedFormat
			}
		}
		return metaFileInfos, errs
	}

	versionID := lfi.VersionID
	if versionID == "" {
		versionID = nullVersionID
	}

	for index := range metadataArray {
		if metadataArray[index] == nil {
			continue
		}

		// make sure to preserve this for diskmtime based healing bugfix.
		diskMTime := metaFileInfos[index].DiskMTime
		metaFileInfos[index], errs[index] = metadataArray[index].ToFileInfo(bucket, object, versionID, inclFreeVers)
		if errs[index] != nil {
			continue
		}

		if readData {
			metaFileInfos[index].Data = metadataArray[index].data.find(versionID)
		}
		metaFileInfos[index].DiskMTime = diskMTime
	}

	// Return all the metadata.
	return metaFileInfos, errs
}

func (er erasureObjects) getObjectFileInfo(ctx context.Context, bucket, object string, opts ObjectOptions, readData bool) (fi FileInfo, metaArr []FileInfo, onlineDisks []StorageAPI, err error) {
	disks := er.getDisks()

	var errs []error

	// Read metadata associated with the object from all disks.
	if opts.VersionID != "" {
		metaArr, errs = readAllFileInfo(ctx, disks, bucket, object, opts.VersionID, readData)
	} else {
		metaArr, errs = readAllXL(ctx, disks, bucket, object, readData, opts.InclFreeVersions)
	}

	readQuorum, _, err := objectQuorumFromMeta(ctx, metaArr, errs, er.defaultParityCount)
	if err != nil {
		if errors.Is(err, errErasureReadQuorum) && !strings.HasPrefix(bucket, minioMetaBucket) {
			_, derr := er.deleteIfDangling(ctx, bucket, object, metaArr, errs, nil, opts)
			if derr != nil {
				err = derr
			}
		}
		return fi, nil, nil, toObjectErr(err, bucket, object)
	}

	if reducedErr := reduceReadQuorumErrs(ctx, errs, objectOpIgnoredErrs, readQuorum); reducedErr != nil {
		if errors.Is(reducedErr, errErasureReadQuorum) && !strings.HasPrefix(bucket, minioMetaBucket) {
			_, derr := er.deleteIfDangling(ctx, bucket, object, metaArr, errs, nil, opts)
			if derr != nil {
				reducedErr = derr
			}
		}
		return fi, nil, nil, toObjectErr(reducedErr, bucket, object)
	}

	// List all online disks.
	onlineDisks, modTime := listOnlineDisks(disks, metaArr, errs)

	// Pick latest valid metadata.
	fi, err = pickValidFileInfo(ctx, metaArr, modTime, readQuorum)
	if err != nil {
		return fi, nil, nil, err
	}

	if !fi.Deleted && len(fi.Erasure.Distribution) != len(onlineDisks) {
		err := fmt.Errorf("unexpected file distribution (%v) from online disks (%v), looks like backend disks have been manually modified refusing to heal %s/%s(%s)",
			fi.Erasure.Distribution, onlineDisks, bucket, object, opts.VersionID)
		logger.LogIf(ctx, err)
		return fi, nil, nil, toObjectErr(err, bucket, object, opts.VersionID)
	}

	filterOnlineDisksInplace(fi, metaArr, onlineDisks)

	// if one of the disk is offline, return right here no need
	// to attempt a heal on the object.
	if countErrs(errs, errDiskNotFound) > 0 {
		return fi, metaArr, onlineDisks, nil
	}

	var missingBlocks int
	for i, err := range errs {
		if err != nil && errors.Is(err, errFileNotFound) {
			missingBlocks++
			continue
		}
		if metaArr[i].IsValid() && metaArr[i].ModTime.Equal(fi.ModTime) {
			continue
		}
		metaArr[i] = FileInfo{}
		onlineDisks[i] = nil
		missingBlocks++
	}

	// if missing metadata can be reconstructed, attempt to reconstruct.
	// additionally do not heal delete markers inline, let them be
	// healed upon regular heal process.
	if !fi.Deleted && missingBlocks > 0 && missingBlocks < readQuorum {
		if _, healing := er.getOnlineDisksWithHealing(); !healing {
			go healObject(bucket, object, fi.VersionID, madmin.HealNormalScan)
		}
	}

	return fi, metaArr, onlineDisks, nil
}

// getObjectInfo - wrapper for reading object metadata and constructs ObjectInfo.
func (er erasureObjects) getObjectInfo(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	fi, _, _, err := er.getObjectFileInfo(ctx, bucket, object, opts, false)
	if err != nil {
		return objInfo, toObjectErr(err, bucket, object)
	}
	objInfo = fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	if fi.Deleted {
		if opts.VersionID == "" || opts.DeleteMarker {
			return objInfo, toObjectErr(errFileNotFound, bucket, object)
		}
		// Make sure to return object info to provide extra information.
		return objInfo, toObjectErr(errMethodNotAllowed, bucket, object)
	}

	return objInfo, nil
}

// getObjectInfoAndQuroum - wrapper for reading object metadata and constructs ObjectInfo, additionally returns write quorum for the object.
func (er erasureObjects) getObjectInfoAndQuorum(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, wquorum int, err error) {
	fi, _, _, err := er.getObjectFileInfo(ctx, bucket, object, opts, false)
	if err != nil {
		return objInfo, er.defaultWQuorum(), toObjectErr(err, bucket, object)
	}

	wquorum = fi.WriteQuorum(er.defaultWQuorum())

	objInfo = fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	if !fi.VersionPurgeStatus().Empty() && opts.VersionID != "" {
		// Make sure to return object info to provide extra information.
		return objInfo, wquorum, toObjectErr(errMethodNotAllowed, bucket, object)
	}

	if fi.Deleted {
		if opts.VersionID == "" || opts.DeleteMarker {
			return objInfo, wquorum, toObjectErr(errFileNotFound, bucket, object)
		}
		// Make sure to return object info to provide extra information.
		return objInfo, wquorum, toObjectErr(errMethodNotAllowed, bucket, object)
	}

	return objInfo, wquorum, nil
}

// Similar to rename but renames data from srcEntry to dstEntry at dataDir
func renameData(ctx context.Context, disks []StorageAPI, srcBucket, srcEntry string, metadata []FileInfo, dstBucket, dstEntry string, writeQuorum int) ([]StorageAPI, bool, error) {
	g := errgroup.WithNErrs(len(disks))

	fvID := mustGetUUID()
	for index := range disks {
		metadata[index].SetTierFreeVersionID(fvID)
	}

	diskVersions := make([]uint64, len(disks))
	// Rename file on all underlying storage disks.
	for index := range disks {
		index := index
		g.Go(func() error {
			if disks[index] == nil {
				return errDiskNotFound
			}

			// Pick one FileInfo for a disk at index.
			fi := metadata[index]
			// Assign index when index is initialized
			if fi.Erasure.Index == 0 {
				fi.Erasure.Index = index + 1
			}

			if !fi.IsValid() {
				return errFileCorrupt
			}
			sign, err := disks[index].RenameData(ctx, srcBucket, srcEntry, fi, dstBucket, dstEntry)
			if err != nil {
				return err
			}
			diskVersions[index] = sign
			return nil
		}, index)
	}

	// Wait for all renames to finish.
	errs := g.Wait()

	var versionsDisparity bool

	err := reduceWriteQuorumErrs(ctx, errs, objectOpIgnoredErrs, writeQuorum)
	if err == nil {
		versions := reduceCommonVersions(diskVersions, writeQuorum)
		for index, dversions := range diskVersions {
			if errs[index] != nil {
				continue
			}
			if versions != dversions {
				versionsDisparity = true
				break
			}
		}
	}

	// We can safely allow RenameData errors up to len(er.getDisks()) - writeQuorum
	// otherwise return failure.
	return evalDisks(disks, errs), versionsDisparity, err
}

func (er erasureObjects) putMetacacheObject(ctx context.Context, key string, r *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	data := r.Reader

	// No metadata is set, allocate a new one.
	if opts.UserDefined == nil {
		opts.UserDefined = make(map[string]string)
	}

	storageDisks := er.getDisks()
	// Get parity and data drive count based on storage class metadata
	parityDrives := globalStorageClass.GetParityForSC(opts.UserDefined[xhttp.AmzStorageClass])
	if parityDrives < 0 {
		parityDrives = er.defaultParityCount
	}
	dataDrives := len(storageDisks) - parityDrives

	// we now know the number of blocks this object needs for data and parity.
	// writeQuorum is dataBlocks + 1
	writeQuorum := dataDrives
	if dataDrives == parityDrives {
		writeQuorum++
	}

	// Validate input data size and it can never be less than zero.
	if data.Size() < -1 {
		logger.LogIf(ctx, errInvalidArgument, logger.Application)
		return ObjectInfo{}, toObjectErr(errInvalidArgument)
	}

	// Initialize parts metadata
	partsMetadata := make([]FileInfo, len(storageDisks))

	fi := newFileInfo(pathJoin(minioMetaBucket, key), dataDrives, parityDrives)
	fi.DataDir = mustGetUUID()

	// Initialize erasure metadata.
	for index := range partsMetadata {
		partsMetadata[index] = fi
	}

	// Order disks according to erasure distribution
	var onlineDisks []StorageAPI
	onlineDisks, partsMetadata = shuffleDisksAndPartsMetadata(storageDisks, partsMetadata, fi)

	erasure, err := NewErasure(ctx, fi.Erasure.DataBlocks, fi.Erasure.ParityBlocks, fi.Erasure.BlockSize)
	if err != nil {
		return ObjectInfo{}, toObjectErr(err, minioMetaBucket, key)
	}

	// Fetch buffer for I/O, returns from the pool if not allocates a new one and returns.
	var buffer []byte
	switch size := data.Size(); {
	case size == 0:
		buffer = make([]byte, 1) // Allocate atleast a byte to reach EOF
	case size >= fi.Erasure.BlockSize:
		buffer = er.bp.Get()
		defer er.bp.Put(buffer)
	case size < fi.Erasure.BlockSize:
		// No need to allocate fully blockSizeV1 buffer if the incoming data is smaller.
		buffer = make([]byte, size, 2*size+int64(fi.Erasure.ParityBlocks+fi.Erasure.DataBlocks-1))
	}

	if len(buffer) > int(fi.Erasure.BlockSize) {
		buffer = buffer[:fi.Erasure.BlockSize]
	}

	shardFileSize := erasure.ShardFileSize(data.Size())
	writers := make([]io.Writer, len(onlineDisks))
	inlineBuffers := make([]*bytes.Buffer, len(onlineDisks))
	for i, disk := range onlineDisks {
		if disk == nil {
			continue
		}
		if disk.IsOnline() {
			inlineBuffers[i] = bytes.NewBuffer(make([]byte, 0, shardFileSize))
			writers[i] = newStreamingBitrotWriterBuffer(inlineBuffers[i], DefaultBitrotAlgorithm, erasure.ShardSize())
		}
	}

	n, erasureErr := erasure.Encode(ctx, data, writers, buffer, writeQuorum)
	closeBitrotWriters(writers)
	if erasureErr != nil {
		return ObjectInfo{}, toObjectErr(erasureErr, minioMetaBucket, key)
	}

	// Should return IncompleteBody{} error when reader has fewer bytes
	// than specified in request header.
	if n < data.Size() {
		return ObjectInfo{}, IncompleteBody{Bucket: minioMetaBucket, Object: key}
	}
	var index []byte
	if opts.IndexCB != nil {
		index = opts.IndexCB()
	}

	modTime := UTCNow()

	for i, w := range writers {
		if w == nil {
			// Make sure to avoid writing to disks which we couldn't complete in erasure.Encode()
			onlineDisks[i] = nil
			continue
		}
		partsMetadata[i].Data = inlineBuffers[i].Bytes()
		partsMetadata[i].AddObjectPart(1, "", n, data.ActualSize(), modTime, index, nil)
		partsMetadata[i].Erasure.AddChecksumInfo(ChecksumInfo{
			PartNumber: 1,
			Algorithm:  DefaultBitrotAlgorithm,
			Hash:       bitrotWriterSum(w),
		})
	}

	// Fill all the necessary metadata.
	// Update `xl.meta` content on each disks.
	for index := range partsMetadata {
		partsMetadata[index].Size = n
		partsMetadata[index].Fresh = true
		partsMetadata[index].ModTime = modTime
		partsMetadata[index].Metadata = opts.UserDefined
	}

	// Set an additional header when data is inlined.
	for index := range partsMetadata {
		partsMetadata[index].SetInlineData()
	}

	for i := 0; i < len(onlineDisks); i++ {
		if onlineDisks[i] != nil && onlineDisks[i].IsOnline() {
			// Object info is the same in all disks, so we can pick
			// the first meta from online disk
			fi = partsMetadata[i]
			break
		}
	}

	if _, err = writeUniqueFileInfo(ctx, onlineDisks, minioMetaBucket, key, partsMetadata, writeQuorum); err != nil {
		return ObjectInfo{}, toObjectErr(err, minioMetaBucket, key)
	}

	return fi.ToObjectInfo(minioMetaBucket, key, opts.Versioned || opts.VersionSuspended), nil
}

// PutObject - creates an object upon reading from the input stream
// until EOF, erasure codes the data across all disk and additionally
// writes `xl.meta` which carries the necessary metadata for future
// object operations.
func (er erasureObjects) PutObject(ctx context.Context, bucket string, object string, data *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	return er.putObject(ctx, bucket, object, data, opts)
}

// Heal up to two versions of one object when there is disparity between disks
func healObjectVersionsDisparity(bucket string, entry metaCacheEntry) error {
	if entry.isDir() {
		return nil
	}
	// We might land at .metacache, .trash, .multipart
	// no need to heal them skip, only when bucket
	// is '.minio.sys'
	if bucket == minioMetaBucket {
		if wildcard.Match("buckets/*/.metacache/*", entry.name) {
			return nil
		}
		if wildcard.Match("tmp/*", entry.name) {
			return nil
		}
		if wildcard.Match("multipart/*", entry.name) {
			return nil
		}
		if wildcard.Match("tmp-old/*", entry.name) {
			return nil
		}
	}

	fivs, err := entry.fileInfoVersions(bucket)
	if err != nil {
		go healObject(bucket, entry.name, "", madmin.HealDeepScan)
		return err
	}

	if len(fivs.Versions) <= 2 {
		for _, version := range fivs.Versions {
			go healObject(bucket, entry.name, version.VersionID, madmin.HealNormalScan)
		}
	}

	return nil
}

// putObject wrapper for erasureObjects PutObject
func (er erasureObjects) putObject(ctx context.Context, bucket string, object string, r *PutObjReader, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	auditObjectErasureSet(ctx, object, &er)

	if opts.CheckPrecondFn != nil {
		obj, err := er.getObjectInfo(ctx, bucket, object, opts)
		if err != nil && !isErrVersionNotFound(err) {
			return objInfo, err
		}
		if opts.CheckPrecondFn(obj) {
			return objInfo, PreConditionFailed{}
		}
	}

	data := r.Reader

	userDefined := cloneMSS(opts.UserDefined)

	storageDisks := er.getDisks()

	parityDrives := len(storageDisks) / 2
	if !opts.MaxParity {
		// Get parity and data drive count based on storage class metadata
		parityDrives = globalStorageClass.GetParityForSC(userDefined[xhttp.AmzStorageClass])
		if parityDrives < 0 {
			parityDrives = er.defaultParityCount
		}

		// If we have offline disks upgrade the number of erasure codes for this object.
		parityOrig := parityDrives

		atomicParityDrives := uatomic.NewInt64(0)
		// Start with current parityDrives
		atomicParityDrives.Store(int64(parityDrives))

		var wg sync.WaitGroup
		for _, disk := range storageDisks {
			if disk == nil {
				atomicParityDrives.Inc()
				continue
			}
			if !disk.IsOnline() {
				atomicParityDrives.Inc()
				continue
			}
			wg.Add(1)
			go func(disk StorageAPI) {
				defer wg.Done()
				di, err := disk.DiskInfo(ctx)
				if err != nil || di.ID == "" {
					atomicParityDrives.Inc()
				}
			}(disk)
		}
		wg.Wait()

		parityDrives = int(atomicParityDrives.Load())
		if parityDrives >= len(storageDisks)/2 {
			parityDrives = len(storageDisks) / 2
		}
		if parityOrig != parityDrives {
			userDefined[minIOErasureUpgraded] = strconv.Itoa(parityOrig) + "->" + strconv.Itoa(parityDrives)
		}
	}
	dataDrives := len(storageDisks) - parityDrives

	// we now know the number of blocks this object needs for data and parity.
	// writeQuorum is dataBlocks + 1
	writeQuorum := dataDrives
	if dataDrives == parityDrives {
		writeQuorum++
	}

	// Validate input data size and it can never be less than zero.
	if data.Size() < -1 {
		logger.LogIf(ctx, errInvalidArgument, logger.Application)
		return ObjectInfo{}, toObjectErr(errInvalidArgument)
	}

	// Initialize parts metadata
	partsMetadata := make([]FileInfo, len(storageDisks))

	fi := newFileInfo(pathJoin(bucket, object), dataDrives, parityDrives)
	fi.VersionID = opts.VersionID
	if opts.Versioned && fi.VersionID == "" {
		fi.VersionID = mustGetUUID()
	}

	fi.DataDir = mustGetUUID()
	fi.Checksum = opts.WantChecksum.AppendTo(nil)
	if opts.EncryptFn != nil {
		fi.Checksum = opts.EncryptFn("object-checksum", fi.Checksum)
	}
	uniqueID := mustGetUUID()
	tempObj := uniqueID

	// Initialize erasure metadata.
	for index := range partsMetadata {
		partsMetadata[index] = fi
	}

	// Order disks according to erasure distribution
	var onlineDisks []StorageAPI
	onlineDisks, partsMetadata = shuffleDisksAndPartsMetadata(storageDisks, partsMetadata, fi)

	erasure, err := NewErasure(ctx, fi.Erasure.DataBlocks, fi.Erasure.ParityBlocks, fi.Erasure.BlockSize)
	if err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	// Fetch buffer for I/O, returns from the pool if not allocates a new one and returns.
	var buffer []byte
	switch size := data.Size(); {
	case size == 0:
		buffer = make([]byte, 1) // Allocate atleast a byte to reach EOF
	case size >= fi.Erasure.BlockSize || size == -1:
		buffer = er.bp.Get()
		defer er.bp.Put(buffer)
	case size < fi.Erasure.BlockSize:
		// No need to allocate fully blockSizeV1 buffer if the incoming data is smaller.
		buffer = make([]byte, size, 2*size+int64(fi.Erasure.ParityBlocks+fi.Erasure.DataBlocks-1))
	}

	if len(buffer) > int(fi.Erasure.BlockSize) {
		buffer = buffer[:fi.Erasure.BlockSize]
	}

	partName := "part.1"
	tempErasureObj := pathJoin(uniqueID, fi.DataDir, partName)

	// Delete temporary object in the event of failure.
	// If PutObject succeeded there would be no temporary
	// object to delete.
	var online int
	defer func() {
		if online != len(onlineDisks) {
			er.deleteAll(context.Background(), minioMetaTmpBucket, tempObj)
		}
	}()

	shardFileSize := erasure.ShardFileSize(data.Size())
	writers := make([]io.Writer, len(onlineDisks))
	var inlineBuffers []*bytes.Buffer
	if shardFileSize >= 0 {
		if !opts.Versioned && shardFileSize < smallFileThreshold {
			inlineBuffers = make([]*bytes.Buffer, len(onlineDisks))
		} else if shardFileSize < smallFileThreshold/8 {
			inlineBuffers = make([]*bytes.Buffer, len(onlineDisks))
		}
	} else {
		// If compressed, use actual size to determine.
		if sz := erasure.ShardFileSize(data.ActualSize()); sz > 0 {
			if !opts.Versioned && sz < smallFileThreshold {
				inlineBuffers = make([]*bytes.Buffer, len(onlineDisks))
			} else if sz < smallFileThreshold/8 {
				inlineBuffers = make([]*bytes.Buffer, len(onlineDisks))
			}
		}
	}
	for i, disk := range onlineDisks {
		if disk == nil {
			continue
		}

		if !disk.IsOnline() {
			continue
		}

		if len(inlineBuffers) > 0 {
			sz := shardFileSize
			if sz < 0 {
				sz = data.ActualSize()
			}
			inlineBuffers[i] = bytes.NewBuffer(make([]byte, 0, sz))
			writers[i] = newStreamingBitrotWriterBuffer(inlineBuffers[i], DefaultBitrotAlgorithm, erasure.ShardSize())
			continue
		}

		writers[i] = newBitrotWriter(disk, minioMetaTmpBucket, tempErasureObj, shardFileSize, DefaultBitrotAlgorithm, erasure.ShardSize())
	}

	toEncode := io.Reader(data)
	if data.Size() > bigFileThreshold {
		// We use 2 buffers, so we always have a full buffer of input.
		bufA := er.bp.Get()
		bufB := er.bp.Get()
		defer er.bp.Put(bufA)
		defer er.bp.Put(bufB)
		ra, err := readahead.NewReaderBuffer(data, [][]byte{bufA[:fi.Erasure.BlockSize], bufB[:fi.Erasure.BlockSize]})
		if err == nil {
			toEncode = ra
			defer ra.Close()
		}
		logger.LogIf(ctx, err)
	}
	n, erasureErr := erasure.Encode(ctx, toEncode, writers, buffer, writeQuorum)
	closeBitrotWriters(writers)
	if erasureErr != nil {
		return ObjectInfo{}, toObjectErr(erasureErr, minioMetaTmpBucket, tempErasureObj)
	}

	// Should return IncompleteBody{} error when reader has fewer bytes
	// than specified in request header.
	if n < data.Size() {
		return ObjectInfo{}, IncompleteBody{Bucket: bucket, Object: object}
	}

	var compIndex []byte
	if opts.IndexCB != nil {
		compIndex = opts.IndexCB()
	}
	if !opts.NoLock {
		lk := er.NewNSLock(bucket, object)
		lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return ObjectInfo{}, err
		}
		ctx = lkctx.Context()
		defer lk.Unlock(lkctx)
	}

	modTime := opts.MTime
	if opts.MTime.IsZero() {
		modTime = UTCNow()
	}

	for i, w := range writers {
		if w == nil {
			onlineDisks[i] = nil
			continue
		}
		if len(inlineBuffers) > 0 && inlineBuffers[i] != nil {
			partsMetadata[i].Data = inlineBuffers[i].Bytes()
		} else {
			partsMetadata[i].Data = nil
		}
		// No need to add checksum to part. We already have it on the object.
		partsMetadata[i].AddObjectPart(1, "", n, data.ActualSize(), modTime, compIndex, nil)
		partsMetadata[i].Erasure.AddChecksumInfo(ChecksumInfo{
			PartNumber: 1,
			Algorithm:  DefaultBitrotAlgorithm,
			Hash:       bitrotWriterSum(w),
		})
	}

	userDefined["etag"] = r.MD5CurrentHexString()
	if opts.PreserveETag != "" {
		userDefined["etag"] = opts.PreserveETag
	}

	// Guess content-type from the extension if possible.
	if userDefined["content-type"] == "" {
		userDefined["content-type"] = mimedb.TypeByExtension(path.Ext(object))
	}

	// Fill all the necessary metadata.
	// Update `xl.meta` content on each disks.
	for index := range partsMetadata {
		partsMetadata[index].Metadata = userDefined
		partsMetadata[index].Size = n
		partsMetadata[index].ModTime = modTime
	}

	if len(inlineBuffers) > 0 {
		// Set an additional header when data is inlined.
		for index := range partsMetadata {
			partsMetadata[index].SetInlineData()
		}
	}

	// Rename the successfully written temporary object to final location.
	onlineDisks, versionsDisparity, err := renameData(ctx, onlineDisks, minioMetaTmpBucket, tempObj, partsMetadata, bucket, object, writeQuorum)
	if err != nil {
		if errors.Is(err, errFileNotFound) {
			return ObjectInfo{}, toObjectErr(errErasureWriteQuorum, bucket, object)
		}
		logger.LogIf(ctx, err)
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	for i := 0; i < len(onlineDisks); i++ {
		if onlineDisks[i] != nil && onlineDisks[i].IsOnline() {
			// Object info is the same in all disks, so we can pick
			// the first meta from online disk
			fi = partsMetadata[i]
			break
		}
	}

	// For speedtest objects do not attempt to heal them.
	if !opts.Speedtest {
		// Whether a disk was initially or becomes offline
		// during this upload, send it to the MRF list.
		for i := 0; i < len(onlineDisks); i++ {
			if onlineDisks[i] != nil && onlineDisks[i].IsOnline() {
				continue
			}

			er.addPartial(bucket, object, fi.VersionID, fi.Size)
			break
		}

		if versionsDisparity {
			listAndHeal(ctx, bucket, object, &er, healObjectVersionsDisparity)
		}
	}

	fi.ReplicationState = opts.PutReplicationState()
	online = countOnlineDisks(onlineDisks)

	// we are adding a new version to this object under the namespace lock, so this is the latest version.
	fi.IsLatest = true

	return fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended), nil
}

func (er erasureObjects) deleteObjectVersion(ctx context.Context, bucket, object string, fi FileInfo, forceDelMarker bool) error {
	disks := er.getDisks()
	// Assume (N/2 + 1) quorum for Delete()
	// this is a theoretical assumption such that
	// for delete's we do not need to honor storage
	// class for objects that have reduced quorum
	// due to storage class - this only needs to be honored
	// for Read() requests alone that we already do.
	writeQuorum := len(disks)/2 + 1

	g := errgroup.WithNErrs(len(disks))
	for index := range disks {
		index := index
		g.Go(func() error {
			if disks[index] == nil {
				return errDiskNotFound
			}
			return disks[index].DeleteVersion(ctx, bucket, object, fi, forceDelMarker)
		}, index)
	}
	// return errors if any during deletion
	return reduceWriteQuorumErrs(ctx, g.Wait(), objectOpIgnoredErrs, writeQuorum)
}

// DeleteObjects deletes objects/versions in bulk, this function will still automatically split objects list
// into smaller bulks if some object names are found to be duplicated in the delete list, splitting
// into smaller bulks will avoid holding twice the write lock of the duplicated object names.
func (er erasureObjects) DeleteObjects(ctx context.Context, bucket string, objects []ObjectToDelete, opts ObjectOptions) ([]DeletedObject, []error) {
	for _, obj := range objects {
		auditObjectErasureSet(ctx, obj.ObjectV.ObjectName, &er)
	}

	errs := make([]error, len(objects))
	dobjects := make([]DeletedObject, len(objects))
	writeQuorums := make([]int, len(objects))

	storageDisks := er.getDisks()

	for i := range objects {
		// Assume (N/2 + 1) quorums for all objects
		// this is a theoretical assumption such that
		// for delete's we do not need to honor storage
		// class for objects which have reduced quorum
		// storage class only needs to be honored for
		// Read() requests alone which we already do.
		writeQuorums[i] = len(storageDisks)/2 + 1
	}

	versionsMap := make(map[string]FileInfoVersions, len(objects))
	for i := range objects {
		// Construct the FileInfo data that needs to be preserved on the disk.
		vr := FileInfo{
			Name:             objects[i].ObjectName,
			VersionID:        objects[i].VersionID,
			ReplicationState: objects[i].ReplicationState(),
			// save the index to set correct error at this index.
			Idx: i,
		}
		vr.SetTierFreeVersionID(mustGetUUID())
		// VersionID is not set means delete is not specific about
		// any version, look for if the bucket is versioned or not.
		if objects[i].VersionID == "" {
			// MinIO extension to bucket version configuration
			suspended := opts.VersionSuspended
			versioned := opts.Versioned
			if opts.PrefixEnabledFn != nil {
				versioned = opts.PrefixEnabledFn(objects[i].ObjectName)
			}
			if versioned || suspended {
				// Bucket is versioned and no version was explicitly
				// mentioned for deletes, create a delete marker instead.
				vr.ModTime = UTCNow()
				vr.Deleted = true
				// Versioning suspended means that we add a `null` version
				// delete marker, if not add a new version for this delete
				// marker.
				if versioned {
					vr.VersionID = mustGetUUID()
				}
			}
		}
		// De-dup same object name to collect multiple versions for same object.
		v, ok := versionsMap[objects[i].ObjectName]
		if ok {
			v.Versions = append(v.Versions, vr)
		} else {
			v = FileInfoVersions{
				Name:     vr.Name,
				Versions: []FileInfo{vr},
			}
		}
		if vr.Deleted {
			dobjects[i] = DeletedObject{
				DeleteMarker:          vr.Deleted,
				DeleteMarkerVersionID: vr.VersionID,
				DeleteMarkerMTime:     DeleteMarkerMTime{vr.ModTime},
				ObjectName:            vr.Name,
				ReplicationState:      vr.ReplicationState,
			}
		} else {
			dobjects[i] = DeletedObject{
				ObjectName:       vr.Name,
				VersionID:        vr.VersionID,
				ReplicationState: vr.ReplicationState,
			}
		}
		versionsMap[objects[i].ObjectName] = v
	}

	dedupVersions := make([]FileInfoVersions, 0, len(versionsMap))
	for _, version := range versionsMap {
		dedupVersions = append(dedupVersions, version)
	}

	// Initialize list of errors.
	delObjErrs := make([][]error, len(storageDisks))

	var wg sync.WaitGroup
	// Remove versions in bulk for each disk
	for index, disk := range storageDisks {
		wg.Add(1)
		go func(index int, disk StorageAPI) {
			defer wg.Done()
			delObjErrs[index] = make([]error, len(objects))
			if disk == nil {
				for i := range objects {
					delObjErrs[index][i] = errDiskNotFound
				}
				return
			}
			errs := disk.DeleteVersions(ctx, bucket, dedupVersions)
			for i, err := range errs {
				if err == nil {
					continue
				}
				for _, v := range dedupVersions[i].Versions {
					if err == errFileNotFound || err == errFileVersionNotFound {
						if !dobjects[v.Idx].DeleteMarker {
							// Not delete marker, if not found, ok.
							continue
						}
					}
					delObjErrs[index][v.Idx] = err
				}
			}
		}(index, disk)
	}
	wg.Wait()

	// Reduce errors for each object
	for objIndex := range objects {
		diskErrs := make([]error, len(storageDisks))
		// Iterate over disks to fetch the error
		// of deleting of the current object
		for i := range delObjErrs {
			// delObjErrs[i] is not nil when disks[i] is also not nil
			if delObjErrs[i] != nil {
				diskErrs[i] = delObjErrs[i][objIndex]
			}
		}
		err := reduceWriteQuorumErrs(ctx, diskErrs, objectOpIgnoredErrs, writeQuorums[objIndex])
		if objects[objIndex].VersionID != "" {
			errs[objIndex] = toObjectErr(err, bucket, objects[objIndex].ObjectName, objects[objIndex].VersionID)
		} else {
			errs[objIndex] = toObjectErr(err, bucket, objects[objIndex].ObjectName)
		}
	}

	// Check failed deletes across multiple objects
	for i, dobj := range dobjects {
		// This object errored, no need to attempt a heal.
		if errs[i] != nil {
			continue
		}

		// Check if there is any offline disk and add it to the MRF list
		for _, disk := range storageDisks {
			if disk != nil && disk.IsOnline() {
				// Skip attempted heal on online disks.
				continue
			}

			// all other direct versionId references we should
			// ensure no dangling file is left over.
			er.addPartial(bucket, dobj.ObjectName, dobj.VersionID, -1)
			break
		}
	}

	return dobjects, errs
}

func (er erasureObjects) deletePrefix(ctx context.Context, bucket, prefix string) error {
	disks := er.getDisks()
	g := errgroup.WithNErrs(len(disks))
	dirPrefix := encodeDirObject(prefix)
	for index := range disks {
		index := index
		g.Go(func() error {
			if disks[index] == nil {
				return nil
			}
			// Deletes
			// - The prefix and its children
			// - The prefix__XLDIR__
			defer disks[index].Delete(ctx, bucket, dirPrefix, DeleteOptions{
				Recursive: true,
				Force:     true,
			})
			return disks[index].Delete(ctx, bucket, prefix, DeleteOptions{
				Recursive: true,
				Force:     true,
			})
		}, index)
	}
	for _, err := range g.Wait() {
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteObject - deletes an object, this call doesn't necessary reply
// any error as it is not necessary for the handler to reply back a
// response to the client request.
func (er erasureObjects) DeleteObject(ctx context.Context, bucket, object string, opts ObjectOptions) (objInfo ObjectInfo, err error) {
	auditObjectErasureSet(ctx, object, &er)

	if opts.DeletePrefix {
		return ObjectInfo{}, toObjectErr(er.deletePrefix(ctx, bucket, object), bucket, object)
	}

	var lc *lifecycle.Lifecycle
	var rcfg lock.Retention
	if opts.Expiration.Expire {
		// Check if the current bucket has a configured lifecycle policy
		lc, _ = globalLifecycleSys.Get(bucket)
		rcfg, _ = globalBucketObjectLockSys.Get(bucket)
	}

	// expiration attempted on a bucket with no lifecycle
	// rules shall be rejected.
	if lc == nil && opts.Expiration.Expire {
		if opts.VersionID != "" {
			return objInfo, VersionNotFound{
				Bucket:    bucket,
				Object:    object,
				VersionID: opts.VersionID,
			}
		}
		return objInfo, ObjectNotFound{
			Bucket: bucket,
			Object: object,
		}
	}

	storageDisks := er.getDisks()
	versionFound := true
	objInfo = ObjectInfo{VersionID: opts.VersionID} // version id needed in Delete API response.
	goi, _, gerr := er.getObjectInfoAndQuorum(ctx, bucket, object, opts)
	if gerr != nil && goi.Name == "" {
		if _, ok := gerr.(InsufficientReadQuorum); ok {
			return objInfo, InsufficientWriteQuorum{}
		}
		// For delete marker replication, versionID being replicated will not exist on disk
		if opts.DeleteMarker {
			versionFound = false
		} else {
			return objInfo, gerr
		}
	}

	if opts.Expiration.Expire {
		if gerr == nil {
			evt := evalActionFromLifecycle(ctx, *lc, rcfg, goi)
			var isErr bool
			switch evt.Action {
			case lifecycle.NoneAction:
				isErr = true
			case lifecycle.TransitionAction, lifecycle.TransitionVersionAction:
				isErr = true
			}
			if isErr {
				if goi.VersionID != "" {
					return goi, VersionNotFound{
						Bucket:    bucket,
						Object:    object,
						VersionID: goi.VersionID,
					}
				}
				return goi, ObjectNotFound{
					Bucket: bucket,
					Object: object,
				}
			}
		}
	}

	//  Determine whether to mark object deleted for replication
	markDelete := goi.VersionID != ""

	// Default deleteMarker to true if object is under versioning
	deleteMarker := opts.Versioned

	if opts.VersionID != "" {
		// case where replica version needs to be deleted on target cluster
		if versionFound && opts.DeleteMarkerReplicationStatus() == replication.Replica {
			markDelete = false
		}
		if opts.VersionPurgeStatus().Empty() && opts.DeleteMarkerReplicationStatus().Empty() {
			markDelete = false
		}
		if opts.VersionPurgeStatus() == Complete {
			markDelete = false
		}
		// now, since VersionPurgeStatus() is already set, we can let the
		// lower layers decide this. This fixes a regression that was introduced
		// in PR #14555 where !VersionPurgeStatus.Empty() is automatically
		// considered as Delete marker true to avoid listing such objects by
		// regular ListObjects() calls. However for delete replication this
		// ends up being a problem because "upon" a successful delete this
		// ends up creating a new delete marker that is spurious and unnecessary.
		//
		// Regression introduced by #14555 was reintroduced in #15564
		if versionFound {
			if !goi.VersionPurgeStatus.Empty() {
				deleteMarker = false
			} else if !goi.DeleteMarker { // implies a versioned delete of object
				deleteMarker = false
			}
		}
	}

	modTime := opts.MTime
	if opts.MTime.IsZero() {
		modTime = UTCNow()
	}
	fvID := mustGetUUID()

	if markDelete && (opts.Versioned || opts.VersionSuspended) {
		if !deleteMarker {
			// versioning suspended means we add `null` version as
			// delete marker, if its not decided already.
			deleteMarker = opts.VersionSuspended && opts.VersionID == ""
		}
		fi := FileInfo{
			Name:             object,
			Deleted:          deleteMarker,
			MarkDeleted:      markDelete,
			ModTime:          modTime,
			ReplicationState: opts.DeleteReplication,
			TransitionStatus: opts.Transition.Status,
			ExpireRestored:   opts.Transition.ExpireRestored,
		}
		fi.SetTierFreeVersionID(fvID)
		if opts.VersionID != "" {
			fi.VersionID = opts.VersionID
		} else if opts.Versioned {
			fi.VersionID = mustGetUUID()
		}
		// versioning suspended means we add `null` version as
		// delete marker. Add delete marker, since we don't have
		// any version specified explicitly. Or if a particular
		// version id needs to be replicated.
		if err = er.deleteObjectVersion(ctx, bucket, object, fi, opts.DeleteMarker); err != nil {
			return objInfo, toObjectErr(err, bucket, object)
		}
		return fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended), nil
	}

	// Delete the object version on all disks.
	dfi := FileInfo{
		Name:             object,
		VersionID:        opts.VersionID,
		MarkDeleted:      markDelete,
		Deleted:          deleteMarker,
		ModTime:          modTime,
		ReplicationState: opts.DeleteReplication,
		TransitionStatus: opts.Transition.Status,
		ExpireRestored:   opts.Transition.ExpireRestored,
	}
	dfi.SetTierFreeVersionID(fvID)
	if err = er.deleteObjectVersion(ctx, bucket, object, dfi, opts.DeleteMarker); err != nil {
		return objInfo, toObjectErr(err, bucket, object)
	}

	for _, disk := range storageDisks {
		if disk != nil && disk.IsOnline() {
			continue
		}
		er.addPartial(bucket, object, opts.VersionID, -1)
		break
	}

	return dfi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended), nil
}

// Send the successful but partial upload/delete, however ignore
// if the channel is blocked by other items.
func (er erasureObjects) addPartial(bucket, object, versionID string, size int64) {
	globalMRFState.addPartialOp(partialOperation{
		bucket:    bucket,
		object:    object,
		versionID: versionID,
		size:      size,
		setIndex:  er.setIndex,
		poolIndex: er.poolIndex,
	})
}

func (er erasureObjects) PutObjectMetadata(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	if !opts.NoLock {
		// Lock the object before updating metadata.
		lk := er.NewNSLock(bucket, object)
		lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return ObjectInfo{}, err
		}
		ctx = lkctx.Context()
		defer lk.Unlock(lkctx)
	}

	disks := er.getDisks()

	var metaArr []FileInfo
	var errs []error

	// Read metadata associated with the object from all disks.
	if opts.VersionID != "" {
		metaArr, errs = readAllFileInfo(ctx, disks, bucket, object, opts.VersionID, false)
	} else {
		metaArr, errs = readAllXL(ctx, disks, bucket, object, false, false)
	}

	readQuorum, _, err := objectQuorumFromMeta(ctx, metaArr, errs, er.defaultParityCount)
	if err != nil {
		if errors.Is(err, errErasureReadQuorum) && !strings.HasPrefix(bucket, minioMetaBucket) {
			_, derr := er.deleteIfDangling(ctx, bucket, object, metaArr, errs, nil, opts)
			if derr != nil {
				err = derr
			}
		}
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	// List all online disks.
	onlineDisks, modTime := listOnlineDisks(disks, metaArr, errs)

	// Pick latest valid metadata.
	fi, err := pickValidFileInfo(ctx, metaArr, modTime, readQuorum)
	if err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	if fi.Deleted {
		return ObjectInfo{}, toObjectErr(errMethodNotAllowed, bucket, object)
	}

	filterOnlineDisksInplace(fi, metaArr, onlineDisks)

	// if version-id is not specified retention is supposed to be set on the latest object.
	if opts.VersionID == "" {
		opts.VersionID = fi.VersionID
	}

	objInfo := fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	if opts.EvalMetadataFn != nil {
		if err := opts.EvalMetadataFn(&objInfo); err != nil {
			return ObjectInfo{}, err
		}
	}
	for k, v := range objInfo.UserDefined {
		fi.Metadata[k] = v
	}
	fi.ModTime = opts.MTime
	fi.VersionID = opts.VersionID

	if err = er.updateObjectMeta(ctx, bucket, object, fi, onlineDisks); err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	return fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended), nil
}

// PutObjectTags - replace or add tags to an existing object
func (er erasureObjects) PutObjectTags(ctx context.Context, bucket, object string, tags string, opts ObjectOptions) (ObjectInfo, error) {
	// Lock the object before updating tags.
	lk := er.NewNSLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalOperationTimeout)
	if err != nil {
		return ObjectInfo{}, err
	}
	ctx = lkctx.Context()
	defer lk.Unlock(lkctx)

	disks := er.getDisks()

	var metaArr []FileInfo
	var errs []error

	// Read metadata associated with the object from all disks.
	if opts.VersionID != "" {
		metaArr, errs = readAllFileInfo(ctx, disks, bucket, object, opts.VersionID, false)
	} else {
		metaArr, errs = readAllXL(ctx, disks, bucket, object, false, false)
	}

	readQuorum, _, err := objectQuorumFromMeta(ctx, metaArr, errs, er.defaultParityCount)
	if err != nil {
		if errors.Is(err, errErasureReadQuorum) && !strings.HasPrefix(bucket, minioMetaBucket) {
			_, derr := er.deleteIfDangling(ctx, bucket, object, metaArr, errs, nil, opts)
			if derr != nil {
				err = derr
			}
		}
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	// List all online disks.
	onlineDisks, modTime := listOnlineDisks(disks, metaArr, errs)

	// Pick latest valid metadata.
	fi, err := pickValidFileInfo(ctx, metaArr, modTime, readQuorum)
	if err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}
	if fi.Deleted {
		if opts.VersionID == "" {
			return ObjectInfo{}, toObjectErr(errFileNotFound, bucket, object)
		}
		return ObjectInfo{}, toObjectErr(errMethodNotAllowed, bucket, object)
	}

	filterOnlineDisksInplace(fi, metaArr, onlineDisks)

	fi.Metadata[xhttp.AmzObjectTagging] = tags
	fi.ReplicationState = opts.PutReplicationState()
	for k, v := range opts.UserDefined {
		fi.Metadata[k] = v
	}

	if err = er.updateObjectMeta(ctx, bucket, object, fi, onlineDisks); err != nil {
		return ObjectInfo{}, toObjectErr(err, bucket, object)
	}

	return fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended), nil
}

// updateObjectMeta will update the metadata of a file.
func (er erasureObjects) updateObjectMeta(ctx context.Context, bucket, object string, fi FileInfo, onlineDisks []StorageAPI) error {
	if len(fi.Metadata) == 0 {
		return nil
	}

	g := errgroup.WithNErrs(len(onlineDisks))

	// Start writing `xl.meta` to all disks in parallel.
	for index := range onlineDisks {
		index := index
		g.Go(func() error {
			if onlineDisks[index] == nil {
				return errDiskNotFound
			}
			return onlineDisks[index].UpdateMetadata(ctx, bucket, object, fi)
		}, index)
	}

	// Wait for all the routines.
	mErrs := g.Wait()

	return reduceWriteQuorumErrs(ctx, mErrs, objectOpIgnoredErrs, er.defaultWQuorum())
}

// DeleteObjectTags - delete object tags from an existing object
func (er erasureObjects) DeleteObjectTags(ctx context.Context, bucket, object string, opts ObjectOptions) (ObjectInfo, error) {
	return er.PutObjectTags(ctx, bucket, object, "", opts)
}

// GetObjectTags - get object tags from an existing object
func (er erasureObjects) GetObjectTags(ctx context.Context, bucket, object string, opts ObjectOptions) (*tags.Tags, error) {
	// GetObjectInfo will return tag value as well
	oi, err := er.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return nil, err
	}

	return tags.ParseObjectTags(oi.UserTags)
}

// TransitionObject - transition object content to target tier.
func (er erasureObjects) TransitionObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	tgtClient, err := globalTierConfigMgr.getDriver(opts.Transition.Tier)
	if err != nil {
		return err
	}

	// Acquire write lock before starting to transition the object.
	lk := er.NewNSLock(bucket, object)
	lkctx, err := lk.GetLock(ctx, globalDeleteOperationTimeout)
	if err != nil {
		return err
	}
	ctx = lkctx.Context()
	defer lk.Unlock(lkctx)

	fi, metaArr, onlineDisks, err := er.getObjectFileInfo(ctx, bucket, object, opts, true)
	if err != nil {
		return toObjectErr(err, bucket, object)
	}
	if fi.Deleted {
		if opts.VersionID == "" {
			return toObjectErr(errFileNotFound, bucket, object)
		}
		// Make sure to return object info to provide extra information.
		return toObjectErr(errMethodNotAllowed, bucket, object)
	}
	// verify that the object queued for transition is identical to that on disk.
	if !opts.MTime.Equal(fi.ModTime) || !strings.EqualFold(opts.Transition.ETag, extractETag(fi.Metadata)) {
		return toObjectErr(errFileNotFound, bucket, object)
	}
	// if object already transitioned, return
	if fi.TransitionStatus == lifecycle.TransitionComplete {
		return nil
	}

	if fi.XLV1 {
		if _, err = er.HealObject(ctx, bucket, object, "", madmin.HealOpts{NoLock: true}); err != nil {
			return err
		}
		// Fetch FileInfo again. HealObject migrates object the latest
		// format. Among other things this changes fi.DataDir and
		// possibly fi.Data (if data is inlined).
		fi, metaArr, onlineDisks, err = er.getObjectFileInfo(ctx, bucket, object, opts, true)
		if err != nil {
			return toObjectErr(err, bucket, object)
		}
	}

	destObj, err := genTransitionObjName(bucket)
	if err != nil {
		return err
	}

	pr, pw := xioutil.WaitPipe()
	go func() {
		err := er.getObjectWithFileInfo(ctx, bucket, object, 0, fi.Size, pw, fi, metaArr, onlineDisks)
		pw.CloseWithError(err)
	}()

	var rv remoteVersionID
	rv, err = tgtClient.Put(ctx, destObj, pr, fi.Size)
	pr.CloseWithError(err)
	if err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to transition %s/%s(%s) to %s tier: %w", bucket, object, opts.VersionID, opts.Transition.Tier, err))
		return err
	}
	fi.TransitionStatus = lifecycle.TransitionComplete
	fi.TransitionedObjName = destObj
	fi.TransitionTier = opts.Transition.Tier
	fi.TransitionVersionID = string(rv)
	eventName := event.ObjectTransitionComplete

	storageDisks := er.getDisks()

	if err = er.deleteObjectVersion(ctx, bucket, object, fi, false); err != nil {
		eventName = event.ObjectTransitionFailed
	}

	for _, disk := range storageDisks {
		if disk != nil && disk.IsOnline() {
			continue
		}
		er.addPartial(bucket, object, opts.VersionID, -1)
		break
	}

	objInfo := fi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	sendEvent(eventArgs{
		EventName:  eventName,
		BucketName: bucket,
		Object:     objInfo,
		Host:       "Internal: [ILM-Transition]",
	})
	auditLogLifecycle(ctx, objInfo, ILMTransition)
	return err
}

// RestoreTransitionedObject - restore transitioned object content locally on this cluster.
// This is similar to PostObjectRestore from AWS GLACIER
// storage class. When PostObjectRestore API is called, a temporary copy of the object
// is restored locally to the bucket on source cluster until the restore expiry date.
// The copy that was transitioned continues to reside in the transitioned tier.
func (er erasureObjects) RestoreTransitionedObject(ctx context.Context, bucket, object string, opts ObjectOptions) error {
	return er.restoreTransitionedObject(ctx, bucket, object, opts)
}

// update restore status header in the metadata
func (er erasureObjects) updateRestoreMetadata(ctx context.Context, bucket, object string, objInfo ObjectInfo, opts ObjectOptions) error {
	oi := objInfo.Clone()
	oi.metadataOnly = true // Perform only metadata updates.

	// allow retry in the case of failure to restore
	delete(oi.UserDefined, xhttp.AmzRestore)

	if _, err := er.CopyObject(ctx, bucket, object, bucket, object, oi, ObjectOptions{
		VersionID: oi.VersionID,
	}, ObjectOptions{
		VersionID: oi.VersionID,
	}); err != nil {
		logger.LogIf(ctx, fmt.Errorf("Unable to update transition restore metadata for %s/%s(%s): %s", bucket, object, oi.VersionID, err))
		return err
	}
	return nil
}

// restoreTransitionedObject for multipart object chunks the file stream from remote tier into the same number of parts
// as in the xl.meta for this version and rehydrates the part.n into the fi.DataDir for this version as in the xl.meta
func (er erasureObjects) restoreTransitionedObject(ctx context.Context, bucket string, object string, opts ObjectOptions) error {
	setRestoreHeaderFn := func(oi ObjectInfo, rerr error) error {
		if rerr == nil {
			return nil // nothing to do; restore object was successful
		}
		er.updateRestoreMetadata(ctx, bucket, object, oi, opts)
		return rerr
	}
	var oi ObjectInfo
	// get the file info on disk for transitioned object
	actualfi, _, _, err := er.getObjectFileInfo(ctx, bucket, object, opts, false)
	if err != nil {
		return setRestoreHeaderFn(oi, toObjectErr(err, bucket, object))
	}

	oi = actualfi.ToObjectInfo(bucket, object, opts.Versioned || opts.VersionSuspended)
	ropts := putRestoreOpts(bucket, object, opts.Transition.RestoreRequest, oi)
	if len(oi.Parts) == 1 {
		var rs *HTTPRangeSpec
		gr, err := getTransitionedObjectReader(ctx, bucket, object, rs, http.Header{}, oi, opts)
		if err != nil {
			return setRestoreHeaderFn(oi, toObjectErr(err, bucket, object))
		}
		defer gr.Close()
		hashReader, err := hash.NewReader(gr, gr.ObjInfo.Size, "", "", gr.ObjInfo.Size)
		if err != nil {
			return setRestoreHeaderFn(oi, toObjectErr(err, bucket, object))
		}
		pReader := NewPutObjReader(hashReader)
		_, err = er.PutObject(ctx, bucket, object, pReader, ropts)
		return setRestoreHeaderFn(oi, toObjectErr(err, bucket, object))
	}

	res, err := er.NewMultipartUpload(ctx, bucket, object, ropts)
	if err != nil {
		return setRestoreHeaderFn(oi, err)
	}

	var uploadedParts []CompletePart
	var rs *HTTPRangeSpec
	// get reader from the warm backend - note that even in the case of encrypted objects, this stream is still encrypted.
	gr, err := getTransitionedObjectReader(ctx, bucket, object, rs, http.Header{}, oi, opts)
	if err != nil {
		return setRestoreHeaderFn(oi, err)
	}
	defer gr.Close()

	// rehydrate the parts back on disk as per the original xl.meta prior to transition
	for _, partInfo := range oi.Parts {
		hr, err := hash.NewReader(gr, partInfo.Size, "", "", partInfo.Size)
		if err != nil {
			return setRestoreHeaderFn(oi, err)
		}
		pInfo, err := er.PutObjectPart(ctx, bucket, object, res.UploadID, partInfo.Number, NewPutObjReader(hr), ObjectOptions{})
		if err != nil {
			return setRestoreHeaderFn(oi, err)
		}
		if pInfo.Size != partInfo.Size {
			return setRestoreHeaderFn(oi, InvalidObjectState{Bucket: bucket, Object: object})
		}
		uploadedParts = append(uploadedParts, CompletePart{
			PartNumber: pInfo.PartNumber,
			ETag:       pInfo.ETag,
		})
	}
	_, err = er.CompleteMultipartUpload(ctx, bucket, object, res.UploadID, uploadedParts, ObjectOptions{
		MTime: oi.ModTime,
	})
	return setRestoreHeaderFn(oi, err)
}

// DecomTieredObject - moves tiered object to another pool during decommissioning.
func (er erasureObjects) DecomTieredObject(ctx context.Context, bucket, object string, fi FileInfo, opts ObjectOptions) error {
	if opts.UserDefined == nil {
		opts.UserDefined = make(map[string]string)
	}
	// overlay Erasure info for this set of disks
	storageDisks := er.getDisks()
	// Get parity and data drive count based on storage class metadata
	parityDrives := globalStorageClass.GetParityForSC(opts.UserDefined[xhttp.AmzStorageClass])
	if parityDrives < 0 {
		parityDrives = er.defaultParityCount
	}
	dataDrives := len(storageDisks) - parityDrives

	// we now know the number of blocks this object needs for data and parity.
	// writeQuorum is dataBlocks + 1
	writeQuorum := dataDrives
	if dataDrives == parityDrives {
		writeQuorum++
	}

	// Initialize parts metadata
	partsMetadata := make([]FileInfo, len(storageDisks))

	fi2 := newFileInfo(pathJoin(bucket, object), dataDrives, parityDrives)
	fi.Erasure = fi2.Erasure
	// Initialize erasure metadata.
	for index := range partsMetadata {
		partsMetadata[index] = fi
		partsMetadata[index].Erasure.Index = index + 1
	}

	// Order disks according to erasure distribution
	var onlineDisks []StorageAPI
	onlineDisks, partsMetadata = shuffleDisksAndPartsMetadata(storageDisks, partsMetadata, fi)

	if _, err := writeUniqueFileInfo(ctx, onlineDisks, bucket, object, partsMetadata, writeQuorum); err != nil {
		return toObjectErr(err, bucket, object)
	}

	return nil
}
