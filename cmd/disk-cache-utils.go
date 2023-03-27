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
	"container/list"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/etag"
)

// CacheStatusType - whether the request was served from cache.
type CacheStatusType string

const (
	// CacheHit - whether object was served from cache.
	CacheHit CacheStatusType = "HIT"

	// CacheMiss - object served from backend.
	CacheMiss CacheStatusType = "MISS"
)

func (c CacheStatusType) String() string {
	if c != "" {
		return string(c)
	}
	return string(CacheMiss)
}

type cacheControl struct {
	expiry       time.Time
	maxAge       int
	sMaxAge      int
	minFresh     int
	maxStale     int
	noStore      bool
	onlyIfCached bool
	noCache      bool
}

func (c *cacheControl) isStale(modTime time.Time) bool {
	if c == nil {
		return false
	}
	// response will never be stale if only-if-cached is set
	if c.onlyIfCached {
		return false
	}
	// Cache-Control value no-store indicates never cache
	if c.noStore {
		return true
	}
	// Cache-Control value no-cache indicates cache entry needs to be revalidated before
	// serving from cache
	if c.noCache {
		return true
	}
	now := time.Now()

	if c.sMaxAge > 0 && c.sMaxAge < int(now.Sub(modTime).Seconds()) {
		return true
	}
	if c.maxAge > 0 && c.maxAge < int(now.Sub(modTime).Seconds()) {
		return true
	}

	if !c.expiry.Equal(time.Time{}) && c.expiry.Before(time.Now().Add(time.Duration(c.maxStale))) {
		return true
	}

	if c.minFresh > 0 && c.minFresh <= int(now.Sub(modTime).Seconds()) {
		return true
	}

	return false
}

// returns struct with cache-control settings from user metadata.
func cacheControlOpts(o ObjectInfo) *cacheControl {
	c := cacheControl{}
	m := o.UserDefined
	if !o.Expires.Equal(timeSentinel) {
		c.expiry = o.Expires
	}

	var headerVal string
	for k, v := range m {
		if strings.EqualFold(k, "cache-control") {
			headerVal = v
		}
	}
	if headerVal == "" {
		return nil
	}
	headerVal = strings.ToLower(headerVal)
	headerVal = strings.TrimSpace(headerVal)

	vals := strings.Split(headerVal, ",")
	for _, val := range vals {
		val = strings.TrimSpace(val)

		if val == "no-store" {
			c.noStore = true
			continue
		}
		if val == "only-if-cached" {
			c.onlyIfCached = true
			continue
		}
		if val == "no-cache" {
			c.noCache = true
			continue
		}
		p := strings.Split(val, "=")

		if len(p) != 2 {
			continue
		}
		if p[0] == "max-age" ||
			p[0] == "s-maxage" ||
			p[0] == "min-fresh" ||
			p[0] == "max-stale" {
			i, err := strconv.Atoi(p[1])
			if err != nil {
				return nil
			}
			if p[0] == "max-age" {
				c.maxAge = i
			}
			if p[0] == "s-maxage" {
				c.sMaxAge = i
			}
			if p[0] == "min-fresh" {
				c.minFresh = i
			}
			if p[0] == "max-stale" {
				c.maxStale = i
			}
		}
	}
	return &c
}

// backendDownError returns true if err is due to backend failure or faulty disk if in server mode
func backendDownError(err error) bool {
	_, backendDown := err.(BackendDown)
	return backendDown || IsErr(err, baseErrs...)
}

// IsCacheable returns if the object should be saved in the cache.
func (o ObjectInfo) IsCacheable() bool {
	if globalCacheKMS != nil {
		return true
	}
	_, ok := crypto.IsEncrypted(o.UserDefined)
	return !ok
}

// reads file cached on disk from offset upto length
func readCacheFileStream(filePath string, offset, length int64) (io.ReadCloser, error) {
	if filePath == "" || offset < 0 {
		return nil, errInvalidArgument
	}
	if err := checkPathLength(filePath); err != nil {
		return nil, err
	}

	fr, err := os.Open(filePath)
	if err != nil {
		return nil, osErrToFileErr(err)
	}
	// Stat to get the size of the file at path.
	st, err := fr.Stat()
	if err != nil {
		err = osErrToFileErr(err)
		return nil, err
	}

	if err = os.Chtimes(filePath, time.Now(), st.ModTime()); err != nil {
		return nil, err
	}

	// Verify if its not a regular file, since subsequent Seek is undefined.
	if !st.Mode().IsRegular() {
		return nil, errIsNotRegular
	}

	if err = os.Chtimes(filePath, time.Now(), st.ModTime()); err != nil {
		return nil, err
	}

	// Seek to the requested offset.
	if offset > 0 {
		_, err = fr.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, err
		}
	}
	return struct {
		io.Reader
		io.Closer
	}{Reader: io.LimitReader(fr, length), Closer: fr}, nil
}

func isCacheEncrypted(meta map[string]string) bool {
	_, ok := meta[SSECacheEncrypted]
	return ok
}

// decryptCacheObjectETag tries to decrypt the ETag saved in encrypted format using the cache KMS
func decryptCacheObjectETag(info *ObjectInfo) error {
	if info.IsDir {
		return nil // Directories are never encrypted.
	}

	// Depending on the SSE type we handle ETags slightly
	// differently. ETags encrypted with SSE-S3 must be
	// decrypted first, since the client expects that
	// a single-part SSE-S3 ETag is equal to the content MD5.
	//
	// For all other SSE types, the ETag is not the content MD5.
	// Therefore, we don't decrypt but only format it.
	switch kind, ok := crypto.IsEncrypted(info.UserDefined); {
	case ok && kind == crypto.S3 && isCacheEncrypted(info.UserDefined):
		ETag, err := etag.Parse(info.ETag)
		if err != nil {
			return err
		}
		if !ETag.IsEncrypted() {
			info.ETag = ETag.Format().String()
			return nil
		}

		key, err := crypto.S3.UnsealObjectKey(globalCacheKMS, info.UserDefined, info.Bucket, info.Name)
		if err != nil {
			return err
		}
		ETag, err = etag.Decrypt(key[:], ETag)
		if err != nil {
			return err
		}
		info.ETag = ETag.Format().String()
	case ok && (kind == crypto.S3KMS || kind == crypto.SSEC) && isCacheEncrypted(info.UserDefined):
		ETag, err := etag.Parse(info.ETag)
		if err != nil {
			return err
		}
		info.ETag = ETag.Format().String()
	}
	return nil
}

// decryptCacheObjectETag tries to decrypt the ETag saved in encrypted format using the cache KMS
func decryptCachePartETags(c *cacheMeta) ([]string, error) {
	// Depending on the SSE type we handle ETags slightly
	// differently. ETags encrypted with SSE-S3 must be
	// decrypted first, since the client expects that
	// a single-part SSE-S3 ETag is equal to the content MD5.
	//
	// For all other SSE types, the ETag is not the content MD5.
	// Therefore, we don't decrypt but only format it.
	switch kind, ok := crypto.IsEncrypted(c.Meta); {
	case ok && kind == crypto.S3 && isCacheEncrypted(c.Meta):
		key, err := crypto.S3.UnsealObjectKey(globalCacheKMS, c.Meta, c.Bucket, c.Object)
		if err != nil {
			return nil, err
		}
		etags := make([]string, 0, len(c.PartETags))
		for i := range c.PartETags {
			ETag, err := etag.Parse(c.PartETags[i])
			if err != nil {
				return nil, err
			}
			ETag, err = etag.Decrypt(key[:], ETag)
			if err != nil {
				return nil, err
			}
			etags = append(etags, ETag.Format().String())
		}
		return etags, nil
	case ok && (kind == crypto.S3KMS || kind == crypto.SSEC) && isCacheEncrypted(c.Meta):
		etags := make([]string, 0, len(c.PartETags))
		for i := range c.PartETags {
			ETag, err := etag.Parse(c.PartETags[i])
			if err != nil {
				return nil, err
			}
			etags = append(etags, ETag.Format().String())
		}
		return etags, nil
	default:
		return c.PartETags, nil
	}
}

func isMetadataSame(m1, m2 map[string]string) bool {
	if m1 == nil && m2 == nil {
		return true
	}
	if (m1 == nil && m2 != nil) || (m2 == nil && m1 != nil) {
		return false
	}
	if len(m1) != len(m2) {
		return false
	}
	for k1, v1 := range m1 {
		if v2, ok := m2[k1]; !ok || (v1 != v2) {
			return false
		}
	}
	return true
}

type fileScorer struct {
	saveBytes uint64
	now       int64
	maxHits   int
	// 1/size for consistent score.
	sizeMult float64

	// queue is a linked list of files we want to delete.
	// The list is kept sorted according to score, highest at top, lowest at bottom.
	queue       list.List
	queuedBytes uint64
	seenBytes   uint64
}

type queuedFile struct {
	name      string
	versionID string
	size      uint64
	score     float64
}

// newFileScorer allows to collect files to save a specific number of bytes.
// Each file is assigned a score based on its age, size and number of hits.
// A list of files is maintained
func newFileScorer(saveBytes uint64, now int64, maxHits int) (*fileScorer, error) {
	if saveBytes == 0 {
		return nil, errors.New("newFileScorer: saveBytes = 0")
	}
	if now < 0 {
		return nil, errors.New("newFileScorer: now < 0")
	}
	if maxHits <= 0 {
		return nil, errors.New("newFileScorer: maxHits <= 0")
	}
	f := fileScorer{saveBytes: saveBytes, maxHits: maxHits, now: now, sizeMult: 1 / float64(saveBytes)}
	f.queue.Init()
	return &f, nil
}

func (f *fileScorer) addFile(name string, accTime time.Time, size int64, hits int) {
	f.addFileWithObjInfo(ObjectInfo{
		Name:    name,
		AccTime: accTime,
		Size:    size,
	}, hits)
}

func (f *fileScorer) addFileWithObjInfo(objInfo ObjectInfo, hits int) {
	// Calculate how much we want to delete this object.
	file := queuedFile{
		name:      objInfo.Name,
		versionID: objInfo.VersionID,
		size:      uint64(objInfo.Size),
	}
	f.seenBytes += uint64(objInfo.Size)

	var score float64
	if objInfo.ModTime.IsZero() {
		// Mod time is not available with disk cache use atime.
		score = float64(f.now - objInfo.AccTime.Unix())
	} else {
		// if not used mod time when mod time is available.
		score = float64(f.now - objInfo.ModTime.Unix())
	}

	// Size as fraction of how much we want to save, 0->1.
	szWeight := math.Max(0, (math.Min(1, float64(file.size)*f.sizeMult)))
	// 0 at f.maxHits, 1 at 0.
	hitsWeight := (1.0 - math.Max(0, math.Min(1.0, float64(hits)/float64(f.maxHits))))
	file.score = score * (1 + 0.25*szWeight + 0.25*hitsWeight)
	// If we still haven't saved enough, just add the file
	if f.queuedBytes < f.saveBytes {
		f.insertFile(file)
		f.trimQueue()
		return
	}
	// If we score less than the worst, don't insert.
	worstE := f.queue.Back()
	if worstE != nil && file.score < worstE.Value.(queuedFile).score {
		return
	}
	f.insertFile(file)
	f.trimQueue()
}

// adjustSaveBytes allows to adjust the number of bytes to save.
// This can be used to adjust the count on the fly.
// Returns true if there still is a need to delete files (n+saveBytes >0),
// false if no more bytes needs to be saved.
func (f *fileScorer) adjustSaveBytes(n int64) bool {
	if f == nil {
		return false
	}
	if int64(f.saveBytes)+n <= 0 {
		f.saveBytes = 0
		f.trimQueue()
		return false
	}
	if n < 0 {
		f.saveBytes -= ^uint64(n - 1)
	} else {
		f.saveBytes += uint64(n)
	}
	if f.saveBytes == 0 {
		f.queue.Init()
		f.saveBytes = 0
		return false
	}
	if n < 0 {
		f.trimQueue()
	}
	return true
}

// insertFile will insert a file into the list, sorted by its score.
func (f *fileScorer) insertFile(file queuedFile) {
	e := f.queue.Front()
	for e != nil {
		v := e.Value.(queuedFile)
		if v.score < file.score {
			break
		}
		e = e.Next()
	}
	f.queuedBytes += file.size
	// We reached the end.
	if e == nil {
		f.queue.PushBack(file)
		return
	}
	f.queue.InsertBefore(file, e)
}

// trimQueue will trim the back of queue and still keep below wantSave.
func (f *fileScorer) trimQueue() {
	for {
		e := f.queue.Back()
		if e == nil {
			return
		}
		v := e.Value.(queuedFile)
		if f.queuedBytes-v.size < f.saveBytes {
			return
		}
		f.queue.Remove(e)
		f.queuedBytes -= v.size
	}
}

func (f *fileScorer) purgeFunc(p func(qfile queuedFile)) {
	e := f.queue.Front()
	for e != nil {
		p(e.Value.(queuedFile))
		e = e.Next()
	}
}

// fileNames returns all queued file names.
func (f *fileScorer) fileNames() []string {
	res := make([]string, 0, f.queue.Len())
	e := f.queue.Front()
	for e != nil {
		res = append(res, e.Value.(queuedFile).name)
		e = e.Next()
	}
	return res
}

func (f *fileScorer) reset() {
	f.queue.Init()
	f.queuedBytes = 0
}

func (f *fileScorer) queueString() string {
	var res strings.Builder
	e := f.queue.Front()
	i := 0
	for e != nil {
		v := e.Value.(queuedFile)
		if i > 0 {
			res.WriteByte('\n')
		}
		res.WriteString(fmt.Sprintf("%03d: %s (score: %.3f, bytes: %d)", i, v.name, v.score, v.size))
		i++
		e = e.Next()
	}
	return res.String()
}

// bytesToClear() returns the number of bytes to clear to reach low watermark
// w.r.t quota given disk total and free space, quota in % allocated to cache
// and low watermark % w.r.t allowed quota.
// If the high watermark hasn't been reached 0 will be returned.
func bytesToClear(total, free int64, quotaPct, lowWatermark, highWatermark uint64) uint64 {
	used := total - free
	quotaAllowed := total * (int64)(quotaPct) / 100
	highWMUsage := total * (int64)(highWatermark*quotaPct) / (100 * 100)
	if used < highWMUsage {
		return 0
	}
	// Return bytes needed to reach low watermark.
	lowWMUsage := total * (int64)(lowWatermark*quotaPct) / (100 * 100)
	return (uint64)(math.Min(float64(quotaAllowed), math.Max(0.0, float64(used-lowWMUsage))))
}

type multiWriter struct {
	backendWriter io.Writer
	cacheWriter   *io.PipeWriter
	pipeClosed    bool
}

// multiWriter writes to backend and cache - if cache write
// fails close the pipe, but continue writing to the backend
func (t *multiWriter) Write(p []byte) (n int, err error) {
	n, err = t.backendWriter.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
		return
	}
	if err != nil {
		if !t.pipeClosed {
			t.cacheWriter.CloseWithError(err)
		}
		return
	}

	// ignore errors writing to cache
	if !t.pipeClosed {
		_, cerr := t.cacheWriter.Write(p)
		if cerr != nil {
			t.pipeClosed = true
			t.cacheWriter.CloseWithError(cerr)
		}
	}
	return len(p), nil
}

func cacheMultiWriter(w1 io.Writer, w2 *io.PipeWriter) io.Writer {
	return &multiWriter{backendWriter: w1, cacheWriter: w2}
}

// writebackInProgress returns true if writeback commit is not complete
func writebackInProgress(m map[string]string) bool {
	if v, ok := m[writeBackStatusHeader]; ok {
		switch cacheCommitStatus(v) {
		case CommitPending, CommitFailed:
			return true
		}
	}
	return false
}
