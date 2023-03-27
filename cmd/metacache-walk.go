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
	"net/url"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	xhttp "github.com/minio/minio/internal/http"
	xioutil "github.com/minio/minio/internal/ioutil"
	"github.com/minio/minio/internal/logger"
)

// WalkDirOptions provides options for WalkDir operations.
type WalkDirOptions struct {
	// Bucket to scanner
	Bucket string

	// Directory inside the bucket.
	BaseDir string

	// Do a full recursive scan.
	Recursive bool

	// ReportNotFound will return errFileNotFound if all disks reports the BaseDir cannot be found.
	ReportNotFound bool

	// FilterPrefix will only return results with given prefix within folder.
	// Should never contain a slash.
	FilterPrefix string

	// ForwardTo will forward to the given object path.
	ForwardTo string

	// Limit the number of returned objects if > 0.
	Limit int
}

// WalkDir will traverse a directory and return all entries found.
// On success a sorted meta cache stream will be returned.
// Metadata has data stripped, if any.
func (s *xlStorage) WalkDir(ctx context.Context, opts WalkDirOptions, wr io.Writer) (err error) {
	// Verify if volume is valid and it exists.
	volumeDir, err := s.getVolDir(opts.Bucket)
	if err != nil {
		return err
	}

	// Stat a volume entry.
	if err = Access(volumeDir); err != nil {
		if osIsNotExist(err) {
			return errVolumeNotFound
		} else if isSysErrIO(err) {
			return errFaultyDisk
		}
		return err
	}

	// Use a small block size to start sending quickly
	w := newMetacacheWriter(wr, 16<<10)
	w.reuseBlocks = true // We are not sharing results, so reuse buffers.
	defer w.Close()
	out, err := w.stream()
	if err != nil {
		return err
	}
	defer close(out)
	var objsReturned int

	objReturned := func(metadata []byte) {
		if opts.Limit <= 0 {
			return
		}
		if m, _, _ := isIndexedMetaV2(metadata); m != nil && !m.AllHidden(true) {
			objsReturned++
		}
	}

	// Fast exit track to check if we are listing an object with
	// a trailing slash, this will avoid to list the object content.
	if HasSuffix(opts.BaseDir, SlashSeparator) {
		metadata, err := s.readMetadata(ctx, pathJoin(volumeDir,
			opts.BaseDir[:len(opts.BaseDir)-1]+globalDirSuffix,
			xlStorageFormatFile))
		if err == nil {
			// if baseDir is already a directory object, consider it
			// as part of the list call, this is AWS S3 specific
			// behavior.
			out <- metaCacheEntry{
				name:     opts.BaseDir,
				metadata: metadata,
			}
			objReturned(metadata)
		} else {
			st, sterr := Lstat(pathJoin(volumeDir, opts.BaseDir, xlStorageFormatFile))
			if sterr == nil && st.Mode().IsRegular() {
				return errFileNotFound
			}
		}
	}

	prefix := opts.FilterPrefix
	var scanDir func(path string) error

	scanDir = func(current string) error {
		// Skip forward, if requested...
		forward := ""
		if len(opts.ForwardTo) > 0 && strings.HasPrefix(opts.ForwardTo, current) {
			forward = strings.TrimPrefix(opts.ForwardTo, current)
			// Trim further directories and trailing slash.
			if idx := strings.IndexByte(forward, '/'); idx > 0 {
				forward = forward[:idx]
			}
		}
		if contextCanceled(ctx) {
			return ctx.Err()
		}
		if opts.Limit > 0 && objsReturned >= opts.Limit {
			return nil
		}

		s.walkMu.Lock()
		entries, err := s.ListDir(ctx, opts.Bucket, current, -1)
		s.walkMu.Unlock()
		if err != nil {
			// Folder could have gone away in-between
			if err != errVolumeNotFound && err != errFileNotFound {
				logger.LogIf(ctx, err)
			}
			if opts.ReportNotFound && err == errFileNotFound && current == opts.BaseDir {
				return errFileNotFound
			}
			// Forward some errors?
			return nil
		}
		diskHealthCheckOK(ctx, err)
		if len(entries) == 0 {
			return nil
		}
		dirObjects := make(map[string]struct{})
		for i, entry := range entries {
			if opts.Limit > 0 && objsReturned >= opts.Limit {
				return nil
			}
			if len(prefix) > 0 && !strings.HasPrefix(entry, prefix) {
				// Do not retain the file, since it doesn't
				// match the prefix.
				entries[i] = ""
				continue
			}
			if len(forward) > 0 && entry < forward {
				// Do not retain the file, since its
				// lexially smaller than 'forward'
				entries[i] = ""
				continue
			}
			if strings.HasSuffix(entry, slashSeparator) {
				if strings.HasSuffix(entry, globalDirSuffixWithSlash) {
					// Add without extension so it is sorted correctly.
					entry = strings.TrimSuffix(entry, globalDirSuffixWithSlash) + slashSeparator
					dirObjects[entry] = struct{}{}
					entries[i] = entry
					continue
				}
				// Trim slash, since we don't know if this is folder or object.
				entries[i] = entries[i][:len(entry)-1]
				continue
			}
			// Do not retain the file.
			entries[i] = ""

			if contextCanceled(ctx) {
				return ctx.Err()
			}
			// If root was an object return it as such.
			if HasSuffix(entry, xlStorageFormatFile) {
				var meta metaCacheEntry
				s.walkReadMu.Lock()
				meta.metadata, err = s.readMetadata(ctx, pathJoin(volumeDir, current, entry))
				s.walkReadMu.Unlock()
				diskHealthCheckOK(ctx, err)
				if err != nil {
					// It is totally possible that xl.meta was overwritten
					// while being concurrently listed at the same time in
					// such scenarios the 'xl.meta' might get truncated
					if !IsErrIgnored(err, io.EOF, io.ErrUnexpectedEOF) {
						logger.LogIf(ctx, err)
					}
					continue
				}
				meta.name = strings.TrimSuffix(entry, xlStorageFormatFile)
				meta.name = strings.TrimSuffix(meta.name, SlashSeparator)
				meta.name = pathJoin(current, meta.name)
				meta.name = decodeDirObject(meta.name)

				objReturned(meta.metadata)
				out <- meta
				return nil
			}
			// Check legacy.
			if HasSuffix(entry, xlStorageFormatFileV1) {
				var meta metaCacheEntry
				s.walkReadMu.Lock()
				meta.metadata, err = xioutil.ReadFile(pathJoin(volumeDir, current, entry))
				s.walkReadMu.Unlock()
				diskHealthCheckOK(ctx, err)
				if err != nil {
					if !IsErrIgnored(err, io.EOF, io.ErrUnexpectedEOF) {
						logger.LogIf(ctx, err)
					}
					continue
				}
				meta.name = strings.TrimSuffix(entry, xlStorageFormatFileV1)
				meta.name = strings.TrimSuffix(meta.name, SlashSeparator)
				meta.name = pathJoin(current, meta.name)
				objReturned(meta.metadata)

				out <- meta
				return nil
			}
			// Skip all other files.
		}

		// Process in sort order.
		sort.Strings(entries)
		dirStack := make([]string, 0, 5)
		prefix = "" // Remove prefix after first level as we have already filtered the list.
		if len(forward) > 0 {
			// Conservative forwarding. Entries may be either objects or prefixes.
			for i, entry := range entries {
				if entry >= forward || strings.HasPrefix(forward, entry) {
					entries = entries[i:]
					break
				}
			}
		}

		for _, entry := range entries {
			if opts.Limit > 0 && objsReturned >= opts.Limit {
				return nil
			}
			if entry == "" {
				continue
			}
			if contextCanceled(ctx) {
				return ctx.Err()
			}
			meta := metaCacheEntry{name: pathJoin(current, entry)}

			// If directory entry on stack before this, pop it now.
			for len(dirStack) > 0 && dirStack[len(dirStack)-1] < meta.name {
				pop := dirStack[len(dirStack)-1]
				out <- metaCacheEntry{name: pop}
				if opts.Recursive {
					// Scan folder we found. Should be in correct sort order where we are.
					err := scanDir(pop)
					if err != nil && !IsErrIgnored(err, context.Canceled) {
						logger.LogIf(ctx, err)
					}
				}
				dirStack = dirStack[:len(dirStack)-1]
			}

			// All objects will be returned as directories, there has been no object check yet.
			// Check it by attempting to read metadata.
			_, isDirObj := dirObjects[entry]
			if isDirObj {
				meta.name = meta.name[:len(meta.name)-1] + globalDirSuffixWithSlash
			}

			s.walkReadMu.Lock()
			meta.metadata, err = s.readMetadata(ctx, pathJoin(volumeDir, meta.name, xlStorageFormatFile))
			s.walkReadMu.Unlock()
			diskHealthCheckOK(ctx, err)
			switch {
			case err == nil:
				// It was an object
				if isDirObj {
					meta.name = strings.TrimSuffix(meta.name, globalDirSuffixWithSlash) + slashSeparator
				}
				objReturned(meta.metadata)

				out <- meta
			case osIsNotExist(err), isSysErrIsDir(err):
				meta.metadata, err = xioutil.ReadFile(pathJoin(volumeDir, meta.name, xlStorageFormatFileV1))
				diskHealthCheckOK(ctx, err)
				if err == nil {
					// It was an object
					objReturned(meta.metadata)

					out <- meta
					continue
				}

				// NOT an object, append to stack (with slash)
				// If dirObject, but no metadata (which is unexpected) we skip it.
				if !isDirObj {
					if !isDirEmpty(pathJoin(volumeDir, meta.name+slashSeparator)) {
						dirStack = append(dirStack, meta.name+slashSeparator)
					}
				}
			case isSysErrNotDir(err):
				// skip
			}
		}

		// If directory entry left on stack, pop it now.
		for len(dirStack) > 0 {
			if opts.Limit > 0 && objsReturned >= opts.Limit {
				return nil
			}
			if contextCanceled(ctx) {
				return ctx.Err()
			}
			pop := dirStack[len(dirStack)-1]
			out <- metaCacheEntry{name: pop}
			if opts.Recursive {
				// Scan folder we found. Should be in correct sort order where we are.
				logger.LogIf(ctx, scanDir(pop))
			}
			dirStack = dirStack[:len(dirStack)-1]
		}
		return nil
	}

	// Stream output.
	return scanDir(opts.BaseDir)
}

func (p *xlStorageDiskIDCheck) WalkDir(ctx context.Context, opts WalkDirOptions, wr io.Writer) (err error) {
	ctx, done, err := p.TrackDiskHealth(ctx, storageMetricWalkDir, opts.Bucket, opts.BaseDir)
	if err != nil {
		return err
	}
	defer done(&err)

	return p.storage.WalkDir(ctx, opts, wr)
}

// WalkDir will traverse a directory and return all entries found.
// On success a meta cache stream will be returned, that should be closed when done.
func (client *storageRESTClient) WalkDir(ctx context.Context, opts WalkDirOptions, wr io.Writer) error {
	values := make(url.Values)
	values.Set(storageRESTVolume, opts.Bucket)
	values.Set(storageRESTDirPath, opts.BaseDir)
	values.Set(storageRESTRecursive, strconv.FormatBool(opts.Recursive))
	values.Set(storageRESTReportNotFound, strconv.FormatBool(opts.ReportNotFound))
	values.Set(storageRESTPrefixFilter, opts.FilterPrefix)
	values.Set(storageRESTForwardFilter, opts.ForwardTo)
	respBody, err := client.call(ctx, storageRESTMethodWalkDir, values, nil, -1)
	if err != nil {
		logger.LogIf(ctx, err)
		return err
	}
	defer xhttp.DrainBody(respBody)
	return waitForHTTPStream(respBody, wr)
}

// WalkDirHandler - remote caller to list files and folders in a requested directory path.
func (s *storageRESTServer) WalkDirHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	dirPath := r.Form.Get(storageRESTDirPath)
	recursive, err := strconv.ParseBool(r.Form.Get(storageRESTRecursive))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	var reportNotFound bool
	if v := r.Form.Get(storageRESTReportNotFound); v != "" {
		reportNotFound, err = strconv.ParseBool(v)
		if err != nil {
			s.writeErrorResponse(w, err)
			return
		}
	}

	prefix := r.Form.Get(storageRESTPrefixFilter)
	forward := r.Form.Get(storageRESTForwardFilter)
	writer := streamHTTPResponse(w)
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			writer.CloseWithError(fmt.Errorf("panic: %v", r))
		}
	}()
	writer.CloseWithError(s.storage.WalkDir(r.Context(), WalkDirOptions{
		Bucket:         volume,
		BaseDir:        dirPath,
		Recursive:      recursive,
		ReportNotFound: reportNotFound,
		FilterPrefix:   prefix,
		ForwardTo:      forward,
	}, writer))
}
