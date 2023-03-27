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
	"bufio"
	"context"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/user"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinylib/msgp/msgp"

	jwtreq "github.com/golang-jwt/jwt/v4/request"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/config"
	xhttp "github.com/minio/minio/internal/http"
	xioutil "github.com/minio/minio/internal/ioutil"
	xjwt "github.com/minio/minio/internal/jwt"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/mux"
	xnet "github.com/minio/pkg/net"
)

var errDiskStale = errors.New("drive stale")

// To abstract a disk over network.
type storageRESTServer struct {
	storage *xlStorageDiskIDCheck
}

func (s *storageRESTServer) writeErrorResponse(w http.ResponseWriter, err error) {
	if errors.Is(err, errDiskStale) {
		w.WriteHeader(http.StatusPreconditionFailed)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
	w.Write([]byte(err.Error()))
}

// DefaultSkewTime - skew time is 15 minutes between minio peers.
const DefaultSkewTime = 15 * time.Minute

// Authenticates storage client's requests and validates for skewed time.
func storageServerRequestValidate(r *http.Request) error {
	token, err := jwtreq.AuthorizationHeaderExtractor.ExtractToken(r)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return errNoAuthToken
		}
		return err
	}

	claims := xjwt.NewStandardClaims()
	if err = xjwt.ParseWithStandardClaims(token, claims, []byte(globalActiveCred.SecretKey)); err != nil {
		return errAuthentication
	}

	owner := claims.AccessKey == globalActiveCred.AccessKey || claims.Subject == globalActiveCred.AccessKey
	if !owner {
		return errAuthentication
	}

	if claims.Audience != r.URL.RawQuery {
		return errAuthentication
	}

	requestTimeStr := r.Header.Get("X-Minio-Time")
	requestTime, err := time.Parse(time.RFC3339, requestTimeStr)
	if err != nil {
		return err
	}
	utcNow := UTCNow()
	delta := requestTime.Sub(utcNow)
	if delta < 0 {
		delta *= -1
	}
	if delta > DefaultSkewTime {
		return fmt.Errorf("client time %v is too apart with server time %v", requestTime, utcNow)
	}

	return nil
}

// IsValid - To authenticate and verify the time difference.
func (s *storageRESTServer) IsAuthValid(w http.ResponseWriter, r *http.Request) bool {
	if s.storage == nil {
		s.writeErrorResponse(w, errDiskNotFound)
		return false
	}

	if err := storageServerRequestValidate(r); err != nil {
		s.writeErrorResponse(w, err)
		return false
	}

	return true
}

// IsValid - To authenticate and check if the disk-id in the request corresponds to the underlying disk.
func (s *storageRESTServer) IsValid(w http.ResponseWriter, r *http.Request) bool {
	if !s.IsAuthValid(w, r) {
		return false
	}

	if err := r.ParseForm(); err != nil {
		s.writeErrorResponse(w, err)
		return false
	}

	diskID := r.Form.Get(storageRESTDiskID)
	if diskID == "" {
		// Request sent empty disk-id, we allow the request
		// as the peer might be coming up and trying to read format.json
		// or create format.json
		return true
	}

	storedDiskID, err := s.storage.GetDiskID()
	if err != nil {
		s.writeErrorResponse(w, err)
		return false
	}

	if diskID != storedDiskID {
		s.writeErrorResponse(w, errDiskStale)
		return false
	}

	// If format.json is available and request sent the right disk-id, we allow the request
	return true
}

// HealthHandler handler checks if disk is stale
func (s *storageRESTServer) HealthHandler(w http.ResponseWriter, r *http.Request) {
	s.IsValid(w, r)
}

// DiskInfoHandler - returns disk info.
func (s *storageRESTServer) DiskInfoHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsAuthValid(w, r) {
		return
	}
	info, err := s.storage.DiskInfo(r.Context())
	if err != nil {
		info.Error = err.Error()
	}
	logger.LogIf(r.Context(), msgp.Encode(w, &info))
}

func (s *storageRESTServer) NSScannerHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}

	scanMode, err := strconv.Atoi(r.Form.Get(storageRESTScanMode))
	if err != nil {
		logger.LogIf(r.Context(), err)
		s.writeErrorResponse(w, err)
		return
	}

	setEventStreamHeaders(w)

	var cache dataUsageCache
	err = cache.deserialize(r.Body)
	if err != nil {
		logger.LogIf(r.Context(), err)
		s.writeErrorResponse(w, err)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	resp := streamHTTPResponse(w)
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			resp.CloseWithError(fmt.Errorf("panic: %v", r))
		}
	}()
	respW := msgp.NewWriter(resp)

	// Collect updates, stream them before the full cache is sent.
	updates := make(chan dataUsageEntry, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for update := range updates {
			// Write true bool to indicate update.
			var err error
			if err = respW.WriteBool(true); err == nil {
				err = update.EncodeMsg(respW)
			}
			respW.Flush()
			if err != nil {
				cancel()
				resp.CloseWithError(err)
				return
			}
		}
	}()
	usageInfo, err := s.storage.NSScanner(ctx, cache, updates, madmin.HealScanMode(scanMode))
	if err != nil {
		respW.Flush()
		resp.CloseWithError(err)
		return
	}

	// Write false bool to indicate we finished.
	wg.Wait()
	if err = respW.WriteBool(false); err == nil {
		err = usageInfo.EncodeMsg(respW)
	}
	if err != nil {
		resp.CloseWithError(err)
		return
	}
	resp.CloseWithError(respW.Flush())
}

// MakeVolHandler - make a volume.
func (s *storageRESTServer) MakeVolHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	err := s.storage.MakeVol(r.Context(), volume)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// MakeVolBulkHandler - create multiple volumes as a bulk operation.
func (s *storageRESTServer) MakeVolBulkHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volumes := strings.Split(r.Form.Get(storageRESTVolumes), ",")
	err := s.storage.MakeVolBulk(r.Context(), volumes...)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// ListVolsHandler - list volumes.
func (s *storageRESTServer) ListVolsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	infos, err := s.storage.ListVols(r.Context())
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	logger.LogIf(r.Context(), msgp.Encode(w, VolsInfo(infos)))
}

// StatVolHandler - stat a volume.
func (s *storageRESTServer) StatVolHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	info, err := s.storage.StatVol(r.Context(), volume)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	logger.LogIf(r.Context(), msgp.Encode(w, &info))
}

// DeleteVolumeHandler - delete a volume.
func (s *storageRESTServer) DeleteVolHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	forceDelete := r.Form.Get(storageRESTForceDelete) == "true"
	err := s.storage.DeleteVol(r.Context(), volume, forceDelete)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// AppendFileHandler - append data from the request to the file specified.
func (s *storageRESTServer) AppendFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	buf := make([]byte, r.ContentLength)
	_, err := io.ReadFull(r.Body, buf)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	err = s.storage.AppendFile(r.Context(), volume, filePath, buf)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// CreateFileHandler - copy the contents from the request.
func (s *storageRESTServer) CreateFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	fileSizeStr := r.Form.Get(storageRESTLength)
	fileSize, err := strconv.Atoi(fileSizeStr)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	done, body := keepHTTPReqResponseAlive(w, r)
	done(s.storage.CreateFile(r.Context(), volume, filePath, int64(fileSize), body))
}

// DeleteVersion delete updated metadata.
func (s *storageRESTServer) DeleteVersionHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	forceDelMarker, err := strconv.ParseBool(r.Form.Get(storageRESTForceDelMarker))
	if err != nil {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	err = s.storage.DeleteVersion(r.Context(), volume, filePath, fi, forceDelMarker)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// ReadVersion read metadata of versionID
func (s *storageRESTServer) ReadVersionHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	versionID := r.Form.Get(storageRESTVersionID)
	readData, err := strconv.ParseBool(r.Form.Get(storageRESTReadData))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	fi, err := s.storage.ReadVersion(r.Context(), volume, filePath, versionID, readData)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	logger.LogIf(r.Context(), msgp.Encode(w, &fi))
}

// WriteMetadata write new updated metadata.
func (s *storageRESTServer) WriteMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	err := s.storage.WriteMetadata(r.Context(), volume, filePath, fi)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// UpdateMetadata update new updated metadata.
func (s *storageRESTServer) UpdateMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	err := s.storage.UpdateMetadata(r.Context(), volume, filePath, fi)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// WriteAllHandler - write to file all content.
func (s *storageRESTServer) WriteAllHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}
	tmp := make([]byte, r.ContentLength)
	_, err := io.ReadFull(r.Body, tmp)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	err = s.storage.WriteAll(r.Context(), volume, filePath, tmp)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// CheckPartsHandler - check if a file metadata exists.
func (s *storageRESTServer) CheckPartsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	if err := s.storage.CheckParts(r.Context(), volume, filePath, fi); err != nil {
		s.writeErrorResponse(w, err)
	}
}

// ReadAllHandler - read all the contents of a file.
func (s *storageRESTServer) ReadAllHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	buf, err := s.storage.ReadAll(r.Context(), volume, filePath)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	// Reuse after return.
	defer metaDataPoolPut(buf)
	w.Header().Set(xhttp.ContentLength, strconv.Itoa(len(buf)))
	w.Write(buf)
}

// ReadXLHandler - read xl.meta for an object at path.
func (s *storageRESTServer) ReadXLHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	readData, err := strconv.ParseBool(r.Form.Get(storageRESTReadData))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	rf, err := s.storage.ReadXL(r.Context(), volume, filePath, readData)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	logger.LogIf(r.Context(), msgp.Encode(w, &rf))
}

// ReadFileHandler - read section of a file.
func (s *storageRESTServer) ReadFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	offset, err := strconv.Atoi(r.Form.Get(storageRESTOffset))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	length, err := strconv.Atoi(r.Form.Get(storageRESTLength))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	if offset < 0 || length < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}
	var verifier *BitrotVerifier
	if r.Form.Get(storageRESTBitrotAlgo) != "" {
		hashStr := r.Form.Get(storageRESTBitrotHash)
		var hash []byte
		hash, err = hex.DecodeString(hashStr)
		if err != nil {
			s.writeErrorResponse(w, err)
			return
		}
		verifier = NewBitrotVerifier(BitrotAlgorithmFromString(r.Form.Get(storageRESTBitrotAlgo)), hash)
	}
	buf := make([]byte, length)
	defer metaDataPoolPut(buf) // Reuse if we can.
	_, err = s.storage.ReadFile(r.Context(), volume, filePath, int64(offset), buf, verifier)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	w.Header().Set(xhttp.ContentLength, strconv.Itoa(len(buf)))
	w.Write(buf)
}

// ReadFileHandler - read section of a file.
func (s *storageRESTServer) ReadFileStreamHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	offset, err := strconv.Atoi(r.Form.Get(storageRESTOffset))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	length, err := strconv.Atoi(r.Form.Get(storageRESTLength))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	rc, err := s.storage.ReadFileStream(r.Context(), volume, filePath, int64(offset), int64(length))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	defer rc.Close()

	w.Header().Set(xhttp.ContentLength, strconv.Itoa(length))
	if _, err = xioutil.Copy(w, rc); err != nil {
		if !xnet.IsNetworkOrHostDown(err, true) { // do not need to log disconnected clients
			logger.LogIf(r.Context(), err)
		}
		return
	}
}

// ListDirHandler - list a directory.
func (s *storageRESTServer) ListDirHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	dirPath := r.Form.Get(storageRESTDirPath)
	count, err := strconv.Atoi(r.Form.Get(storageRESTCount))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	entries, err := s.storage.ListDir(r.Context(), volume, dirPath, count)
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	gob.NewEncoder(w).Encode(&entries)
}

// DeleteFileHandler - delete a file.
func (s *storageRESTServer) DeleteFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	recursive, err := strconv.ParseBool(r.Form.Get(storageRESTRecursive))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	force, err := strconv.ParseBool(r.Form.Get(storageRESTForceDelete))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}
	err = s.storage.Delete(r.Context(), volume, filePath, DeleteOptions{
		Recursive: recursive,
		Force:     force,
	})
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// DeleteVersionsErrsResp - collection of delete errors
// for bulk version deletes
type DeleteVersionsErrsResp struct {
	Errs []error
}

// DeleteVersionsHandler - delete a set of a versions.
func (s *storageRESTServer) DeleteVersionsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}

	volume := r.Form.Get(storageRESTVolume)
	totalVersions, err := strconv.Atoi(r.Form.Get(storageRESTTotalVersions))
	if err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	versions := make([]FileInfoVersions, totalVersions)
	decoder := msgp.NewReader(r.Body)
	for i := 0; i < totalVersions; i++ {
		dst := &versions[i]
		if err := dst.DecodeMsg(decoder); err != nil {
			s.writeErrorResponse(w, err)
			return
		}
	}

	dErrsResp := &DeleteVersionsErrsResp{Errs: make([]error, totalVersions)}

	setEventStreamHeaders(w)
	encoder := gob.NewEncoder(w)
	done := keepHTTPResponseAlive(w)
	errs := s.storage.DeleteVersions(r.Context(), volume, versions)
	done(nil)
	for idx := range versions {
		if errs[idx] != nil {
			dErrsResp.Errs[idx] = StorageErr(errs[idx].Error())
		}
	}
	encoder.Encode(dErrsResp)
}

// RenameDataResp - RenameData()'s response.
type RenameDataResp struct {
	Signature uint64
	Err       error
}

// RenameDataHandler - renames a meta object and data dir to destination.
func (s *storageRESTServer) RenameDataHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}

	srcVolume := r.Form.Get(storageRESTSrcVolume)
	srcFilePath := r.Form.Get(storageRESTSrcPath)
	dstVolume := r.Form.Get(storageRESTDstVolume)
	dstFilePath := r.Form.Get(storageRESTDstPath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	setEventStreamHeaders(w)
	encoder := gob.NewEncoder(w)
	done := keepHTTPResponseAlive(w)

	sign, err := s.storage.RenameData(r.Context(), srcVolume, srcFilePath, fi, dstVolume, dstFilePath)
	done(nil)

	resp := &RenameDataResp{
		Signature: sign,
	}
	if err != nil {
		resp.Err = StorageErr(err.Error())
	}
	encoder.Encode(resp)
}

// RenameFileHandler - rename a file.
func (s *storageRESTServer) RenameFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	srcVolume := r.Form.Get(storageRESTSrcVolume)
	srcFilePath := r.Form.Get(storageRESTSrcPath)
	dstVolume := r.Form.Get(storageRESTDstVolume)
	dstFilePath := r.Form.Get(storageRESTDstPath)
	err := s.storage.RenameFile(r.Context(), srcVolume, srcFilePath, dstVolume, dstFilePath)
	if err != nil {
		s.writeErrorResponse(w, err)
	}
}

// CleanAbandonedDataHandler - Clean unused data directories.
func (s *storageRESTServer) CleanAbandonedDataHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	if volume == "" || filePath == "" {
		return // Ignore
	}
	keepHTTPResponseAlive(w)(s.storage.CleanAbandonedData(r.Context(), volume, filePath))
}

// closeNotifier is itself a ReadCloser that will notify when either an error occurs or
// the Close() function is called.
type closeNotifier struct {
	rc   io.ReadCloser
	done chan struct{}
}

func (c *closeNotifier) Read(p []byte) (n int, err error) {
	n, err = c.rc.Read(p)
	if err != nil {
		if c.done != nil {
			close(c.done)
			c.done = nil
		}
	}
	return n, err
}

func (c *closeNotifier) Close() error {
	if c.done != nil {
		close(c.done)
		c.done = nil
	}
	return c.rc.Close()
}

// keepHTTPReqResponseAlive can be used to avoid timeouts with long storage
// operations, such as bitrot verification or data usage scanning.
// Every 10 seconds a space character is sent.
// keepHTTPReqResponseAlive will wait for the returned body to be read before starting the ticker.
// The returned function should always be called to release resources.
// An optional error can be sent which will be picked as text only error,
// without its original type by the receiver.
// waitForHTTPResponse should be used to the receiving side.
func keepHTTPReqResponseAlive(w http.ResponseWriter, r *http.Request) (resp func(error), body io.ReadCloser) {
	bodyDoneCh := make(chan struct{})
	doneCh := make(chan error)
	ctx := r.Context()
	go func() {
		canWrite := true
		write := func(b []byte) {
			if canWrite {
				n, err := w.Write(b)
				if err != nil || n != len(b) {
					canWrite = false
				}
			}
		}
		// Wait for body to be read.
		select {
		case <-ctx.Done():
		case <-bodyDoneCh:
		case err := <-doneCh:
			if err != nil {
				write([]byte{1})
				write([]byte(err.Error()))
			} else {
				write([]byte{0})
			}
			close(doneCh)
			return
		}
		defer close(doneCh)
		// Initiate ticker after body has been read.
		ticker := time.NewTicker(time.Second * 10)
		for {
			select {
			case <-ticker.C:
				// Response not ready, write a filler byte.
				write([]byte{32})
				if canWrite {
					w.(http.Flusher).Flush()
				}
			case err := <-doneCh:
				if err != nil {
					write([]byte{1})
					write([]byte(err.Error()))
				} else {
					write([]byte{0})
				}
				ticker.Stop()
				return
			}
		}
	}()
	return func(err error) {
		if doneCh == nil {
			return
		}

		// Indicate we are ready to write.
		doneCh <- err

		// Wait for channel to be closed so we don't race on writes.
		<-doneCh

		// Clear so we can be called multiple times without crashing.
		doneCh = nil
	}, &closeNotifier{rc: r.Body, done: bodyDoneCh}
}

// keepHTTPResponseAlive can be used to avoid timeouts with long storage
// operations, such as bitrot verification or data usage scanning.
// keepHTTPResponseAlive may NOT be used until the request body has been read,
// use keepHTTPReqResponseAlive instead.
// Every 10 seconds a space character is sent.
// The returned function should always be called to release resources.
// An optional error can be sent which will be picked as text only error,
// without its original type by the receiver.
// waitForHTTPResponse should be used to the receiving side.
func keepHTTPResponseAlive(w http.ResponseWriter) func(error) {
	doneCh := make(chan error)
	go func() {
		canWrite := true
		write := func(b []byte) {
			if canWrite {
				n, err := w.Write(b)
				if err != nil || n != len(b) {
					canWrite = false
				}
			}
		}
		defer close(doneCh)
		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Response not ready, write a filler byte.
				write([]byte{32})
				if canWrite {
					w.(http.Flusher).Flush()
				}
			case err := <-doneCh:
				if err != nil {
					write([]byte{1})
					write([]byte(err.Error()))
				} else {
					write([]byte{0})
				}
				return
			}
		}
	}()
	return func(err error) {
		if doneCh == nil {
			return
		}
		// Indicate we are ready to write.
		doneCh <- err

		// Wait for channel to be closed so we don't race on writes.
		<-doneCh

		// Clear so we can be called multiple times without crashing.
		doneCh = nil
	}
}

// waitForHTTPResponse will wait for responses where keepHTTPResponseAlive
// has been used.
// The returned reader contains the payload.
func waitForHTTPResponse(respBody io.Reader) (io.Reader, error) {
	reader := bufio.NewReader(respBody)
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		// Check if we have a response ready or a filler byte.
		switch b {
		case 0:
			return reader, nil
		case 1:
			errorText, err := io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
			return nil, errors.New(string(errorText))
		case 32:
			continue
		default:
			return nil, fmt.Errorf("unexpected filler byte: %d", b)
		}
	}
}

// httpStreamResponse allows streaming a response, but still send an error.
type httpStreamResponse struct {
	done  chan error
	block chan []byte
	err   error
}

// Write part of the streaming response.
// Note that upstream errors are currently not forwarded, but may be in the future.
func (h *httpStreamResponse) Write(b []byte) (int, error) {
	if len(b) == 0 || h.err != nil {
		// Ignore 0 length blocks
		return 0, h.err
	}
	tmp := make([]byte, len(b))
	copy(tmp, b)
	h.block <- tmp
	return len(b), h.err
}

// CloseWithError will close the stream and return the specified error.
// This can be done several times, but only the first error will be sent.
// After calling this the stream should not be written to.
func (h *httpStreamResponse) CloseWithError(err error) {
	if h.done == nil {
		return
	}
	h.done <- err
	h.err = err
	// Indicates that the response is done.
	<-h.done
	h.done = nil
}

// streamHTTPResponse can be used to avoid timeouts with long storage
// operations, such as bitrot verification or data usage scanning.
// Every 10 seconds a space character is sent.
// The returned function should always be called to release resources.
// An optional error can be sent which will be picked as text only error,
// without its original type by the receiver.
// waitForHTTPStream should be used to the receiving side.
func streamHTTPResponse(w http.ResponseWriter) *httpStreamResponse {
	doneCh := make(chan error)
	blockCh := make(chan []byte)
	h := httpStreamResponse{done: doneCh, block: blockCh}
	go func() {
		canWrite := true
		write := func(b []byte) {
			if canWrite {
				n, err := w.Write(b)
				if err != nil || n != len(b) {
					canWrite = false
				}
			}
		}

		ticker := time.NewTicker(time.Second * 10)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Response not ready, write a filler byte.
				write([]byte{32})
				if canWrite {
					w.(http.Flusher).Flush()
				}
			case err := <-doneCh:
				if err != nil {
					write([]byte{1})
					write([]byte(err.Error()))
				} else {
					write([]byte{0})
				}
				close(doneCh)
				return
			case block := <-blockCh:
				var tmp [5]byte
				tmp[0] = 2
				binary.LittleEndian.PutUint32(tmp[1:], uint32(len(block)))
				write(tmp[:])
				write(block)
				if canWrite {
					w.(http.Flusher).Flush()
				}
			}
		}
	}()
	return &h
}

var poolBuf8k = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 8192)
		return &b
	},
}

var poolBuf128k = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 128<<10)
		return b
	},
}

// waitForHTTPStream will wait for responses where
// streamHTTPResponse has been used.
// The returned reader contains the payload and must be closed if no error is returned.
func waitForHTTPStream(respBody io.ReadCloser, w io.Writer) error {
	var tmp [1]byte
	// 8K copy buffer, reused for less allocs...
	bufp := poolBuf8k.Get().(*[]byte)
	buf := *bufp
	defer poolBuf8k.Put(bufp)
	for {
		_, err := io.ReadFull(respBody, tmp[:])
		if err != nil {
			return err
		}
		// Check if we have a response ready or a filler byte.
		switch tmp[0] {
		case 0:
			// 0 is unbuffered, copy the rest.
			_, err := io.CopyBuffer(w, respBody, buf)
			if err == io.EOF {
				return nil
			}
			return err
		case 1:
			errorText, err := io.ReadAll(respBody)
			if err != nil {
				return err
			}
			return errors.New(string(errorText))
		case 2:
			// Block of data
			var tmp [4]byte
			_, err := io.ReadFull(respBody, tmp[:])
			if err != nil {
				return err
			}
			length := binary.LittleEndian.Uint32(tmp[:])
			n, err := io.CopyBuffer(w, io.LimitReader(respBody, int64(length)), buf)
			if err != nil {
				return err
			}
			if n != int64(length) {
				return io.ErrUnexpectedEOF
			}
			continue
		case 32:
			continue
		default:
			return fmt.Errorf("unexpected filler byte: %d", tmp[0])
		}
	}
}

// VerifyFileResp - VerifyFile()'s response.
type VerifyFileResp struct {
	Err error
}

// VerifyFileHandler - Verify all part of file for bitrot errors.
func (s *storageRESTServer) VerifyFileHandler(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)

	if r.ContentLength < 0 {
		s.writeErrorResponse(w, errInvalidArgument)
		return
	}

	var fi FileInfo
	if err := msgp.Decode(r.Body, &fi); err != nil {
		s.writeErrorResponse(w, err)
		return
	}

	setEventStreamHeaders(w)
	encoder := gob.NewEncoder(w)
	done := keepHTTPResponseAlive(w)
	err := s.storage.VerifyFile(r.Context(), volume, filePath, fi)
	done(nil)
	vresp := &VerifyFileResp{}
	if err != nil {
		vresp.Err = StorageErr(err.Error())
	}
	encoder.Encode(vresp)
}

func checkDiskFatalErrs(errs []error) error {
	// This returns a common error if all errors are
	// same errors, then there is no point starting
	// the server.
	if countErrs(errs, errUnsupportedDisk) == len(errs) {
		return errUnsupportedDisk
	}

	if countErrs(errs, errDiskAccessDenied) == len(errs) {
		return errDiskAccessDenied
	}

	if countErrs(errs, errFileAccessDenied) == len(errs) {
		return errDiskAccessDenied
	}

	if countErrs(errs, errDiskNotDir) == len(errs) {
		return errDiskNotDir
	}

	if countErrs(errs, errFaultyDisk) == len(errs) {
		return errFaultyDisk
	}

	if countErrs(errs, errXLBackend) == len(errs) {
		return errXLBackend
	}

	return nil
}

// A single function to write certain errors to be fatal
// or informative based on the `exit` flag, please look
// at each implementation of error for added hints.
//
// FIXME: This is an unusual function but serves its purpose for
// now, need to revist the overall erroring structure here.
// Do not like it :-(
func logFatalErrs(err error, endpoint Endpoint, exit bool) {
	switch {
	case errors.Is(err, errXLBackend):
		logger.Fatal(config.ErrInvalidXLValue(err), "Unable to initialize backend")
	case errors.Is(err, errUnsupportedDisk):
		var hint string
		if endpoint.URL != nil {
			hint = fmt.Sprintf("Drive '%s' does not support O_DIRECT flags, MinIO erasure coding requires filesystems with O_DIRECT support", endpoint.Path)
		} else {
			hint = "Drives do not support O_DIRECT flags, MinIO erasure coding requires filesystems with O_DIRECT support"
		}
		logger.Fatal(config.ErrUnsupportedBackend(err).Hint(hint), "Unable to initialize backend")
	case errors.Is(err, errDiskNotDir):
		var hint string
		if endpoint.URL != nil {
			hint = fmt.Sprintf("Drive '%s' is not a directory, MinIO erasure coding needs a directory", endpoint.Path)
		} else {
			hint = "Drives are not directories, MinIO erasure coding needs directories"
		}
		logger.Fatal(config.ErrUnableToWriteInBackend(err).Hint(hint), "Unable to initialize backend")
	case errors.Is(err, errDiskAccessDenied):
		// Show a descriptive error with a hint about how to fix it.
		var username string
		if u, err := user.Current(); err == nil {
			username = u.Username
		} else {
			username = "<your-username>"
		}
		var hint string
		if endpoint.URL != nil {
			hint = fmt.Sprintf("Run the following command to add write permissions: `sudo chown -R %s %s && sudo chmod u+rxw %s`",
				username, endpoint.Path, endpoint.Path)
		} else {
			hint = fmt.Sprintf("Run the following command to add write permissions: `sudo chown -R %s. <path> && sudo chmod u+rxw <path>`", username)
		}
		if !exit {
			logger.LogIf(GlobalContext, fmt.Errorf("Drive is not writable %s, %s", endpoint, hint))
		} else {
			logger.Fatal(config.ErrUnableToWriteInBackend(err).Hint(hint), "Unable to initialize backend")
		}
	case errors.Is(err, errFaultyDisk):
		if !exit {
			logger.LogIf(GlobalContext, fmt.Errorf("Drive is faulty at %s, please replace the drive - drive will be offline", endpoint))
		} else {
			logger.Fatal(err, "Unable to initialize backend")
		}
	case errors.Is(err, errDiskFull):
		if !exit {
			logger.LogIf(GlobalContext, fmt.Errorf("Drive is already full at %s, incoming I/O will fail - drive will be offline", endpoint))
		} else {
			logger.Fatal(err, "Unable to initialize backend")
		}
	default:
		if !exit {
			logger.LogIf(GlobalContext, fmt.Errorf("Drive returned an unexpected error at %s, please investigate - drive will be offline (%w)", endpoint, err))
		} else {
			logger.Fatal(err, "Unable to initialize backend")
		}
	}
}

// StatInfoFile returns file stat info.
func (s *storageRESTServer) StatInfoFile(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	volume := r.Form.Get(storageRESTVolume)
	filePath := r.Form.Get(storageRESTFilePath)
	glob := r.Form.Get(storageRESTGlob)
	done := keepHTTPResponseAlive(w)
	stats, err := s.storage.StatInfoFile(r.Context(), volume, filePath, glob == "true")
	done(err)
	if err != nil {
		return
	}
	for _, si := range stats {
		msgp.Encode(w, &si)
	}
}

// ReadMultiple returns multiple files
func (s *storageRESTServer) ReadMultiple(w http.ResponseWriter, r *http.Request) {
	if !s.IsValid(w, r) {
		return
	}
	rw := streamHTTPResponse(w)
	defer func() {
		if r := recover(); r != nil {
			debug.PrintStack()
			rw.CloseWithError(fmt.Errorf("panic: %v", r))
		}
	}()

	var req ReadMultipleReq
	mr := msgpNewReader(r.Body)
	err := req.DecodeMsg(mr)
	if err != nil {
		rw.CloseWithError(err)
		return
	}

	mw := msgp.NewWriter(rw)
	responses := make(chan ReadMultipleResp, len(req.Files))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for resp := range responses {
			err := resp.EncodeMsg(mw)
			if err != nil {
				rw.CloseWithError(err)
				return
			}
			mw.Flush()
		}
	}()
	err = s.storage.ReadMultiple(r.Context(), req, responses)
	wg.Wait()
	rw.CloseWithError(err)
}

// registerStorageRPCRouter - register storage rpc router.
func registerStorageRESTHandlers(router *mux.Router, endpointServerPools EndpointServerPools) {
	storageDisks := make([][]*xlStorage, len(endpointServerPools))
	for poolIdx, ep := range endpointServerPools {
		storageDisks[poolIdx] = make([]*xlStorage, len(ep.Endpoints))
	}
	var wg sync.WaitGroup
	for poolIdx, ep := range endpointServerPools {
		for setIdx, endpoint := range ep.Endpoints {
			if !endpoint.IsLocal {
				continue
			}
			wg.Add(1)
			go func(poolIdx, setIdx int, endpoint Endpoint) {
				defer wg.Done()
				var err error
				storageDisks[poolIdx][setIdx], err = newXLStorage(endpoint, false)
				if err != nil {
					// if supported errors don't fail, we proceed to
					// printing message and moving forward.
					logFatalErrs(err, endpoint, false)
				}
			}(poolIdx, setIdx, endpoint)
		}
	}
	wg.Wait()

	for _, setDisks := range storageDisks {
		for _, storage := range setDisks {
			if storage == nil {
				continue
			}

			endpoint := storage.Endpoint()

			server := &storageRESTServer{storage: newXLStorageDiskIDCheck(storage)}
			server.storage.SetDiskID(storage.diskID)

			subrouter := router.PathPrefix(path.Join(storageRESTPrefix, endpoint.Path)).Subrouter()

			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodHealth).HandlerFunc(httpTraceHdrs(server.HealthHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodDiskInfo).HandlerFunc(httpTraceHdrs(server.DiskInfoHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodNSScanner).HandlerFunc(httpTraceHdrs(server.NSScannerHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodMakeVol).HandlerFunc(httpTraceHdrs(server.MakeVolHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodMakeVolBulk).HandlerFunc(httpTraceHdrs(server.MakeVolBulkHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodStatVol).HandlerFunc(httpTraceHdrs(server.StatVolHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodDeleteVol).HandlerFunc(httpTraceHdrs(server.DeleteVolHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodListVols).HandlerFunc(httpTraceHdrs(server.ListVolsHandler))

			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodAppendFile).HandlerFunc(httpTraceHdrs(server.AppendFileHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodWriteAll).HandlerFunc(httpTraceHdrs(server.WriteAllHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodWriteMetadata).HandlerFunc(httpTraceHdrs(server.WriteMetadataHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodUpdateMetadata).HandlerFunc(httpTraceHdrs(server.UpdateMetadataHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodDeleteVersion).HandlerFunc(httpTraceHdrs(server.DeleteVersionHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadVersion).HandlerFunc(httpTraceHdrs(server.ReadVersionHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadXL).HandlerFunc(httpTraceHdrs(server.ReadXLHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodRenameData).HandlerFunc(httpTraceHdrs(server.RenameDataHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodCreateFile).HandlerFunc(httpTraceHdrs(server.CreateFileHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodCheckParts).HandlerFunc(httpTraceHdrs(server.CheckPartsHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadAll).HandlerFunc(httpTraceHdrs(server.ReadAllHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadFile).HandlerFunc(httpTraceHdrs(server.ReadFileHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadFileStream).HandlerFunc(httpTraceHdrs(server.ReadFileStreamHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodListDir).HandlerFunc(httpTraceHdrs(server.ListDirHandler))

			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodDeleteVersions).HandlerFunc(httpTraceHdrs(server.DeleteVersionsHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodDeleteFile).HandlerFunc(httpTraceHdrs(server.DeleteFileHandler))

			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodRenameFile).HandlerFunc(httpTraceHdrs(server.RenameFileHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodVerifyFile).HandlerFunc(httpTraceHdrs(server.VerifyFileHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodWalkDir).HandlerFunc(httpTraceHdrs(server.WalkDirHandler))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodStatInfoFile).HandlerFunc(httpTraceHdrs(server.StatInfoFile))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodReadMultiple).HandlerFunc(httpTraceHdrs(server.ReadMultiple))
			subrouter.Methods(http.MethodPost).Path(storageRESTVersionPrefix + storageRESTMethodCleanAbandoned).HandlerFunc(httpTraceHdrs(server.CleanAbandonedDataHandler))
		}
	}
}
