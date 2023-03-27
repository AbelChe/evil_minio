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
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dustin/go-humanize"
	"github.com/felixge/fgprof"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio-go/v7"
	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/config/api"
	xtls "github.com/minio/minio/internal/config/identity/tls"
	"github.com/minio/minio/internal/deadlineconn"
	"github.com/minio/minio/internal/fips"
	"github.com/minio/minio/internal/handlers"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
	ioutilx "github.com/minio/minio/internal/ioutil"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/logger/message/audit"
	"github.com/minio/minio/internal/mcontext"
	"github.com/minio/minio/internal/rest"
	"github.com/minio/mux"
	"github.com/minio/pkg/certs"
	"github.com/minio/pkg/env"
	pkgAudit "github.com/minio/pkg/logger/message/audit"
	xnet "github.com/minio/pkg/net"
	"golang.org/x/oauth2"
)

const (
	slashSeparator = "/"
)

// BucketAccessPolicy - Collection of canned bucket policy at a given prefix.
type BucketAccessPolicy struct {
	Bucket string                     `json:"bucket"`
	Prefix string                     `json:"prefix"`
	Policy miniogopolicy.BucketPolicy `json:"policy"`
}

// IsErrIgnored returns whether given error is ignored or not.
func IsErrIgnored(err error, ignoredErrs ...error) bool {
	return IsErr(err, ignoredErrs...)
}

// IsErr returns whether given error is exact error.
func IsErr(err error, errs ...error) bool {
	for _, exactErr := range errs {
		if errors.Is(err, exactErr) {
			return true
		}
	}
	return false
}

// ErrorRespToObjectError converts MinIO errors to minio object layer errors.
func ErrorRespToObjectError(err error, params ...string) error {
	if err == nil {
		return nil
	}

	bucket := ""
	object := ""
	if len(params) >= 1 {
		bucket = params[0]
	}
	if len(params) == 2 {
		object = params[1]
	}

	if xnet.IsNetworkOrHostDown(err, false) {
		return BackendDown{Err: err.Error()}
	}

	minioErr, ok := err.(minio.ErrorResponse)
	if !ok {
		// We don't interpret non MinIO errors. As minio errors will
		// have StatusCode to help to convert to object errors.
		return err
	}

	switch minioErr.Code {
	case "PreconditionFailed":
		err = PreConditionFailed{}
	case "InvalidRange":
		err = InvalidRange{}
	case "BucketAlreadyOwnedByYou":
		err = BucketAlreadyOwnedByYou{}
	case "BucketNotEmpty":
		err = BucketNotEmpty{}
	case "NoSuchBucketPolicy":
		err = BucketPolicyNotFound{}
	case "NoSuchLifecycleConfiguration":
		err = BucketLifecycleNotFound{}
	case "InvalidBucketName":
		err = BucketNameInvalid{Bucket: bucket}
	case "InvalidPart":
		err = InvalidPart{}
	case "NoSuchBucket":
		err = BucketNotFound{Bucket: bucket}
	case "NoSuchKey":
		if object != "" {
			err = ObjectNotFound{Bucket: bucket, Object: object}
		} else {
			err = BucketNotFound{Bucket: bucket}
		}
	case "XMinioInvalidObjectName":
		err = ObjectNameInvalid{}
	case "AccessDenied":
		err = PrefixAccessDenied{
			Bucket: bucket,
			Object: object,
		}
	case "XAmzContentSHA256Mismatch":
		err = hash.SHA256Mismatch{}
	case "NoSuchUpload":
		err = InvalidUploadID{}
	case "EntityTooSmall":
		err = PartTooSmall{}
	}

	if minioErr.StatusCode == http.StatusMethodNotAllowed {
		err = toObjectErr(errMethodNotAllowed, bucket, object)
	}
	return err
}

// returns 'true' if either string has space in the
// - beginning of a string
// OR
// - end of a string
func hasSpaceBE(s string) bool {
	return strings.TrimSpace(s) != s
}

func request2BucketObjectName(r *http.Request) (bucketName, objectName string) {
	path, err := getResource(r.URL.Path, r.Host, globalDomainNames)
	if err != nil {
		logger.CriticalIf(GlobalContext, err)
	}

	return path2BucketObject(path)
}

// path2BucketObjectWithBasePath returns bucket and prefix, if any,
// of a 'path'. basePath is trimmed from the front of the 'path'.
func path2BucketObjectWithBasePath(basePath, path string) (bucket, prefix string) {
	path = strings.TrimPrefix(path, basePath)
	path = strings.TrimPrefix(path, SlashSeparator)
	m := strings.Index(path, SlashSeparator)
	if m < 0 {
		return path, ""
	}
	return path[:m], path[m+len(SlashSeparator):]
}

func path2BucketObject(s string) (bucket, prefix string) {
	return path2BucketObjectWithBasePath("", s)
}

// cloneMSS will clone a map[string]string.
// If input is nil an empty map is returned, not nil.
func cloneMSS(v map[string]string) map[string]string {
	r := make(map[string]string, len(v))
	for k, v := range v {
		r[k] = v
	}
	return r
}

// URI scheme constants.
const (
	httpScheme  = "http"
	httpsScheme = "https"
)

// nopCharsetConverter is a dummy charset convert which just copies input to output,
// it is used to ignore custom encoding charset in S3 XML body.
func nopCharsetConverter(label string, input io.Reader) (io.Reader, error) {
	return input, nil
}

// xmlDecoder provide decoded value in xml.
func xmlDecoder(body io.Reader, v interface{}, size int64) error {
	var lbody io.Reader
	if size > 0 {
		lbody = io.LimitReader(body, size)
	} else {
		lbody = body
	}
	d := xml.NewDecoder(lbody)
	// Ignore any encoding set in the XML body
	d.CharsetReader = nopCharsetConverter
	err := d.Decode(v)
	if errors.Is(err, io.EOF) {
		err = &xml.SyntaxError{
			Line: 0,
			Msg:  err.Error(),
		}
	}
	return err
}

// hasContentMD5 returns true if Content-MD5 header is set.
func hasContentMD5(h http.Header) bool {
	_, ok := h[xhttp.ContentMD5]
	return ok
}

// http://docs.aws.amazon.com/AmazonS3/latest/dev/UploadingObjects.html
const (
	// Maximum object size per PUT request is 5TB.
	// This is a divergence from S3 limit on purpose to support
	// use cases where users are going to upload large files
	// using 'curl' and presigned URL.
	globalMaxObjectSize = 5 * humanize.TiByte

	// Minimum Part size for multipart upload is 5MiB
	globalMinPartSize = 5 * humanize.MiByte

	// Maximum Part ID for multipart upload is 10000
	// (Acceptable values range from 1 to 10000 inclusive)
	globalMaxPartID = 10000
)

// isMaxObjectSize - verify if max object size
func isMaxObjectSize(size int64) bool {
	return size > globalMaxObjectSize
}

// Check if part size is more than or equal to minimum allowed size.
func isMinAllowedPartSize(size int64) bool {
	return size >= globalMinPartSize
}

// isMaxPartNumber - Check if part ID is greater than the maximum allowed ID.
func isMaxPartID(partID int) bool {
	return partID > globalMaxPartID
}

func contains(slice interface{}, elem interface{}) bool {
	v := reflect.ValueOf(slice)
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).Interface() == elem {
				return true
			}
		}
	}
	return false
}

// profilerWrapper is created becauses pkg/profiler doesn't
// provide any API to calculate the profiler file path in the
// disk since the name of this latter is randomly generated.
type profilerWrapper struct {
	// Profile recorded at start of benchmark.
	records map[string][]byte
	stopFn  func() ([]byte, error)
	ext     string
}

// record will record the profile and store it as the base.
func (p *profilerWrapper) record(profileType string, debug int, recordName string) {
	var buf bytes.Buffer
	if p.records == nil {
		p.records = make(map[string][]byte)
	}
	err := pprof.Lookup(profileType).WriteTo(&buf, debug)
	if err != nil {
		return
	}
	p.records[recordName] = buf.Bytes()
}

// Records returns the recorded profiling if any.
func (p profilerWrapper) Records() map[string][]byte {
	return p.records
}

// Stop the currently running benchmark.
func (p profilerWrapper) Stop() ([]byte, error) {
	return p.stopFn()
}

// Extension returns the extension without dot prefix.
func (p profilerWrapper) Extension() string {
	return p.ext
}

// Returns current profile data, returns error if there is no active
// profiling in progress. Stops an active profile.
func getProfileData() (map[string][]byte, error) {
	globalProfilerMu.Lock()
	defer globalProfilerMu.Unlock()

	if len(globalProfiler) == 0 {
		return nil, errors.New("profiler not enabled")
	}

	dst := make(map[string][]byte, len(globalProfiler))
	for typ, prof := range globalProfiler {
		// Stop the profiler
		var err error
		buf, err := prof.Stop()
		delete(globalProfiler, typ)
		if err == nil {
			dst[typ+"."+prof.Extension()] = buf
		}
		for name, buf := range prof.Records() {
			if len(buf) > 0 {
				dst[typ+"-"+name+"."+prof.Extension()] = buf
			}
		}
	}
	return dst, nil
}

func setDefaultProfilerRates() {
	runtime.MemProfileRate = 4096      // 512K -> 4K - Must be constant throughout application lifetime.
	runtime.SetMutexProfileFraction(0) // Disable until needed
	runtime.SetBlockProfileRate(0)     // Disable until needed
}

// Starts a profiler returns nil if profiler is not enabled, caller needs to handle this.
func startProfiler(profilerType string) (minioProfiler, error) {
	var prof profilerWrapper
	prof.ext = "pprof"
	// Enable profiler and set the name of the file that pkg/pprof
	// library creates to store profiling data.
	switch madmin.ProfilerType(profilerType) {
	case madmin.ProfilerCPU:
		dirPath, err := os.MkdirTemp("", "profile")
		if err != nil {
			return nil, err
		}
		fn := filepath.Join(dirPath, "cpu.out")
		f, err := Create(fn)
		if err != nil {
			return nil, err
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			return nil, err
		}
		prof.stopFn = func() ([]byte, error) {
			pprof.StopCPUProfile()
			err := f.Close()
			if err != nil {
				return nil, err
			}
			defer RemoveAll(dirPath)
			return ioutilx.ReadFile(fn)
		}
	case madmin.ProfilerCPUIO:
		// at 10k or more goroutines fgprof is likely to become
		// unable to maintain its sampling rate and to significantly
		// degrade the performance of your application
		// https://github.com/felixge/fgprof#fgprof
		if n := runtime.NumGoroutine(); n > 10000 && !globalIsCICD {
			return nil, fmt.Errorf("unable to perform CPU IO profile with %d goroutines", n)
		}
		dirPath, err := os.MkdirTemp("", "profile")
		if err != nil {
			return nil, err
		}
		fn := filepath.Join(dirPath, "cpuio.out")
		f, err := Create(fn)
		if err != nil {
			return nil, err
		}
		stop := fgprof.Start(f, fgprof.FormatPprof)
		prof.stopFn = func() ([]byte, error) {
			err := stop()
			if err != nil {
				return nil, err
			}
			err = f.Close()
			if err != nil {
				return nil, err
			}
			defer RemoveAll(dirPath)
			return ioutilx.ReadFile(fn)
		}
	case madmin.ProfilerMEM:
		runtime.GC()
		prof.record("heap", 0, "before")
		prof.stopFn = func() ([]byte, error) {
			runtime.GC()
			var buf bytes.Buffer
			err := pprof.Lookup("heap").WriteTo(&buf, 0)
			return buf.Bytes(), err
		}
	case madmin.ProfilerBlock:
		runtime.SetBlockProfileRate(100)
		prof.stopFn = func() ([]byte, error) {
			var buf bytes.Buffer
			err := pprof.Lookup("block").WriteTo(&buf, 0)
			runtime.SetBlockProfileRate(0)
			return buf.Bytes(), err
		}
	case madmin.ProfilerMutex:
		prof.record("mutex", 0, "before")
		runtime.SetMutexProfileFraction(1)
		prof.stopFn = func() ([]byte, error) {
			var buf bytes.Buffer
			err := pprof.Lookup("mutex").WriteTo(&buf, 0)
			runtime.SetMutexProfileFraction(0)
			return buf.Bytes(), err
		}
	case madmin.ProfilerThreads:
		prof.record("threadcreate", 0, "before")
		prof.stopFn = func() ([]byte, error) {
			var buf bytes.Buffer
			err := pprof.Lookup("threadcreate").WriteTo(&buf, 0)
			return buf.Bytes(), err
		}
	case madmin.ProfilerGoroutines:
		prof.ext = "txt"
		prof.record("goroutine", 1, "before")
		prof.record("goroutine", 2, "before,debug=2")
		prof.stopFn = func() ([]byte, error) {
			var buf bytes.Buffer
			err := pprof.Lookup("goroutine").WriteTo(&buf, 1)
			return buf.Bytes(), err
		}
	case madmin.ProfilerTrace:
		dirPath, err := os.MkdirTemp("", "profile")
		if err != nil {
			return nil, err
		}
		fn := filepath.Join(dirPath, "trace.out")
		f, err := Create(fn)
		if err != nil {
			return nil, err
		}
		err = trace.Start(f)
		if err != nil {
			return nil, err
		}
		prof.ext = "trace"
		prof.stopFn = func() ([]byte, error) {
			trace.Stop()
			err := f.Close()
			if err != nil {
				return nil, err
			}
			defer RemoveAll(dirPath)
			return ioutilx.ReadFile(fn)
		}
	default:
		return nil, errors.New("profiler type unknown")
	}

	return prof, nil
}

// minioProfiler - minio profiler interface.
type minioProfiler interface {
	// Return recorded profiles, each profile associated with a distinct generic name.
	Records() map[string][]byte
	// Stop the profiler
	Stop() ([]byte, error)
	// Return extension of profile
	Extension() string
}

// Global profiler to be used by service go-routine.
var (
	globalProfiler   map[string]minioProfiler
	globalProfilerMu sync.Mutex
)

// dump the request into a string in JSON format.
func dumpRequest(r *http.Request) string {
	header := r.Header.Clone()
	header.Set("Host", r.Host)
	// Replace all '%' to '%%' so that printer format parser
	// to ignore URL encoded values.
	rawURI := strings.ReplaceAll(r.RequestURI, "%", "%%")
	req := struct {
		Method     string      `json:"method"`
		RequestURI string      `json:"reqURI"`
		Header     http.Header `json:"header"`
	}{r.Method, rawURI, header}

	var buffer bytes.Buffer
	enc := json.NewEncoder(&buffer)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&req); err != nil {
		// Upon error just return Go-syntax representation of the value
		return fmt.Sprintf("%#v", req)
	}

	// Formatted string.
	return strings.TrimSpace(buffer.String())
}

// isFile - returns whether given path is a file or not.
func isFile(path string) bool {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().IsRegular()
	}

	return false
}

// UTCNow - returns current UTC time.
func UTCNow() time.Time {
	return time.Now().UTC()
}

// GenETag - generate UUID based ETag
func GenETag() string {
	return ToS3ETag(getMD5Hash([]byte(mustGetUUID())))
}

// ToS3ETag - return checksum to ETag
func ToS3ETag(etag string) string {
	etag = canonicalizeETag(etag)

	if !strings.HasSuffix(etag, "-1") {
		// Tools like s3cmd uses ETag as checksum of data to validate.
		// Append "-1" to indicate ETag is not a checksum.
		etag += "-1"
	}

	return etag
}

// GetDefaultConnSettings returns default HTTP connection settings.
func GetDefaultConnSettings() xhttp.ConnSettings {
	return xhttp.ConnSettings{
		DNSCache:    globalDNSCache,
		DialTimeout: rest.DefaultTimeout,
		RootCAs:     globalRootCAs,
	}
}

// NewInternodeHTTPTransport returns a transport for internode MinIO
// connections.
func NewInternodeHTTPTransport() func() http.RoundTripper {
	return xhttp.ConnSettings{
		DNSCache:         globalDNSCache,
		DialTimeout:      rest.DefaultTimeout,
		RootCAs:          globalRootCAs,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),
		EnableHTTP2:      false,
	}.NewInternodeHTTPTransport()
}

// NewCustomHTTPProxyTransport is used only for proxied requests, specifically
// only supports HTTP/1.1
func NewCustomHTTPProxyTransport() func() *http.Transport {
	return xhttp.ConnSettings{
		DNSCache:         globalDNSCache,
		DialTimeout:      rest.DefaultTimeout,
		RootCAs:          globalRootCAs,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),
		EnableHTTP2:      false,
	}.NewCustomHTTPProxyTransport()
}

// NewHTTPTransportWithClientCerts returns a new http configuration
// used while communicating with the cloud backends.
func NewHTTPTransportWithClientCerts(clientCert, clientKey string) *http.Transport {
	s := xhttp.ConnSettings{
		DNSCache:    globalDNSCache,
		DialTimeout: defaultDialTimeout,
		RootCAs:     globalRootCAs,
		EnableHTTP2: false,
	}

	if clientCert != "" && clientKey != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		transport, err := s.NewHTTPTransportWithClientCerts(ctx, clientCert, clientKey)
		if err != nil {
			logger.LogIf(ctx, fmt.Errorf("failed to load client key and cert, please check your endpoint configuration: %s",
				err.Error()))
		}
		return transport
	}

	return s.NewHTTPTransportWithTimeout(1 * time.Minute)
}

// NewHTTPTransport returns a new http configuration
// used while communicating with the cloud backends.
func NewHTTPTransport() *http.Transport {
	return NewHTTPTransportWithTimeout(1 * time.Minute)
}

// Default values for dial timeout
const defaultDialTimeout = 5 * time.Second

// NewHTTPTransportWithTimeout allows setting a timeout.
func NewHTTPTransportWithTimeout(timeout time.Duration) *http.Transport {
	return xhttp.ConnSettings{
		DialContext: newCustomDialContext(),
		DNSCache:    globalDNSCache,
		DialTimeout: defaultDialTimeout,
		RootCAs:     globalRootCAs,
		EnableHTTP2: false,
	}.NewHTTPTransportWithTimeout(timeout)
}

type dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// newCustomDialContext setups a custom dialer for any external communication and proxies.
func newCustomDialContext() dialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		dconn := deadlineconn.New(conn).
			WithReadDeadline(globalConnReadDeadline).
			WithWriteDeadline(globalConnWriteDeadline)

		return dconn, nil
	}
}

// NewRemoteTargetHTTPTransport returns a new http configuration
// used while communicating with the remote replication targets.
func NewRemoteTargetHTTPTransport() func() *http.Transport {
	return xhttp.ConnSettings{
		DialContext: newCustomDialContext(),
		DNSCache:    globalDNSCache,
		RootCAs:     globalRootCAs,
		EnableHTTP2: false,
	}.NewRemoteTargetHTTPTransport()
}

// Load the json (typically from disk file).
func jsonLoad(r io.ReadSeeker, data interface{}) error {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return json.NewDecoder(r).Decode(data)
}

// Save to disk file in json format.
func jsonSave(f interface {
	io.WriteSeeker
	Truncate(int64) error
}, data interface{},
) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if err = f.Truncate(0); err != nil {
		return err
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = f.Write(b)
	if err != nil {
		return err
	}
	return nil
}

// ceilFrac takes a numerator and denominator representing a fraction
// and returns its ceiling. If denominator is 0, it returns 0 instead
// of crashing.
func ceilFrac(numerator, denominator int64) (ceil int64) {
	if denominator == 0 {
		// do nothing on invalid input
		return
	}
	// Make denominator positive
	if denominator < 0 {
		numerator = -numerator
		denominator = -denominator
	}
	ceil = numerator / denominator
	if numerator > 0 && numerator%denominator != 0 {
		ceil++
	}
	return
}

// cleanMinioInternalMetadataKeys removes X-Amz-Meta- prefix from minio internal
// encryption metadata.
func cleanMinioInternalMetadataKeys(metadata map[string]string) map[string]string {
	newMeta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		if strings.HasPrefix(k, "X-Amz-Meta-X-Minio-Internal-") {
			newMeta[strings.TrimPrefix(k, "X-Amz-Meta-")] = v
		} else {
			newMeta[k] = v
		}
	}
	return newMeta
}

// pathClean is like path.Clean but does not return "." for
// empty inputs, instead returns "empty" as is.
func pathClean(p string) string {
	cp := path.Clean(p)
	if cp == "." {
		return ""
	}
	return cp
}

func trimLeadingSlash(ep string) string {
	if len(ep) > 0 && ep[0] == '/' {
		// Path ends with '/' preserve it
		if ep[len(ep)-1] == '/' && len(ep) > 1 {
			ep = path.Clean(ep)
			ep += slashSeparator
		} else {
			ep = path.Clean(ep)
		}
		ep = ep[1:]
	}
	return ep
}

// unescapeGeneric is similar to url.PathUnescape or url.QueryUnescape
// depending on input, additionally also handles situations such as
// `//` are normalized as `/`, also removes any `/` prefix before
// returning.
func unescapeGeneric(p string, escapeFn func(string) (string, error)) (string, error) {
	ep, err := escapeFn(p)
	if err != nil {
		return "", err
	}
	return trimLeadingSlash(ep), nil
}

// unescapePath is similar to unescapeGeneric but for specifically
// path unescaping.
func unescapePath(p string) (string, error) {
	return unescapeGeneric(p, url.PathUnescape)
}

// similar to unescapeGeneric but never returns any error if the unescaping
// fails, returns the input as is in such occasion, not meant to be
// used where strict validation is expected.
func likelyUnescapeGeneric(p string, escapeFn func(string) (string, error)) string {
	ep, err := unescapeGeneric(p, escapeFn)
	if err != nil {
		return p
	}
	return ep
}

func updateReqContext(ctx context.Context, objects ...ObjectV) context.Context {
	req := logger.GetReqInfo(ctx)
	if req != nil {
		req.Lock()
		defer req.Unlock()
		req.Objects = make([]logger.ObjectVersion, 0, len(objects))
		for _, ov := range objects {
			req.Objects = append(req.Objects, logger.ObjectVersion{
				ObjectName: ov.ObjectName,
				VersionID:  ov.VersionID,
			})
		}
		return logger.SetReqInfo(ctx, req)
	}
	return ctx
}

// Returns context with ReqInfo details set in the context.
func newContext(r *http.Request, w http.ResponseWriter, api string) context.Context {
	reqID := w.Header().Get(xhttp.AmzRequestID)

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := likelyUnescapeGeneric(vars["object"], url.PathUnescape)
	reqInfo := &logger.ReqInfo{
		DeploymentID: globalDeploymentID,
		RequestID:    reqID,
		RemoteHost:   handlers.GetSourceIP(r),
		Host:         getHostName(r),
		UserAgent:    r.UserAgent(),
		API:          api,
		BucketName:   bucket,
		ObjectName:   object,
		VersionID:    strings.TrimSpace(r.Form.Get(xhttp.VersionID)),
	}

	ctx := context.WithValue(r.Context(),
		mcontext.ContextTraceKey,
		&mcontext.TraceCtxt{
			AmzReqID: reqID,
		},
	)

	return logger.SetReqInfo(ctx, reqInfo)
}

// Used for registering with rest handlers (have a look at registerStorageRESTHandlers for usage example)
// If it is passed ["aaaa", "bbbb"], it returns ["aaaa", "{aaaa:.*}", "bbbb", "{bbbb:.*}"]
func restQueries(keys ...string) []string {
	var accumulator []string
	for _, key := range keys {
		accumulator = append(accumulator, key, "{"+key+":.*}")
	}
	return accumulator
}

// Suffix returns the longest common suffix of the provided strings
func lcpSuffix(strs []string) string {
	return lcp(strs, false)
}

func lcp(strs []string, pre bool) string {
	// short-circuit empty list
	if len(strs) == 0 {
		return ""
	}
	xfix := strs[0]
	// short-circuit single-element list
	if len(strs) == 1 {
		return xfix
	}
	// compare first to rest
	for _, str := range strs[1:] {
		xfixl := len(xfix)
		strl := len(str)
		// short-circuit empty strings
		if xfixl == 0 || strl == 0 {
			return ""
		}
		// maximum possible length
		maxl := xfixl
		if strl < maxl {
			maxl = strl
		}
		// compare letters
		if pre {
			// prefix, iterate left to right
			for i := 0; i < maxl; i++ {
				if xfix[i] != str[i] {
					xfix = xfix[:i]
					break
				}
			}
		} else {
			// suffix, iterate right to left
			for i := 0; i < maxl; i++ {
				xi := xfixl - i - 1
				si := strl - i - 1
				if xfix[xi] != str[si] {
					xfix = xfix[xi+1:]
					break
				}
			}
		}
	}
	return xfix
}

// Returns the mode in which MinIO is running
func getMinioMode() string {
	switch {
	case globalIsDistErasure:
		return globalMinioModeDistErasure
	case globalIsErasure:
		return globalMinioModeErasure
	case globalIsErasureSD:
		return globalMinioModeErasureSD
	default:
		return globalMinioModeFS
	}
}

func iamPolicyClaimNameOpenID() string {
	return globalIAMSys.OpenIDConfig.GetIAMPolicyClaimName()
}

func iamPolicyClaimNameSA() string {
	return "sa-policy"
}

// timedValue contains a synchronized value that is considered valid
// for a specific amount of time.
// An Update function must be set to provide an updated value when needed.
type timedValue struct {
	// Update must return an updated value.
	// If an error is returned the cached value is not set.
	// Only one caller will call this function at any time, others will be blocking.
	// The returned value can no longer be modified once returned.
	// Should be set before calling Get().
	Update func() (interface{}, error)

	// TTL for a cached value.
	// If not set 1 second TTL is assumed.
	// Should be set before calling Get().
	TTL time.Duration

	// When set to true, return the last cached value
	// even if updating the value errors out
	Relax bool

	// Once can be used to initialize values for lazy initialization.
	// Should be set before calling Get().
	Once sync.Once

	// Managed values.
	value      interface{}
	lastUpdate time.Time
	mu         sync.RWMutex
}

// Get will return a cached value or fetch a new one.
// If the Update function returns an error the value is forwarded as is and not cached.
func (t *timedValue) Get() (interface{}, error) {
	v := t.get(t.ttl())
	if v != nil {
		return v, nil
	}

	v, err := t.Update()
	if err != nil {
		if t.Relax {
			// if update fails, return current
			// cached value along with error.
			//
			// Let the caller decide if they want
			// to use the returned value based
			// on error.
			v = t.get(0)
			return v, err
		}
		return v, err
	}

	t.update(v)
	return v, nil
}

func (t *timedValue) ttl() time.Duration {
	ttl := t.TTL
	if ttl <= 0 {
		ttl = time.Second
	}
	return ttl
}

func (t *timedValue) get(ttl time.Duration) (v interface{}) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v = t.value
	if ttl <= 0 {
		return v
	}
	if time.Since(t.lastUpdate) < ttl {
		return v
	}
	return nil
}

func (t *timedValue) update(v interface{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.value = v
	t.lastUpdate = time.Now()
}

// On MinIO a directory object is stored as a regular object with "__XLDIR__" suffix.
// For ex. "prefix/" is stored as "prefix__XLDIR__"
func encodeDirObject(object string) string {
	if HasSuffix(object, slashSeparator) {
		return strings.TrimSuffix(object, slashSeparator) + globalDirSuffix
	}
	return object
}

// Reverse process of encodeDirObject()
func decodeDirObject(object string) string {
	if HasSuffix(object, globalDirSuffix) {
		return strings.TrimSuffix(object, globalDirSuffix) + slashSeparator
	}
	return object
}

// Helper method to return total number of nodes in cluster
func totalNodeCount() uint64 {
	peers, _ := globalEndpoints.peers()
	totalNodesCount := uint64(len(peers))
	if totalNodesCount == 0 {
		totalNodesCount = 1 // For standalone erasure coding
	}
	return totalNodesCount
}

// AuditLogOptions takes options for audit logging subsystem activity
type AuditLogOptions struct {
	Event     string
	APIName   string
	Status    string
	Bucket    string
	Object    string
	VersionID string
	Error     string
	Tags      map[string]interface{}
}

// sends audit logs for internal subsystem activity
func auditLogInternal(ctx context.Context, opts AuditLogOptions) {
	if len(logger.AuditTargets()) == 0 {
		return
	}
	entry := audit.NewEntry(globalDeploymentID)
	entry.Trigger = opts.Event
	entry.Event = opts.Event
	entry.Error = opts.Error
	entry.API.Name = opts.APIName
	entry.API.Bucket = opts.Bucket
	entry.API.Objects = []pkgAudit.ObjectVersion{{ObjectName: opts.Object, VersionID: opts.VersionID}}
	entry.API.Status = opts.Status
	entry.Tags = opts.Tags
	// Merge tag information if found - this is currently needed for tags
	// set during decommissioning.
	if reqInfo := logger.GetReqInfo(ctx); reqInfo != nil {
		if tags := reqInfo.GetTagsMap(); len(tags) > 0 {
			if entry.Tags == nil {
				entry.Tags = make(map[string]interface{}, len(tags))
			}
			for k, v := range tags {
				entry.Tags[k] = v
			}
		}
	}
	ctx = logger.SetAuditEntry(ctx, &entry)
	logger.AuditLog(ctx, nil, nil, nil)
}

func newTLSConfig(getCert certs.GetCertificateFunc) *tls.Config {
	if getCert == nil {
		return nil
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		NextProtos:               []string{"http/1.1", "h2"},
		GetCertificate:           getCert,
		ClientSessionCache:       tls.NewLRUClientSessionCache(tlsClientSessionCacheSize),
	}

	tlsClientIdentity := env.Get(xtls.EnvIdentityTLSEnabled, "") == config.EnableOn
	if tlsClientIdentity {
		tlsConfig.ClientAuth = tls.RequestClientCert
	}

	if secureCiphers := env.Get(api.EnvAPISecureCiphers, config.EnableOn) == config.EnableOn; secureCiphers {
		tlsConfig.CipherSuites = fips.TLSCiphers()
	} else {
		tlsConfig.CipherSuites = fips.TLSCiphersBackwardCompatible()
	}
	tlsConfig.CurvePreferences = fips.TLSCurveIDs()
	return tlsConfig
}

/////////// Types and functions for OpenID IAM testing

// OpenIDClientAppParams - contains openID client application params, used in
// testing.
type OpenIDClientAppParams struct {
	ClientID, ClientSecret, ProviderURL, RedirectURL string
}

// MockOpenIDTestUserInteraction - tries to login to dex using provided credentials.
// It performs the user's browser interaction to login and retrieves the auth
// code from dex and exchanges it for a JWT.
func MockOpenIDTestUserInteraction(ctx context.Context, pro OpenIDClientAppParams, username, password string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, pro.ProviderURL)
	if err != nil {
		return "", fmt.Errorf("unable to create provider: %v", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     pro.ClientID,
		ClientSecret: pro.ClientSecret,
		RedirectURL:  pro.RedirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "groups"},
	}

	state := fmt.Sprintf("x%dx", time.Now().Unix())
	authCodeURL := oauth2Config.AuthCodeURL(state)
	// fmt.Printf("authcodeurl: %s\n", authCodeURL)

	var lastReq *http.Request
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		// fmt.Printf("CheckRedirect:\n")
		// fmt.Printf("Upcoming: %s %s\n", req.Method, req.URL.String())
		// for i, c := range via {
		// 	fmt.Printf("Sofar %d: %s %s\n", i, c.Method, c.URL.String())
		// }
		// Save the last request in a redirect chain.
		lastReq = req
		// We do not follow redirect back to client application.
		if req.URL.Path == "/oauth_callback" {
			return http.ErrUseLastResponse
		}
		return nil
	}

	dexClient := http.Client{
		CheckRedirect: checkRedirect,
	}

	u, err := url.Parse(authCodeURL)
	if err != nil {
		return "", fmt.Errorf("url parse err: %v", err)
	}

	// Start the user auth flow. This page would present the login with
	// email or LDAP option.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("new request err: %v", err)
	}
	_, err = dexClient.Do(req)
	// fmt.Printf("Do: %#v %#v\n", resp, err)
	if err != nil {
		return "", fmt.Errorf("auth url request err: %v", err)
	}

	// Modify u to choose the ldap option
	u.Path += "/ldap"
	// fmt.Println(u)

	// Pick the LDAP login option. This would return a form page after
	// following some redirects. `lastReq` would be the URL of the form
	// page, where we need to POST (submit) the form.
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("new request err (/ldap): %v", err)
	}
	_, err = dexClient.Do(req)
	// fmt.Printf("Fetch LDAP login page: %#v %#v\n", resp, err)
	if err != nil {
		return "", fmt.Errorf("request err: %v", err)
	}
	// {
	// 	bodyBuf, err := io.ReadAll(resp.Body)
	// 	if err != nil {
	// 		return "", fmt.Errorf("Error reading body: %v", err)
	// 	}
	// 	fmt.Printf("bodyBuf (for LDAP login page): %s\n", string(bodyBuf))
	// }

	// Fill the login form with our test creds:
	// fmt.Printf("login form url: %s\n", lastReq.URL.String())
	formData := url.Values{}
	formData.Set("login", username)
	formData.Set("password", password)
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, lastReq.URL.String(), strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("new request err (/login): %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = dexClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("post form err: %v", err)
	}
	// fmt.Printf("resp: %#v %#v\n", resp.StatusCode, resp.Header)
	// bodyBuf, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return "", fmt.Errorf("Error reading body: %v", err)
	// }
	// fmt.Printf("resp body: %s\n", string(bodyBuf))
	// fmt.Printf("lastReq: %#v\n", lastReq.URL.String())

	// On form submission, the last redirect response contains the auth
	// code, which we now have in `lastReq`. Exchange it for a JWT id_token.
	q := lastReq.URL.Query()
	// fmt.Printf("lastReq.URL: %#v q: %#v\n", lastReq.URL, q)
	code := q.Get("code")
	oauth2Token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("unable to exchange code for id token: %v", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("id_token not found!")
	}

	// fmt.Printf("TOKEN: %s\n", rawIDToken)
	return rawIDToken, nil
}
