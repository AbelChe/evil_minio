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
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/mcontext"
	"github.com/minio/minio/internal/rest"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/procfs"
)

var (
	nodeCollector     *minioNodeCollector
	clusterCollector  *minioClusterCollector
	peerMetricsGroups []*MetricsGroup
)

func init() {
	clusterMetricsGroups := []*MetricsGroup{
		getBucketUsageMetrics(),
		getNodeHealthMetrics(),
		getClusterStorageMetrics(),
		getClusterTierMetrics(),
		getKMSMetrics(),
	}

	peerMetricsGroups = []*MetricsGroup{
		getCacheMetrics(),
		getGoMetrics(),
		getHTTPMetrics(),
		getNotificationMetrics(),
		getLocalStorageMetrics(),
		getMinioProcMetrics(),
		getMinioVersionMetrics(),
		getNetworkMetrics(),
		getS3TTFBMetric(),
		getILMNodeMetrics(),
		getScannerNodeMetrics(),
		getIAMNodeMetrics(),
		getKMSNodeMetrics(),
		getMinioHealingMetrics(),
	}

	allMetricsGroups := func() (allMetrics []*MetricsGroup) {
		allMetrics = append(allMetrics, clusterMetricsGroups...)
		allMetrics = append(allMetrics, peerMetricsGroups...)
		return allMetrics
	}()

	nodeCollector = newMinioCollectorNode([]*MetricsGroup{
		getNodeHealthMetrics(),
		getLocalDriveStorageMetrics(),
		getCacheMetrics(),
		getHTTPMetrics(),
		getNetworkMetrics(),
		getMinioVersionMetrics(),
		getS3TTFBMetric(),
		getNotificationMetrics(),
	})
	clusterCollector = newMinioClusterCollector(allMetricsGroups)
}

// MetricNamespace is top level grouping of metrics to create the metric name.
type MetricNamespace string

// MetricSubsystem is the sub grouping for metrics within a namespace.
type MetricSubsystem string

const (
	bucketMetricNamespace    MetricNamespace = "minio_bucket"
	clusterMetricNamespace   MetricNamespace = "minio_cluster"
	healMetricNamespace      MetricNamespace = "minio_heal"
	interNodeMetricNamespace MetricNamespace = "minio_inter_node"
	nodeMetricNamespace      MetricNamespace = "minio_node"
	minioMetricNamespace     MetricNamespace = "minio"
	s3MetricNamespace        MetricNamespace = "minio_s3"
)

const (
	cacheSubsystem            MetricSubsystem = "cache"
	capacityRawSubsystem      MetricSubsystem = "capacity_raw"
	capacityUsableSubsystem   MetricSubsystem = "capacity_usable"
	diskSubsystem             MetricSubsystem = "disk"
	fileDescriptorSubsystem   MetricSubsystem = "file_descriptor"
	goRoutines                MetricSubsystem = "go_routine"
	ioSubsystem               MetricSubsystem = "io"
	nodesSubsystem            MetricSubsystem = "nodes"
	objectsSubsystem          MetricSubsystem = "objects"
	processSubsystem          MetricSubsystem = "process"
	replicationSubsystem      MetricSubsystem = "replication"
	requestsSubsystem         MetricSubsystem = "requests"
	requestsRejectedSubsystem MetricSubsystem = "requests_rejected"
	timeSubsystem             MetricSubsystem = "time"
	trafficSubsystem          MetricSubsystem = "traffic"
	softwareSubsystem         MetricSubsystem = "software"
	sysCallSubsystem          MetricSubsystem = "syscall"
	usageSubsystem            MetricSubsystem = "usage"
	quotaSubsystem            MetricSubsystem = "quota"
	ilmSubsystem              MetricSubsystem = "ilm"
	scannerSubsystem          MetricSubsystem = "scanner"
	iamSubsystem              MetricSubsystem = "iam"
	kmsSubsystem              MetricSubsystem = "kms"
	notifySubsystem           MetricSubsystem = "notify"
	lambdaSubsystem           MetricSubsystem = "lambda"
	auditSubsystem            MetricSubsystem = "audit"
)

// MetricName are the individual names for the metric.
type MetricName string

const (
	authTotal      MetricName = "auth_total"
	canceledTotal  MetricName = "canceled_total"
	errorsTotal    MetricName = "errors_total"
	headerTotal    MetricName = "header_total"
	healTotal      MetricName = "heal_total"
	hitsTotal      MetricName = "hits_total"
	inflightTotal  MetricName = "inflight_total"
	invalidTotal   MetricName = "invalid_total"
	limitTotal     MetricName = "limit_total"
	missedTotal    MetricName = "missed_total"
	waitingTotal   MetricName = "waiting_total"
	incomingTotal  MetricName = "incoming_total"
	objectTotal    MetricName = "object_total"
	offlineTotal   MetricName = "offline_total"
	onlineTotal    MetricName = "online_total"
	openTotal      MetricName = "open_total"
	readTotal      MetricName = "read_total"
	timestampTotal MetricName = "timestamp_total"
	writeTotal     MetricName = "write_total"
	total          MetricName = "total"
	freeInodes     MetricName = "free_inodes"

	failedCount     MetricName = "failed_count"
	failedBytes     MetricName = "failed_bytes"
	freeBytes       MetricName = "free_bytes"
	readBytes       MetricName = "read_bytes"
	rcharBytes      MetricName = "rchar_bytes"
	receivedBytes   MetricName = "received_bytes"
	latencyMilliSec MetricName = "latency_ms"
	sentBytes       MetricName = "sent_bytes"
	totalBytes      MetricName = "total_bytes"
	usedBytes       MetricName = "used_bytes"
	writeBytes      MetricName = "write_bytes"
	wcharBytes      MetricName = "wchar_bytes"

	latencyMicroSec MetricName = "latency_us"
	latencyNanoSec  MetricName = "latency_ns"

	usagePercent MetricName = "update_percent"

	commitInfo  MetricName = "commit_info"
	usageInfo   MetricName = "usage_info"
	versionInfo MetricName = "version_info"

	sizeDistribution    = "size_distribution"
	versionDistribution = "version_distribution"
	ttfbDistribution    = "ttfb_seconds_distribution"

	lastActivityTime = "last_activity_nano_seconds"
	startTime        = "starttime_seconds"
	upTime           = "uptime_seconds"
	memory           = "resident_memory_bytes"
	cpu              = "cpu_total_seconds"

	expiryPendingTasks     MetricName = "expiry_pending_tasks"
	transitionPendingTasks MetricName = "transition_pending_tasks"
	transitionActiveTasks  MetricName = "transition_active_tasks"

	transitionedBytes    MetricName = "transitioned_bytes"
	transitionedObjects  MetricName = "transitioned_objects"
	transitionedVersions MetricName = "transitioned_versions"

	kmsOnline          = "online"
	kmsRequestsSuccess = "request_success"
	kmsRequestsError   = "request_error"
	kmsRequestsFail    = "request_failure"
	kmsUptime          = "uptime"
)

const (
	serverName = "server"
)

// MetricType for the types of metrics supported
type MetricType string

const (
	gaugeMetric     = "gaugeMetric"
	counterMetric   = "counterMetric"
	histogramMetric = "histogramMetric"
)

// MetricDescription describes the metric
type MetricDescription struct {
	Namespace MetricNamespace `json:"MetricNamespace"`
	Subsystem MetricSubsystem `json:"Subsystem"`
	Name      MetricName      `json:"MetricName"`
	Help      string          `json:"Help"`
	Type      MetricType      `json:"Type"`
}

// Metric captures the details for a metric
type Metric struct {
	Description          MetricDescription `json:"Description"`
	StaticLabels         map[string]string `json:"StaticLabels"`
	Value                float64           `json:"Value"`
	VariableLabels       map[string]string `json:"VariableLabels"`
	HistogramBucketLabel string            `json:"HistogramBucketLabel"`
	Histogram            map[string]uint64 `json:"Histogram"`
}

// MetricsGroup are a group of metrics that are initialized together.
type MetricsGroup struct {
	metricsCache  timedValue
	cacheInterval time.Duration
}

// RegisterRead register the metrics populator function to be used
// to populate new values upon cache invalidation.
func (g *MetricsGroup) RegisterRead(read func(ctx context.Context) []Metric) {
	g.metricsCache.Once.Do(func() {
		g.metricsCache.Relax = true
		g.metricsCache.TTL = g.cacheInterval
		g.metricsCache.Update = func() (interface{}, error) {
			return read(GlobalContext), nil
		}
	})
}

func (m *Metric) copyMetric() Metric {
	metric := Metric{
		Description:          m.Description,
		Value:                m.Value,
		HistogramBucketLabel: m.HistogramBucketLabel,
		StaticLabels:         make(map[string]string),
		VariableLabels:       make(map[string]string),
		Histogram:            make(map[string]uint64),
	}
	for k, v := range m.StaticLabels {
		metric.StaticLabels[k] = v
	}
	for k, v := range m.VariableLabels {
		metric.VariableLabels[k] = v
	}
	for k, v := range m.Histogram {
		metric.Histogram[k] = v
	}
	return metric
}

// Get - returns cached value always upton the configured TTL,
// once the TTL expires "read()" registered function is called
// to return the new values and updated.
func (g *MetricsGroup) Get() (metrics []Metric) {
	c, _ := g.metricsCache.Get()
	m, ok := c.([]Metric)
	if !ok {
		return []Metric{}
	}

	metrics = make([]Metric, 0, len(m))
	for i := range m {
		metrics = append(metrics, m[i].copyMetric())
	}
	return metrics
}

func getClusterCapacityTotalBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: capacityRawSubsystem,
		Name:      totalBytes,
		Help:      "Total capacity online in the cluster",
		Type:      gaugeMetric,
	}
}

func getClusterCapacityFreeBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: capacityRawSubsystem,
		Name:      freeBytes,
		Help:      "Total free capacity online in the cluster",
		Type:      gaugeMetric,
	}
}

func getClusterCapacityUsageBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: capacityUsableSubsystem,
		Name:      totalBytes,
		Help:      "Total usable capacity online in the cluster",
		Type:      gaugeMetric,
	}
}

func getClusterCapacityUsageFreeBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: capacityUsableSubsystem,
		Name:      freeBytes,
		Help:      "Total free usable capacity online in the cluster",
		Type:      gaugeMetric,
	}
}

func getNodeDriveAPILatencyMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      latencyMicroSec,
		Help:      "Average last minute latency in µs for drive API storage operations",
		Type:      gaugeMetric,
	}
}

func getNodeDriveUsedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      usedBytes,
		Help:      "Total storage used on a drive",
		Type:      gaugeMetric,
	}
}

func getNodeDriveFreeBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      freeBytes,
		Help:      "Total storage available on a drive",
		Type:      gaugeMetric,
	}
}

func getClusterDrivesOfflineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      offlineTotal,
		Help:      "Total drives offline",
		Type:      gaugeMetric,
	}
}

func getClusterDrivesOnlineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      onlineTotal,
		Help:      "Total drives online",
		Type:      gaugeMetric,
	}
}

func getClusterDrivesTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      total,
		Help:      "Total drives",
		Type:      gaugeMetric,
	}
}

func getNodeDrivesOfflineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      offlineTotal,
		Help:      "Total drives offline",
		Type:      gaugeMetric,
	}
}

func getNodeDrivesOnlineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      onlineTotal,
		Help:      "Total drives online",
		Type:      gaugeMetric,
	}
}

func getNodeDrivesTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      total,
		Help:      "Total drives",
		Type:      gaugeMetric,
	}
}

func getNodeDrivesFreeInodes() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      freeInodes,
		Help:      "Total free inodes",
		Type:      gaugeMetric,
	}
}

func getNodeDriveTotalBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: diskSubsystem,
		Name:      totalBytes,
		Help:      "Total storage on a drive",
		Type:      gaugeMetric,
	}
}

func getUsageLastScanActivityMD() MetricDescription {
	return MetricDescription{
		Namespace: minioMetricNamespace,
		Subsystem: usageSubsystem,
		Name:      lastActivityTime,
		Help:      "Time elapsed (in nano seconds) since last scan activity. This is set to 0 until first scan cycle",
		Type:      gaugeMetric,
	}
}

func getBucketUsageQuotaTotalBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: quotaSubsystem,
		Name:      totalBytes,
		Help:      "Total bucket quota size in bytes",
		Type:      gaugeMetric,
	}
}

func getBucketTrafficReceivedBytes() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      receivedBytes,
		Help:      "Total number of S3 bytes received for this bucket",
		Type:      gaugeMetric,
	}
}

func getBucketTrafficSentBytes() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      sentBytes,
		Help:      "Total number of S3 bytes sent for this bucket",
		Type:      gaugeMetric,
	}
}

func getBucketUsageTotalBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: usageSubsystem,
		Name:      totalBytes,
		Help:      "Total bucket size in bytes",
		Type:      gaugeMetric,
	}
}

func getBucketUsageObjectsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: usageSubsystem,
		Name:      objectTotal,
		Help:      "Total number of objects",
		Type:      gaugeMetric,
	}
}

func getBucketRepLatencyMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: replicationSubsystem,
		Name:      latencyMilliSec,
		Help:      "Replication latency in milliseconds",
		Type:      histogramMetric,
	}
}

func getBucketRepFailedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: replicationSubsystem,
		Name:      failedBytes,
		Help:      "Total number of bytes failed at least once to replicate",
		Type:      gaugeMetric,
	}
}

func getBucketRepSentBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: replicationSubsystem,
		Name:      sentBytes,
		Help:      "Total number of bytes replicated to the target bucket",
		Type:      gaugeMetric,
	}
}

func getBucketRepReceivedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: replicationSubsystem,
		Name:      receivedBytes,
		Help:      "Total number of bytes replicated to this bucket from another source bucket",
		Type:      gaugeMetric,
	}
}

func getBucketRepFailedOperationsMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: replicationSubsystem,
		Name:      failedCount,
		Help:      "Total number of objects which failed replication",
		Type:      gaugeMetric,
	}
}

func getBucketObjectDistributionMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: objectsSubsystem,
		Name:      sizeDistribution,
		Help:      "Distribution of object sizes in the bucket, includes label for the bucket name",
		Type:      histogramMetric,
	}
}

func getBucketObjectVersionsMD() MetricDescription {
	return MetricDescription{
		Namespace: bucketMetricNamespace,
		Subsystem: objectsSubsystem,
		Name:      versionDistribution,
		Help:      "Distribution of object sizes in the bucket, includes label for the bucket name",
		Type:      histogramMetric,
	}
}

func getInternodeFailedRequests() MetricDescription {
	return MetricDescription{
		Namespace: interNodeMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      errorsTotal,
		Help:      "Total number of failed internode calls",
		Type:      counterMetric,
	}
}

func getInternodeTCPDialTimeout() MetricDescription {
	return MetricDescription{
		Namespace: interNodeMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      "dial_errors",
		Help:      "Total number of internode TCP dial timeouts and errors",
		Type:      counterMetric,
	}
}

func getInternodeTCPAvgDuration() MetricDescription {
	return MetricDescription{
		Namespace: interNodeMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      "dial_avg_time",
		Help:      "Average time of internodes TCP dial calls",
		Type:      gaugeMetric,
	}
}

func getInterNodeSentBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: interNodeMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      sentBytes,
		Help:      "Total number of bytes sent to the other peer nodes",
		Type:      counterMetric,
	}
}

func getInterNodeReceivedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: interNodeMetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      receivedBytes,
		Help:      "Total number of bytes received from other peer nodes",
		Type:      counterMetric,
	}
}

func getS3SentBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      sentBytes,
		Help:      "Total number of s3 bytes sent",
		Type:      counterMetric,
	}
}

func getS3ReceivedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: trafficSubsystem,
		Name:      receivedBytes,
		Help:      "Total number of s3 bytes received",
		Type:      counterMetric,
	}
}

func getS3RequestsInFlightMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      inflightTotal,
		Help:      "Total number of S3 requests currently in flight",
		Type:      gaugeMetric,
	}
}

func getS3RequestsInQueueMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      waitingTotal,
		Help:      "Number of S3 requests in the waiting queue",
		Type:      gaugeMetric,
	}
}

func getIncomingS3RequestsMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      incomingTotal,
		Help:      "Volatile number of total incoming S3 requests",
		Type:      gaugeMetric,
	}
}

func getS3RequestsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      total,
		Help:      "Total number S3 requests",
		Type:      counterMetric,
	}
}

func getS3RequestsErrorsMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      errorsTotal,
		Help:      "Total number S3 requests with (4xx and 5xx) errors",
		Type:      counterMetric,
	}
}

func getS3Requests4xxErrorsMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      "4xx_" + errorsTotal,
		Help:      "Total number S3 requests with (4xx) errors",
		Type:      counterMetric,
	}
}

func getS3Requests5xxErrorsMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      "5xx_" + errorsTotal,
		Help:      "Total number S3 requests with (5xx) errors",
		Type:      counterMetric,
	}
}

func getS3RequestsCanceledMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsSubsystem,
		Name:      canceledTotal,
		Help:      "Total number S3 requests that were canceled from the client while processing",
		Type:      counterMetric,
	}
}

func getS3RejectedAuthRequestsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsRejectedSubsystem,
		Name:      authTotal,
		Help:      "Total number S3 requests rejected for auth failure",
		Type:      counterMetric,
	}
}

func getS3RejectedHeaderRequestsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsRejectedSubsystem,
		Name:      headerTotal,
		Help:      "Total number S3 requests rejected for invalid header",
		Type:      counterMetric,
	}
}

func getS3RejectedTimestampRequestsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsRejectedSubsystem,
		Name:      timestampTotal,
		Help:      "Total number S3 requests rejected for invalid timestamp",
		Type:      counterMetric,
	}
}

func getS3RejectedInvalidRequestsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: requestsRejectedSubsystem,
		Name:      invalidTotal,
		Help:      "Total number S3 invalid requests",
		Type:      counterMetric,
	}
}

func getCacheHitsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      hitsTotal,
		Help:      "Total number of drive cache hits",
		Type:      counterMetric,
	}
}

func getCacheHitsMissedTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      missedTotal,
		Help:      "Total number of drive cache misses",
		Type:      counterMetric,
	}
}

func getCacheUsagePercentMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: minioNamespace,
		Name:      usagePercent,
		Help:      "Total percentage cache usage",
		Type:      gaugeMetric,
	}
}

func getCacheUsageInfoMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      usageInfo,
		Help:      "Total percentage cache usage, value of 1 indicates high and 0 low, label level is set as well",
		Type:      gaugeMetric,
	}
}

func getCacheUsedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      usedBytes,
		Help:      "Current cache usage in bytes",
		Type:      gaugeMetric,
	}
}

func getCacheTotalBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      totalBytes,
		Help:      "Total size of cache drive in bytes",
		Type:      gaugeMetric,
	}
}

func getCacheSentBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: minioNamespace,
		Subsystem: cacheSubsystem,
		Name:      sentBytes,
		Help:      "Total number of bytes served from cache",
		Type:      counterMetric,
	}
}

func getHealObjectsTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: healMetricNamespace,
		Subsystem: objectsSubsystem,
		Name:      total,
		Help:      "Objects scanned in current self healing run",
		Type:      gaugeMetric,
	}
}

func getHealObjectsHealTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: healMetricNamespace,
		Subsystem: objectsSubsystem,
		Name:      healTotal,
		Help:      "Objects healed in current self healing run",
		Type:      gaugeMetric,
	}
}

func getHealObjectsFailTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: healMetricNamespace,
		Subsystem: objectsSubsystem,
		Name:      errorsTotal,
		Help:      "Objects for which healing failed in current self healing run",
		Type:      gaugeMetric,
	}
}

func getHealLastActivityTimeMD() MetricDescription {
	return MetricDescription{
		Namespace: healMetricNamespace,
		Subsystem: timeSubsystem,
		Name:      lastActivityTime,
		Help:      "Time elapsed (in nano seconds) since last self healing activity. This is set to -1 until initial self heal activity",
		Type:      gaugeMetric,
	}
}

func getNodeOnlineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: nodesSubsystem,
		Name:      onlineTotal,
		Help:      "Total number of MinIO nodes online",
		Type:      gaugeMetric,
	}
}

func getNodeOfflineTotalMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: nodesSubsystem,
		Name:      offlineTotal,
		Help:      "Total number of MinIO nodes offline",
		Type:      gaugeMetric,
	}
}

func getMinIOVersionMD() MetricDescription {
	return MetricDescription{
		Namespace: minioMetricNamespace,
		Subsystem: softwareSubsystem,
		Name:      versionInfo,
		Help:      "MinIO Release tag for the server",
		Type:      gaugeMetric,
	}
}

func getMinIOCommitMD() MetricDescription {
	return MetricDescription{
		Namespace: minioMetricNamespace,
		Subsystem: softwareSubsystem,
		Name:      commitInfo,
		Help:      "Git commit hash for the MinIO release",
		Type:      gaugeMetric,
	}
}

func getS3TTFBDistributionMD() MetricDescription {
	return MetricDescription{
		Namespace: s3MetricNamespace,
		Subsystem: timeSubsystem,
		Name:      ttfbDistribution,
		Help:      "Distribution of the time to first byte across API calls",
		Type:      gaugeMetric,
	}
}

func getMinioFDOpenMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: fileDescriptorSubsystem,
		Name:      openTotal,
		Help:      "Total number of open file descriptors by the MinIO Server process",
		Type:      gaugeMetric,
	}
}

func getMinioFDLimitMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: fileDescriptorSubsystem,
		Name:      limitTotal,
		Help:      "Limit on total number of open file descriptors for the MinIO Server process",
		Type:      gaugeMetric,
	}
}

func getMinioProcessIOWriteBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ioSubsystem,
		Name:      writeBytes,
		Help:      "Total bytes written by the process to the underlying storage system, /proc/[pid]/io write_bytes",
		Type:      counterMetric,
	}
}

func getMinioProcessIOReadBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ioSubsystem,
		Name:      readBytes,
		Help:      "Total bytes read by the process from the underlying storage system, /proc/[pid]/io read_bytes",
		Type:      counterMetric,
	}
}

func getMinioProcessIOWriteCachedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ioSubsystem,
		Name:      wcharBytes,
		Help:      "Total bytes written by the process to the underlying storage system including page cache, /proc/[pid]/io wchar",
		Type:      counterMetric,
	}
}

func getMinioProcessIOReadCachedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ioSubsystem,
		Name:      rcharBytes,
		Help:      "Total bytes read by the process from the underlying storage system including cache, /proc/[pid]/io rchar",
		Type:      counterMetric,
	}
}

func getMinIOProcessSysCallRMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: sysCallSubsystem,
		Name:      readTotal,
		Help:      "Total read SysCalls to the kernel. /proc/[pid]/io syscr",
		Type:      counterMetric,
	}
}

func getMinIOProcessSysCallWMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: sysCallSubsystem,
		Name:      writeTotal,
		Help:      "Total write SysCalls to the kernel. /proc/[pid]/io syscw",
		Type:      counterMetric,
	}
}

func getMinIOGORoutineCountMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: goRoutines,
		Name:      total,
		Help:      "Total number of go routines running",
		Type:      gaugeMetric,
	}
}

func getMinIOProcessStartTimeMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: processSubsystem,
		Name:      startTime,
		Help:      "Start time for MinIO process per node, time in seconds since Unix epoc",
		Type:      gaugeMetric,
	}
}

func getMinIOProcessUptimeMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: processSubsystem,
		Name:      upTime,
		Help:      "Uptime for MinIO process per node in seconds",
		Type:      gaugeMetric,
	}
}

func getMinIOProcessResidentMemory() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: processSubsystem,
		Name:      memory,
		Help:      "Resident memory size in bytes",
		Type:      gaugeMetric,
	}
}

func getMinIOProcessCPUTime() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: processSubsystem,
		Name:      cpu,
		Help:      "Total user and system CPU time spent in seconds",
		Type:      counterMetric,
	}
}

func getMinioProcMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		if runtime.GOOS == "windows" {
			return nil
		}
		metrics = make([]Metric, 0, 20)
		p, err := procfs.Self()
		if err != nil {
			logger.LogOnceIf(ctx, err, string(nodeMetricNamespace))
			return
		}

		openFDs, _ := p.FileDescriptorsLen()
		l, _ := p.Limits()
		io, _ := p.IO()
		stat, _ := p.Stat()
		startTime, _ := stat.StartTime()

		if openFDs > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioFDOpenMD(),
					Value:       float64(openFDs),
				},
			)
		}

		if l.OpenFiles > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioFDLimitMD(),
					Value:       float64(l.OpenFiles),
				})
		}

		if io.SyscR > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessSysCallRMD(),
					Value:       float64(io.SyscR),
				})
		}

		if io.SyscW > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessSysCallWMD(),
					Value:       float64(io.SyscW),
				})
		}

		if io.ReadBytes > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioProcessIOReadBytesMD(),
					Value:       float64(io.ReadBytes),
				})
		}

		if io.WriteBytes > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioProcessIOWriteBytesMD(),
					Value:       float64(io.WriteBytes),
				})
		}

		if io.RChar > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioProcessIOReadCachedBytesMD(),
					Value:       float64(io.RChar),
				})
		}

		if io.WChar > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinioProcessIOWriteCachedBytesMD(),
					Value:       float64(io.WChar),
				})
		}

		if startTime > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessStartTimeMD(),
					Value:       startTime,
				})
		}

		if !globalBootTime.IsZero() {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessUptimeMD(),
					Value:       time.Since(globalBootTime).Seconds(),
				})
		}

		if stat.ResidentMemory() > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessResidentMemory(),
					Value:       float64(stat.ResidentMemory()),
				})
		}

		if stat.CPUTime() > 0 {
			metrics = append(metrics,
				Metric{
					Description: getMinIOProcessCPUTime(),
					Value:       stat.CPUTime(),
				})
		}
		return
	})
	return mg
}

func getGoMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		metrics = append(metrics, Metric{
			Description: getMinIOGORoutineCountMD(),
			Value:       float64(runtime.NumGoroutine()),
		})
		return
	})
	return mg
}

func getS3TTFBMetric() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		// Read prometheus metric on this channel
		ch := make(chan prometheus.Metric)
		var wg sync.WaitGroup
		wg.Add(1)

		// Read prometheus histogram data and convert it to internal metric data
		go func() {
			defer wg.Done()
			for promMetric := range ch {
				dtoMetric := &dto.Metric{}
				err := promMetric.Write(dtoMetric)
				if err != nil {
					logger.LogIf(GlobalContext, err)
					return
				}
				h := dtoMetric.GetHistogram()
				for _, b := range h.Bucket {
					labels := make(map[string]string)
					for _, lp := range dtoMetric.GetLabel() {
						labels[*lp.Name] = *lp.Value
					}
					labels["le"] = fmt.Sprintf("%.3f", *b.UpperBound)
					metric := Metric{
						Description:    getS3TTFBDistributionMD(),
						VariableLabels: labels,
						Value:          float64(b.GetCumulativeCount()),
					}
					metrics = append(metrics, metric)
				}
			}
		}()

		httpRequestsDuration.Collect(ch)
		close(ch)
		wg.Wait()
		return
	})
	return mg
}

func getTransitionPendingTasksMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      transitionPendingTasks,
		Help:      "Number of pending ILM transition tasks in the queue",
		Type:      gaugeMetric,
	}
}

func getTransitionActiveTasksMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      transitionActiveTasks,
		Help:      "Number of active ILM transition tasks",
		Type:      gaugeMetric,
	}
}

func getExpiryPendingTasksMD() MetricDescription {
	return MetricDescription{
		Namespace: nodeMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      expiryPendingTasks,
		Help:      "Number of pending ILM expiry tasks in the queue",
		Type:      gaugeMetric,
	}
}

func getILMNodeMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(_ context.Context) []Metric {
		expPendingTasks := Metric{
			Description: getExpiryPendingTasksMD(),
		}
		trPendingTasks := Metric{
			Description: getTransitionPendingTasksMD(),
		}
		trActiveTasks := Metric{
			Description: getTransitionActiveTasksMD(),
		}
		if globalExpiryState != nil {
			expPendingTasks.Value = float64(globalExpiryState.PendingTasks())
		}
		if globalTransitionState != nil {
			trPendingTasks.Value = float64(globalTransitionState.PendingTasks())
			trActiveTasks.Value = float64(globalTransitionState.ActiveTasks())
		}
		return []Metric{
			expPendingTasks,
			trPendingTasks,
			trActiveTasks,
		}
	})
	return mg
}

func getScannerNodeMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(_ context.Context) []Metric {
		metrics := []Metric{
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: scannerSubsystem,
					Name:      "objects_scanned",
					Help:      "Total number of unique objects scanned since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricScanObject)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: scannerSubsystem,
					Name:      "versions_scanned",
					Help:      "Total number of object versions scanned since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricApplyVersion)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: scannerSubsystem,
					Name:      "directories_scanned",
					Help:      "Total number of directories scanned since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricScanFolder)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: scannerSubsystem,
					Name:      "bucket_scans_started",
					Help:      "Total number of bucket scans started since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricScanBucketDrive) + uint64(globalScannerMetrics.activeDrives())),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: scannerSubsystem,
					Name:      "bucket_scans_finished",
					Help:      "Total number of bucket scans finished since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricScanBucketDrive)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: ilmSubsystem,
					Name:      "versions_scanned",
					Help:      "Total number of object versions checked for ilm actions since server start",
					Type:      counterMetric,
				},
				Value: float64(globalScannerMetrics.lifetime(scannerMetricILM)),
			},
		}
		for i := range globalScannerMetrics.actions {
			action := lifecycle.Action(i)
			v := globalScannerMetrics.lifetimeActions(action)
			if v == 0 {
				continue
			}
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: ilmSubsystem,
					Name:      MetricName("action_count_" + toSnake(action.String())),
					Help:      "Total action outcome of lifecycle checks since server start",
					Type:      counterMetric,
				},
				Value: float64(v),
			})
		}
		return metrics
	})
	return mg
}

func getIAMNodeMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(_ context.Context) (metrics []Metric) {
		lastSyncTime := atomic.LoadUint64(&globalIAMSys.LastRefreshTimeUnixNano)
		var sinceLastSyncMillis uint64
		if lastSyncTime != 0 {
			sinceLastSyncMillis = (uint64(time.Now().UnixNano()) - lastSyncTime) / uint64(time.Millisecond)
		}

		pluginAuthNMetrics := globalAuthNPlugin.Metrics()
		metrics = []Metric{
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "last_sync_duration_millis",
					Help:      "Last successful IAM data sync duration in milliseconds",
					Type:      gaugeMetric,
				},
				Value: float64(atomic.LoadUint64(&globalIAMSys.LastRefreshDurationMilliseconds)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "since_last_sync_millis",
					Help:      "Time (in milliseconds) since last successful IAM data sync. This is set to 0 until the first sync after server start.",
					Type:      gaugeMetric,
				},
				Value: float64(sinceLastSyncMillis),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "sync_successes",
					Help:      "Number of successful IAM data syncs since server start.",
					Type:      counterMetric,
				},
				Value: float64(atomic.LoadUint64(&globalIAMSys.TotalRefreshSuccesses)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "sync_failures",
					Help:      "Number of failed IAM data syncs since server start.",
					Type:      counterMetric,
				},
				Value: float64(atomic.LoadUint64(&globalIAMSys.TotalRefreshFailures)),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_last_succ_seconds",
					Help:      "When plugin authentication is configured, returns time (in seconds) since the last successful request to the service",
					Type:      gaugeMetric,
				},
				Value: pluginAuthNMetrics.LastReachableSecs,
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_last_fail_seconds",
					Help:      "When plugin authentication is configured, returns time (in seconds) since the last failed request to the service",
					Type:      gaugeMetric,
				},
				Value: pluginAuthNMetrics.LastUnreachableSecs,
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_total_requests_minute",
					Help:      "When plugin authentication is configured, returns total requests count in the last full minute",
					Type:      gaugeMetric,
				},
				Value: float64(pluginAuthNMetrics.TotalRequests),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_failed_requests_minute",
					Help:      "When plugin authentication is configured, returns failed requests count in the last full minute",
					Type:      gaugeMetric,
				},
				Value: float64(pluginAuthNMetrics.FailedRequests),
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_succ_avg_rtt_ms_minute",
					Help:      "When plugin authentication is configured, returns average round-trip-time of successful requests in the last full minute",
					Type:      gaugeMetric,
				},
				Value: pluginAuthNMetrics.AvgSuccRTTMs,
			},
			{
				Description: MetricDescription{
					Namespace: nodeMetricNamespace,
					Subsystem: iamSubsystem,
					Name:      "plugin_authn_service_succ_max_rtt_ms_minute",
					Help:      "When plugin authentication is configured, returns maximum round-trip-time of successful requests in the last full minute",
					Type:      gaugeMetric,
				},
				Value: pluginAuthNMetrics.MaxSuccRTTMs,
			},
		}

		return metrics
	})
	return mg
}

func getMinioVersionMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(_ context.Context) (metrics []Metric) {
		metrics = append(metrics, Metric{
			Description:    getMinIOCommitMD(),
			VariableLabels: map[string]string{"commit": CommitID},
		})
		metrics = append(metrics, Metric{
			Description:    getMinIOVersionMD(),
			VariableLabels: map[string]string{"version": Version},
		})
		return
	})
	return mg
}

func getNodeHealthMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(_ context.Context) (metrics []Metric) {
		metrics = make([]Metric, 0, 16)
		nodesUp, nodesDown := globalNotificationSys.GetPeerOnlineCount()
		metrics = append(metrics, Metric{
			Description: getNodeOnlineTotalMD(),
			Value:       float64(nodesUp),
		})
		metrics = append(metrics, Metric{
			Description: getNodeOfflineTotalMD(),
			Value:       float64(nodesDown),
		})
		return
	})
	return mg
}

func getMinioHealingMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(_ context.Context) (metrics []Metric) {
		metrics = make([]Metric, 0, 5)
		bgSeq, exists := globalBackgroundHealState.getHealSequenceByToken(bgHealingUUID)
		if !exists {
			return
		}

		if bgSeq.lastHealActivity.IsZero() {
			return
		}

		metrics = append(metrics, Metric{
			Description: getHealLastActivityTimeMD(),
			Value:       float64(time.Since(bgSeq.lastHealActivity)),
		})
		metrics = append(metrics, getObjectsScanned(bgSeq)...)
		metrics = append(metrics, getHealedItems(bgSeq)...)
		metrics = append(metrics, getFailedItems(bgSeq)...)
		return
	})
	return mg
}

func getFailedItems(seq *healSequence) (m []Metric) {
	m = make([]Metric, 0, 1)
	for k, v := range seq.gethealFailedItemsMap() {
		s := strings.Split(k, ",")
		m = append(m, Metric{
			Description: getHealObjectsFailTotalMD(),
			VariableLabels: map[string]string{
				"mount_path":    s[0],
				"volume_status": s[1],
			},
			Value: float64(v),
		})
	}
	return
}

func getHealedItems(seq *healSequence) (m []Metric) {
	items := seq.getHealedItemsMap()
	m = make([]Metric, 0, len(items))
	for k, v := range items {
		m = append(m, Metric{
			Description:    getHealObjectsHealTotalMD(),
			VariableLabels: map[string]string{"type": string(k)},
			Value:          float64(v),
		})
	}
	return
}

func getObjectsScanned(seq *healSequence) (m []Metric) {
	items := seq.getScannedItemsMap()
	m = make([]Metric, 0, len(items))
	for k, v := range items {
		m = append(m, Metric{
			Description:    getHealObjectsTotalMD(),
			VariableLabels: map[string]string{"type": string(k)},
			Value:          float64(v),
		})
	}
	return
}

func getCacheMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		metrics = make([]Metric, 0, 20)
		cacheObjLayer := newCachedObjectLayerFn()
		// Service not initialized yet
		if cacheObjLayer == nil {
			return
		}
		metrics = append(metrics, Metric{
			Description: getCacheHitsTotalMD(),
			Value:       float64(cacheObjLayer.CacheStats().getHits()),
		})
		metrics = append(metrics, Metric{
			Description: getCacheHitsMissedTotalMD(),
			Value:       float64(cacheObjLayer.CacheStats().getMisses()),
		})
		metrics = append(metrics, Metric{
			Description: getCacheSentBytesMD(),
			Value:       float64(cacheObjLayer.CacheStats().getBytesServed()),
		})
		for _, cdStats := range cacheObjLayer.CacheStats().GetDiskStats() {
			metrics = append(metrics, Metric{
				Description:    getCacheUsagePercentMD(),
				Value:          float64(cdStats.UsagePercent),
				VariableLabels: map[string]string{"disk": cdStats.Dir},
			})
			metrics = append(metrics, Metric{
				Description:    getCacheUsageInfoMD(),
				Value:          float64(cdStats.UsageState),
				VariableLabels: map[string]string{"disk": cdStats.Dir, "level": cdStats.GetUsageLevelString()},
			})
			metrics = append(metrics, Metric{
				Description:    getCacheUsedBytesMD(),
				Value:          float64(cdStats.UsageSize),
				VariableLabels: map[string]string{"disk": cdStats.Dir},
			})
			metrics = append(metrics, Metric{
				Description:    getCacheTotalBytesMD(),
				Value:          float64(cdStats.TotalCapacity),
				VariableLabels: map[string]string{"disk": cdStats.Dir},
			})
		}
		return
	})
	return mg
}

func getNotificationMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) []Metric {
		nstats := globalNotifyTargetList.Stats()
		metrics := make([]Metric, 0, 1+len(nstats.TargetStats))
		metrics = append(metrics, Metric{
			Description: MetricDescription{
				Namespace: minioNamespace,
				Subsystem: notifySubsystem,
				Name:      "current_send_in_progress",
				Help:      "Number of concurrent async Send calls active to all targets",
				Type:      gaugeMetric,
			},
			Value: float64(nstats.CurrentSendCalls),
		})
		for _, st := range nstats.TargetStats {
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: notifySubsystem,
					Name:      "target_queue_length",
					Help:      "Number of unsent notifications in queue for target",
					Type:      gaugeMetric,
				},
				VariableLabels: map[string]string{"target_id": st.ID.ID, "target_name": st.ID.Name},
				Value:          float64(st.CurrentQueue),
			})
		}

		lstats := globalLambdaTargetList.Stats()
		for _, st := range lstats.TargetStats {
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: lambdaSubsystem,
					Name:      "active_requests",
					Help:      "Number of in progress requests",
				},
				VariableLabels: map[string]string{"target_id": st.ID.ID, "target_name": st.ID.Name},
				Value:          float64(st.ActiveRequests),
			})
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: lambdaSubsystem,
					Name:      "total_requests",
					Help:      "Total number of requests sent since start",
					Type:      counterMetric,
				},
				VariableLabels: map[string]string{"target_id": st.ID.ID, "target_name": st.ID.Name},
				Value:          float64(st.TotalRequests),
			})
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: lambdaSubsystem,
					Name:      "failed_requests",
					Help:      "Total number of requests that failed to send since start",
					Type:      counterMetric,
				},
				VariableLabels: map[string]string{"target_id": st.ID.ID, "target_name": st.ID.Name},
				Value:          float64(st.FailedRequests),
			})
		}

		// Audit and system:
		audit := logger.CurrentStats()
		for id, st := range audit {
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: auditSubsystem,
					Name:      "target_queue_length",
					Help:      "Number of unsent messages in queue for target",
					Type:      gaugeMetric,
				},
				VariableLabels: map[string]string{"target_id": id},
				Value:          float64(st.QueueLength),
			})
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: auditSubsystem,
					Name:      "total_messages",
					Help:      "Total number of messages sent since start",
					Type:      counterMetric,
				},
				VariableLabels: map[string]string{"target_id": id},
				Value:          float64(st.TotalMessages),
			})
			metrics = append(metrics, Metric{
				Description: MetricDescription{
					Namespace: minioNamespace,
					Subsystem: auditSubsystem,
					Name:      "failed_messages",
					Help:      "Total number of messages that failed to send since start",
					Type:      counterMetric,
				},
				VariableLabels: map[string]string{"target_id": id},
				Value:          float64(st.FailedMessages),
			})
		}
		return metrics
	})
	return mg
}

func getHTTPMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		httpStats := globalHTTPStats.toServerHTTPStats()
		metrics = make([]Metric, 0, 3+
			len(httpStats.CurrentS3Requests.APIStats)+
			len(httpStats.TotalS3Requests.APIStats)+
			len(httpStats.TotalS3Errors.APIStats)+
			len(httpStats.TotalS35xxErrors.APIStats)+
			len(httpStats.TotalS34xxErrors.APIStats))
		metrics = append(metrics, Metric{
			Description: getS3RejectedAuthRequestsTotalMD(),
			Value:       float64(httpStats.TotalS3RejectedAuth),
		})
		metrics = append(metrics, Metric{
			Description: getS3RejectedTimestampRequestsTotalMD(),
			Value:       float64(httpStats.TotalS3RejectedTime),
		})
		metrics = append(metrics, Metric{
			Description: getS3RejectedHeaderRequestsTotalMD(),
			Value:       float64(httpStats.TotalS3RejectedHeader),
		})
		metrics = append(metrics, Metric{
			Description: getS3RejectedInvalidRequestsTotalMD(),
			Value:       float64(httpStats.TotalS3RejectedInvalid),
		})
		metrics = append(metrics, Metric{
			Description: getS3RequestsInQueueMD(),
			Value:       float64(httpStats.S3RequestsInQueue),
		})
		metrics = append(metrics, Metric{
			Description: getIncomingS3RequestsMD(),
			Value:       float64(httpStats.S3RequestsIncoming),
		})

		for api, value := range httpStats.CurrentS3Requests.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3RequestsInFlightMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		for api, value := range httpStats.TotalS3Requests.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3RequestsTotalMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		for api, value := range httpStats.TotalS3Errors.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3RequestsErrorsMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		for api, value := range httpStats.TotalS35xxErrors.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3Requests5xxErrorsMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		for api, value := range httpStats.TotalS34xxErrors.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3Requests4xxErrorsMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		for api, value := range httpStats.TotalS3Canceled.APIStats {
			metrics = append(metrics, Metric{
				Description:    getS3RequestsCanceledMD(),
				Value:          float64(value),
				VariableLabels: map[string]string{"api": api},
			})
		}
		return
	})
	return mg
}

func getNetworkMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		metrics = make([]Metric, 0, 10)
		connStats := globalConnStats.toServerConnStats()
		rpcStats := rest.GetRPCStats()
		if globalIsDistErasure {
			metrics = append(metrics, Metric{
				Description: getInternodeFailedRequests(),
				Value:       float64(rpcStats.Errs),
			})
			metrics = append(metrics, Metric{
				Description: getInternodeTCPDialTimeout(),
				Value:       float64(rpcStats.DialErrs),
			})
			metrics = append(metrics, Metric{
				Description: getInternodeTCPAvgDuration(),
				Value:       float64(rpcStats.DialAvgDuration),
			})
			metrics = append(metrics, Metric{
				Description: getInterNodeSentBytesMD(),
				Value:       float64(connStats.TotalOutputBytes),
			})
			metrics = append(metrics, Metric{
				Description: getInterNodeReceivedBytesMD(),
				Value:       float64(connStats.TotalInputBytes),
			})
		}
		metrics = append(metrics, Metric{
			Description: getS3SentBytesMD(),
			Value:       float64(connStats.S3OutputBytes),
		})
		metrics = append(metrics, Metric{
			Description: getS3ReceivedBytesMD(),
			Value:       float64(connStats.S3InputBytes),
		})
		return
	})
	return mg
}

func getBucketUsageMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil {
			return
		}

		metrics = make([]Metric, 0, 50)
		dataUsageInfo, err := loadDataUsageFromBackend(ctx, objLayer)
		if err != nil {
			logger.LogIf(ctx, err)
			return
		}

		// data usage has not captured any data yet.
		if dataUsageInfo.LastUpdate.IsZero() {
			return
		}

		metrics = append(metrics, Metric{
			Description: getUsageLastScanActivityMD(),
			Value:       float64(time.Since(dataUsageInfo.LastUpdate)),
		})

		bucketReplStats := globalReplicationStats.getAllLatest(dataUsageInfo.BucketsUsage)
		for bucket, usage := range dataUsageInfo.BucketsUsage {
			stats := bucketReplStats[bucket]

			quota, _ := globalBucketQuotaSys.Get(ctx, bucket)

			metrics = append(metrics, Metric{
				Description:    getBucketUsageTotalBytesMD(),
				Value:          float64(usage.Size),
				VariableLabels: map[string]string{"bucket": bucket},
			})

			metrics = append(metrics, Metric{
				Description:    getBucketUsageObjectsTotalMD(),
				Value:          float64(usage.ObjectsCount),
				VariableLabels: map[string]string{"bucket": bucket},
			})

			metrics = append(metrics, Metric{
				Description:    getBucketRepReceivedBytesMD(),
				Value:          float64(stats.ReplicaSize),
				VariableLabels: map[string]string{"bucket": bucket},
			})

			if quota != nil && quota.Quota > 0 {
				metrics = append(metrics, Metric{
					Description:    getBucketUsageQuotaTotalBytesMD(),
					Value:          float64(quota.Quota),
					VariableLabels: map[string]string{"bucket": bucket},
				})
			}

			recvBytes := globalBucketConnStats.getS3InputBytes(bucket)
			if recvBytes > 0 {
				metrics = append(metrics, Metric{
					Description:    getBucketTrafficReceivedBytes(),
					Value:          float64(recvBytes),
					VariableLabels: map[string]string{"bucket": bucket},
				})
			}

			sentBytes := globalBucketConnStats.getS3OutputBytes(bucket)
			if sentBytes > 0 {
				metrics = append(metrics, Metric{
					Description:    getBucketTrafficSentBytes(),
					Value:          float64(sentBytes),
					VariableLabels: map[string]string{"bucket": bucket},
				})
			}

			if stats.hasReplicationUsage() {
				for arn, stat := range stats.Stats {
					metrics = append(metrics, Metric{
						Description:    getBucketRepFailedBytesMD(),
						Value:          float64(stat.FailedSize),
						VariableLabels: map[string]string{"bucket": bucket, "targetArn": arn},
					})
					metrics = append(metrics, Metric{
						Description:    getBucketRepSentBytesMD(),
						Value:          float64(stat.ReplicatedSize),
						VariableLabels: map[string]string{"bucket": bucket, "targetArn": arn},
					})
					metrics = append(metrics, Metric{
						Description:    getBucketRepFailedOperationsMD(),
						Value:          float64(stat.FailedCount),
						VariableLabels: map[string]string{"bucket": bucket, "targetArn": arn},
					})
					metrics = append(metrics, Metric{
						Description:          getBucketRepLatencyMD(),
						HistogramBucketLabel: "range",
						Histogram:            stat.Latency.getUploadLatency(),
						VariableLabels:       map[string]string{"bucket": bucket, "operation": "upload", "targetArn": arn},
					})

				}
			}

			metrics = append(metrics, Metric{
				Description:          getBucketObjectDistributionMD(),
				Histogram:            usage.ObjectSizesHistogram,
				HistogramBucketLabel: "range",
				VariableLabels:       map[string]string{"bucket": bucket},
			})
			metrics = append(metrics, Metric{
				Description:          getBucketObjectVersionsMD(),
				Histogram:            usage.ObjectVersionsHistogram,
				HistogramBucketLabel: "range",
				VariableLabels:       map[string]string{"bucket": bucket},
			})
		}
		return
	})
	return mg
}

func getClusterTransitionedBytesMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      transitionedBytes,
		Help:      "Total bytes transitioned to a tier",
		Type:      gaugeMetric,
	}
}

func getClusterTransitionedObjectsMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      transitionedObjects,
		Help:      "Total number of objects transitioned to a tier",
		Type:      gaugeMetric,
	}
}

func getClusterTransitionedVersionsMD() MetricDescription {
	return MetricDescription{
		Namespace: clusterMetricNamespace,
		Subsystem: ilmSubsystem,
		Name:      transitionedVersions,
		Help:      "Total number of versions transitioned to a tier",
		Type:      gaugeMetric,
	}
}

func getClusterTierMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		if objLayer == nil {
			return
		}
		if globalTierConfigMgr.Empty() {
			return
		}

		dui, err := loadDataUsageFromBackend(ctx, objLayer)
		if err != nil {
			logger.LogIf(ctx, err)
			return
		}
		// data usage has not captured any tier stats yet.
		if dui.TierStats == nil {
			return
		}

		return dui.tierMetrics()
	})
	return mg
}

func getLocalStorageMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil {
			return
		}

		metrics = make([]Metric, 0, 50)
		storageInfo := objLayer.LocalStorageInfo(ctx)
		onlineDrives, offlineDrives := getOnlineOfflineDisksStats(storageInfo.Disks)
		totalDrives := onlineDrives.Merge(offlineDrives)

		for _, disk := range storageInfo.Disks {
			metrics = append(metrics, Metric{
				Description:    getNodeDriveUsedBytesMD(),
				Value:          float64(disk.UsedSpace),
				VariableLabels: map[string]string{"disk": disk.DrivePath},
			})

			metrics = append(metrics, Metric{
				Description:    getNodeDriveFreeBytesMD(),
				Value:          float64(disk.AvailableSpace),
				VariableLabels: map[string]string{"disk": disk.DrivePath},
			})

			metrics = append(metrics, Metric{
				Description:    getNodeDriveTotalBytesMD(),
				Value:          float64(disk.TotalSpace),
				VariableLabels: map[string]string{"disk": disk.DrivePath},
			})

			metrics = append(metrics, Metric{
				Description:    getNodeDrivesFreeInodes(),
				Value:          float64(disk.FreeInodes),
				VariableLabels: map[string]string{"disk": disk.DrivePath},
			})

			metrics = append(metrics, Metric{
				Description: getNodeDrivesOfflineTotalMD(),
				Value:       float64(offlineDrives.Sum()),
			})

			metrics = append(metrics, Metric{
				Description: getNodeDrivesOnlineTotalMD(),
				Value:       float64(onlineDrives.Sum()),
			})

			metrics = append(metrics, Metric{
				Description: getNodeDrivesTotalMD(),
				Value:       float64(totalDrives.Sum()),
			})

		}
		return
	})
	return mg
}

func getLocalDriveStorageMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil {
			return
		}

		storageInfo := objLayer.LocalStorageInfo(ctx)
		if storageInfo.Backend.Type == madmin.FS {
			return
		}
		metrics = make([]Metric, 0, 50)
		for _, disk := range storageInfo.Disks {
			if disk.Metrics == nil {
				continue
			}
			for apiName, latency := range disk.Metrics.LastMinute {
				metrics = append(metrics, Metric{
					Description:    getNodeDriveAPILatencyMD(),
					Value:          float64(latency.Avg().Microseconds()),
					VariableLabels: map[string]string{"disk": disk.DrivePath, "api": "storage." + apiName},
				})
			}
		}
		return
	})
	return mg
}

func getClusterStorageMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 1 * time.Minute,
	}
	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil {
			return
		}

		// Fetch disk space info, ignore errors
		metrics = make([]Metric, 0, 10)
		storageInfo := objLayer.StorageInfo(ctx)
		onlineDrives, offlineDrives := getOnlineOfflineDisksStats(storageInfo.Disks)
		totalDrives := onlineDrives.Merge(offlineDrives)

		metrics = append(metrics, Metric{
			Description: getClusterCapacityTotalBytesMD(),
			Value:       float64(GetTotalCapacity(storageInfo.Disks)),
		})

		metrics = append(metrics, Metric{
			Description: getClusterCapacityFreeBytesMD(),
			Value:       float64(GetTotalCapacityFree(storageInfo.Disks)),
		})

		metrics = append(metrics, Metric{
			Description: getClusterCapacityUsageBytesMD(),
			Value:       float64(GetTotalUsableCapacity(storageInfo.Disks, storageInfo)),
		})

		metrics = append(metrics, Metric{
			Description: getClusterCapacityUsageFreeBytesMD(),
			Value:       float64(GetTotalUsableCapacityFree(storageInfo.Disks, storageInfo)),
		})

		metrics = append(metrics, Metric{
			Description: getClusterDrivesOfflineTotalMD(),
			Value:       float64(offlineDrives.Sum()),
		})

		metrics = append(metrics, Metric{
			Description: getClusterDrivesOnlineTotalMD(),
			Value:       float64(onlineDrives.Sum()),
		})

		metrics = append(metrics, Metric{
			Description: getClusterDrivesTotalMD(),
			Value:       float64(totalDrives.Sum()),
		})
		return
	})
	return mg
}

func getKMSNodeMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}

	mg.RegisterRead(func(ctx context.Context) (metrics []Metric) {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil || GlobalKMS == nil {
			return
		}

		const (
			Online  = 1
			Offline = 0
		)
		desc := MetricDescription{
			Namespace: clusterMetricNamespace,
			Subsystem: kmsSubsystem,
			Name:      kmsOnline,
			Help:      "Reports whether the KMS is online (1) or offline (0)",
			Type:      gaugeMetric,
		}
		_, err := GlobalKMS.Metrics(ctx)
		if _, ok := kes.IsConnError(err); ok {
			return []Metric{{
				Description: desc,
				Value:       float64(Offline),
			}}
		}
		return []Metric{{
			Description: desc,
			Value:       float64(Online),
		}}
	})
	return mg
}

func getKMSMetrics() *MetricsGroup {
	mg := &MetricsGroup{
		cacheInterval: 10 * time.Second,
	}

	mg.RegisterRead(func(ctx context.Context) []Metric {
		objLayer := newObjectLayerFn()
		// Service not initialized yet
		if objLayer == nil || GlobalKMS == nil {
			return []Metric{}
		}

		metrics := make([]Metric, 0, 4)
		metric, err := GlobalKMS.Metrics(ctx)
		if err != nil {
			return metrics
		}
		metrics = append(metrics, Metric{
			Description: MetricDescription{
				Namespace: clusterMetricNamespace,
				Subsystem: kmsSubsystem,
				Name:      kmsRequestsSuccess,
				Help:      "Number of KMS requests that succeeded",
				Type:      counterMetric,
			},
			Value: float64(metric.RequestOK),
		})
		metrics = append(metrics, Metric{
			Description: MetricDescription{
				Namespace: clusterMetricNamespace,
				Subsystem: kmsSubsystem,
				Name:      kmsRequestsError,
				Help:      "Number of KMS requests that failed due to some error. (HTTP 4xx status code)",
				Type:      counterMetric,
			},
			Value: float64(metric.RequestErr),
		})
		metrics = append(metrics, Metric{
			Description: MetricDescription{
				Namespace: clusterMetricNamespace,
				Subsystem: kmsSubsystem,
				Name:      kmsRequestsFail,
				Help:      "Number of KMS requests that failed due to some internal failure. (HTTP 5xx status code)",
				Type:      counterMetric,
			},
			Value: float64(metric.RequestFail),
		})
		metrics = append(metrics, Metric{
			Description: MetricDescription{
				Namespace: clusterMetricNamespace,
				Subsystem: kmsSubsystem,
				Name:      kmsUptime,
				Help:      "The time the KMS has been up and running in seconds.",
				Type:      counterMetric,
			},
			Value: metric.UpTime.Seconds(),
		})

		return metrics
	})
	return mg
}

type minioClusterCollector struct {
	metricsGroups []*MetricsGroup
	desc          *prometheus.Desc
}

func newMinioClusterCollector(metricsGroups []*MetricsGroup) *minioClusterCollector {
	return &minioClusterCollector{
		metricsGroups: metricsGroups,
		desc:          prometheus.NewDesc("minio_stats", "Statistics exposed by MinIO server per cluster", nil, nil),
	}
}

// Describe sends the super-set of all possible descriptors of metrics
func (c *minioClusterCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// Collect is called by the Prometheus registry when collecting metrics.
func (c *minioClusterCollector) Collect(out chan<- prometheus.Metric) {
	var wg sync.WaitGroup
	publish := func(in <-chan Metric) {
		defer wg.Done()
		for metric := range in {
			labels, values := getOrderedLabelValueArrays(metric.VariableLabels)
			if metric.Description.Type == histogramMetric {
				if metric.Histogram == nil {
					continue
				}
				for k, v := range metric.Histogram {
					out <- prometheus.MustNewConstMetric(
						prometheus.NewDesc(
							prometheus.BuildFQName(string(metric.Description.Namespace),
								string(metric.Description.Subsystem),
								string(metric.Description.Name)),
							metric.Description.Help,
							append(labels, metric.HistogramBucketLabel),
							metric.StaticLabels,
						),
						prometheus.GaugeValue,
						float64(v),
						append(values, k)...)
				}
				continue
			}
			metricType := prometheus.GaugeValue
			if metric.Description.Type == counterMetric {
				metricType = prometheus.CounterValue
			}
			toPost := prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(string(metric.Description.Namespace),
						string(metric.Description.Subsystem),
						string(metric.Description.Name)),
					metric.Description.Help,
					labels,
					metric.StaticLabels,
				),
				metricType,
				metric.Value,
				values...)
			out <- toPost
		}
	}

	// Call peer api to fetch metrics
	wg.Add(2)
	go publish(ReportMetrics(GlobalContext, c.metricsGroups))
	go publish(globalNotificationSys.GetClusterMetrics(GlobalContext))
	wg.Wait()
}

// ReportMetrics reports serialized metrics to the channel passed for the metrics generated.
func ReportMetrics(ctx context.Context, metricsGroups []*MetricsGroup) <-chan Metric {
	ch := make(chan Metric)
	go func() {
		defer close(ch)
		populateAndPublish(metricsGroups, func(m Metric) bool {
			if m.VariableLabels == nil {
				m.VariableLabels = make(map[string]string)
			}
			m.VariableLabels[serverName] = globalLocalNodeName
			for {
				select {
				case ch <- m:
					return true
				case <-ctx.Done():
					return false
				}
			}
		})
	}()
	return ch
}

// minioNodeCollector is the Custom Collector
type minioNodeCollector struct {
	metricsGroups []*MetricsGroup
	desc          *prometheus.Desc
}

// Describe sends the super-set of all possible descriptors of metrics
func (c *minioNodeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

// populateAndPublish populates and then publishes the metrics generated by the generator function.
func populateAndPublish(metricsGroups []*MetricsGroup, publish func(m Metric) bool) {
	for _, mg := range metricsGroups {
		if mg == nil {
			continue
		}
		for _, metric := range mg.Get() {
			if !publish(metric) {
				return
			}
		}
	}
}

// Collect is called by the Prometheus registry when collecting metrics.
func (c *minioNodeCollector) Collect(ch chan<- prometheus.Metric) {
	// Expose MinIO's version information
	minioVersionInfo.WithLabelValues(Version, CommitID).Set(1.0)

	populateAndPublish(c.metricsGroups, func(metric Metric) bool {
		labels, values := getOrderedLabelValueArrays(metric.VariableLabels)
		values = append(values, globalLocalNodeName)
		labels = append(labels, serverName)

		if metric.Description.Type == histogramMetric {
			if metric.Histogram == nil {
				return true
			}
			for k, v := range metric.Histogram {
				labels = append(labels, metric.HistogramBucketLabel)
				values = append(values, k)
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(string(metric.Description.Namespace),
							string(metric.Description.Subsystem),
							string(metric.Description.Name)),
						metric.Description.Help,
						labels,
						metric.StaticLabels,
					),
					prometheus.GaugeValue,
					float64(v),
					values...)
			}
			return true
		}

		metricType := prometheus.GaugeValue
		if metric.Description.Type == counterMetric {
			metricType = prometheus.CounterValue
		}
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(
				prometheus.BuildFQName(string(metric.Description.Namespace),
					string(metric.Description.Subsystem),
					string(metric.Description.Name)),
				metric.Description.Help,
				labels,
				metric.StaticLabels,
			),
			metricType,
			metric.Value,
			values...)
		return true
	})
}

func getOrderedLabelValueArrays(labelsWithValue map[string]string) (labels, values []string) {
	labels = make([]string, 0)
	values = make([]string, 0)
	for l, v := range labelsWithValue {
		labels = append(labels, l)
		values = append(values, v)
	}
	return
}

// newMinioCollectorNode describes the collector
// and returns reference of minioCollector for version 2
// It creates the Prometheus Description which is used
// to define Metric and  help string
func newMinioCollectorNode(metricsGroups []*MetricsGroup) *minioNodeCollector {
	return &minioNodeCollector{
		metricsGroups: metricsGroups,
		desc:          prometheus.NewDesc("minio_stats", "Statistics exposed by MinIO server per node", nil, nil),
	}
}

func metricsServerHandler() http.Handler {
	registry := prometheus.NewRegistry()

	// Report all other metrics
	logger.CriticalIf(GlobalContext, registry.Register(clusterCollector))

	// DefaultGatherers include golang metrics and process metrics.
	gatherers := prometheus.Gatherers{
		registry,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, ok := r.Context().Value(mcontext.ContextTraceKey).(*mcontext.TraceCtxt)
		if ok {
			tc.FuncName = "handler.MetricsCluster"
			tc.ResponseRecorder.LogErrBody = true
		}

		mfs, err := gatherers.Gather()
		if err != nil {
			if len(mfs) == 0 {
				writeErrorResponseJSON(r.Context(), w, toAdminAPIErr(r.Context(), err), r.URL)
				return
			}
		}

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))

		enc := expfmt.NewEncoder(w, contentType)
		for _, mf := range mfs {
			if err := enc.Encode(mf); err != nil {
				// client may disconnect for any reasons
				// we do not have to log this.
				return
			}
		}
		if closer, ok := enc.(expfmt.Closer); ok {
			closer.Close()
		}
	})
}

func metricsNodeHandler() http.Handler {
	registry := prometheus.NewRegistry()

	logger.CriticalIf(GlobalContext, registry.Register(nodeCollector))
	if err := registry.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
		Namespace:    minioNamespace,
		ReportErrors: true,
	})); err != nil {
		logger.CriticalIf(GlobalContext, err)
	}
	if err := registry.Register(prometheus.NewGoCollector()); err != nil {
		logger.CriticalIf(GlobalContext, err)
	}
	gatherers := prometheus.Gatherers{
		registry,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, ok := r.Context().Value(mcontext.ContextTraceKey).(*mcontext.TraceCtxt)
		if ok {
			tc.FuncName = "handler.MetricsNode"
			tc.ResponseRecorder.LogErrBody = true
		}

		mfs, err := gatherers.Gather()
		if err != nil {
			if len(mfs) == 0 {
				writeErrorResponseJSON(r.Context(), w, toAdminAPIErr(r.Context(), err), r.URL)
				return
			}
		}

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))

		enc := expfmt.NewEncoder(w, contentType)
		for _, mf := range mfs {
			if err := enc.Encode(mf); err != nil {
				logger.LogIf(r.Context(), err)
				return
			}
		}
		if closer, ok := enc.(expfmt.Closer); ok {
			closer.Close()
		}
	})
}

func toSnake(camel string) (snake string) {
	var b strings.Builder
	l := len(camel)
	for i, v := range camel {
		// A is 65, a is 97
		if v >= 'a' {
			b.WriteRune(v)
			continue
		}
		// v is capital letter here
		// disregard first letter
		// add underscore if last letter is capital letter
		// add underscore when previous letter is lowercase
		// add underscore when next letter is lowercase
		if (i != 0 || i == l-1) && ((i > 0 && rune(camel[i-1]) >= 'a') ||
			(i < l-1 && rune(camel[i+1]) >= 'a')) {
			b.WriteRune('_')
		}
		b.WriteRune(v + 'a' - 'A')
	}
	return b.String()
}
