# MinIO Server Limits Per Tenant

For best deployment experience MinIO recommends operating systems RHEL/CentOS 8.x or later, Ubuntu 18.04 LTS or later. These operating systems package the latest 'xfsprogs' that support large scale deployments.

## Erasure Code (Multiple Drives / Servers)

| Item                                                            | Specification |
|:----------------------------------------------------------------|:--------------|
| Maximum number of servers per cluster                           | no-limit      |
| Minimum number of servers                                       | 02            |
| Minimum number of drives per server when server count is 1      | 02            |
| Minimum number of drives per server when server count is 2 or 3 | 01            |
| Minimum number of drives per server when server count is 4      | 01            |
| Maximum number of drives per server                             | no-limit      |
| Read quorum                                                     | N/2           |
| Write quorum                                                    | N/2+1         |

## Limits of S3 API

| Item                                                                            | Specification                                   |
|:--------------------------------------------------------------------------------|:------------------------------------------------|
| Maximum number of buckets                                                       | unlimited (recommend not beyond 500000 buckets) |
| Maximum number of objects per bucket                                            | no-limit                                        |
| Maximum object size                                                             | 50 TiB                                          |
| Minimum object size                                                             | 0 B                                             |
| Maximum object size per PUT operation                                           | 5 TiB                                           |
| Maximum number of parts per upload                                              | 10,000                                          |
| Part size range                                                                 | 5 MiB to 5 GiB. Last part can be 0 B to 5 GiB   |
| Maximum number of parts returned per list parts request                         | 10000                                           |
| Maximum number of objects returned per list objects request                     | 1000                                            |
| Maximum number of multipart uploads returned per list multipart uploads request | 1000                                            |
| Maximum length for bucket names                                                 | 63                                              |
| Maximum length for object names                                                 | 1024                                            |
| Maximum length for '/' separated object name segment                            | 255                                             |

## List of Amazon S3 API's not supported on MinIO

We found the following APIs to be redundant or less useful outside of AWS S3. If you have a different view on any of the APIs we missed, please open a [GitHub issue](https://github.com/minio/minio/issues).

### List of Amazon S3 Bucket API's not supported on MinIO

- BucketACL (Use [bucket policies](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html) instead)
- BucketCORS (CORS enabled by default on all buckets for all HTTP verbs)
- BucketWebsite (Use [`caddy`](https://github.com/caddyserver/caddy) or [`nginx`](https://www.nginx.com/resources/wiki/))
- BucketAnalytics, BucketMetrics, BucketLogging (Use [bucket notification](https://min.io/docs/minio/linux/administration/monitoring/bucket-notifications.html) APIs)
- BucketRequestPayment

### List of Amazon S3 Object API's not supported on MinIO

- ObjectACL (Use [bucket policies](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html) instead)

## Object name restrictions on MinIO

- Object name restrictions on MinIO are governed by OS and filesystem limitations. For example object names that contain characters `^*|\/&";` are unsupported on Windows platform or any other file systems that do not support filenames with special charaters.

> **This list is non exhaustive, it depends on the operating system and filesystem under use - please consult your operating system vendor for a more comprehensiv list**.

MinIO recommends using Linux operating system for for production workloads.

- Objects must not have conflicting objects as parent objects, applications using this behavior should change their behavior and use non-conflicting unique keys, for example situations such as following conflicting key patterns are not supported.

```
PUT <bucketname>/a/b/1.txt
PUT <bucketname>/a/b
```

```
PUT <bucketname>/a/b
PUT <bucketname>/a/b/1.txt
```
