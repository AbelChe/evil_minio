#!/bin/bash -e
#

set -E
set -o pipefail
set -x

if [ ! -x "$PWD/minio" ]; then
    echo "minio executable binary not found in current directory"
    exit 1
fi

WORK_DIR="$PWD/.verify-$RANDOM"
MINIO_CONFIG_DIR="$WORK_DIR/.minio"
MINIO_OLD=( "$PWD/minio.RELEASE.2021-11-24T23-19-33Z" --config-dir "$MINIO_CONFIG_DIR" server )
MINIO=( "$PWD/minio" --config-dir "$MINIO_CONFIG_DIR" server )

function download_old_release() {
    if [ ! -f minio.RELEASE.2021-11-24T23-19-33Z ]; then
	curl --silent -O https://dl.minio.io/server/minio/release/linux-amd64/archive/minio.RELEASE.2021-11-24T23-19-33Z
	chmod a+x minio.RELEASE.2021-11-24T23-19-33Z
    fi
}

function start_minio_16drive() {
    start_port=$1

    export MINIO_ROOT_USER=minio
    export MINIO_ROOT_PASSWORD=minio123
    export MC_HOST_minio="http://minio:minio123@127.0.0.1:${start_port}/"
    unset MINIO_KMS_AUTO_ENCRYPTION # do not auto-encrypt objects
    export _MINIO_SHARD_DISKTIME_DELTA="5s" # do not change this as its needed for tests
    export MINIO_CI_CD=1

    MC_BUILD_DIR="mc-$RANDOM"
    if ! git clone --quiet https://github.com/minio/mc "$MC_BUILD_DIR"; then
	echo "failed to download https://github.com/minio/mc"
	purge "${MC_BUILD_DIR}"
	exit 1
    fi

    (cd "${MC_BUILD_DIR}" && go build -o "$WORK_DIR/mc")

    # remove mc source.
    purge "${MC_BUILD_DIR}"

    "${MINIO_OLD[@]}" --address ":$start_port" "${WORK_DIR}/xl{1...16}" > "${WORK_DIR}/server1.log" 2>&1 &
    pid=$!
    disown $pid
    sleep 30

    if ! ps -p ${pid} 1>&2 >/dev/null; then
	echo "server1 log:"
	cat "${WORK_DIR}/server1.log"
	echo "FAILED"
	purge "$WORK_DIR"
	exit 1
    fi

    shred --iterations=1 --size=5241856 - 1>"${WORK_DIR}/unaligned" 2>/dev/null
    "${WORK_DIR}/mc" mb minio/healing-shard-bucket --quiet
    "${WORK_DIR}/mc" cp \
		     "${WORK_DIR}/unaligned" \
		     minio/healing-shard-bucket/unaligned \
		     --disable-multipart --quiet

    ## "unaligned" object name gets consistently distributed
    ## to disks in following distribution order
    ##
    ## NOTE: if you change the name make sure to change the
    ## distribution order present here
    ##
    ## [15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

    ## make sure to remove the "last" data shard
    rm -rf "${WORK_DIR}/xl14/healing-shard-bucket/unaligned"
    sleep 10
    ## Heal the shard
    "${WORK_DIR}/mc" admin heal --quiet --recursive minio/healing-shard-bucket
    ## then remove any other data shard let's pick first disk
    ## - 1st data shard.
    rm -rf "${WORK_DIR}/xl3/healing-shard-bucket/unaligned"
    sleep 10

    go build ./docs/debugging/s3-check-md5/
    if ! ./s3-check-md5 \
	 -debug \
	 -access-key minio \
	 -secret-key minio123 \
	 -endpoint http://127.0.0.1:${start_port}/ 2>&1 | grep CORRUPTED; then
	echo "server1 log:"
	cat "${WORK_DIR}/server1.log"
	echo "FAILED"
	purge "$WORK_DIR"
	exit 1
    fi

    pkill minio
    sleep 3

    "${MINIO[@]}" --address ":$start_port" "${WORK_DIR}/xl{1...16}" > "${WORK_DIR}/server1.log" 2>&1 &
    pid=$!
    disown $pid
    sleep 30

    if ! ps -p ${pid} 1>&2 >/dev/null; then
	echo "server1 log:"
	cat "${WORK_DIR}/server1.log"
	echo "FAILED"
	purge "$WORK_DIR"
	exit 1
    fi

    if ! ./s3-check-md5 \
	 -debug \
	 -access-key minio \
	 -secret-key minio123 \
	 -endpoint http://127.0.0.1:${start_port}/ 2>&1 | grep INTACT; then
	echo "server1 log:"
	cat "${WORK_DIR}/server1.log"
	echo "FAILED"
	mkdir -p inspects
	(cd inspects; "${WORK_DIR}/mc" support inspect minio/healing-shard-bucket/unaligned/**)

	"${WORK_DIR}/mc" mb play/inspects
	"${WORK_DIR}/mc" mirror inspects play/inspects

	purge "$WORK_DIR"
	exit 1
    fi

    "${WORK_DIR}/mc" admin heal --quiet --recursive minio/healing-shard-bucket

    if ! ./s3-check-md5 \
	 -debug \
	 -access-key minio \
	 -secret-key minio123 \
	 -endpoint http://127.0.0.1:${start_port}/ 2>&1 | grep INTACT; then
	echo "server1 log:"
	cat "${WORK_DIR}/server1.log"
	echo "FAILED"
	mkdir -p inspects
	(cd inspects; "${WORK_DIR}/mc" support inspect minio/healing-shard-bucket/unaligned/**)

	"${WORK_DIR}/mc" mb play/inspects
	"${WORK_DIR}/mc" mirror inspects play/inspects

	purge "$WORK_DIR"
	exit 1
    fi

    pkill minio
    sleep 3
}

function main() {
    download_old_release

    start_port=$(shuf -i 10000-65000 -n 1)

    start_minio_16drive ${start_port}
}

function purge()
{
    rm -rf "$1"
}

( main "$@" )
rv=$?
purge "$WORK_DIR"
exit "$rv"
