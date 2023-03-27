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
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/logger"
)

const (
	mrfInfoResetInterval = 10 * time.Second
	mrfOpsQueueSize      = 10000
)

// partialOperation is a successful upload/delete of an object
// but not written in all disks (having quorum)
type partialOperation struct {
	bucket    string
	object    string
	versionID string
	size      int64
	setIndex  int
	poolIndex int
}

type setInfo struct {
	index, pool int
}

// mrfState sncapsulates all the information
// related to the global background MRF.
type mrfState struct {
	ready int32 // ref: https://golang.org/pkg/sync/atomic/#pkg-note-BUG
	_     int32 // For 64 bits alignment

	ctx       context.Context
	objectAPI ObjectLayer

	mu                sync.Mutex
	opCh              chan partialOperation
	pendingOps        map[partialOperation]setInfo
	setReconnectEvent chan setInfo

	itemsHealed  uint64
	bytesHealed  uint64
	pendingItems uint64
	pendingBytes uint64

	triggeredAt time.Time
}

// Initialize healing MRF subsystem
func (m *mrfState) init(ctx context.Context, objAPI ObjectLayer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ctx = ctx
	m.objectAPI = objAPI
	m.opCh = make(chan partialOperation, mrfOpsQueueSize)
	m.pendingOps = make(map[partialOperation]setInfo)
	m.setReconnectEvent = make(chan setInfo)

	go globalMRFState.maintainMRFList()
	go globalMRFState.healRoutine()

	atomic.StoreInt32(&m.ready, 1)
}

func (m *mrfState) initialized() bool {
	return atomic.LoadInt32(&m.ready) != 0
}

// Add a partial S3 operation (put/delete) when one or more disks are offline.
func (m *mrfState) addPartialOp(op partialOperation) {
	if !m.initialized() {
		return
	}

	select {
	case m.opCh <- op:
	default:
	}
}

// Receive the new set (disk) reconnection event
func (m *mrfState) newSetReconnected(pool, set int) {
	if !m.initialized() {
		return
	}

	idler := time.NewTimer(100 * time.Millisecond)
	defer idler.Stop()

	select {
	case m.setReconnectEvent <- setInfo{index: set, pool: pool}:
	case <-idler.C:
	}
}

// Get current MRF stats of the last MRF activity
func (m *mrfState) getCurrentMRFRoundInfo() madmin.MRFStatus {
	m.mu.Lock()
	triggeredAt := m.triggeredAt
	itemsHealed := m.itemsHealed
	bytesHealed := m.bytesHealed
	pendingItems := m.pendingItems
	pendingBytes := m.pendingBytes
	m.mu.Unlock()

	if pendingItems == 0 {
		return madmin.MRFStatus{}
	}

	return madmin.MRFStatus{
		Started:     triggeredAt,
		ItemsHealed: itemsHealed,
		BytesHealed: bytesHealed,
		TotalItems:  itemsHealed + pendingItems,
		TotalBytes:  bytesHealed + pendingBytes,
	}
}

// maintainMRFList gathers the list of successful partial uploads
// from all underlying er.sets and puts them in a global map which
// should not have more than 10000 entries.
func (m *mrfState) maintainMRFList() {
	for fOp := range m.opCh {
		m.mu.Lock()
		if len(m.pendingOps) > mrfOpsQueueSize {
			m.mu.Unlock()
			continue
		}

		m.pendingOps[fOp] = setInfo{index: fOp.setIndex, pool: fOp.poolIndex}
		m.pendingItems++
		if fOp.size > 0 {
			m.pendingBytes += uint64(fOp.size)
		}

		m.mu.Unlock()
	}
}

// Reset current MRF stats
func (m *mrfState) resetMRFInfoIfNoPendingOps() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pendingItems > 0 {
		return
	}

	m.itemsHealed = 0
	m.bytesHealed = 0
	m.pendingItems = 0
	m.pendingBytes = 0
	m.triggeredAt = time.Time{}
}

// healRoutine listens to new disks reconnection events and
// issues healing requests for queued objects belonging to the
// corresponding erasure set
func (m *mrfState) healRoutine() {
	idler := time.NewTimer(mrfInfoResetInterval)
	defer idler.Stop()

	mrfHealingOpts := madmin.HealOpts{
		ScanMode: madmin.HealNormalScan,
		Remove:   healDeleteDangling,
	}

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-idler.C:
			m.resetMRFInfoIfNoPendingOps()
			idler.Reset(mrfInfoResetInterval)
		case setInfo := <-m.setReconnectEvent:
			// Get the list of objects related the er.set
			// to which the connected disk belongs.
			var mrfOperations []partialOperation
			m.mu.Lock()
			for k, v := range m.pendingOps {
				if v == setInfo {
					mrfOperations = append(mrfOperations, k)
				}
			}
			m.mu.Unlock()

			if len(mrfOperations) == 0 {
				continue
			}

			m.mu.Lock()
			m.triggeredAt = time.Now().UTC()
			m.mu.Unlock()

			// Heal objects
			for _, u := range mrfOperations {
				_, err := m.objectAPI.HealObject(m.ctx, u.bucket, u.object, u.versionID, mrfHealingOpts)
				m.mu.Lock()
				if err == nil {
					m.itemsHealed++
					m.bytesHealed += uint64(u.size)
				}
				m.pendingItems--
				m.pendingBytes -= uint64(u.size)
				delete(m.pendingOps, u)
				m.mu.Unlock()

				if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
					// Log healing error if any
					logger.LogIf(m.ctx, err)
				}
			}

			waitForLowHTTPReq()
		}
	}
}

// Initialize healing MRF
func initHealMRF(ctx context.Context, obj ObjectLayer) {
	globalMRFState.init(ctx, obj)
}
