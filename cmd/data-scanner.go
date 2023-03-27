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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/minio/madmin-go/v2"
	"github.com/minio/minio/internal/bucket/lifecycle"
	"github.com/minio/minio/internal/bucket/object/lock"
	"github.com/minio/minio/internal/bucket/replication"
	"github.com/minio/minio/internal/color"
	"github.com/minio/minio/internal/config/heal"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/console"
	uatomic "go.uber.org/atomic"
)

const (
	dataScannerSleepPerFolder        = time.Millisecond                 // Time to wait between folders.
	dataUsageUpdateDirCycles         = 16                               // Visit all folders every n cycles.
	dataScannerCompactLeastObject    = 500                              // Compact when there is less than this many objects in a branch.
	dataScannerCompactAtChildren     = 10000                            // Compact when there are this many children in a branch.
	dataScannerCompactAtFolders      = dataScannerCompactAtChildren / 4 // Compact when this many subfolders in a single folder.
	dataScannerForceCompactAtFolders = 1_000_000                        // Compact when this many subfolders in a single folder (even top level).
	dataScannerStartDelay            = 1 * time.Minute                  // Time to wait on startup and between cycles.

	healDeleteDangling    = true
	healFolderIncludeProb = 32  // Include a clean folder one in n cycles.
	healObjectSelectProb  = 512 // Overall probability of a file being scanned; one in n.

	dataScannerExcessiveVersionsThreshold = 1000  // Issue a warning when a single object has more versions than this
	dataScannerExcessiveFoldersThreshold  = 50000 // Issue a warning when a folder has more subfolders than this in a *set*
)

var (
	globalHealConfig heal.Config

	// Sleeper values are updated when config is loaded.
	scannerSleeper = newDynamicSleeper(10, 10*time.Second, true)
	scannerCycle   = uatomic.NewDuration(dataScannerStartDelay)
)

// initDataScanner will start the scanner in the background.
func initDataScanner(ctx context.Context, objAPI ObjectLayer) {
	go func() {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		// Run the data scanner in a loop
		for {
			runDataScanner(ctx, objAPI)
			duration := time.Duration(r.Float64() * float64(scannerCycle.Load()))
			if duration < time.Second {
				// Make sure to sleep atleast a second to avoid high CPU ticks.
				duration = time.Second
			}
			time.Sleep(duration)
		}
	}()
}

func getCycleScanMode(currentCycle, bitrotStartCycle uint64, bitrotStartTime time.Time) madmin.HealScanMode {
	bitrotCycle := globalHealConfig.BitrotScanCycle()
	switch bitrotCycle {
	case -1:
		return madmin.HealNormalScan
	case 0:
		return madmin.HealDeepScan
	}

	if currentCycle-bitrotStartCycle < healObjectSelectProb {
		return madmin.HealDeepScan
	}

	if time.Since(bitrotStartTime) > bitrotCycle {
		return madmin.HealDeepScan
	}

	return madmin.HealNormalScan
}

type backgroundHealInfo struct {
	BitrotStartTime  time.Time           `json:"bitrotStartTime"`
	BitrotStartCycle uint64              `json:"bitrotStartCycle"`
	CurrentScanMode  madmin.HealScanMode `json:"currentScanMode"`
}

func readBackgroundHealInfo(ctx context.Context, objAPI ObjectLayer) backgroundHealInfo {
	if globalIsErasureSD {
		return backgroundHealInfo{}
	}

	// Get last healing information
	buf, err := readConfig(ctx, objAPI, backgroundHealInfoPath)
	if err != nil {
		if !errors.Is(err, errConfigNotFound) {
			logger.LogIf(ctx, err)
		}
		return backgroundHealInfo{}
	}
	var info backgroundHealInfo
	if err = json.Unmarshal(buf, &info); err != nil {
		logger.LogIf(ctx, err)
	}
	return info
}

func saveBackgroundHealInfo(ctx context.Context, objAPI ObjectLayer, info backgroundHealInfo) {
	if globalIsErasureSD {
		return
	}

	b, err := json.Marshal(info)
	if err != nil {
		logger.LogIf(ctx, err)
		return
	}
	// Get last healing information
	err = saveConfig(ctx, objAPI, backgroundHealInfoPath, b)
	if err != nil {
		logger.LogIf(ctx, err)
	}
}

// runDataScanner will start a data scanner.
// The function will block until the context is canceled.
// There should only ever be one scanner running per cluster.
func runDataScanner(ctx context.Context, objAPI ObjectLayer) {
	ctx, cancel := globalLeaderLock.GetLock(ctx)
	defer cancel()

	// Load current bloom cycle
	var cycleInfo currentScannerCycle

	buf, _ := readConfig(ctx, objAPI, dataUsageBloomNamePath)
	if len(buf) == 8 {
		cycleInfo.next = binary.LittleEndian.Uint64(buf)
	} else if len(buf) > 8 {
		cycleInfo.next = binary.LittleEndian.Uint64(buf[:8])
		buf = buf[8:]
		_, err := cycleInfo.UnmarshalMsg(buf)
		logger.LogIf(ctx, err)
	}

	scannerTimer := time.NewTimer(scannerCycle.Load())
	defer scannerTimer.Stop()
	defer globalScannerMetrics.setCycle(nil)

	for {
		select {
		case <-ctx.Done():
			return
		case <-scannerTimer.C:
			// Reset the timer for next cycle.
			// If scanner takes longer we start at once.
			scannerTimer.Reset(scannerCycle.Load())

			stopFn := globalScannerMetrics.log(scannerMetricScanCycle)
			cycleInfo.current = cycleInfo.next
			cycleInfo.started = time.Now()
			globalScannerMetrics.setCycle(&cycleInfo)

			bgHealInfo := readBackgroundHealInfo(ctx, objAPI)
			scanMode := getCycleScanMode(cycleInfo.current, bgHealInfo.BitrotStartCycle, bgHealInfo.BitrotStartTime)
			if bgHealInfo.CurrentScanMode != scanMode {
				newHealInfo := bgHealInfo
				newHealInfo.CurrentScanMode = scanMode
				if scanMode == madmin.HealDeepScan {
					newHealInfo.BitrotStartTime = time.Now().UTC()
					newHealInfo.BitrotStartCycle = cycleInfo.current
				}
				saveBackgroundHealInfo(ctx, objAPI, newHealInfo)
			}

			// Wait before starting next cycle and wait on startup.
			results := make(chan DataUsageInfo, 1)
			go storeDataUsageInBackend(ctx, objAPI, results)
			err := objAPI.NSScanner(ctx, results, uint32(cycleInfo.current), scanMode)
			logger.LogIf(ctx, err)
			res := map[string]string{"cycle": fmt.Sprint(cycleInfo.current)}
			if err != nil {
				res["error"] = err.Error()
			}
			stopFn(res)
			if err == nil {
				// Store new cycle...
				cycleInfo.next++
				cycleInfo.current = 0
				cycleInfo.cycleCompleted = append(cycleInfo.cycleCompleted, time.Now())
				if len(cycleInfo.cycleCompleted) > dataUsageUpdateDirCycles {
					cycleInfo.cycleCompleted = cycleInfo.cycleCompleted[len(cycleInfo.cycleCompleted)-dataUsageUpdateDirCycles:]
				}
				globalScannerMetrics.setCycle(&cycleInfo)
				tmp := make([]byte, 8, 8+cycleInfo.Msgsize())
				// Cycle for backward compat.
				binary.LittleEndian.PutUint64(tmp, cycleInfo.next)
				tmp, _ = cycleInfo.MarshalMsg(tmp)
				err = saveConfig(ctx, objAPI, dataUsageBloomNamePath, tmp)
				logger.LogIf(ctx, err)
			}
		}
	}
}

type cachedFolder struct {
	name              string
	parent            *dataUsageHash
	objectHealProbDiv uint32
}

type folderScanner struct {
	root        string
	getSize     getSizeFn
	oldCache    dataUsageCache
	newCache    dataUsageCache
	updateCache dataUsageCache

	dataUsageScannerDebug bool
	healObjectSelect      uint32 // Do a heal check on an object once every n cycles. Must divide into healFolderInclude
	scanMode              madmin.HealScanMode

	disks       []StorageAPI
	disksQuorum int

	// If set updates will be sent regularly to this channel.
	// Will not be closed when returned.
	updates    chan<- dataUsageEntry
	lastUpdate time.Time

	// updateCurrentPath should be called whenever a new path is scanned.
	updateCurrentPath func(string)
}

// Cache structure and compaction:
//
// A cache structure will be kept with a tree of usages.
// The cache is a tree structure where each keeps track of its children.
//
// An uncompacted branch contains a count of the files only directly at the
// branch level, and contains link to children branches or leaves.
//
// The leaves are "compacted" based on a number of properties.
// A compacted leaf contains the totals of all files beneath it.
//
// A leaf is only scanned once every dataUsageUpdateDirCycles,
// rarer if the bloom filter for the path is clean and no lifecycles are applied.
// Skipped leaves have their totals transferred from the previous cycle.
//
// A clean leaf will be included once every healFolderIncludeProb for partial heal scans.
// When selected there is a one in healObjectSelectProb that any object will be chosen for heal scan.
//
// Compaction happens when either:
//
// 1) The folder (and subfolders) contains less than dataScannerCompactLeastObject objects.
// 2) The folder itself contains more than dataScannerCompactAtFolders folders.
// 3) The folder only contains objects and no subfolders.
//
// A bucket root will never be compacted.
//
// Furthermore if a has more than dataScannerCompactAtChildren recursive children (uncompacted folders)
// the tree will be recursively scanned and the branches with the least number of objects will be
// compacted until the limit is reached.
//
// This ensures that any branch will never contain an unreasonable amount of other branches,
// and also that small branches with few objects don't take up unreasonable amounts of space.
// This keeps the cache size at a reasonable size for all buckets.
//
// Whenever a branch is scanned, it is assumed that it will be un-compacted
// before it hits any of the above limits.
// This will make the branch rebalance itself when scanned if the distribution of objects has changed.

// scanDataFolder will scanner the basepath+cache.Info.Name and return an updated cache.
// The returned cache will always be valid, but may not be updated from the existing.
// Before each operation sleepDuration is called which can be used to temporarily halt the scanner.
// If the supplied context is canceled the function will return at the first chance.
func scanDataFolder(ctx context.Context, poolIdx, setIdx int, basePath string, cache dataUsageCache, getSize getSizeFn, scanMode madmin.HealScanMode) (dataUsageCache, error) {
	switch cache.Info.Name {
	case "", dataUsageRoot:
		return cache, errors.New("internal error: root scan attempted")
	}
	updatePath, closeDisk := globalScannerMetrics.currentPathUpdater(basePath, cache.Info.Name)
	defer closeDisk()

	s := folderScanner{
		root:                  basePath,
		getSize:               getSize,
		oldCache:              cache,
		newCache:              dataUsageCache{Info: cache.Info},
		updateCache:           dataUsageCache{Info: cache.Info},
		dataUsageScannerDebug: false,
		healObjectSelect:      0,
		scanMode:              scanMode,
		updates:               cache.Info.updates,
		updateCurrentPath:     updatePath,
	}

	// Add disks for set healing.
	if poolIdx >= 0 && setIdx >= 0 {
		objAPI, ok := newObjectLayerFn().(*erasureServerPools)
		if ok {
			if poolIdx < len(objAPI.serverPools) && setIdx < len(objAPI.serverPools[poolIdx].sets) {
				// Pass the disks belonging to the set.
				s.disks = objAPI.serverPools[poolIdx].sets[setIdx].getDisks()
				s.disksQuorum = len(s.disks) / 2
			} else {
				logger.LogIf(ctx, fmt.Errorf("Matching pool %s, set %s not found", humanize.Ordinal(poolIdx+1), humanize.Ordinal(setIdx+1)))
			}
		}
	}

	// Enable healing in XL mode.
	if globalIsErasure && !cache.Info.SkipHealing {
		// Do a heal check on an object once every n cycles. Must divide into healFolderInclude
		s.healObjectSelect = healObjectSelectProb
	}

	done := ctx.Done()

	// Read top level in bucket.
	select {
	case <-done:
		return cache, ctx.Err()
	default:
	}
	root := dataUsageEntry{}
	folder := cachedFolder{name: cache.Info.Name, objectHealProbDiv: 1}
	err := s.scanFolder(ctx, folder, &root)
	if err != nil {
		// No useful information...
		return cache, err
	}

	s.newCache.Info.LastUpdate = UTCNow()
	s.newCache.Info.NextCycle = cache.Info.NextCycle
	return s.newCache, nil
}

// sendUpdate() should be called on a regular basis when the newCache contains more recent total than previously.
// May or may not send an update upstream.
func (f *folderScanner) sendUpdate() {
	// Send at most an update every minute.
	if f.updates == nil || time.Since(f.lastUpdate) < time.Minute {
		return
	}
	if flat := f.updateCache.sizeRecursive(f.newCache.Info.Name); flat != nil {
		select {
		case f.updates <- *flat:
		default:
		}
		f.lastUpdate = time.Now()
	}
}

// scanFolder will scan the provided folder.
// Files found in the folders will be added to f.newCache.
// If final is provided folders will be put into f.newFolders or f.existingFolders.
// If final is not provided the folders found are returned from the function.
func (f *folderScanner) scanFolder(ctx context.Context, folder cachedFolder, into *dataUsageEntry) error {
	done := ctx.Done()
	scannerLogPrefix := color.Green("folder-scanner:")

	thisHash := hashPath(folder.name)
	// Store initial compaction state.
	wasCompacted := into.Compacted

	for {
		select {
		case <-done:
			return ctx.Err()
		default:
		}
		var abandonedChildren dataUsageHashMap
		if !into.Compacted {
			abandonedChildren = f.oldCache.findChildrenCopy(thisHash)
		}

		// If there are lifecycle rules for the prefix, remove the filter.
		_, prefix := path2BucketObjectWithBasePath(f.root, folder.name)
		var activeLifeCycle *lifecycle.Lifecycle
		if f.oldCache.Info.lifeCycle != nil && f.oldCache.Info.lifeCycle.HasActiveRules(prefix) {
			if f.dataUsageScannerDebug {
				console.Debugf(scannerLogPrefix+" Prefix %q has active rules\n", prefix)
			}
			activeLifeCycle = f.oldCache.Info.lifeCycle
		}
		// If there are replication rules for the prefix, remove the filter.
		var replicationCfg replicationConfig
		if !f.oldCache.Info.replication.Empty() && f.oldCache.Info.replication.Config.HasActiveRules(prefix, true) {
			replicationCfg = f.oldCache.Info.replication
		}
		// Check if we can skip it due to bloom filter...
		scannerSleeper.Sleep(ctx, dataScannerSleepPerFolder)

		var existingFolders, newFolders []cachedFolder
		var foundObjects bool
		err := readDirFn(path.Join(f.root, folder.name), func(entName string, typ os.FileMode) error {
			// Parse
			entName = pathClean(path.Join(folder.name, entName))
			if entName == "" || entName == folder.name {
				if f.dataUsageScannerDebug {
					console.Debugf(scannerLogPrefix+" no entity (%s,%s)\n", f.root, entName)
				}
				return nil
			}
			bucket, prefix := path2BucketObjectWithBasePath(f.root, entName)
			if bucket == "" {
				if f.dataUsageScannerDebug {
					console.Debugf(scannerLogPrefix+" no bucket (%s,%s)\n", f.root, entName)
				}
				return errDoneForNow
			}

			if isReservedOrInvalidBucket(bucket, false) {
				if f.dataUsageScannerDebug {
					console.Debugf(scannerLogPrefix+" invalid bucket: %v, entry: %v\n", bucket, entName)
				}
				return errDoneForNow
			}

			select {
			case <-done:
				return errDoneForNow
			default:
			}

			if typ&os.ModeDir != 0 {
				h := hashPath(entName)
				_, exists := f.oldCache.Cache[h.Key()]
				if h == thisHash {
					return nil
				}
				this := cachedFolder{name: entName, parent: &thisHash, objectHealProbDiv: folder.objectHealProbDiv}
				delete(abandonedChildren, h.Key()) // h.Key() already accounted for.
				if exists {
					existingFolders = append(existingFolders, this)
					f.updateCache.copyWithChildren(&f.oldCache, h, &thisHash)
				} else {
					newFolders = append(newFolders, this)
				}
				return nil
			}

			// Dynamic time delay.
			wait := scannerSleeper.Timer(ctx)

			// Get file size, ignore errors.
			item := scannerItem{
				Path:        path.Join(f.root, entName),
				Typ:         typ,
				bucket:      bucket,
				prefix:      path.Dir(prefix),
				objectName:  path.Base(entName),
				debug:       f.dataUsageScannerDebug,
				lifeCycle:   activeLifeCycle,
				replication: replicationCfg,
			}

			item.heal.enabled = thisHash.modAlt(f.oldCache.Info.NextCycle/folder.objectHealProbDiv, f.healObjectSelect/folder.objectHealProbDiv) && globalIsErasure
			item.heal.bitrot = f.scanMode == madmin.HealDeepScan

			// if the drive belongs to an erasure set
			// that is already being healed, skip the
			// healing attempt on this drive.
			item.heal.enabled = item.heal.enabled && f.healObjectSelect > 0

			sz, err := f.getSize(item)
			if err != nil {
				wait() // wait to proceed to next entry.
				if err != errSkipFile && f.dataUsageScannerDebug {
					console.Debugf(scannerLogPrefix+" getSize \"%v/%v\" returned err: %v\n", bucket, item.objectPath(), err)
				}
				return nil
			}

			// successfully read means we have a valid object.
			foundObjects = true
			// Remove filename i.e is the meta file to construct object name
			item.transformMetaDir()

			// Object already accounted for, remove from heal map,
			// simply because getSize() function already heals the
			// object.
			delete(abandonedChildren, path.Join(item.bucket, item.objectPath()))

			into.addSizes(sz)
			into.Objects++

			wait() // wait to proceed to next entry.

			return nil
		})
		if err != nil {
			return err
		}

		if foundObjects && globalIsErasure {
			// If we found an object in erasure mode, we skip subdirs (only datadirs)...
			break
		}

		// If we have many subfolders, compact ourself.
		shouldCompact := f.newCache.Info.Name != folder.name &&
			len(existingFolders)+len(newFolders) >= dataScannerCompactAtFolders ||
			len(existingFolders)+len(newFolders) >= dataScannerForceCompactAtFolders

		if len(existingFolders)+len(newFolders) > dataScannerExcessiveFoldersThreshold {
			// Notify object accessed via a GET request.
			sendEvent(eventArgs{
				EventName:  event.PrefixManyFolders,
				BucketName: f.root,
				Object: ObjectInfo{
					Name: strings.TrimSuffix(folder.name, "/") + "/",
					Size: int64(len(existingFolders) + len(newFolders)),
				},
				UserAgent: "scanner",
				Host:      globalMinioHost,
			})
		}
		if !into.Compacted && shouldCompact {
			into.Compacted = true
			newFolders = append(newFolders, existingFolders...)
			existingFolders = nil
			if f.dataUsageScannerDebug {
				console.Debugf(scannerLogPrefix+" Preemptively compacting: %v, entries: %v\n", folder.name, len(existingFolders)+len(newFolders))
			}
		}

		scanFolder := func(folder cachedFolder) {
			if contextCanceled(ctx) {
				return
			}
			dst := into
			if !into.Compacted {
				dst = &dataUsageEntry{Compacted: false}
			}
			if err := f.scanFolder(ctx, folder, dst); err != nil {
				logger.LogIf(ctx, err)
				return
			}
			if !into.Compacted {
				h := dataUsageHash(folder.name)
				into.addChild(h)
				// We scanned a folder, optionally send update.
				f.updateCache.deleteRecursive(h)
				f.updateCache.copyWithChildren(&f.newCache, h, folder.parent)
				f.sendUpdate()
			}
		}

		// Transfer existing
		if !into.Compacted {
			for _, folder := range existingFolders {
				h := hashPath(folder.name)
				f.updateCache.copyWithChildren(&f.oldCache, h, folder.parent)
			}
		}
		// Scan new...
		for _, folder := range newFolders {
			h := hashPath(folder.name)
			// Add new folders to the update tree so totals update for these.
			if !into.Compacted {
				var foundAny bool
				parent := thisHash
				for parent != hashPath(f.updateCache.Info.Name) {
					e := f.updateCache.find(parent.Key())
					if e == nil || e.Compacted {
						foundAny = true
						break
					}
					if next := f.updateCache.searchParent(parent); next == nil {
						foundAny = true
						break
					} else {
						parent = *next
					}
				}
				if !foundAny {
					// Add non-compacted empty entry.
					f.updateCache.replaceHashed(h, &thisHash, dataUsageEntry{})
				}
			}
			f.updateCurrentPath(folder.name)
			stopFn := globalScannerMetrics.log(scannerMetricScanFolder, f.root, folder.name)
			scanFolder(folder)
			stopFn(map[string]string{"type": "new"})

			// Add new folders if this is new and we don't have existing.
			if !into.Compacted {
				parent := f.updateCache.find(thisHash.Key())
				if parent != nil && !parent.Compacted {
					f.updateCache.deleteRecursive(h)
					f.updateCache.copyWithChildren(&f.newCache, h, &thisHash)
				}
			}
		}

		// Scan existing...
		for _, folder := range existingFolders {
			h := hashPath(folder.name)
			// Check if we should skip scanning folder...
			// We can only skip if we are not indexing into a compacted destination
			// and the entry itself is compacted.
			if !into.Compacted && f.oldCache.isCompacted(h) {
				if !h.mod(f.oldCache.Info.NextCycle, dataUsageUpdateDirCycles) {
					// Transfer and add as child...
					f.newCache.copyWithChildren(&f.oldCache, h, folder.parent)
					into.addChild(h)
					continue
				}
			}
			f.updateCurrentPath(folder.name)
			stopFn := globalScannerMetrics.log(scannerMetricScanFolder, f.root, folder.name)
			scanFolder(folder)
			stopFn(map[string]string{"type": "existing"})
		}

		// Scan for healing
		if f.healObjectSelect == 0 || len(abandonedChildren) == 0 {
			// If we are not heal scanning, return now.
			break
		}

		objAPI, ok := newObjectLayerFn().(*erasureServerPools)
		if !ok || len(f.disks) == 0 || f.disksQuorum == 0 {
			break
		}

		bgSeq, found := globalBackgroundHealState.getHealSequenceByToken(bgHealingUUID)
		if !found {
			break
		}

		// Whatever remains in 'abandonedChildren' are folders at this level
		// that existed in the previous run but wasn't found now.
		//
		// This may be because of 2 reasons:
		//
		// 1) The folder/object was deleted.
		// 2) We come from another disk and this disk missed the write.
		//
		// We therefore perform a heal check.
		// If that doesn't bring it back we remove the folder and assume it was deleted.
		// This means that the next run will not look for it.
		// How to resolve results.
		resolver := metadataResolutionParams{
			dirQuorum: f.disksQuorum,
			objQuorum: f.disksQuorum,
			bucket:    "",
			strict:    false,
		}

		healObjectsPrefix := color.Green("healObjects:")
		for k := range abandonedChildren {
			bucket, prefix := path2BucketObject(k)
			stopFn := globalScannerMetrics.time(scannerMetricCheckMissing)
			f.updateCurrentPath(k)

			if bucket != resolver.bucket {
				// Bucket might be missing as well with abandoned children.
				// make sure it is created first otherwise healing won't proceed
				// for objects.
				_, _ = objAPI.HealBucket(ctx, bucket, madmin.HealOpts{})
			}

			resolver.bucket = bucket

			foundObjs := false
			ctx, cancel := context.WithCancel(ctx)

			err := listPathRaw(ctx, listPathRawOptions{
				disks:          f.disks,
				bucket:         bucket,
				path:           prefix,
				recursive:      true,
				reportNotFound: true,
				minDisks:       f.disksQuorum,
				agreed: func(entry metaCacheEntry) {
					if f.dataUsageScannerDebug {
						console.Debugf(healObjectsPrefix+" got agreement: %v\n", entry.name)
					}
				},
				// Some disks have data for this.
				partial: func(entries metaCacheEntries, errs []error) {
					entry, ok := entries.resolve(&resolver)
					if !ok {
						// check if we can get one entry atleast
						// proceed to heal nonetheless, since
						// this object might be dangling.
						entry, _ = entries.firstFound()
					}

					if f.dataUsageScannerDebug {
						console.Debugf(healObjectsPrefix+" resolved to: %v, dir: %v\n", entry.name, entry.isDir())
					}

					if entry.isDir() {
						return
					}

					// wait on timer per object.
					wait := scannerSleeper.Timer(ctx)

					// We got an entry which we should be able to heal.
					fiv, err := entry.fileInfoVersions(bucket)
					if err != nil {
						wait()
						err := bgSeq.queueHealTask(healSource{
							bucket:    bucket,
							object:    entry.name,
							versionID: "",
						}, madmin.HealItemObject)
						if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
							logger.LogIf(ctx, err)
						}
						foundObjs = foundObjs || err == nil
						return
					}

					for _, ver := range fiv.Versions {
						// Sleep and reset.
						wait()
						wait = scannerSleeper.Timer(ctx)

						err := bgSeq.queueHealTask(healSource{
							bucket:    bucket,
							object:    fiv.Name,
							versionID: ver.VersionID,
						}, madmin.HealItemObject)
						if !isErrObjectNotFound(err) && !isErrVersionNotFound(err) {
							logger.LogIf(ctx, err)
						}
						foundObjs = foundObjs || err == nil
					}
				},
				// Too many disks failed.
				finished: func(errs []error) {
					if f.dataUsageScannerDebug {
						console.Debugf(healObjectsPrefix+" too many errors: %v\n", errs)
					}
					cancel()
				},
			})

			stopFn()
			if f.dataUsageScannerDebug && err != nil && err != errFileNotFound {
				console.Debugf(healObjectsPrefix+" checking returned value %v (%T)\n", err, err)
			}

			// Add unless healing returned an error.
			if foundObjs {
				this := cachedFolder{name: k, parent: &thisHash, objectHealProbDiv: 1}
				stopFn := globalScannerMetrics.log(scannerMetricScanFolder, f.root, this.name, "HEALED")
				scanFolder(this)
				stopFn(map[string]string{"type": "healed"})
			}
		}
		break
	}
	if !wasCompacted {
		f.newCache.replaceHashed(thisHash, folder.parent, *into)
	}

	if !into.Compacted && f.newCache.Info.Name != folder.name {
		flat := f.newCache.sizeRecursive(thisHash.Key())
		flat.Compacted = true
		var compact bool
		if flat.Objects < dataScannerCompactLeastObject {
			compact = true
		} else {
			// Compact if we only have objects as children...
			compact = true
			for k := range into.Children {
				if v, ok := f.newCache.Cache[k]; ok {
					if len(v.Children) > 0 || v.Objects > 1 {
						compact = false
						break
					}
				}
			}

		}
		if compact {
			stop := globalScannerMetrics.log(scannerMetricCompactFolder, folder.name)
			f.newCache.deleteRecursive(thisHash)
			f.newCache.replaceHashed(thisHash, folder.parent, *flat)
			total := map[string]string{
				"objects": fmt.Sprint(flat.Objects),
				"size":    fmt.Sprint(flat.Size),
			}
			if flat.Versions > 0 {
				total["versions"] = fmt.Sprint(flat.Versions)
			}
			stop(total)
		}

	}
	// Compact if too many children...
	if !into.Compacted {
		f.newCache.reduceChildrenOf(thisHash, dataScannerCompactAtChildren, f.newCache.Info.Name != folder.name)
	}
	if _, ok := f.updateCache.Cache[thisHash.Key()]; !wasCompacted && ok {
		// Replace if existed before.
		if flat := f.newCache.sizeRecursive(thisHash.Key()); flat != nil {
			f.updateCache.deleteRecursive(thisHash)
			f.updateCache.replaceHashed(thisHash, folder.parent, *flat)
		}
	}

	return nil
}

// scannerItem represents each file while walking.
type scannerItem struct {
	Path        string
	bucket      string // Bucket.
	prefix      string // Only the prefix if any, does not have final object name.
	objectName  string // Only the object name without prefixes.
	replication replicationConfig
	lifeCycle   *lifecycle.Lifecycle
	Typ         fs.FileMode
	heal        struct {
		enabled bool
		bitrot  bool
	} // Has the object been selected for heal check?
	debug bool
}

type sizeSummary struct {
	totalSize       int64
	versions        uint64
	replicatedSize  int64
	pendingSize     int64
	failedSize      int64
	replicaSize     int64
	pendingCount    uint64
	failedCount     uint64
	replTargetStats map[string]replTargetSizeSummary
	tiers           map[string]tierStats
}

// replTargetSizeSummary holds summary of replication stats by target
type replTargetSizeSummary struct {
	replicatedSize int64
	pendingSize    int64
	failedSize     int64
	pendingCount   uint64
	failedCount    uint64
}

type getSizeFn func(item scannerItem) (sizeSummary, error)

// transformMetaDir will transform a directory to prefix/file.ext
func (i *scannerItem) transformMetaDir() {
	split := strings.Split(i.prefix, SlashSeparator)
	if len(split) > 1 {
		i.prefix = path.Join(split[:len(split)-1]...)
	} else {
		i.prefix = ""
	}
	// Object name is last element
	i.objectName = split[len(split)-1]
}

var (
	applyActionsLogPrefix        = color.Green("applyActions:")
	applyVersionActionsLogPrefix = color.Green("applyVersionActions:")
)

func (i *scannerItem) applyHealing(ctx context.Context, o ObjectLayer, oi ObjectInfo) (size int64) {
	if i.debug {
		if oi.VersionID != "" {
			console.Debugf(applyActionsLogPrefix+" heal checking: %v/%v v(%s)\n", i.bucket, i.objectPath(), oi.VersionID)
		} else {
			console.Debugf(applyActionsLogPrefix+" heal checking: %v/%v\n", i.bucket, i.objectPath())
		}
	}
	scanMode := madmin.HealNormalScan
	if i.heal.bitrot {
		scanMode = madmin.HealDeepScan
	}
	healOpts := madmin.HealOpts{
		Remove:   healDeleteDangling,
		ScanMode: scanMode,
	}
	res, err := o.HealObject(ctx, i.bucket, i.objectPath(), oi.VersionID, healOpts)
	if err != nil {
		if errors.Is(err, NotImplemented{}) || isErrObjectNotFound(err) || isErrVersionNotFound(err) {
			err = nil
		}
		logger.LogIf(ctx, err)
		return 0
	}
	return res.ObjectSize
}

func (i *scannerItem) applyLifecycle(ctx context.Context, o ObjectLayer, oi ObjectInfo) (applied bool, size int64) {
	size, err := oi.GetActualSize()
	if i.debug {
		logger.LogIf(ctx, err)
	}
	if i.lifeCycle == nil {
		return false, size
	}

	versionID := oi.VersionID
	rCfg, _ := globalBucketObjectLockSys.Get(i.bucket)
	lcEvt := evalActionFromLifecycle(ctx, *i.lifeCycle, rCfg, oi)
	if i.debug {
		if versionID != "" {
			console.Debugf(applyActionsLogPrefix+" lifecycle: %q (version-id=%s), Initial scan: %v\n", i.objectPath(), versionID, lcEvt.Action)
		} else {
			console.Debugf(applyActionsLogPrefix+" lifecycle: %q Initial scan: %v\n", i.objectPath(), lcEvt.Action)
		}
	}
	defer globalScannerMetrics.timeILM(lcEvt.Action)

	switch lcEvt.Action {
	case lifecycle.DeleteAction, lifecycle.DeleteVersionAction, lifecycle.DeleteRestoredAction, lifecycle.DeleteRestoredVersionAction:
		return applyLifecycleAction(lcEvt.Action, oi, ""), 0
	case lifecycle.TransitionAction, lifecycle.TransitionVersionAction:
		return applyLifecycleAction(lcEvt.Action, oi, lcEvt.StorageClass), size
	default:
		// No action.
		return false, size
	}
}

// applyTierObjSweep removes remote object pending deletion and the free-version
// tracking this information.
func (i *scannerItem) applyTierObjSweep(ctx context.Context, o ObjectLayer, oi ObjectInfo) {
	if !oi.TransitionedObject.FreeVersion {
		// nothing to be done
		return
	}

	ignoreNotFoundErr := func(err error) error {
		switch {
		case isErrVersionNotFound(err), isErrObjectNotFound(err):
			return nil
		}
		return err
	}
	// Remove the remote object
	err := deleteObjectFromRemoteTier(ctx, oi.TransitionedObject.Name, oi.TransitionedObject.VersionID, oi.TransitionedObject.Tier)
	if ignoreNotFoundErr(err) != nil {
		logger.LogIf(ctx, err)
		return
	}

	// Remove this free version
	_, err = o.DeleteObject(ctx, oi.Bucket, oi.Name, ObjectOptions{
		VersionID:        oi.VersionID,
		InclFreeVersions: true,
	})
	if err == nil {
		auditLogLifecycle(ctx, oi, ILMFreeVersionDelete)
	}
	if ignoreNotFoundErr(err) != nil {
		logger.LogIf(ctx, err)
	}
}

// applyNewerNoncurrentVersionLimit removes noncurrent versions older than the most recent NewerNoncurrentVersions configured.
// Note: This function doesn't update sizeSummary since it always removes versions that it doesn't return.
func (i *scannerItem) applyNewerNoncurrentVersionLimit(ctx context.Context, _ ObjectLayer, fivs []FileInfo) ([]FileInfo, error) {
	if i.lifeCycle == nil {
		return fivs, nil
	}
	done := globalScannerMetrics.time(scannerMetricApplyNonCurrent)
	defer done()

	_, days, lim := i.lifeCycle.NoncurrentVersionsExpirationLimit(lifecycle.ObjectOpts{Name: i.objectPath()})
	if lim == 0 || len(fivs) <= lim+1 { // fewer than lim _noncurrent_ versions
		return fivs, nil
	}

	overflowVersions := fivs[lim+1:]
	// current version + most recent lim noncurrent versions
	fivs = fivs[:lim+1]

	rcfg, _ := globalBucketObjectLockSys.Get(i.bucket)
	vcfg, _ := globalBucketVersioningSys.Get(i.bucket)

	versioned := vcfg != nil && vcfg.Versioned(i.objectPath())

	toDel := make([]ObjectToDelete, 0, len(overflowVersions))
	for _, fi := range overflowVersions {
		obj := fi.ToObjectInfo(i.bucket, i.objectPath(), versioned)
		// skip versions with object locking enabled
		if rcfg.LockEnabled && enforceRetentionForDeletion(ctx, obj) {
			if i.debug {
				if obj.VersionID != "" {
					console.Debugf(applyVersionActionsLogPrefix+" lifecycle: %s v(%s) is locked, not deleting\n", obj.Name, obj.VersionID)
				} else {
					console.Debugf(applyVersionActionsLogPrefix+" lifecycle: %s is locked, not deleting\n", obj.Name)
				}
			}
			// add this version back to remaining versions for
			// subsequent lifecycle policy applications
			fivs = append(fivs, fi)
			continue
		}

		// NoncurrentDays not passed yet.
		if time.Now().UTC().Before(lifecycle.ExpectedExpiryTime(obj.SuccessorModTime, days)) {
			// add this version back to remaining versions for
			// subsequent lifecycle policy applications
			fivs = append(fivs, fi)
			continue
		}

		toDel = append(toDel, ObjectToDelete{
			ObjectV: ObjectV{
				ObjectName: fi.Name,
				VersionID:  fi.VersionID,
			},
		})
	}

	globalExpiryState.enqueueByNewerNoncurrent(i.bucket, toDel)
	return fivs, nil
}

// applyVersionActions will apply lifecycle checks on all versions of a scanned item. Returns versions that remain
// after applying lifecycle checks configured.
func (i *scannerItem) applyVersionActions(ctx context.Context, o ObjectLayer, fivs []FileInfo) ([]FileInfo, error) {
	if i.heal.enabled {
		if healDeleteDangling {
			done := globalScannerMetrics.time(scannerMetricCleanAbandoned)
			err := o.CheckAbandonedParts(ctx, i.bucket, i.objectPath(), madmin.HealOpts{Remove: healDeleteDangling})
			done()
			if err != nil {
				logger.LogIf(ctx, fmt.Errorf("unable to check object %s/%s for abandoned data: %w", i.bucket, i.objectPath(), err))
			}
		}
	}
	fivs, err := i.applyNewerNoncurrentVersionLimit(ctx, o, fivs)
	if err != nil {
		return fivs, err
	}

	// Check if we have many versions after applyNewerNoncurrentVersionLimit.
	if len(fivs) > dataScannerExcessiveVersionsThreshold {
		// Notify object accessed via a GET request.
		sendEvent(eventArgs{
			EventName:  event.ObjectManyVersions,
			BucketName: i.bucket,
			Object: ObjectInfo{
				Name: i.objectPath(),
			},
			UserAgent:    "scanner",
			Host:         globalMinioHost,
			RespElements: map[string]string{"x-minio-versions": strconv.Itoa(len(fivs))},
		})
	}

	return fivs, nil
}

// applyActions will apply lifecycle checks on to a scanned item.
// The resulting size on disk will always be returned.
// The metadata will be compared to consensus on the object layer before any changes are applied.
// If no metadata is supplied, -1 is returned if no action is taken.
func (i *scannerItem) applyActions(ctx context.Context, o ObjectLayer, oi ObjectInfo, sizeS *sizeSummary) int64 {
	done := globalScannerMetrics.time(scannerMetricILM)
	applied, size := i.applyLifecycle(ctx, o, oi)
	done()

	// For instance, an applied lifecycle means we remove/transitioned an object
	// from the current deployment, which means we don't have to call healing
	// routine even if we are asked to do via heal flag.
	if !applied {
		if i.heal.enabled {
			done := globalScannerMetrics.time(scannerMetricHealCheck)
			size = i.applyHealing(ctx, o, oi)
			done()
		}
		// replicate only if lifecycle rules are not applied.
		done := globalScannerMetrics.time(scannerMetricCheckReplication)
		i.healReplication(ctx, o, oi.Clone(), sizeS)
		done()
	}
	return size
}

func evalActionFromLifecycle(ctx context.Context, lc lifecycle.Lifecycle, lr lock.Retention, obj ObjectInfo) lifecycle.Event {
	event := lc.Eval(obj.ToLifecycleOpts())
	if serverDebugLog {
		console.Debugf(applyActionsLogPrefix+" lifecycle: Secondary scan: %v\n", event.Action)
	}

	if event.Action == lifecycle.NoneAction {
		return event
	}

	switch event.Action {
	case lifecycle.DeleteVersionAction, lifecycle.DeleteRestoredVersionAction:
		// Defensive code, should never happen
		if obj.VersionID == "" {
			return lifecycle.Event{Action: lifecycle.NoneAction}
		}
		if lr.LockEnabled && enforceRetentionForDeletion(ctx, obj) {
			if serverDebugLog {
				if obj.VersionID != "" {
					console.Debugf(applyActionsLogPrefix+" lifecycle: %s v(%s) is locked, not deleting\n", obj.Name, obj.VersionID)
				} else {
					console.Debugf(applyActionsLogPrefix+" lifecycle: %s is locked, not deleting\n", obj.Name)
				}
			}
			return lifecycle.Event{Action: lifecycle.NoneAction}
		}
	}

	return event
}

func applyTransitionRule(obj ObjectInfo, storageClass string) bool {
	if obj.DeleteMarker {
		return false
	}
	globalTransitionState.queueTransitionTask(obj, storageClass)
	return true
}

func applyExpiryOnTransitionedObject(ctx context.Context, objLayer ObjectLayer, obj ObjectInfo, restoredObject bool) bool {
	action := expireObj
	if restoredObject {
		action = expireRestoredObj
	}
	if err := expireTransitionedObject(ctx, objLayer, &obj, obj.ToLifecycleOpts(), action); err != nil {
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) {
			return false
		}
		logger.LogIf(ctx, err)
		return false
	}
	// Notification already sent in *expireTransitionedObject*, just return 'true' here.
	return true
}

func applyExpiryOnNonTransitionedObjects(ctx context.Context, objLayer ObjectLayer, obj ObjectInfo, applyOnVersion bool) bool {
	opts := ObjectOptions{
		Expiration: ExpirationOptions{Expire: true},
	}

	if applyOnVersion {
		opts.VersionID = obj.VersionID
	}
	if opts.VersionID == "" {
		opts.Versioned = globalBucketVersioningSys.PrefixEnabled(obj.Bucket, obj.Name)
		opts.VersionSuspended = globalBucketVersioningSys.PrefixSuspended(obj.Bucket, obj.Name)
	}

	obj, err := objLayer.DeleteObject(ctx, obj.Bucket, obj.Name, opts)
	if err != nil {
		if isErrObjectNotFound(err) || isErrVersionNotFound(err) {
			return false
		}
		// Assume it is still there.
		logger.LogIf(ctx, err)
		return false
	}

	// Send audit for the lifecycle delete operation
	auditLogLifecycle(ctx, obj, ILMExpiry)

	eventName := event.ObjectRemovedDelete
	if obj.DeleteMarker {
		eventName = event.ObjectRemovedDeleteMarkerCreated
	}

	// Notify object deleted event.
	sendEvent(eventArgs{
		EventName:  eventName,
		BucketName: obj.Bucket,
		Object:     obj,
		Host:       "Internal: [ILM-Expiry]",
	})

	return true
}

// Apply object, object version, restored object or restored object version action on the given object
func applyExpiryRule(obj ObjectInfo, restoredObject, applyOnVersion bool) bool {
	globalExpiryState.enqueueByDays(obj, restoredObject, applyOnVersion)
	return true
}

// Perform actions (removal or transitioning of objects), return true the action is successfully performed
func applyLifecycleAction(action lifecycle.Action, obj ObjectInfo, storageClass string) (success bool) {
	switch action {
	case lifecycle.DeleteVersionAction, lifecycle.DeleteAction:
		success = applyExpiryRule(obj, false, action == lifecycle.DeleteVersionAction)
	case lifecycle.DeleteRestoredAction, lifecycle.DeleteRestoredVersionAction:
		success = applyExpiryRule(obj, true, action == lifecycle.DeleteRestoredVersionAction)
	case lifecycle.TransitionAction, lifecycle.TransitionVersionAction:
		success = applyTransitionRule(obj, storageClass)
	}
	return
}

// objectPath returns the prefix and object name.
func (i *scannerItem) objectPath() string {
	return path.Join(i.prefix, i.objectName)
}

// healReplication will heal a scanned item that has failed replication.
func (i *scannerItem) healReplication(ctx context.Context, o ObjectLayer, oi ObjectInfo, sizeS *sizeSummary) {
	if oi.VersionID == "" {
		return
	}
	if i.replication.Config == nil {
		return
	}
	roi := queueReplicationHeal(ctx, oi.Bucket, oi, i.replication)
	if oi.DeleteMarker || !oi.VersionPurgeStatus.Empty() {
		return
	}

	if sizeS.replTargetStats == nil && len(roi.TargetStatuses) > 0 {
		sizeS.replTargetStats = make(map[string]replTargetSizeSummary)
	}

	for arn, tgtStatus := range roi.TargetStatuses {
		tgtSizeS, ok := sizeS.replTargetStats[arn]
		if !ok {
			tgtSizeS = replTargetSizeSummary{}
		}
		switch tgtStatus {
		case replication.Pending:
			tgtSizeS.pendingCount++
			tgtSizeS.pendingSize += oi.Size
			sizeS.pendingCount++
			sizeS.pendingSize += oi.Size
		case replication.Failed:
			tgtSizeS.failedSize += oi.Size
			tgtSizeS.failedCount++
			sizeS.failedSize += oi.Size
			sizeS.failedCount++
		case replication.Completed, replication.CompletedLegacy:
			tgtSizeS.replicatedSize += oi.Size
			sizeS.replicatedSize += oi.Size
		}
		sizeS.replTargetStats[arn] = tgtSizeS
	}

	if oi.ReplicationStatus == replication.Replica {
		sizeS.replicaSize += oi.Size
	}
}

type dynamicSleeper struct {
	mu sync.RWMutex

	// Sleep factor
	factor float64

	// maximum sleep cap,
	// set to <= 0 to disable.
	maxSleep time.Duration

	// Don't sleep at all, if time taken is below this value.
	// This is to avoid too small costly sleeps.
	minSleep time.Duration

	// cycle will be closed
	cycle chan struct{}

	// isScanner should be set when this is used by the scanner
	// to record metrics.
	isScanner bool
}

// newDynamicSleeper
func newDynamicSleeper(factor float64, maxWait time.Duration, isScanner bool) *dynamicSleeper {
	return &dynamicSleeper{
		factor:    factor,
		cycle:     make(chan struct{}),
		maxSleep:  maxWait,
		minSleep:  100 * time.Microsecond,
		isScanner: isScanner,
	}
}

// Timer returns a timer that has started.
// When the returned function is called it will wait.
func (d *dynamicSleeper) Timer(ctx context.Context) func() {
	t := time.Now()
	return func() {
		doneAt := time.Now()
		for {
			// Grab current values
			d.mu.RLock()
			minWait, maxWait := d.minSleep, d.maxSleep
			factor := d.factor
			cycle := d.cycle
			d.mu.RUnlock()
			elapsed := doneAt.Sub(t)
			// Don't sleep for really small amount of time
			wantSleep := time.Duration(float64(elapsed) * factor)
			if wantSleep <= minWait {
				return
			}
			if maxWait > 0 && wantSleep > maxWait {
				wantSleep = maxWait
			}
			timer := time.NewTimer(wantSleep)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					if d.isScanner {
						globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
					}
					<-timer.C
				}
				return
			case <-timer.C:
				if d.isScanner {
					globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
				}
				return
			case <-cycle:
				if !timer.Stop() {
					// We expired.
					<-timer.C
					if d.isScanner {
						globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
					}
					return
				}
			}
		}
	}
}

// Sleep sleeps the specified time multiplied by the sleep factor.
// If the factor is updated the sleep will be done again with the new factor.
func (d *dynamicSleeper) Sleep(ctx context.Context, base time.Duration) {
	for {
		// Grab current values
		d.mu.RLock()
		minWait, maxWait := d.minSleep, d.maxSleep
		factor := d.factor
		cycle := d.cycle
		d.mu.RUnlock()
		// Don't sleep for really small amount of time
		wantSleep := time.Duration(float64(base) * factor)
		if wantSleep <= minWait {
			return
		}
		if maxWait > 0 && wantSleep > maxWait {
			wantSleep = maxWait
		}
		timer := time.NewTimer(wantSleep)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
				if d.isScanner {
					globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
				}
			}
			return
		case <-timer.C:
			if d.isScanner {
				globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
			}
			return
		case <-cycle:
			if !timer.Stop() {
				// We expired.
				<-timer.C
				if d.isScanner {
					globalScannerMetrics.incTime(scannerMetricYield, wantSleep)
				}
				return
			}
		}
	}
}

// Update the current settings and cycle all waiting.
// Parameters are the same as in the contructor.
func (d *dynamicSleeper) Update(factor float64, maxWait time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if math.Abs(d.factor-factor) < 1e-10 && d.maxSleep == maxWait {
		return nil
	}
	// Update values and cycle waiting.
	close(d.cycle)
	d.factor = factor
	d.maxSleep = maxWait
	d.cycle = make(chan struct{})
	return nil
}

const (
	// ILMExpiry - audit trail for ILM expiry
	ILMExpiry = "ilm:expiry"
	// ILMFreeVersionDelete - audit trail for ILM free-version delete
	ILMFreeVersionDelete = "ilm:free-version-delete"
	// ILMTransition - audit trail for ILM transitioning.
	ILMTransition = " ilm:transition"
)

func auditLogLifecycle(ctx context.Context, oi ObjectInfo, event string) {
	var apiName string
	switch event {
	case ILMExpiry:
		apiName = "ILMExpiry"
	case ILMFreeVersionDelete:
		apiName = "ILMFreeVersionDelete"
	case ILMTransition:
		apiName = "ILMTransition"
	}
	auditLogInternal(ctx, AuditLogOptions{
		Event:     event,
		APIName:   apiName,
		Bucket:    oi.Bucket,
		Object:    oi.Name,
		VersionID: oi.VersionID,
	})
}
