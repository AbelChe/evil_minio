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
	"runtime"
	"runtime/debug"

	"github.com/minio/madmin-go/v2/kernel"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/pkg/sys"
)

func oldLinux() bool {
	currentKernel, err := kernel.CurrentVersion()
	if err != nil {
		// Could not probe the kernel version
		return false
	}

	if currentKernel == 0 {
		// We could not get any valid value return false
		return false
	}

	// legacy linux indicator for printing warnings
	// about older Linux kernels and Go runtime.
	return currentKernel < kernel.Version(4, 0, 0)
}

func setMaxResources() (err error) {
	// Set the Go runtime max threads threshold to 90% of kernel setting.
	sysMaxThreads, err := sys.GetMaxThreads()
	if err == nil {
		minioMaxThreads := (sysMaxThreads * 90) / 100
		// Only set max threads if it is greater than the default one
		if minioMaxThreads > 10000 {
			debug.SetMaxThreads(minioMaxThreads)
		}
	}

	var maxLimit uint64

	// Set open files limit to maximum.
	if _, maxLimit, err = sys.GetMaxOpenFileLimit(); err != nil {
		return err
	}

	if maxLimit < 4096 && runtime.GOOS != globalWindowsOSName {
		logger.Info("WARNING: maximum file descriptor limit %d is too low for production servers. At least 4096 is recommended. Fix with \"ulimit -n 4096\"",
			maxLimit)
	}

	if err = sys.SetMaxOpenFileLimit(maxLimit, maxLimit); err != nil {
		return err
	}

	// Set max memory limit as current memory limit.
	if _, maxLimit, err = sys.GetMaxMemoryLimit(); err != nil {
		return err
	}

	err = sys.SetMaxMemoryLimit(maxLimit, maxLimit)
	return err
}
