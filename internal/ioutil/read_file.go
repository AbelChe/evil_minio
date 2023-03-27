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

package ioutil

import (
	"io"
	"io/fs"
	"os"

	"github.com/minio/minio/internal/disk"
)

var (
	// OpenFileDirectIO allows overriding default function.
	OpenFileDirectIO = disk.OpenFileDirectIO
	// OsOpen allows overriding default function.
	OsOpen = os.Open
	// OsOpenFile allows overriding default function.
	OsOpenFile = os.OpenFile
)

// ReadFileWithFileInfo reads the named file and returns the contents.
// A successful call returns err == nil, not err == EOF.
// Because ReadFile reads the whole file, it does not treat an EOF from Read
// as an error to be reported, additionall returns os.FileInfo
func ReadFileWithFileInfo(name string) ([]byte, fs.FileInfo, error) {
	f, err := OsOpen(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}

	dst := make([]byte, st.Size())
	_, err = io.ReadFull(f, dst)
	return dst, st, err
}

// ReadFile reads the named file and returns the contents.
// A successful call returns err == nil, not err == EOF.
// Because ReadFile reads the whole file, it does not treat an EOF from Read
// as an error to be reported.
//
// passes NOATIME flag for reads on Unix systems to avoid atime updates.
func ReadFile(name string) ([]byte, error) {
	f, err := OpenFileDirectIO(name, readMode, 0o666)
	if err != nil {
		// fallback if there is an error to read
		// 'name' with O_DIRECT
		f, err = OsOpenFile(name, readMode, 0o666)
		if err != nil {
			return nil, err
		}
	}
	r := &ODirectReader{
		File:      f,
		SmallFile: true,
	}
	defer r.Close()

	st, err := f.Stat()
	if err != nil {
		return io.ReadAll(r)
	}

	// Select bigger blocks when reading at least 50% of a big block.
	r.SmallFile = st.Size() <= BlockSizeLarge/2

	dst := make([]byte, st.Size())
	_, err = io.ReadFull(r, dst)
	return dst, err
}
