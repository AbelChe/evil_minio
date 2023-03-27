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

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/klauspost/compress/zip"
	"github.com/klauspost/filepathx"
	"github.com/minio/cli"
	"github.com/tinylib/msgp/msgp"
)

func main() {
	app := cli.NewApp()
	app.Copyright = "MinIO, Inc."
	app.Usage = "xl.meta to JSON"
	app.HideVersion = true
	app.CustomAppHelpTemplate = `NAME:
  {{.Name}} - {{.Usage}}

USAGE:
  {{.Name}} {{if .VisibleFlags}}[FLAGS]{{end}} METAFILES...

Multiple files can be added. Files ending in '.zip' will be searched
for 'xl.meta' files. Wildcards are accepted: 'testdir/*.txt' will compress
all files in testdir ending with '.txt', directories can be wildcards
as well. 'testdir/*/*.txt' will match 'testdir/subdir/b.txt', double stars
means full recursive. 'testdir/**/xl.meta' will search for all xl.meta
recursively.

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
`

	app.HideHelpCommand = true

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Usage: "print each file as a separate line without formatting",
			Name:  "ndjson",
		},
		cli.BoolFlag{
			Usage: "display inline data keys and sizes",
			Name:  "data",
		},
		cli.BoolFlag{
			Usage: "export inline data",
			Name:  "export",
		},
	}

	app.Action = func(c *cli.Context) error {
		ndjson := c.Bool("ndjson")
		decode := func(r io.Reader, file string) ([]byte, error) {
			b, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			b, _, minor, err := checkXL2V1(b)
			if err != nil {
				return nil, err
			}

			buf := bytes.NewBuffer(nil)
			var data xlMetaInlineData
			switch minor {
			case 0:
				_, err = msgp.CopyToJSON(buf, bytes.NewReader(b))
				if err != nil {
					return nil, err
				}
			case 1, 2:
				v, b, err := msgp.ReadBytesZC(b)
				if err != nil {
					return nil, err
				}
				if _, nbuf, err := msgp.ReadUint32Bytes(b); err == nil {
					// Read metadata CRC (added in v2, ignore if not found)
					b = nbuf
				}

				_, err = msgp.CopyToJSON(buf, bytes.NewReader(v))
				if err != nil {
					return nil, err
				}
				data = b
			case 3:
				v, b, err := msgp.ReadBytesZC(b)
				if err != nil {
					return nil, err
				}
				if _, nbuf, err := msgp.ReadUint32Bytes(b); err == nil {
					// Read metadata CRC (added in v2, ignore if not found)
					b = nbuf
				}

				nVers, v, err := decodeXLHeaders(v)
				if err != nil {
					return nil, err
				}
				type version struct {
					Idx      int
					Header   json.RawMessage
					Metadata json.RawMessage
				}
				versions := make([]version, nVers)
				err = decodeVersions(v, nVers, func(idx int, hdr, meta []byte) error {
					var header xlMetaV2VersionHeaderV2
					if _, err := header.UnmarshalMsg(hdr); err != nil {
						return err
					}
					b, err := header.MarshalJSON()
					if err != nil {
						return err
					}
					var buf bytes.Buffer
					if _, err := msgp.UnmarshalAsJSON(&buf, meta); err != nil {
						return err
					}
					versions[idx] = version{
						Idx:      idx,
						Header:   b,
						Metadata: buf.Bytes(),
					}
					return nil
				})
				if err != nil {
					return nil, err
				}
				enc := json.NewEncoder(buf)
				if err := enc.Encode(struct {
					Versions []version
				}{Versions: versions}); err != nil {
					return nil, err
				}
				data = b
			default:
				return nil, fmt.Errorf("unknown metadata version %d", minor)
			}

			if c.Bool("data") {
				b, err := data.json()
				if err != nil {
					return nil, err
				}
				buf = bytes.NewBuffer(b)
			}
			if c.Bool("export") {
				file := strings.Map(func(r rune) rune {
					switch {
					case r >= 'a' && r <= 'z':
						return r
					case r >= 'A' && r <= 'Z':
						return r
					case r >= '0' && r <= '9':
						return r
					case strings.ContainsAny(string(r), "+=-_()!@."):
						return r
					default:
						return '_'
					}
				}, file)
				err := data.files(func(name string, data []byte) {
					err = os.WriteFile(fmt.Sprintf("%s-%s.data", file, name), data, os.ModePerm)
					if err != nil {
						fmt.Println(err)
					}
				})
				if err != nil {
					return nil, err
				}
			}
			if ndjson {
				return buf.Bytes(), nil
			}
			var msi map[string]interface{}
			dec := json.NewDecoder(buf)
			// Use number to preserve integers.
			dec.UseNumber()
			err = dec.Decode(&msi)
			if err != nil {
				return nil, err
			}
			b, err = json.MarshalIndent(msi, "", "  ")
			if err != nil {
				return nil, err
			}
			return b, nil
		}

		args := c.Args()
		if len(args) == 0 {
			// If no args, assume xl.meta
			args = []string{"xl.meta"}
		}
		var files []string

		for _, pattern := range args {
			if pattern == "-" {
				files = append(files, pattern)
				continue
			}
			found, err := filepathx.Glob(pattern)
			if err != nil {
				return err
			}
			if len(found) == 0 {
				return fmt.Errorf("unable to find file %v", pattern)
			}
			files = append(files, found...)
		}
		if len(files) == 0 {
			return fmt.Errorf("no files found")
		}
		multiple := len(files) > 1 || strings.HasSuffix(files[0], ".zip")
		if multiple {
			ndjson = true
			fmt.Println("{")
		}

		hasWritten := false
		for _, file := range files {
			var r io.Reader
			var sz int64
			switch file {
			case "-":
				r = os.Stdin
			default:
				f, err := os.Open(file)
				if err != nil {
					return err
				}
				if st, err := f.Stat(); err == nil {
					sz = st.Size()
				}
				defer f.Close()
				r = f
			}
			if strings.HasSuffix(file, ".zip") {
				zr, err := zip.NewReader(r.(io.ReaderAt), sz)
				if err != nil {
					return err
				}
				for _, file := range zr.File {
					if !file.FileInfo().IsDir() && strings.HasSuffix(file.Name, "xl.meta") {
						r, err := file.Open()
						if err != nil {
							return err
						}
						// Quote string...
						b, _ := json.Marshal(file.Name)
						if hasWritten {
							fmt.Print(",\n")
						}
						fmt.Printf("\t%s: ", string(b))

						b, err = decode(r, file.Name)
						if err != nil {
							return err
						}
						fmt.Print(string(b))
						hasWritten = true
					}
				}
			} else {
				if multiple {
					// Quote string...
					b, _ := json.Marshal(file)
					if hasWritten {
						fmt.Print(",\n")
					}
					fmt.Printf("\t%s: ", string(b))
				}

				b, err := decode(r, file)
				if err != nil {
					return err
				}

				hasWritten = true
				fmt.Print(string(b))
			}
		}
		fmt.Println("")
		if multiple {
			fmt.Println("}")
		}

		return nil
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

var (
	// XL header specifies the format
	xlHeader = [4]byte{'X', 'L', '2', ' '}

	// Current version being written.
	xlVersionCurrent [4]byte
)

const (
	// Breaking changes.
	// Newer versions cannot be read by older software.
	// This will prevent downgrades to incompatible versions.
	xlVersionMajor = 1

	// Non breaking changes.
	// Bumping this is informational, but should be done
	// if any change is made to the data stored, bumping this
	// will allow to detect the exact version later.
	xlVersionMinor = 1
)

func init() {
	binary.LittleEndian.PutUint16(xlVersionCurrent[0:2], xlVersionMajor)
	binary.LittleEndian.PutUint16(xlVersionCurrent[2:4], xlVersionMinor)
}

// checkXL2V1 will check if the metadata has correct header and is a known major version.
// The remaining payload and versions are returned.
func checkXL2V1(buf []byte) (payload []byte, major, minor uint16, err error) {
	if len(buf) <= 8 {
		return payload, 0, 0, fmt.Errorf("xlMeta: no data")
	}

	if !bytes.Equal(buf[:4], xlHeader[:]) {
		return payload, 0, 0, fmt.Errorf("xlMeta: unknown XLv2 header, expected %v, got %v", xlHeader[:4], buf[:4])
	}

	if bytes.Equal(buf[4:8], []byte("1   ")) {
		// Set as 1,0.
		major, minor = 1, 0
	} else {
		major, minor = binary.LittleEndian.Uint16(buf[4:6]), binary.LittleEndian.Uint16(buf[6:8])
	}
	if major > xlVersionMajor {
		return buf[8:], major, minor, fmt.Errorf("xlMeta: unknown major version %d found", major)
	}

	return buf[8:], major, minor, nil
}

const xlMetaInlineDataVer = 1

type xlMetaInlineData []byte

// afterVersion returns the payload after the version, if any.
func (x xlMetaInlineData) afterVersion() []byte {
	if len(x) == 0 {
		return x
	}
	return x[1:]
}

// versionOK returns whether the version is ok.
func (x xlMetaInlineData) versionOK() bool {
	if len(x) == 0 {
		return true
	}
	return x[0] > 0 && x[0] <= xlMetaInlineDataVer
}

func (x xlMetaInlineData) json() ([]byte, error) {
	if len(x) == 0 {
		return []byte("{}"), nil
	}
	if !x.versionOK() {
		return nil, errors.New("xlMetaInlineData: unknown version")
	}

	sz, buf, err := msgp.ReadMapHeaderBytes(x.afterVersion())
	if err != nil {
		return nil, err
	}
	res := []byte("{")

	for i := uint32(0); i < sz; i++ {
		var key, val []byte
		key, buf, err = msgp.ReadMapKeyZC(buf)
		if err != nil {
			return nil, err
		}
		if len(key) == 0 {
			return nil, fmt.Errorf("xlMetaInlineData: key %d is length 0", i)
		}
		// Skip data...
		val, buf, err = msgp.ReadBytesZC(buf)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			res = append(res, ',')
		}
		s := fmt.Sprintf(`"%s":%d`, string(key), len(val))
		res = append(res, []byte(s)...)
	}
	res = append(res, '}')
	return res, nil
}

// files returns files as callback.
func (x xlMetaInlineData) files(fn func(name string, data []byte)) error {
	if len(x) == 0 {
		return nil
	}
	if !x.versionOK() {
		return errors.New("xlMetaInlineData: unknown version")
	}

	sz, buf, err := msgp.ReadMapHeaderBytes(x.afterVersion())
	if err != nil {
		return err
	}

	for i := uint32(0); i < sz; i++ {
		var key, val []byte
		key, buf, err = msgp.ReadMapKeyZC(buf)
		if err != nil {
			return err
		}
		if len(key) == 0 {
			return fmt.Errorf("xlMetaInlineData: key %d is length 0", i)
		}
		// Read data...
		val, buf, err = msgp.ReadBytesZC(buf)
		if err != nil {
			return err
		}
		// Call back.
		fn(string(key), val)
	}
	return nil
}

const (
	xlHeaderVersion = 2
	xlMetaVersion   = 2
)

func decodeXLHeaders(buf []byte) (versions int, b []byte, err error) {
	hdrVer, buf, err := msgp.ReadUintBytes(buf)
	if err != nil {
		return 0, buf, err
	}
	metaVer, buf, err := msgp.ReadUintBytes(buf)
	if err != nil {
		return 0, buf, err
	}
	if hdrVer > xlHeaderVersion {
		return 0, buf, fmt.Errorf("decodeXLHeaders: Unknown xl header version %d", metaVer)
	}
	if metaVer > xlMetaVersion {
		return 0, buf, fmt.Errorf("decodeXLHeaders: Unknown xl meta version %d", metaVer)
	}
	versions, buf, err = msgp.ReadIntBytes(buf)
	if err != nil {
		return 0, buf, err
	}
	if versions < 0 {
		return 0, buf, fmt.Errorf("decodeXLHeaders: Negative version count %d", versions)
	}
	return versions, buf, nil
}

// decodeVersions will decode a number of versions from a buffer
// and perform a callback for each version in order, newest first.
// Any non-nil error is returned.
func decodeVersions(buf []byte, versions int, fn func(idx int, hdr, meta []byte) error) (err error) {
	var tHdr, tMeta []byte // Zero copy bytes
	for i := 0; i < versions; i++ {
		tHdr, buf, err = msgp.ReadBytesZC(buf)
		if err != nil {
			return err
		}
		tMeta, buf, err = msgp.ReadBytesZC(buf)
		if err != nil {
			return err
		}
		if err = fn(i, tHdr, tMeta); err != nil {
			return err
		}
	}
	return nil
}

type xlMetaV2VersionHeaderV2 struct {
	VersionID [16]byte
	ModTime   int64
	Signature [4]byte
	Type      uint8
	Flags     uint8
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *xlMetaV2VersionHeaderV2) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var zb0001 uint32
	zb0001, bts, err = msgp.ReadArrayHeaderBytes(bts)
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	if zb0001 != 5 {
		err = msgp.ArrayError{Wanted: 5, Got: zb0001}
		return
	}
	bts, err = msgp.ReadExactBytes(bts, (z.VersionID)[:])
	if err != nil {
		err = msgp.WrapError(err, "VersionID")
		return
	}
	z.ModTime, bts, err = msgp.ReadInt64Bytes(bts)
	if err != nil {
		err = msgp.WrapError(err, "ModTime")
		return
	}
	bts, err = msgp.ReadExactBytes(bts, (z.Signature)[:])
	if err != nil {
		err = msgp.WrapError(err, "Signature")
		return
	}
	{
		var zb0002 uint8
		zb0002, bts, err = msgp.ReadUint8Bytes(bts)
		if err != nil {
			err = msgp.WrapError(err, "Type")
			return
		}
		z.Type = zb0002
	}
	{
		var zb0003 uint8
		zb0003, bts, err = msgp.ReadUint8Bytes(bts)
		if err != nil {
			err = msgp.WrapError(err, "Flags")
			return
		}
		z.Flags = zb0003
	}
	o = bts
	return
}

func (z xlMetaV2VersionHeaderV2) MarshalJSON() (o []byte, err error) {
	tmp := struct {
		VersionID string
		ModTime   time.Time
		Signature string
		Type      uint8
		Flags     uint8
	}{
		VersionID: hex.EncodeToString(z.VersionID[:]),
		ModTime:   time.Unix(0, z.ModTime),
		Signature: hex.EncodeToString(z.Signature[:]),
		Type:      z.Type,
		Flags:     z.Flags,
	}
	return json.Marshal(tmp)
}
