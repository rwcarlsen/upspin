// Copyright 2016 The Upspin Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package file implements the File interface used in client.Open and client.Create.
package file // import "upspin.io/client/file"

import (
	"io"

	"upspin.io/access"
	"upspin.io/bind"
	"upspin.io/client/clientutil"
	"upspin.io/errors"
	"upspin.io/flags"
	"upspin.io/metric"
	"upspin.io/pack"
	"upspin.io/path"
	"upspin.io/upspin"
)

// maxInt is the int64 representation of the maximum value of an int.
// It allows us to verify that an int64 value never exceeds the length of a slice.
// In the tests, we cut it down to manageable size for overflow checking.
var maxInt = int64(^uint(0) >> 1)

// File is a simple implementation of upspin.File.
// It always keeps the whole file in memory under the assumption
// that it is encrypted and must be read and written atomically.
type File struct {
	name     upspin.PathName // Full path name.
	offset   int64           // File location for next read or write operation. Constrained to <= maxInt.
	writable bool            // File is writable (made with Create, not Open).
	closed   bool            // Whether the file has been closed, preventing further operations.
	entry    *upspin.DirEntry

	// Used only by readers.
	config upspin.Config
	size   int64
	bu     upspin.BlockUnpacker
	// Keep the most recently unpacked block around
	// in case a subsequent readAt starts at the same place.
	lastBlockIndex int
	lastBlockBytes []byte

	// Used only by writers.
	client     upspin.Client   // Client the File belongs to.
	data       []byte          // Contents of file.
	dstname    upspin.PathName // fully resolved (i.e. links followed) path for writing
	bufferFull bool
	bp         upspin.BlockPacker
}

var _ upspin.File = (*File)(nil)

// Readable creates a new File for the given DirEntry that must be readable
// using the given Config.
func Readable(cfg upspin.Config, entry *upspin.DirEntry) (*File, error) {
	// TODO(adg): check if this is a dir or link?
	const op = "client/file.Readable"

	packer := pack.Lookup(entry.Packing)
	if packer == nil {
		return nil, errors.E(op, entry.Name, errors.Invalid, errors.Errorf("unrecognized Packing %d", entry.Packing))
	}
	bu, err := packer.Unpack(cfg, entry)
	if err != nil {
		return nil, errors.E(op, entry.Name, err)
	}
	size, err := entry.Size()
	if err != nil {
		return nil, errors.E(op, entry.Name, err)
	}

	return &File{
		config:         cfg,
		name:           entry.Name,
		writable:       false,
		entry:          entry,
		size:           size,
		bu:             bu,
		lastBlockIndex: -1,
	}, nil
}

// Writable creates a new file with a given name, belonging to a given
// client for write. Once closed, the file will overwrite any existing
// file with the same name.
func Writable(client upspin.Client, name upspin.PathName) (*File, error) {
	const op = "file.Writable"
	m, s := newMetric(op)
	defer m.Done()

	parsed, err := path.Parse(name)
	if err != nil {
		return nil, errors.E(op, err)
	}

	// For Access and Group files, we buffer their entire contents locally
	// instead of doing a streaming write because we need to check their
	// validity before finalizing the write.
	accessEntry, evalEntry, err := clientutil.Lookup(f.client.Config(), op, &upspin.DirEntry{Name: parsed.Path()}, clientutil.WhichAccessLookupFn, followFinalLink, s)
	if err != nil {
		return nil, errors.E(op, err)
	}
	dstname = evalEntry.Name
	isAccessFile := access.IsAccessFile(dstname)
	isGroupFile := access.IsGroupFile(dstname)

	f := &File{
		client:     client,
		name:       name,
		writable:   true,
		dstname:    dstname,
		bufferFull: isAccessFile || isGroupFile,
	}
	err = f.startStreamingWrite(op, accessEntry, evalEntry)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Name implements upspin.File.
func (f *File) Name() upspin.PathName {
	return f.name
}

// Read implements upspin.File.
func (f *File) Read(b []byte) (n int, err error) {
	const op = "file.Read"
	n, err = f.readAt(op, b, f.offset)
	if err == nil {
		f.offset += int64(n)
	}
	return n, err
}

// ReadAt implements upspin.File.
func (f *File) ReadAt(b []byte, off int64) (n int, err error) {
	const op = "file.ReadAt"
	return f.readAt(op, b, off)
}

func (f *File) readAt(op string, dst []byte, off int64) (n int, err error) {
	if f.closed {
		return 0, f.errClosed(op)
	}
	if f.writable {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("not open for read"))
	}
	if off < 0 {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("negative offset"))
	}
	if off > f.size {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("offset (%d) beyond end of file (%d)", off, f.size))
	}
	if off == f.size {
		return 0, io.EOF
	}

	// Iterate over blocks that contain the data we're interested in,
	// and unpack and copy the data to dst.
	for i := range f.entry.Blocks {
		b := &f.entry.Blocks[i]

		if b.Offset+b.Size < off {
			// This block is before our interest.
			continue
		}
		if b.Offset >= off+int64(len(dst)) {
			// This block is beyond our interest.
			break
		}

		if _, ok := f.bu.SeekBlock(i); !ok {
			return 0, errors.E(op, errors.IO, f.name, errors.Errorf("could not seek to block %d", i))
		}

		var clear []byte
		if i == f.lastBlockIndex {
			// If this is the block we last read (will often happen
			// with sequential reads) then use that content,
			// to avoid reading and unpacking again.
			// TOOD(adg): write a test to ensure this is happening.
			clear = f.lastBlockBytes
		} else {
			// Otherwise, we need to read the block and unpack.
			cipher, err := clientutil.ReadLocation(f.config, b.Location)
			if err != nil {
				return 0, errors.E(op, errors.IO, f.name, err)
			}
			clear, err = f.bu.Unpack(cipher)
			if err != nil {
				return 0, errors.E(op, errors.IO, f.name, err)
			}
			f.lastBlockIndex = i
			f.lastBlockBytes = clear
		}

		clearIdx := 0
		if off > b.Offset {
			clearIdx = int(off - b.Offset)
		}
		n += copy(dst[n:], clear[clearIdx:])
	}

	return n, nil
}

// switchBufferFull puts the file into full buffering mode from a streaming-write mode.
func (f *File) switchBufferFull() error {
	if f.bufferFull {
		return nil
	}
	f.bufferFull = true

	panic("unimplemented")

	return nil
}

// Seek implements upspin.File.
func (f *File) Seek(offset int64, whence int) (ret int64, err error) {
	const op = "file.Seek"
	if f.closed {
		return 0, f.errClosed(op)
	}
	if err := f.switchBufferFull(); err != nil {
		return 0, errors.E(op, err)
	}

	switch whence {
	case 0:
		ret = offset
	case 1:
		ret = f.offset + offset
	case 2:
		if f.writable {
			ret = int64(len(f.data)) + offset
		} else {
			ret = f.size + offset
		}
	default:
		return 0, errors.E(op, errors.Invalid, f.name, errors.Str("bad whence"))
	}
	if ret < 0 || offset > maxInt || !f.writable && ret > f.size {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Str("bad offset"))
	}
	f.offset = ret
	return ret, nil
}

// Write implements upspin.File.
func (f *File) Write(b []byte) (n int, err error) {
	const op = "file.Write"
	n, err = f.writeAt(op, b, f.offset)
	if err == nil {
		f.offset += int64(n)
	} else {
		return n, err
	}

	if !f.bufferFull {
		err = f.streamingWrite(false)
	}
	return n, err
}

const (
	followFinalLink      = true
	doNotFollowFinalLink = false
)

func (f *File) startStreamingWrite(op string, accessEntry, evalEntry *upspin.DirEntry) error {
	name = evalEntry.Name

	// Encrypt data according to the preferred packer
	packer := pack.Lookup(f.client.Config().Packing())
	if packer == nil {
		return nil, errors.E(op, name, errors.Errorf("unrecognized Packing %d", c.config.Packing()))
	}

	f.entry = &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Packing:    packer.Packing(),
		Time:       upspin.Now(),
		Sequence:   upspin.SeqIgnore,
		Writer:     f.client.Config().UserName(),
		Link:       "",
		Attr:       upspin.AttrNone,
	}

	bp, err := packer.Pack(f.config, f.entry)
	if err != nil {
		return err
	}
	f.bp = bp

	return nil
}

func (f *File) streamingWrite(final bool) error {
	if len(f.data) < flags.BlockSize && !final {
		return nil
	}
	// TODO: track metrics here like in client.Put

	ss := s.StartSpan("pack")
	if err := f.pack(f.entry, ss, final); err != nil {
		return nil, errors.E(op, err)
	}
	ss.End()
}

func (f *File) endStreamingWrite(op string) error {
	f.streamingWrite(true)
	err := f.bp.Close()
	if err != nil {
		return err
	}

	readers, err := clientutil.GetReaders(f.client.Config(), name, accessEntry)
	if err != nil {
		return errors.E(op, f.name, err)
	}
	if err := clientutil.AddReaders(op, f.entry, f.entry.Packing, readers); err != nil {
		return errors.E(op, f.name, err)
	}

	// We have evaluated links so can use DirServer.Put directly.
	dir, err := c.DirServer(f.dstname)
	if err != nil {
		return errors.E(op, f.name, err)
	}

	e, err := dir.Put(f.entry)
	if err != nil {
		return errors.E(op, f.name, err)
	}
	// dir.Put returns an incomplete entry, with the updated sequence number.
	if e != nil { // TODO: Can be nil only when talking to old servers.
		entry.Sequence = e.Sequence
	}
	return nil
}

func (f *File) pack(entry *upspin.DirEntry, s *metric.Span, final bool) error {
	packer := entry.Packing
	// Start the I/O.
	store, err := bind.StoreServer(f.config, f.config.StoreEndpoint())
	if err != nil {
		return err
	}

	for len(f.data) > flags.BlockSize || final {
		n := len(f.data)
		if n > flags.BlockSize {
			n = flags.BlockSize
		}
		ss := s.StartSpan("bp.pack")
		cipher, err := f.bp.Pack(f.data[:n])
		ss.End()
		if err != nil {
			return err
		}

		f.data = f.data[:copy(f.data, f.data[n:])]

		ss = s.StartSpan("store.Put")
		refdata, err := store.Put(cipher)
		ss.End()
		if err != nil {
			return err
		}
		f.bp.SetLocation(
			upspin.Location{
				Endpoint:  c.config.StoreEndpoint(),
				Reference: refdata.Reference,
			},
		)
	}
	return nil
}

// WriteAt implements upspin.File.
func (f *File) WriteAt(b []byte, off int64) (n int, err error) {
	const op = "file.WriteAt"
	if err := f.switchBufferFull(); err != nil {
		return 0, errors.E(op, err)
	}
	return f.writeAt(op, b, off)
}

func (f *File) writeAt(op string, b []byte, off int64) (n int, err error) {
	if f.closed {
		return 0, f.errClosed(op)
	}
	if !f.writable {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("not open for write"))
	}
	if off < 0 {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("negative offset"))
	}
	end := off + int64(len(b))
	if end > maxInt {
		return 0, errors.E(op, errors.Invalid, f.name, errors.Errorf("file too long"))
	}
	if end > int64(cap(f.data)) {
		// Grow the capacity of f.data but keep length the same.
		// Be careful not to ask for more than an int's worth of length.
		nLen := end * 3 / 2
		if nLen > maxInt {
			nLen = maxInt
		}
		ndata := make([]byte, len(f.data), nLen)
		copy(ndata, f.data)
		f.data = ndata
	}
	// Capacity is OK now. Fix the length if necessary.
	if end > int64(len(f.data)) {
		f.data = f.data[:end]
	}
	copy(f.data[off:], b)
	return len(b), nil
}

// Close implements upspin.File.
func (f *File) Close() (err error) {
	const op = "file.Close"
	if f.closed {
		return f.errClosed(op)
	}
	f.closed = true
	if !f.writable {
		f.lastBlockIndex = -1
		f.lastBlockBytes = nil
		if err := f.bu.Close(); err != nil {
			return errors.E(op, err)
		}
		return nil
	}
	if f.bufferFull {
		err = validateAccess(op)
		if err != nil {
			return err
		}
		_, err = f.client.Put(f.name, f.data)
	} else {
		err = f.endStreamingWrite()
	}
	f.data = nil // Might as well release it early.
	return err
}

func (f *File) validateAccess(op string) error {
	parsed, err := path.Parse(f.name)
	if err != nil {
		return err
	}

	isAccessFile := access.IsAccessFile(f.dstname)
	isGroupFile := access.IsGroupFile(f.dstname)
	// Ensure Access file is valid.
	if access.IsAccessFile(f.dstname) {
		_, err := access.Parse(f.name, f.data)
		if err != nil {
			return errors.E(op, f.name, err)
		}
	}
	// Ensure Group file is valid.
	if access.IsGroupFile(name) {
		_, err := access.ParseGroup(parsed, f.data)
		if err != nil {
			return errors.E(op, name, err)
		}
	}

	return nil
}

func (f *File) errClosed(op string) error {
	return errors.E(op, errors.Invalid, f.name, errors.Str("is closed"))
}
