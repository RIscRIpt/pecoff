package binary

import (
	"encoding/binary"
	"io"
)

// readerAt is a wrapper for io.ReaderAt which implements binary.ReaderAtInto
type readerAt struct {
	io.ReaderAt
	offset int64
}

// ReaderAt wraps io.ReaderAt and returns a data type, which
// implements binary.ReaderAtInto interface.
func ReaderAt(r io.ReaderAt) ReaderAtInto {
	return readerAt{r, 0}
}

// Read implements io.Reader interface.
// It is required for the current implementation of ReadAtInto method.
func (r readerAt) Read(p []byte) (n int, err error) {
	return r.ReadAt(p, r.offset)
}

// ReadAtInto implements binary.ReaderAtInto interface
func (r readerAt) ReadAtInto(p interface{}, off int64) error {
	if off == 0 {
		return binary.Read(r, binary.LittleEndian, p)
	}
	return readerAt{r.ReaderAt, off}.ReadAtInto(p, 0)
}
