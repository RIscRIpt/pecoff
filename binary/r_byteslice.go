package binary

import (
	"encoding/binary"
	"io"
)

// ByteSlice is an alias type of `[]byte` which implements binary.ReaderAtInto
type ByteSlice []byte

// WrapByteSlice wraps []byte and returns a data type, which
// implements binary.ReaderAtInto interface.
func WrapByteSlice(bs []byte) ReaderAtInto {
	return ByteSlice(bs)
}

// Read implements io.Reader interface.
// It is required for the current implementation of ReadAtInto method.
func (bs ByteSlice) Read(p []byte) (n int, err error) {
	n = len(p)
	if n > len(bs) {
		n = len(bs)
	}
	copy(p, bs[:n])
	if n < len(p) {
		err = io.EOF
	}
	return
}

// ReadAtInto implements binary.ReaderAtInto interface
func (bs ByteSlice) ReadAtInto(p interface{}, off int64) error {
	return binary.Read(bs[off:], binary.LittleEndian, p)
}
