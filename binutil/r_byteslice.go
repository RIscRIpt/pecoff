package binutil

import (
	"encoding/binary"
	"io"
)

// byteSlice is an alias type of `[]byte` which implements binutil.ReaderAtInto
type byteSlice []byte

// ByteSlice wraps []byte and returns a data type, which
// implements binutil.ReaderAtInto interface.
func WrapByteSlice(bs []byte) ReaderAtInto {
	return byteSlice(bs)
}

// Read implements io.Reader interface.
// It is required for the current implementation of ReadAtInto method.
func (bs byteSlice) Read(p []byte) (n int, err error) {
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

func (bs byteSlice) ReadAt(p []byte, off int64) (n int, err error) {
	return bs[off:].Read(p)
}

// ReadAtInto implements binutil.ReaderAtInto interface
func (bs byteSlice) ReadAtInto(p interface{}, off int64) error {
	return binary.Read(bs[off:], binary.LittleEndian, p)
}
