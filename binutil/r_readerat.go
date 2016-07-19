package binutil

import (
	"bufio"
	"encoding/binary"
	"io"
)

// readerAt is a wrapper for io.ReaderAt which implements binutil.ReaderAtInto
type readerAt struct {
	io.ReaderAt
	offset int64
}

// ReaderAt wraps io.ReaderAt and returns a data type, which
// implements binutil.ReaderAtInto interface.
func WrapReaderAt(r io.ReaderAt) ReaderAtInto {
	return readerAt{r, 0}
}

// Read implements io.Reader interface.
// It is required for the current implementation of ReadAtInto method.
func (r readerAt) Read(p []byte) (n int, err error) {
	return r.ReaderAt.ReadAt(p, r.offset)
}

func (r readerAt) ReadAt(p []byte, off int64) (n int, err error) {
	return r.ReaderAt.ReadAt(p, off)
}

// ReadAtInto implements binutil.ReaderAtInto interface
func (r readerAt) ReadAtInto(p interface{}, off int64) error {
	if off != 0 {
		return readerAt{r.ReaderAt, off}.ReadAtInto(p, 0)
	}
	return binary.Read(r, binary.LittleEndian, p)
}

func (r readerAt) ReadStringAt(off int64, maxlen int) (string, error) {
	if off != 0 {
		return readerAt{r.ReaderAt, off}.ReadStringAt(0, maxlen)
	}
	line, err := bufio.NewReader(r).ReadString(0)
	if err != nil {
		return "", err
	}
	if maxlen < 0 {
		maxlen = len(line) - 1
	} else if maxlen > len(line)-1 {
		maxlen = len(line) - 1
	}
	return line[:maxlen], nil

	// const initialChunkSize int64 = 64
	// var chunks [][]byte
	// var totalRead int64

	// for chunkSize := initialChunkSize; ; chunkSize += totalRead {
	// 	chunk := make([]byte, chunkSize)
	// 	n, err := r.ReadAt(chunk, off+totalRead)
	// 	totalRead += n
	// 	chunks = append(chunks, chunk)
	// 	if err == io.EOF {
	// 		chunk = chunk[:n]
	// 		break
	// 	}
	// 	if err != nil {
	// 		return err
	// 	}
	// 	if n = bytes.IndexByte(chunk, 0); n != -1 {
	// 		chunk = chunk[:n]
	// 		break
	// 	}
	// }

	// buf := make([]byte, totalRead)
	// n := 0
	// for i := range chunks {
	// 	n += copy(buf[n:], chunks[i])
	// }
	// return string(buf), nil
}
