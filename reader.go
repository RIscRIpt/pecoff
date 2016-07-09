package pecoff

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
)

// BPReader is Binary Panic Reader: an io.Reader which panics on any error.
// BPReader can read:
//     - binary little-endian data into interface{}
//     - null-terminated/length-limited ASCII strings
type BPReader struct {
	rs   io.ReadSeeker
	file *File
}

// NewBPReader creates a new BPReader out of a *pecoff.File and an io.ReadSeeker
func NewBPReader(file *File, r io.ReadSeeker) *BPReader {
	return &BPReader{
		file: file,
		rs:   r,
	}
}

// Seek sets the offset for the next Read relatively to the start of the file
func (br *BPReader) Seek(offset int64) {
	if _, err := br.rs.Seek(offset, os.SEEK_SET); err != nil {
		panic(err)
	}
}

// ReadAtInto seeks to the specified offset and reads binary little-endian data
func (br *BPReader) ReadAtInto(offset int64, data interface{}) {
	br.Seek(offset)
	if err := binary.Read(br.rs, binary.LittleEndian, data); err != nil {
		panic(err)
	}
}

func (br *BPReader) ReadVaInto(va uint32, data interface{}) {
	br.ReadAtInto(br.file.VaToOffset(va), data)
}

func (br *BPReader) ReadStringAt(offset int64) (line string) {
	br.Seek(offset)
	line, err := bufio.NewReader(br.rs).ReadString(0)
	if err != nil {
		panic(err)
	}
	return
}

func (br *BPReader) ReadStringVa(va uint32) string {
	return br.ReadStringAt(br.file.VaToOffset(va))
}
