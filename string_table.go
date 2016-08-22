package pecoff

import "errors"

// StringTable represents a COFF string table.
// Please note, first four bytes of the string table (uint32 value), represent
// the size of the string table (including the size value),
// so strings are stored after the 4th byte in the table.
type StringTable []byte

// List of errors which can be returned by methods of StringTable.
var (
	ErrStrOffOutOfBounds = errors.New("string offset is out of bounds")
)

// GetString returns a string which starts at
// specified offset inside the string table.
func (t StringTable) GetString(offset int) (string, error) {
	if offset < 0 || offset >= len(t) {
		return "", ErrStrOffOutOfBounds
	}
	nullIndex := offset
	// all strings must be null-terminated,
	// but we don't want to crash unexpectedly,
	// so let's check slice bounds anyway.
	for nullIndex < len(t) && t[nullIndex] != 0 {
		nullIndex++
	}
	// if nullIndex == len(t) { panic("last string is not null-terminated") }
	return string(t[offset:nullIndex]), nil
}
