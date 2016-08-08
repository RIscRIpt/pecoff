package pecoff

import "errors"

type StringTable struct {
	Size uint32
	Data []byte
}

var (
	ErrStrOffOutOfBounds = errors.New("string offset is out of bounds")
)

func (t *StringTable) GetString(offset uint32) (string, error) {
	if offset > 0 && offset < t.Size {
		nullIndex := offset
		// all strings must be null-terminated,
		// but we don't want to crash unexpectedly,
		// so let's check slice bounds anyway.
		for nullIndex < t.Size && t.Data[nullIndex] != 0 {
			nullIndex++
		}
		// if nullIndex == t.Size { panic("last string is not null-terminated") }
		return string(t.Data[offset:nullIndex]), nil
	} else {
		return "", ErrStrOffOutOfBounds
	}
}
