package pecoff

import "errors"

type StringTable []byte

var (
	ErrStrOffOutOfBounds = errors.New("string offset is out of bounds")
)

func (t StringTable) GetString(offset int) (string, error) {
	if offset > 0 && offset < len(t) {
		nullIndex := offset
		// all strings must be null-terminated,
		// but we don't want to crash unexpectedly,
		// so let's check slice bounds anyway.
		for nullIndex < len(t) && t[nullIndex] != 0 {
			nullIndex++
		}
		// if nullIndex == len(t) { panic("last string is not null-terminated") }
		return string(t[offset:nullIndex]), nil
	} else {
		return "", ErrStrOffOutOfBounds
	}
}
