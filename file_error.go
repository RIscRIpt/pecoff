package pecoff

import (
	"bytes"
	"fmt"
)

// FileError represents an internal error which may occur while
// reading/parsing a PE/COFF file.
type FileError struct {
	error
	innerError error
}

// (Error must be already implemented in FileError by embedded `error`)
// func (e *FileError) Error() string {
// 	return e.error.Error()
// }

// ErrorsList returns a flattened list of errors from 'recursive' innerErrors
func (e *FileError) ToMultiError() (list MultiError) {
	err := e
	for err != nil {
		list = append(list, err.error)
		if innerError, ok := err.innerError.(*FileError); ok {
			err = innerError
		} else {
			if err.innerError != nil {
				list = append(list, err.innerError)
			}
			break
		}
	}
	return
}

func ErrorFlatten(err error) error {
	if fe, ok := err.(*FileError); ok {
		return fe.ToMultiError()
	}
	return err
}

type MultiError []error

func (e MultiError) Error() string {
	switch len(e) {
	case 0:
		return ""
	case 1:
		return e[0].Error()
	default:
		var buf bytes.Buffer
		buf.WriteString(fmt.Sprintf("pecoff: multi error (%d)\n", len(e)))
		for _, err := range e {
			buf.WriteRune('\t')
			buf.WriteString(err.Error())
			buf.WriteRune('\n')
		}
		return buf.String()
	}
}
