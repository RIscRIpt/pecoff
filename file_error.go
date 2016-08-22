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

// ToMultiError returns a flattened list of errors
// formed from 'recursive' innerErrors
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

// ErrorFlatten returns err.ToMultiError if `err` implements FileError,
// if not, an `err` without modifications is returned.
func ErrorFlatten(err error) error {
	if fe, ok := err.(*FileError); ok {
		return fe.ToMultiError()
	}
	return err
}

// MultiError represents a collection of errors
type MultiError []error

// Error checks count of errors which are stored in the MultiError and
// returns a string represntation of an error, if:
//     0 entries   : "" (empty string);
//     1 entry     : Error() value of the first error;
//     >=2 entries : Error() values separated with new line character ('\n').
func (e MultiError) Error() string {
	switch len(e) {
	case 0:
		return ""
	case 1:
		return e[0].Error()
	default:
		var buf bytes.Buffer
		// no error checking of Write* methods,
		// as according to the docs, err is always nil.
		buf.WriteString(fmt.Sprintf("pecoff: multi error (%d)\n", len(e)))
		for _, err := range e {
			buf.WriteRune('\t')
			buf.WriteString(err.Error())
			buf.WriteRune('\n')
		}
		return buf.String()
	}
}
