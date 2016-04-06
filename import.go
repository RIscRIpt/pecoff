package pecoff

import (
	"encoding/binary"
	"fmt"
)

type Import struct {
	file *File

	ImageImportDescriptor

	library   string
	functions []string
}

func NewImport(file *File, offset int64) (i *Import) {
	i = &Import{
		file: file,
	}
	file.read_at_into(offset, &i.ImageImportDescriptor)
	if !i.isEmpty() {
		return i
	} else {
		return nil
	}
}

func (i *Import) isEmpty() bool {
	return i.ImageImportDescriptor == ImageImportDescriptor{}
}

func (i *Import) Library() string {
	if i.library == "" {
		i.library = i.file.read_string_va(i.Name)
	}
	return i.library
}

func (i *Import) Functions() []string {
	if i.functions == nil {
		offset := i.file.va_to_offset(i.OriginalFirstThunk)
		for {
			t := i.newThunk(offset)
			if t.IsNull() {
				break
			}
			var newThunkName string
			if !t.IsOrdinal() {
				newThunkName = i.file.read_string_va(t.NameRVA() + 2)
			} else {
				newThunkName = fmt.Sprintf("#%d", t.Ordinal())
			}
			i.functions = append(i.functions, newThunkName)
			offset += int64(binary.Size(t))
		}
	}
	return i.functions
}

func (i *Import) newThunk(offset int64) (t Thunk) {
	if i.file.Is64Bit() {
		t = new(Thunk64)
	} else {
		t = new(Thunk32)
	}
	i.file.read_at_into(offset, t)
	return
}
