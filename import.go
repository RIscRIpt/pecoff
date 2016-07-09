package pecoff

import "fmt"

type Import struct {
	file *File

	ImageImportDescriptor

	library   string
	functions map[string]int64
}

func NewImport(file *File, offset int64) (i *Import) {
	i = &Import{
		file: file,
	}
	file.ReadAtInto(offset, &i.ImageImportDescriptor)
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
		i.library = i.file.ReadStringVa(i.Name)
	}
	return i.library
}

func (i *Import) Functions() map[string]int64 {
	if i.functions == nil {
		i.functions = make(map[string]int64)
		offset := i.file.VaToOffset(i.OriginalFirstThunk)
		for {
			t := i.newThunk(offset)
			if t.IsNull() {
				break
			}
			var newThunkName string
			if !t.IsOrdinal() {
				newThunkName = i.file.ReadStringVa(t.NameRVA())
			} else {
				newThunkName = fmt.Sprintf("#%d", t.Ordinal())
			}
			i.functions[newThunkName] = offset
			offset += t.Size()
		}
	}
	return i.functions
}

func (i *Import) newThunk(offset int64) (t ImportThunk) {
	if i.file.Is64Bit() {
		t = new(ImportThunk64)
	} else {
		t = new(ImportThunk32)
	}
	i.file.ReadAtInto(offset, t)
	return
}

// func (i *Import) SetAddresses(addresses map[string]uint64) {
// 	for function := range addresses {
// 		s := i.file.Sections.GetByVA(i.functions[function])
// 		if i.file.Is64Bit() {
// 			s.WriteVA(va, addresses[function])
// 		} else {
// 			s.WriteVA(va, uint32(addresses[function]))
// 		}
// 	}
// }
