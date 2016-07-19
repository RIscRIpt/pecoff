package pecoff

import "github.com/RIscRIpt/pecoff/windef"

// DdImports {{{1
type DdImports struct {
	windef.DataDirectory
	offset  int64
	imports map[string]*Import
}

func newImports(dd windef.DataDirectory) *DdImports {
	return &DdImports{
		DataDirectory: dd,
		imports:       make(map[string]*Import),
	}
}

// new returns a newImport which must be discarded,
// or passed to the append method afterwards.
func (i *DdImports) new() *Import {
	return newImport(i.offset + int64(len(i.imports)*windef.SIZEOF_IMAGE_IMPORT_DESCRIPTOR))
}

// append an Import returned from the method new
func (i *DdImports) append(imp *Import) {
	i.imports[imp.library] = imp
}

func (i *DdImports) Get() map[string]*Import {
	return i.imports
}

func (i *DdImports) Import(library string) *Import {
	return i.imports[library]
}

// End DdImports }}}1
// ImportThunk {{{1
type ImportThunk interface {
	IsNull() bool
	IsOrdinal() bool

	Ordinal() uint16
	HintRVA() uint32
	NameRVA() uint32

	Size() int64
}

type ImportThunk32 uint32
type ImportThunk64 uint64

func (t ImportThunk32) IsNull() bool { return t == 0 }
func (t ImportThunk64) IsNull() bool { return t == 0 }

func (t ImportThunk32) IsOrdinal() bool { return (t & 0x80000000) != 0 }
func (t ImportThunk64) IsOrdinal() bool { return (t & 0x8000000000000000) != 0 }

func (t ImportThunk32) Ordinal() uint16 { return uint16(t & 0xFFFF) }
func (t ImportThunk64) Ordinal() uint16 { return uint16(t & 0xFFFF) }

func (t ImportThunk32) HintRVA() uint32 { return uint32(t) }
func (t ImportThunk64) HintRVA() uint32 { return uint32(t) }
func (t ImportThunk32) NameRVA() uint32 { return uint32(t) + 2 }
func (t ImportThunk64) NameRVA() uint32 { return uint32(t) + 2 }

func (t ImportThunk32) Size() int64 { return 4 }
func (t ImportThunk64) Size() int64 { return 8 }

// End ImportThunk }}}1
// Import {{{1
type Import struct {
	windef.ImportDescriptor
	offset    int64
	library   string
	functions []ImportFunc
}

func newImport(offset int64) *Import {
	return &Import{
		offset: offset,
	}
}

func (i *Import) Library() string {
	return i.library
}

func (i *Import) Functions() []ImportFunc {
	return i.functions
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
// End Import }}}1
// ImportFunc {{{1
type ImportFunc struct {
	Hint uint16
	Name string
}

// End ImportFunc }}}1
