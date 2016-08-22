package pecoff

import (
	"fmt"

	"github.com/RIscRIpt/pecoff/windef"
)

// DdImports is an imports data directory wrapper which holds
// imported libraries and their functions.
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
	if prevImp, exists := i.imports[imp.library]; !exists {
		i.imports[imp.library] = imp
	} else {
		// must not happen. Buf if it some how happens,
		// it's better to merge import functions, rather than rewriting.
		prevImp.merge(imp)
	}
}

// Get returns a map of imported functions, where the key is a library.
func (i *DdImports) Get() map[string]*Import {
	return i.imports
}

// Import returns a pointer to Import with specified library.
// If library is not imported, nil is returned.
func (i *DdImports) Import(library string) *Import {
	return i.imports[library]
}

// Import represents a collection of imported functions,
// which belong to one library.
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

func (i *Import) merge(other *Import) {
	if i.library != other.library {
		panic(fmt.Errorf(
			"pecoff: merging imports from different libraries ('%s' and '%s')",
			i.library, other.library,
		))
	}
	// FIXME: functions can be dupblicated.
	i.functions = append(i.functions, other.functions...)
}

// Library returns a library name,
// which has imported functions of the current import.
func (i *Import) Library() string {
	return i.library
}

// Functions returns a slice of ImportFunc
func (i *Import) Functions() []ImportFunc {
	return i.functions
}

// ImportFunc represents an import entry
// inside a PE import data directory, it has two fields:
//     - Hint: an index into the export name pointer table. A
//             match is attempted first with this value. If it
//             fails, a binary search is performed on the DLL’s
//             export name pointer table.
//     - Name: an ASCII string that contains the name to
//             import. This is the string that must be matched
//             to the public name in the DLL. This string is
//             case sensitive and terminated by a null byte.
type ImportFunc struct {
	Hint uint16
	Name string
}
