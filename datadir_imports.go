package pecoff

type DdImports struct {
	DataDirectory
	imports []*Import
}

func NewDdImports(file *File, ddh DataDirectoryHeader) *DdImports {
	if ddh.Size <= 0 {
		return nil
	}
	return &DdImports{
		DataDirectory: DataDirectory{
			file:   file,
			Header: ddh,
		},
	}
}

func (i *DdImports) Get() []*Import {
	if i.imports == nil {
		offset := i.file.VaToOffset(i.Header.VirtualAddress)
		for {
			newImport := NewImport(i.file, offset)
			if newImport == nil {
				break
			}
			i.imports = append(i.imports, newImport)
			offset += int64(SIZEOF_IMAGE_IMPORT_DESCRIPTOR)
		}
	}
	return i.imports
}
