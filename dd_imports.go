package pecoff

import "encoding/binary"

type DD_Imports struct {
	DataDirectory
	imports []*Import
}

func NewImports(file *File, ddh DataDirectoryHeader) *DD_Imports {
	return &DD_Imports{
		DataDirectory: DataDirectory{
			file:   file,
			Header: ddh,
		},
	}
}

func (i *DD_Imports) Get() []*Import {
	if i.Header.Size > 0 && i.imports == nil {
		offset := i.file.va_to_offset(i.Header.VirtualAddress)
		for {
			newImport := NewImport(i.file, offset)
			if newImport == nil {
				break
			}
			i.imports = append(i.imports, newImport)
			offset += int64(binary.Size(newImport.ImageImportDescriptor))
		}
	}
	return i.imports
}
