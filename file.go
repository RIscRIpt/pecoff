package pecoff

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
)

type File struct {
	*os.File

	*DosHeader
	*FileHeader
	OptionalHeader IOptionalHeader

	Sections

	//Exports         *DD_Exports
	Imports *DD_Imports
	//Resources       *DD_Resources
	//Exceptions      *DD_Exceptions
	//Security        *DD_Security
	BaseRelocations *DD_BaseRelocations
	//Debug           *DD_Debug
	//Architecture    *DD_Architecture
	//GlobalPtrs      *DD_GlobalPtrs
	//TLS             *DD_TLS
	//LoadConfig      *DD_LoadConfig
	//BoundImports    *DD_BoundImport
	//IAT             *DD_IAT
	//DelayImports    *DD_DelayImports
	//COMDescriptor   *DD_COMDescriptors
}

func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return &File{
		File: f,
	}, nil
}

func (f *File) Close() error {
	return f.File.Close()
}

func (f *File) ReadAll() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	f.read_headers()
	f.read_datadirectories()
	return nil
}

func (f *File) SaveAs(name string) error {
	panic("Not implemented")
}

func (f *File) Parse() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	f.read_headers()
	return nil
}

func (f *File) Is64Bit() bool {
	return f.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
}

// === File offsets getters === {{{1
func (f *File) get_dos_header_offset() int64 {
	return 0 //DOS Header is always in the beggining of the file (MZ)
}

func (f *File) get_coff_header_offset() int64 {
	if f.DosHeader != nil {
		return int64(f.DosHeader.E_lfanew) + 4
	} else {
		return 0
	}
}

func (f *File) get_opt_header_offset() int64 {
	return f.get_coff_header_offset() + int64(binary.Size(f.FileHeader))
}

func (f *File) get_sections_headers_offset() int64 {
	return f.get_opt_header_offset() + int64(f.FileHeader.SizeOfOptionalHeader)
}

// End File offsets getters }}}1
// === File read helpers === {{{1
func (f *File) seek(offset int64) {
	if _, err := f.Seek(offset, os.SEEK_SET); err != nil {
		panic(err)
	}
}

func (f *File) read_at_into(offset int64, data interface{}) {
	f.seek(offset)
	if err := binary.Read(f, binary.LittleEndian, data); err != nil {
		panic(err)
	}
}

func (f *File) va_to_offset(va uint32) int64 {
	i := sort.Search(f.Sections.Len(), func(i int) bool {
		return f.Sections[i].Header.VirtualAddress+f.Sections[i].Header.VirtualSize >= va
	})
	if i < f.Sections.Len() {
		return int64(va - f.Sections[i].Header.VirtualAddress + f.Sections[i].Header.PointerToRawData)
	} else {
		panic(fmt.Errorf("Failed to convert VA(%x) to the section's offset", va))
	}
}

func (f *File) read_va_into(va uint32, data interface{}) {
	f.read_at_into(f.va_to_offset(va), data)
}

func (f *File) read_string_at(offset int64) (line string) {
	f.seek(offset)
	line, err := bufio.NewReader(f).ReadString(0)
	if err != nil {
		panic(err)
	}
	return
}

func (f *File) read_string_va(va uint32) string {
	return f.read_string_at(f.va_to_offset(va))
}

/// End File read helpers }}}1
// === File checkers === {{{1
func (f *File) has_dos_header() bool {
	var sign [2]byte
	f.read_at_into(f.get_dos_header_offset(), &sign)
	return sign == MZ_SIGN
}

func (f *File) is_valid_pe_signature() bool {
	var sign [4]byte
	if f.DosHeader != nil /*&& f.DosHeader.e_lfanew == 0x3C*/ {
		f.read_at_into(int64(f.DosHeader.E_lfanew), &sign)
	}
	return sign == PE_SIGN
}

func (f *File) is_supported_machine() bool {
	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
	case IMAGE_FILE_MACHINE_AMD64:
	default:
		return false
	}
	return true
}

func (f *File) has_opt_header() bool {
	return f.FileHeader != nil && f.FileHeader.SizeOfOptionalHeader > 0
}

// End File checkers }}}1
// === File headers readers === {{{1
func (f *File) get_dd_header(id int) DataDirectoryHeader {
	if id < 0 || id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
		panic(fmt.Errorf("Invalid DataDirectory index (%d)", id))
	}
	return f.OptionalHeader.DD_Headers()[id]
}

func (f *File) read_headers() {
	if f.has_dos_header() {
		f.read_dos_header()
		if !f.is_valid_pe_signature() {
			panic(errors.New("Invalid PE Signature!"))
		}
	}
	f.read_coff_header()
	if !f.is_supported_machine() {
		panic(fmt.Errorf("Unsupported image file machine %04x", f.FileHeader.Machine))
	}
	if f.has_opt_header() {
		f.read_opt_header()
	}
	f.read_sections_headers()
}

func (f *File) read_dos_header() {
	f.DosHeader = new(DosHeader)
	f.read_at_into(f.get_dos_header_offset(), f.DosHeader)
}

func (f *File) read_coff_header() {
	f.FileHeader = new(FileHeader)
	f.read_at_into(f.get_coff_header_offset(), f.FileHeader)
}

func (f *File) read_opt_header() {
	switch f.FileHeader.SizeOfOptionalHeader {
	case SIZEOF_IMAGE_OPTIONAL_HEADER32:
		f.OptionalHeader = new(OptionalHeader32)
		f.read_at_into(f.get_opt_header_offset(), f.OptionalHeader)
	case SIZEOF_IMAGE_OPTIONAL_HEADER64:
		f.OptionalHeader = new(OptionalHeader64)
		f.read_at_into(f.get_opt_header_offset(), f.OptionalHeader)
	default:
		panic(fmt.Errorf("Unknown SizeOfOptionalHeader = %d", f.FileHeader.SizeOfOptionalHeader))
	}
}

func (f *File) read_sections_headers() {
	f.Sections = make(Sections, int(f.NumberOfSections))
	for i := 0; i < len(f.Sections); i++ {
		f.Sections[i] = NewSection(f, i)
	}
	sort.Sort(f.Sections)
}

// End File headers readers }}}1
// === File data directories readers === {{{1
func (f *File) read_datadirectories() {
	f.read_dd_imports()
	f.read_dd_baserelocations()
}

func (f *File) read_dd_imports() {
	ddh := f.get_dd_header(IMAGE_DIRECTORY_ENTRY_IMPORT)
	if ddh.Size != 0 {
		f.Imports = NewImports(f, ddh)
	}
}

func (f *File) read_dd_baserelocations() {
	ddh := f.get_dd_header(IMAGE_DIRECTORY_ENTRY_BASERELOC)
	if ddh.Size != 0 {
		f.BaseRelocations = NewBaseRelocations(f, ddh)
	}
}

// End File data directories readers === }}}1
