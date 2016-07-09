package pecoff

import (
	"errors"
	"fmt"
	"io"
)

// List of supported pe/coff MachineTypes by this parser
var supportedMachineTypes = [...]uint16{
	IMAGE_FILE_MACHINE_I386,
	IMAGE_FILE_MACHINE_AMD64,
}

// File contains embedded io.Reader and all the fields of a PE/COFF file.
type File struct {
	*BPReader
	DosHeader      *DosHeader
	FileHeader     *FileHeader
	OptionalHeader *OptionalHeader
	Sections       Sections
}

// NewFile creates a new File object
func NewFile(reader io.ReadSeeker) (f *File) {
	f = new(File)
	f.BPReader = NewBPReader(f, reader)
	return
}

// Parse parses pe/coff file reading all the header data of the file into memory
// Returns error if any occured during the parsing
func (f *File) Parse() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()
	f.ReadHeaders()
	f.ParseDataDirectories()
	f.ParseSections()
	return nil
}

// SaveAs writes pe/coff file to `out`, and returns error if any
func (f *File) SaveAs(out io.Writer) error {
	return errors.New("Not implemented")
}

// Is64Bit returns true if Machine of file header equals to AMD64
func (f *File) Is64Bit() bool {
	return f.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
}

// VaToOffset returns a file offset which points to
// data pointed by `va` virtual address
func (f *File) VaToOffset(va uint32) int64 {
	s := f.Sections.GetByVA(va)
	if s == nil {
		panic(fmt.Errorf("Failed to get a section by VA(%x)", va))
	}
	return s.VaToSectionOffset(va)
}

// === File offsets getters === {{{1
func (f *File) getDosHeaderOffset() int64 {
	return 0 //DOS Header is always in the beggining of the file (MZ)
}

func (f *File) getCoffHeaderOffset() int64 {
	if f.DosHeader != nil {
		return int64(f.DosHeader.E_lfanew) + 4
	} else {
		return 0
	}
}

func (f *File) getOptHeaderOffset() int64 {
	return f.getCoffHeaderOffset() + int64(SIZEOF_IMAGE_FILE_HEADER)
}

func (f *File) getSectionsHeadersOffset() int64 {
	return f.getOptHeaderOffset() + int64(f.FileHeader.SizeOfOptionalHeader)
}

// End File offsets getters }}}1
// === File checkers === {{{1
func (f *File) HasDosHeader() bool {
	var sign [2]byte
	f.ReadAtInto(f.getDosHeaderOffset(), &sign)
	return sign == MZ_SIGN
}

func (f *File) IsValidPeSignature() bool {
	var sign [4]byte
	if f.DosHeader != nil /*&& f.DosHeader.e_lfanew == 0x3C*/ {
		f.ReadAtInto(int64(f.DosHeader.E_lfanew), &sign)
	}
	return sign == PE_SIGN
}

func (f *File) IsSupportedMachine() bool {
	for _, sm := range supportedMachineTypes {
		if sm == f.FileHeader.Machine {
			return true
		}
	}
	return false
}

func (f *File) HasOptHeader() bool {
	return f.FileHeader != nil && f.FileHeader.SizeOfOptionalHeader > 0
}

// End File checkers }}}1
// === File headers readers === {{{1
func (f *File) ReadHeaders() {
	if f.HasDosHeader() {
		f.ReadDosHeader()
		if !f.IsValidPeSignature() {
			panic(errors.New("Invalid PE Signature!"))
		}
	}
	f.ReadCoffHeader()
	if !f.IsSupportedMachine() {
		panic(fmt.Errorf("Unsupported image file machine %04x", f.FileHeader.Machine))
	}
	if f.HasOptHeader() {
		f.ReadOptHeader()
	}
	f.ReadSectionsHeaders()
}

func (f *File) ReadDosHeader() {
	f.DosHeader = new(DosHeader)
	f.ReadAtInto(f.getDosHeaderOffset(), f.DosHeader)
}

func (f *File) ReadCoffHeader() {
	f.FileHeader = new(FileHeader)
	f.ReadAtInto(f.getCoffHeaderOffset(), f.FileHeader)
}

func (f *File) ReadOptHeader() {
	f.OptionalHeader = NewOptionalHeader(f, f.FileHeader.SizeOfOptionalHeader)
}

func (f *File) ReadSectionsHeaders() {
	f.Sections = NewSections(f, f.FileHeader.NumberOfSections)
}

// End File headers readers }}}1

func (f *File) ParseDataDirectories() {
	if f.OptionalHeader != nil && f.OptionalHeader.DataDirectories != nil {
		f.OptionalHeader.DataDirectories.Parse()
	}
}

func (f *File) ParseSections() {
	for _, s := range f.Sections {
		s.Parse()
	}
}
