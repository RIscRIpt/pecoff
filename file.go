package pecoff

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
)

// List of supported pe/coff MachineTypes by this parser
var supportedMachineTypes = [...]uint16{
	windef.IMAGE_FILE_MACHINE_I386,
	windef.IMAGE_FILE_MACHINE_AMD64,
}

// List of errors {{{1
var (
	ErrAlreadyRead    = errors.New("pecoff: already read")
	ErrInvPeSign      = errors.New("pecoff: invalid PE signature")
	ErrUnsuppMachType = errors.New("pecoff: unsupported image file machine type")

	// A group of errors which are most-likey to be returned if a client
	// of this package is using Read* methods in a wrong order.
	ErrNoDosHeader       = errors.New("pecoff: dos header is not read")
	ErrNoFileHeader      = errors.New("pecoff: file header is not read")
	ErrNoOptHeader       = errors.New("pecoff: optional file header is not read")
	ErrNoSectionsHeaders = errors.New("pecoff: headers of sections are not read")

	// A group of errors which are returned by Read* wrapper methods, such as
	//     ReadAll, ReadHeaders, ReadSectionsRawData, ReadDataDirs, etc...
	// These errors specify what exatcly has been failed to read (or check).
	ErrFailReadHeaders         = errors.New("pecoff: failed to read headers")
	ErrFailReadDosHeader       = errors.New("pecoff: failed to read DOS header")
	ErrFailReadSignature       = errors.New("pecoff: failed to read PE signature")
	ErrFailReadFileHeader      = errors.New("pecoff: failed to read file header")
	ErrFailReadOptHeader       = errors.New("pecoff: failed to read optional file header")
	ErrFailReadSectionsHeaders = errors.New("pecoff: failed to read headers of sections")
	ErrFailReadSections        = errors.New("pecoff: failed to read sections")
	ErrFailReadDataDirs        = errors.New("pecoff: failed to read data directories")
	ErrFailReadImports         = errors.New("pecoff: failed to read imports data directory")
	ErrFailReadBaseRelocs      = errors.New("pecoff: failed to read base relocations data directory")
	ErrFailCheckDosHeader      = errors.New("pecoff: failed to check whether the file has DOS header")

	// A group of errors which are to be formatted (used in errorf or wrapErrorf method)
	ErrfFailVaToOff            = "pecoff: failed to convert VA (%08X) to file offset"      //fmt: VirtualAddress
	ErrfFailGetSectByVA        = "pecoff: failed to find section which contains VA (%08X)" //fmt: VirtualAddress
	ErrfOptHdrUnkSize          = "pecoff: optionalHeader has unexpected size (%d)"         //fmt: size
	ErrfFailReadSectionHeader  = "pecoff: failed to read a header of section#%d (@%X)"     //fmt: sectionId, offset
	ErrfFailReadSectionRawData = "pecoff: failed to read rawdata of section#%d (@%X)"      //fmt: sectionId, offset
	ErrfFailReadImpDesc        = "pecoff: failed to read import descriptor#%d (@%X)"       //fmt: descriptorId, offset
	ErrfFailReadLibName        = "pecoff: failed to read library name (%X)"                //fmt: nameVA
	ErrfFailReadImpThunk       = "pecoff: failed to read import thunk (%X)"                //fmt: offset
	ErrfFailReadImpThunkHint   = "pecoff: failed to read import thunk hint (@%X)"          //fmt: VirtualAddress
	ErrfFailReadImpThunkName   = "pecoff: failed to read import thunk name (@%X)"          //fmt: VirtualAddress
	ErrfFailReadBaseRel        = "pecoff: failed to read base relocation#%d (%X)"          //fmt: relocationId, offset
	ErrfFailReadBaseRelEntries = "pecoff: failed to read base relocation#%d entries (%X)"  //fmt: relocationId, offset
)

// End List of errors }}}1

// File contains embedded io.Reader and all the fields of a PE/COFF file.
type File struct {
	binutil.ReaderAtInto
	DosHeader      *windef.DosHeader
	Signature      [4]byte
	FileHeader     *windef.FileHeader
	OptionalHeader *OptionalHeader
	Sections       Sections

	// DebugErrors
	DebugErrors bool
}

// NewFile creates a new File object
func NewFile(reader binutil.ReaderAtInto) *File {
	return &File{
		ReaderAtInto: reader,
	}
}

// === File helper functions for error handling === {{{1

func (f *File) error(err error) error {
	return err
	// return &FileError{error: err}
}

func (f *File) wrapError(innerError error, outerError error) error {
	return &FileError{
		error:      outerError,
		innerError: innerError,
	}
}

func (f *File) errorf(format string, a ...interface{}) error {
	return f.error(fmt.Errorf(format, a...))
}

func (f *File) wrapErrorf(innerError error, format string, a ...interface{}) error {
	return f.wrapError(innerError, fmt.Errorf(format, a...))
}

// End File helper functions for error handling }}}1

// === File binary readers === {{{1

func (f *File) ReadVaInto(p interface{}, va uint32) error {
	off, err := f.VaToOffset(va)
	if err != nil {
		return f.wrapErrorf(err, ErrfFailVaToOff, va)
	}
	return f.ReadAtInto(p, off)
}

func (f *File) ReadStringVa(va uint32, maxlen int) (string, error) {
	off, err := f.VaToOffset(va)
	if err != nil {
		return "", f.wrapErrorf(err, ErrfFailVaToOff, va)
	}
	return f.ReadStringAt(off, maxlen)
}

// End File binary readers }}}1

// ReadAll parses pe/coff file reading all the data of the file into the memory
// Returns an error if any occured during the parsing
func (f *File) ReadAll() (err error) {
	if err = f.ReadHeaders(); err != nil {
		return f.wrapError(err, ErrFailReadHeaders)
	}
	if err = f.ReadSectionsRawData(); err != nil {
		return f.wrapError(err, ErrFailReadSections)
	}
	if err = f.ReadDataDirs(); err != nil {
		return f.wrapError(err, ErrFailReadDataDirs)
	}
	return
}

// WriteAll writes pe/coff file to `out`, and returns error if any
func (f *File) WriteAll(out io.Writer) error {
	panic("not implemented")
}

// VaToOffset returns a file offset which points to
// data pointed by `va` virtual address
func (f *File) VaToOffset(va uint32) (int64, error) {
	if f.Sections == nil {
		return 0, f.error(ErrNoSectionsHeaders)
	}
	s := f.Sections.GetByVA(va)
	if s == nil {
		return 0, f.errorf(ErrfFailGetSectByVA, va)
	}
	return s.VaToFileOffset(va), nil
}

// === File offsets getters === {{{1
// GetFileHeaderOffset returns an offset to the FileHeader within PE file.
// If DosHeader is nil (i.e. doesn't exists, or wasn't read), offset is
// returned in terms of a COFF file.
func (f *File) GetFileHeaderOffset() int64 {
	if f.DosHeader == nil {
		return windef.OFFSET_COFF_FILE_HEADER
	} else {
		return int64(f.DosHeader.E_lfanew) + int64(len(windef.PE_SIGN))
	}
}

func (f *File) getOptHeaderOffset() int64 {
	return f.GetFileHeaderOffset() + int64(windef.SIZEOF_IMAGE_FILE_HEADER)
}

func (f *File) getSectionsHeadersOffset() int64 {
	return f.getOptHeaderOffset() + int64(f.FileHeader.SizeOfOptionalHeader)
}

// End File offsets getters }}}1
// === File checkers === {{{1

// Is64Bit returns true if Machine type of file header equals to AMD64 or IA64
// If FileHeader is nil (i.e. wasn't read) an error ErrNoFileHeader is returned.
func (f *File) Is64Bit() (bool, error) {
	if f.FileHeader == nil {
		return false, f.error(ErrNoFileHeader)
	}
	return f.is64Bit(), nil
}

func (f *File) is64Bit() bool {
	return f.FileHeader.Machine == windef.IMAGE_FILE_MACHINE_AMD64 ||
		f.FileHeader.Machine == windef.IMAGE_FILE_MACHINE_IA64
}

// IsPe32Plus returns true if Magic field of optional header equals to HDR64_MAGIC.
// If OptionalHeader is nil (i.e. wasn't read) an error ErrNoOptHeader is returned.
func (f *File) IsPe32Plus() (bool, error) {
	if f.OptionalHeader == nil {
		return false, f.error(ErrNoOptHeader)
	}
	return f.isPe32Plus(), nil
}

func (f *File) isPe32Plus() bool {
	return f.OptionalHeader.Magic == windef.IMAGE_NT_OPTIONAL_HDR64_MAGIC
}

// HasDosHeader returns true if file has DOS header.
// If DosHeader is not nil (i.e. DOS header has already been read),
// true is returned straight away, otherwise first two bytes of a file are read
// and a result of comparison with ascii 'MZ' is returned instead.
// An error is returned only if it occured during the read.
func (f *File) HasDosHeader() (bool, error) {
	if f.DosHeader != nil {
		return true, nil
	}
	var sign [2]byte
	if err := f.ReadAtInto(&sign, windef.OFFSET_DOS_HEADER); err != nil {
		return false, err
	}
	return sign == windef.MZ_SIGN, nil
}

// IsValidPeSignature returns whether file Signature equals to the
// PE file signature ('PE\0\0').
func (f *File) IsValidPeSignature() bool {
	return f.Signature == windef.PE_SIGN
}

// IsSupportedMachineType returns true only if Machine type (in the FileHeader)
// is fully supported by all the functions in this package.
// If FileHeader is nil, an error ErrNoFileHeader is returned.
func (f *File) IsSupportedMachineType() (bool, error) {
	if f.FileHeader == nil {
		return false, f.error(ErrNoFileHeader)
	}
	return f.isSupportedMachineType(), nil
}

// isSupportedMachineType is an unsafe version of an exported function, which
// must be used only internally and only after FileHeader has been read.
func (f *File) isSupportedMachineType() bool {
	for _, sm := range supportedMachineTypes {
		if sm == f.FileHeader.Machine {
			return true
		}
	}
	return false
}

// HasOptHeader returns true if OptionalHeader has already been read or it can be read.
// Note: if FileHeader AND OptionalHeader hasn't been read,
// an error ErrNoFileHeader is returned.
func (f *File) HasOptHeader() (bool, error) {
	if f.OptionalHeader != nil {
		return true, nil
	}
	if f.FileHeader == nil {
		return false, f.error(ErrNoOptHeader)
	}
	return f.existsOptHeader(), nil
}

// existsOptHeader returns true if OptionalHeader exists in the current file.
func (f *File) existsOptHeader() bool {
	return f.FileHeader.SizeOfOptionalHeader > 0
}

// End File checkers }}}1
// === File headers readers === {{{1

// ReadHeaders reads:
//     - DosHeader (if it is presented in the file);
//     - Signature (if it is presented in the file), and validates it;
//     - FileHeader;
//     - OptionalHeader (if it is presented);
//     - Headers of sections;
// Returns error if any
func (f *File) ReadHeaders() (err error) {
	hasDosHeader, err := f.HasDosHeader()
	if err != nil {
		return f.wrapError(err, ErrFailCheckDosHeader)
	}
	if hasDosHeader {
		if err = f.ReadDosHeader(); err != nil {
			return f.wrapError(err, ErrFailReadDosHeader)
		}
		if err = f.ReadSignature(); err != nil {
			return f.wrapError(err, ErrFailReadSignature)
		}
		if !f.IsValidPeSignature() {
			return f.error(ErrInvPeSign)
		}
	}
	if err = f.ReadFileHeader(); err != nil {
		return f.wrapError(err, ErrFailReadFileHeader)
	}
	if !f.isSupportedMachineType() {
		return f.error(ErrUnsuppMachType)
	}
	if f.existsOptHeader() {
		if err := f.ReadOptHeader(); err != nil {
			return f.wrapError(err, ErrFailReadOptHeader)
		}
	}
	if err = f.ReadSectionsHeaders(); err != nil {
		return f.wrapError(err, ErrFailReadSectionsHeaders)
	}
	return nil
}

// ReadDosHeader reads DOS header from the file.
// If DosHeader has already been read an error ErrAlreadyRead is returned.
func (f *File) ReadDosHeader() error {
	if f.DosHeader != nil {
		return f.error(ErrAlreadyRead)
	}
	dosHeader := new(windef.DosHeader)
	if err := f.ReadAtInto(dosHeader, windef.OFFSET_DOS_HEADER); err != nil {
		return f.error(err)
	}
	f.DosHeader = dosHeader
	return nil
}

func (f *File) ReadSignature() error {
	if f.DosHeader == nil {
		return f.error(ErrNoDosHeader)
	}
	var signature [4]byte
	if err := f.ReadAtInto(&signature, int64(f.DosHeader.E_lfanew)); err != nil {
		return f.error(err)
	}
	//copy(f.Signature[:], signature[:])
	f.Signature = signature
	return nil
}

func (f *File) ReadFileHeader() error {
	if f.FileHeader != nil {
		return f.error(ErrAlreadyRead)
	}
	fileHeader := new(windef.FileHeader)
	if err := f.ReadAtInto(fileHeader, f.GetFileHeaderOffset()); err != nil {
		return f.error(err)
	}
	f.FileHeader = fileHeader
	return nil
}

func (f *File) ReadOptHeader() error {
	if f.FileHeader == nil {
		return f.error(ErrNoFileHeader)
	}
	if f.OptionalHeader != nil {
		return f.error(ErrAlreadyRead)
	}
	oh := new(OptionalHeader)
	switch f.FileHeader.SizeOfOptionalHeader {
	case windef.SIZEOF_IMAGE_OPTIONAL_HEADER32:
		var oh32 windef.OptionalHeader32
		if err := f.ReadAtInto(&oh32, f.getOptHeaderOffset()); err != nil {
			return f.error(err)
		}
		oh.From32(&oh32)
	case windef.SIZEOF_IMAGE_OPTIONAL_HEADER64:
		var oh64 windef.OptionalHeader64
		if err := f.ReadAtInto(&oh64, f.getOptHeaderOffset()); err != nil {
			return f.error(err)
		}
		oh.From64(&oh64)
	default:
		return f.errorf(ErrfOptHdrUnkSize, f.FileHeader.SizeOfOptionalHeader)
	}
	f.OptionalHeader = oh
	return nil
}

func (f *File) ReadSectionsHeaders() error {
	if f.FileHeader == nil {
		return f.error(ErrNoFileHeader)
	}
	if f.Sections != nil {
		return f.error(ErrAlreadyRead)
	}
	sections := make(Sections, int(f.FileHeader.NumberOfSections))
	baseOffset := f.getSectionsHeadersOffset()
	for i := range sections {
		s := new(Section)
		offset := baseOffset + int64(i*windef.SIZEOF_IMAGE_SECTION_HEADER)
		if err := f.ReadAtInto(&s.SectionHeader, offset); err != nil {
			return f.wrapErrorf(err, ErrfFailReadSectionHeader, i, offset)
		}
		nullIndex := 0
		for nullIndex < 8 && s.Name[nullIndex] != 0 {
			nullIndex++
		}
		//if s.Name[0] == '/' {
		//TODO: read a name of the section into a string, and
		//      add support for sections names which are longer than 8chars
		//      (contain a slash / and ASCII decimal offset in the string table)
		//      For more info read PE/COFF file specification.
		//} else {
		s.nameString = string(s.Name[:nullIndex])
		//}
		sections[i] = s
	}
	// Sort is required for efficient work of Sections.GetByVA method,
	// which uses a binary search algorithm of sort.Search
	// to find a section by VirtualAddress.
	sort.Sort(sections)
	f.Sections = sections
	return nil
}

// End File headers readers }}}1
// === File Sections contents readers === {{{1

func (f *File) ReadSectionsRawData() error {
	if f.Sections == nil {
		return f.error(ErrNoSectionsHeaders)
	}
	for i, s := range f.Sections {
		rawData := make([]byte, s.SizeOfRawData)
		if s.SizeOfRawData != 0 {
			if _, err := f.ReadAt(rawData, int64(s.PointerToRawData)); err != nil {
				return f.wrapErrorf(err, ErrfFailReadSectionRawData, i, s.PointerToRawData)
			}
		}
		s.rawData = rawData
	}
	return nil
}

// End File Sections contents readers }}}1
// === File DataDirectory readers === {{{1

func (f *File) ReadDataDirs() error {
	if f.OptionalHeader == nil {
		return f.error(ErrNoOptHeader)
	}
	var errors MultiError
	table := []struct {
		read    func() error
		failErr error
	}{
		// {f.ReadDataDirExports, ErrFailReadExports},
		{f.ReadDataDirImports, ErrFailReadImports},
		// {f.ReadDataDirResources, ErrFailReadResources},
		// {f.ReadDataDirExceptions, ErrFailReadExceptions},
		// {f.ReadDataDirSecurity, ErrFailReadSecurity},
		{f.ReadDataDirBaseRels, ErrFailReadBaseRelocs},
		// {f.ReadDataDirDebug, ErrFailReadDebug},
		// {f.ReadDataDirArchitecture, ErrFailReadArchitecture},
		// {f.ReadDataDirGlobalPtrs, ErrFailReadGlobalPtrs},
		// {f.ReadDataDirTLS, ErrFailReadTLS},
		// {f.ReadDataDirLoadConfig, ErrFailReadLoadConfig},
		// {f.ReadDataDirBoundImports, ErrFailReadBoundImports},
		// {f.ReadDataDirIAT, ErrFailReadIAT},
		// {f.ReadDataDirDelayImports, ErrFailReadDelayImports},
		// {f.ReadDataDirCOMDesc, ErrFailReadCOMDesc},
	}
	for _, m := range table {
		if err := m.read(); err != nil {
			errors = append(errors, f.wrapError(err, m.failErr))
		}
	}
	// don't return errors straight away,
	// because callerer's return value would always be non-nil otherwise.
	if len(errors) != 0 {
		return errors
	}
	return nil
}

func (f *File) ReadDataDirImports() (err error) {
	if f.OptionalHeader == nil {
		return f.error(ErrNoOptHeader)
	}
	if f.OptionalHeader.DataDirs.Imports != nil {
		return f.error(ErrAlreadyRead)
	}
	imports := newImports(f.OptionalHeader.DataDirectory[windef.IMAGE_DIRECTORY_ENTRY_IMPORT])
	if imports.Size > 0 {
		imports.offset, err = f.VaToOffset(imports.VirtualAddress)
		if err != nil {
			return f.wrapErrorf(err, ErrfFailVaToOff, imports.VirtualAddress)
		}
		var importThunk ImportThunk
		if f.isPe32Plus() {
			importThunk = new(ImportThunk64)
		} else {
			importThunk = new(ImportThunk32)
		}
		for {
			// Read ImportDescriptor
			i := imports.new()
			if err = f.ReadAtInto(&i.ImportDescriptor, i.offset); err != nil {
				return f.wrapErrorf(err, ErrfFailReadImpDesc, len(imports.imports), i.offset)
			}
			if i.OriginalFirstThunk == 0 {
				break
			}
			// Read contents
			var libName string
			var functions []ImportFunc
			var thunkOffset int64
			libName, err = f.ReadStringVa(i.Name, -1)
			if err != nil {
				return f.wrapErrorf(err, ErrfFailReadLibName, i.Name)
			}
			thunkOffset, err = f.VaToOffset(i.FirstThunk)
			if err != nil {
				return f.wrapErrorf(err, ErrfFailVaToOff, i.FirstThunk)
			}
			for {
				if err = f.ReadAtInto(importThunk, thunkOffset); err != nil {
					return f.wrapErrorf(err, ErrfFailReadImpThunk, thunkOffset)
				}
				if importThunk.IsNull() {
					break
				}
				var importFunc ImportFunc
				if !importThunk.IsOrdinal() {
					if err = f.ReadVaInto(&importFunc.Hint, importThunk.HintRVA()); err != nil {
						return f.wrapErrorf(err, ErrfFailReadImpThunkHint)
					}
					importFunc.Name, err = f.ReadStringVa(importThunk.NameRVA(), -1)
					if err != nil {
						return f.wrapErrorf(err, ErrfFailReadImpThunkName)
					}
				} else {
					importFunc.Hint = importThunk.Ordinal()
					importFunc.Name = fmt.Sprintf("#%d", importThunk.Ordinal())
				}
				functions = append(functions, importFunc)
				thunkOffset += importThunk.Size()
			}
			i.library = libName
			i.functions = functions
			imports.append(i)
		}
	}
	f.OptionalHeader.DataDirs.Imports = imports
	return nil
}

func (f *File) ReadDataDirBaseRels() (err error) {
	if f.OptionalHeader == nil {
		return f.error(ErrNoOptHeader)
	}
	baseRels := newBaseRels(f.OptionalHeader.DataDirectory[windef.IMAGE_DIRECTORY_ENTRY_BASERELOC])
	if baseRels.Size > 0 {
		baseRels.offset, err = f.VaToOffset(baseRels.VirtualAddress)
		if err != nil {
			return f.wrapErrorf(err, ErrfFailVaToOff, baseRels.VirtualAddress)
		}
		for {
			block := baseRels.new()
			if err = f.ReadAtInto(&block.BaseRelocation, block.offset); err != nil {
				return f.wrapErrorf(err, ErrfFailReadBaseRel, len(baseRels.blocks), block.offset)
			}
			if block.SizeOfBlock == 0 {
				break
			}
			block.entries = make([]BaseRelocationEntry, block.calcEntryCount())
			offset := block.offset + windef.SIZEOF_IMAGE_BASE_RELOCATION
			if err = f.ReadAtInto(block.entries, offset); err != nil {
				return f.wrapErrorf(err, ErrfFailReadBaseRelEntries, len(baseRels.blocks), offset)
			}
			baseRels.append(block)
		}
	}
	f.OptionalHeader.DataDirs.BaseRelocations = baseRels
	return nil
}

// End File DataDirectory readers }}}1
