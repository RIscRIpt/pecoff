package pecoff

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/windef"
)

// List of supported pe/coff MachineTypes by this parser
var supportedMachineTypes = [...]uint16{
	windef.IMAGE_FILE_MACHINE_I386,
	windef.IMAGE_FILE_MACHINE_AMD64,
}

// List of errors
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
	ErrFailReadSymbols         = errors.New("pecoff: failed to read symbols")
	ErrFailReadStringTable     = errors.New("pecoff: failed to read string table")
	ErrFailReadSectionsHeaders = errors.New("pecoff: failed to read headers of sections")
	ErrFailReadSectionsData    = errors.New("pecoff: failed to read sections raw data")
	ErrFailReadSectionsRelocs  = errors.New("pecoff: failed to read relocations of sections")
	ErrFailReadSectionsLineNrs = errors.New("pecoff: failed to read line numbers of sections")
	ErrFailReadDataDirs        = errors.New("pecoff: failed to read data directories")
	ErrFailReadImports         = errors.New("pecoff: failed to read imports data directory")
	ErrFailReadBaseRelocs      = errors.New("pecoff: failed to read base relocations data directory")
	ErrFailCheckDosHeader      = errors.New("pecoff: failed to check whether the file has DOS header")

	// A group of errors which are to be formatted (used in errorf or wrapErrorf method)
	ErrfFailVaToOff             = "pecoff: failed to convert VA (@%08X) to file offset"                  //fmt: VirtualAddress
	ErrfFailGetSectByVA         = "pecoff: failed to find section which contains VA (@%08X)"             //fmt: VirtualAddress
	ErrfOptHdrUnkSize           = "pecoff: optionalHeader has unexpected size (%d)"                      //fmt: size
	ErrfFailReadSectionHeader   = "pecoff: failed to read a header of section#%d (%X)"                   //fmt: sectionId, offset
	ErrfFailReadSectionRawData  = "pecoff: failed to read rawdata of section#%d (%X)"                    //fmt: sectionId, offset
	ErrfFailReadSectionReloc    = "pecoff: failed to read relocation#%d of section #%d (%X)"             //fmt: relocationId, sectionId, offset
	ErrfFailReadSymbol          = "pecoff: failed to read symbol#%d (%X)"                                //fmt: symbolId, offset
	ErrfFailReadStrTblSize      = "pecoff: failed to read string table size (%X)"                        //fmt: offset
	ErrfFailReadStrTbl          = "pecoff: failed to read string table (%X)"                             //fmt: offset
	ErrfFailReadImpDesc         = "pecoff: failed to read import descriptor#%d (%X)"                     //fmt: descriptorId, offset
	ErrfFailReadLibName         = "pecoff: failed to read library name (@%08X)"                          //fmt: nameVA
	ErrfFailReadImpThunk        = "pecoff: failed to read import thunk (%X)"                             //fmt: offset
	ErrfFailReadImpThunkHint    = "pecoff: failed to read import thunk hint (@%08X)"                     //fmt: VirtualAddress
	ErrfFailReadImpThunkName    = "pecoff: failed to read import thunk name (@%08X)"                     //fmt: VirtualAddress
	ErrfFailReadBaseRel         = "pecoff: failed to read base relocation#%d (%X)"                       //fmt: relocationId, offset
	ErrfFailReadBaseRelEntries  = "pecoff: failed to read base relocation#%d entries (%X)"               //fmt: relocationId, offset
	ErrfFailFindBaseRelsFromInt = "pecoff: failed to find base relocations within interval [%08X; %08X)" //fmt: VirtualAddress, VirtualAddress
)

// File contains embedded io.Reader and all the fields of a PE/COFF file.
type File struct {
	binutil.ReaderAtInto
	DosHeader      *windef.DosHeader
	Signature      [4]byte
	FileHeader     *windef.FileHeader
	OptionalHeader *OptionalHeader
	Sections       *Sections
	Symbols        Symbols
	StringTable    StringTable
}

// Explore creates a new File object
func Explore(reader binutil.ReaderAtInto) *File {
	return &File{
		ReaderAtInto: reader,
	}
}

// Seal eliminates all external pointers (relatively to this package), so a
// File object can be long-term stored without holding any (useless) resources.
// For example after calling ReadAll method, and having all the data read from the file.
func (f *File) Seal() {
	f.ReaderAtInto = nil
}

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

// ReadVaInto is a wrapper method, which uses VaToOffset
// to convert virtual address `va` to a file offset
// and calls ReadAtInto method afterwards.
// If a call to VaToOffset fails, an error is returned.
func (f *File) ReadVaInto(p interface{}, va uint32) error {
	off, err := f.VaToOffset(va)
	if err != nil {
		return f.wrapErrorf(err, ErrfFailVaToOff, va)
	}
	return f.ReadAtInto(p, off)
}

// ReadStringVa is a wrapper method, which uses VaToOffset
// to convert virtual address `va` to a file offset
// and calls ReadStringAt method afterwards.
// If a call to VaToOffset fails, empty string and an error are returned.
func (f *File) ReadStringVa(va uint32, maxlen int) (string, error) {
	off, err := f.VaToOffset(va)
	if err != nil {
		return "", f.wrapErrorf(err, ErrfFailVaToOff, va)
	}
	return f.ReadStringAt(off, maxlen)
}

// ReadAll parses pe/coff file reading all the data of the file into the memory.
// Returns an error if any occured during the parsing.
func (f *File) ReadAll() (err error) {
	if err = f.ReadHeaders(); err != nil {
		return f.wrapError(err, ErrFailReadHeaders)
	}
	if err = f.ReadStringTable(); err != nil {
		return f.wrapError(err, ErrFailReadStringTable)
	}
	if err = f.ReadSymbols(); err != nil {
		return f.wrapError(err, ErrFailReadSymbols)
	}
	if err = f.ReadSectionsHeaders(); err != nil {
		return f.wrapError(err, ErrFailReadSectionsHeaders)
	}
	if err = f.ReadSectionsRawData(); err != nil {
		return f.wrapError(err, ErrFailReadSectionsData)
	}
	if err = f.ReadSectionsRelocations(); err != nil {
		return f.wrapError(err, ErrFailReadSectionsRelocs)
	}
	// if err = f.ReadSectionsLineNumbers(); err != nil {
	// 	return f.wrapError(err, ErrFailReadSectionsLineNrs)
	// }
	if f.OptionalHeader != nil {
		if err = f.ReadDataDirs(); err != nil {
			return f.wrapError(err, ErrFailReadDataDirs)
		}
	}
	return
}

// // WriteAll writes pe/coff file to `out`, and returns error if any
// func (f *File) WriteAll(out io.Writer) error {
// 	panic("not implemented")
// }

// VaToOffset returns a file offset which points to
// data pointed by `va` virtual address
func (f *File) VaToOffset(va uint32) (int64, error) {
	if f.Sections == nil {
		return 0, f.error(ErrNoSectionsHeaders)
	}
	s, err := f.Sections.GetByVA(va)
	if err != nil {
		return 0, f.wrapErrorf(err, ErrfFailGetSectByVA, va)
	}
	return s.VaToFileOffset(va), nil
}

// GetFileHeaderOffset returns an offset to the FileHeader within PE file.
// If DosHeader is nil (i.e. doesn't exists, or wasn't read), offset is
// returned in terms of a COFF file.
func (f *File) GetFileHeaderOffset() int64 {
	if f.DosHeader == nil {
		return windef.OFFSET_COFF_FILE_HEADER
	}
	return int64(f.DosHeader.E_lfanew) + int64(len(windef.PE_SIGN))
}

func (f *File) getOptHeaderOffset() int64 {
	return f.GetFileHeaderOffset() + int64(windef.SIZEOF_IMAGE_FILE_HEADER)
}

func (f *File) getSectionsHeadersOffset() int64 {
	return f.getOptHeaderOffset() + int64(f.FileHeader.SizeOfOptionalHeader)
}

func (f *File) getStringTableOffset() int64 {
	return int64(f.FileHeader.PointerToSymbolTable) + int64(f.FileHeader.NumberOfSymbols)*windef.SIZEOF_IMAGE_SYMBOL
}

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

// ReadSignature tries to read a signature ('PE\0\0')
// pointed by lfanew field of the DosHeader.
// Returns an error ErrNoDosHeader if DosHeader is not presented,
// or an error from ReadAtInto method, if any.
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

// ReadFileHeader reads PE/COFF file header.
// Returns an error ErrAlreadyRead, if it has already been read,
// or an error from ReadAtInto method, if any.
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

// ReadOptHeader reads an optional header of a PE file.
// FileHeader must be read before calling this method,
// otherwise an error ErrNoFileHeader is returned.
// Returns an error ErrAlreadyRead, if it has already been read,
// or an error from ReadAtInto method, if any.
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

// ReadSectionsHeaders reads headers of sections of a PE/COFF file.
// Returns an error ErrAlreadyRead, if it has already been read,
// or an error from ReadAtInto method, if any.
func (f *File) ReadSectionsHeaders() error {
	if f.FileHeader == nil {
		return f.error(ErrNoFileHeader)
	}
	if f.Sections != nil {
		return f.error(ErrAlreadyRead)
	}
	sections := newSections(int(f.FileHeader.NumberOfSections))
	baseOffset := f.getSectionsHeadersOffset()
	for i := range sections.array {
		s := new(Section)
		s.id = i
		offset := baseOffset + int64(i)*windef.SIZEOF_IMAGE_SECTION_HEADER
		if err := f.ReadAtInto(&s.SectionHeader, offset); err != nil {
			return f.wrapErrorf(err, ErrfFailReadSectionHeader, i, offset)
		}
		nullIndex := 0
		for nullIndex < 8 && s.Name[nullIndex] != 0 {
			nullIndex++
		}
		s.nameString = string(s.Name[:nullIndex])
		if s.Name[0] == '/' && f.StringTable != nil {
			// If section name contains garbage, just ignore it.
			// So, if something fails here (err != nil),
			// nothing critical happens can be safely ignored.
			strTblOffset, err := strconv.Atoi(string(s.Name[1:nullIndex]))
			if err == nil {
				nameString, err := f.StringTable.GetString(strTblOffset)
				if err == nil {
					s.nameString = nameString
				}
			}
		}
		sections.array[i] = s
	}
	// Sort is required for efficient work of Sections.GetByVA method,
	// which uses a binary search algorithm of sort.Search
	// to find a section by VirtualAddress.
	sections.sort()
	f.Sections = sections
	return nil
}

// ReadSectionsRawData reads contents (raw data) of all sections into memory.
// Headers of sections must be read before calling this method,
// otherwise an error ErrNoSectionsHeaders is returned.
// An error is returned if any occured while reading data.
func (f *File) ReadSectionsRawData() error {
	if f.Sections == nil {
		return f.error(ErrNoSectionsHeaders)
	}
	for i, s := range f.Sections.array {
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

// ReadSectionsRelocations reads relocations of all sections.
// Headers of sections must be read before calling this method,
// otherwise an error ErrNoSectionsHeaders is returned.
// An error is returned if any occured while reading data.
func (f *File) ReadSectionsRelocations() error {
	if f.Sections == nil {
		return f.error(ErrNoSectionsHeaders)
	}
	for i, s := range f.Sections.array {
		relocations := make([]windef.Relocation, s.NumberOfRelocations)
		for j := range relocations {
			offset := int64(s.PointerToRelocations) + int64(j)*windef.SIZEOF_IMAGE_RELOCATION
			if err := f.ReadAtInto(&relocations[j], offset); err != nil {
				return f.wrapErrorf(err, ErrfFailReadSectionReloc, j, i, offset)
			}
		}
		s.relocations = relocations
	}
	return nil
}

// ReadSectionsLineNumbers reads line numbers of all sections.
// Headers of sections must be read before calling this method,
// otherwise an error ErrNoSectionsHeaders is returned.
// An error is returned if any occured while reading data.
func (f *File) ReadSectionsLineNumbers() error {
	if f.Sections == nil {
		return f.error(ErrNoSectionsHeaders)
	}
	//TODO: implement this.
	return f.error(errors.New("pecoff: ReadSectionsLineNumbers is not implemented"))
}

// ReadSymbols reads all symbols from the symbol table.
// FileHeader must be read before calling this method,
// otherwise an error ErrNoFileHeader is returned.
// An error is returned if any occured while reading data.
func (f *File) ReadSymbols() error {
	if f.FileHeader == nil {
		return f.error(ErrNoFileHeader)
	}
	symbols := make(Symbols, int(f.FileHeader.NumberOfSymbols))
	baseOffset := int64(f.FileHeader.PointerToSymbolTable)
	for i := range symbols {
		s := new(Symbol)
		offset := baseOffset + int64(i)*windef.SIZEOF_IMAGE_SYMBOL
		if err := f.ReadAtInto(&s.Symbol, offset); err != nil {
			return f.wrapErrorf(err, ErrfFailReadSymbol, i, offset)
		}
		// If the name is longer than 8 bytes, first 4 bytes are set to zero
		// and the remaining 4 represent an offset into the string table.
		if *(*uint32)(unsafe.Pointer(&s.Name[0])) == 0 {
			strTblOffset := int(*(*uint32)(unsafe.Pointer(&s.Name[4])))
			nameString, err := f.StringTable.GetString(strTblOffset)
			if err == nil {
				s.nameString = nameString
			} else {
				s.nameString = fmt.Sprintf("/%d", strTblOffset)
			}
		} else {
			nullIndex := 0
			for nullIndex < 8 && s.Name[nullIndex] != 0 {
				nullIndex++
			}
			s.nameString = string(s.Name[:nullIndex])
		}
		symbols[i] = s
	}
	f.Symbols = symbols
	return nil
}

// ReadStringTable reads the whole COFF string table into the memory.
// FileHeader must be read before calling this method,
// otherwise an error ErrNoFileHeader is returned.
// An error is returned if any occured while reading data.
func (f *File) ReadStringTable() error {
	if f.FileHeader == nil {
		return f.error(ErrNoFileHeader)
	}
	offset := f.getStringTableOffset()
	// According to the Microsoft's PE/COFF file specification,
	// symbols and string table *should* only exist in the COFF files.
	// But some compilers of awesome languages (such as Go) ignore this fact,
	// and still have symbols and string table in the PE (.exe) files.
	// Also it's nothing told about if string table can exist w/o symbols, but
	// this is important as calculation of the pointer to the string table is based
	// on the FileHeader.PointerToSymbolTable and FileHeader.NumberOfSymbols.
	// So if offset is 0, there are apparently no symbols and no string table.
	if offset == 0 {
		return nil
	}
	var size uint32
	if err := f.ReadAtInto(&size, offset); err != nil {
		return f.wrapErrorf(err, ErrfFailReadStrTblSize, offset)
	}
	table := make([]byte, size)
	if _, err := f.ReadAt(table, offset); err != nil {
		return f.wrapErrorf(err, ErrfFailReadStrTbl, offset)
	}
	f.StringTable = table
	return nil
}

// ReadDataDirs calls methods which read a
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

// ReadDataDirImports reads import data directory of a PE file.
// OptionalHeader must be read before calling this method,
// otherwise an error ErrNoOptHeader is returned.
// Returns an error ErrAlreadyRead, if it has already been read,
// or an error from ReadAtInto method, if any.
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

// ReadDataDirBaseRels reads base relocations data directory of a PE file.
// OptionalHeader must be read before calling this method,
// otherwise an error ErrNoOptHeader is returned.
// Returns an error ErrAlreadyRead, if it has already been read,
// or an error from ReadAtInto method, if any.
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
	// Sort is required for efficient work of DdBaseRelocations.GetFromInterval
	// method which uses a binary search algorithm of sort.Search
	// to find base relocation block by its VirtualAddress.
	baseRels.sort()
	f.OptionalHeader.DataDirs.BaseRelocations = baseRels
	return nil
}
