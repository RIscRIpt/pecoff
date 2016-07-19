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
	ErrNotCloser        = errors.New("ReadSeeker has no Close() method")
	ErrNotImpl          = errors.New("not implemented")
	ErrNotReady         = errors.New("not ready")
	ErrAlrdyRead        = errors.New("already read")
	ErrInvPeSign        = errors.New("invalid PE signature")
	ErrUnsuppMachType   = errors.New("unsupported image file machine type")
	ErrSectByVaNotFound = errors.New("failed to find section by its' VA")
	ErrOptHdrUxSize     = errors.New("optionalHeader has unexpected size")
	ErrInvDataDirId     = errors.New("invalid DataDirectory id")
)

// End List of errors }}}1

const (
	FuncClose                  = "Close"
	FuncHasDosHeader           = "HasDosHeader"
	FuncHasOptHeader           = "HasOptHeader"
	FuncIs64Bit                = "Is64Bit"
	FuncIsPe32Plus             = "IsPe32Plus"
	FuncIsSupportedMachineType = "IsSupportedMachineType"
	FuncIsValidPeSignature     = "IsValidPeSignature"
	FuncReadAll                = "ReadAll"
	FuncReadDataDirBaseRels    = "ReadDataDirBaseRels"
	FuncReadDataDirImports     = "ReadDataDirImports"
	FuncReadDataDirs           = "ReadDataDirs"
	FuncReadDosHeader          = "ReadDosHeader"
	FuncReadFileHeader         = "ReadFileHeader"
	FuncReadHeaders            = "ReadHeaders"
	FuncReadOptHeader          = "ReadOptHeader"
	FuncReadSections           = "ReadSections"
	FuncReadSectionsHeaders    = "ReadSectionsHeaders"
	FuncReadSignature          = "ReadSignature"
	FuncReadStringAt           = "ReadStringAt"
	FuncReadStringVa           = "ReadStringVa"
	FuncReadVaInto             = "ReadVaInto"
	FuncVaToOffset             = "VaToOffset"
	FuncWriteAll               = "WriteAll"
)

type internalError struct {
	sourceFunc string
	details    error
}

func Error(source string, details error) error {
	return &internalError{
		sourceFunc: source,
		details:    details,
	}
}

func (e *internalError) Error() string {
	if Err, ok := e.details.(*internalError); ok {
		return e.sourceFunc + " > " + Err.Error()
	} else {
		return e.sourceFunc + ": " + e.details.Error()
	}
}

// File contains embedded io.Reader and all the fields of a PE/COFF file.
type File struct {
	binutil.ReaderAtInto
	DosHeader      *windef.DosHeader
	Signature      [4]byte
	FileHeader     *windef.FileHeader
	OptionalHeader *OptionalHeader
	Sections       Sections
}

// NewFile creates a new File object
func NewFile(reader binutil.ReaderAtInto) *File {
	return &File{
		ReaderAtInto: reader,
	}
}

func (f *File) Close() error {
	if closer, ok := f.ReaderAtInto.(io.Closer); ok {
		return closer.Close()
	} else {
		return Error(FuncClose, ErrNotCloser)
	}
}

// === File binary readers === {{{1

func (f *File) ReadVaInto(p interface{}, va uint32) error {
	off, err := f.VaToOffset(va)
	if err != nil {
		return Error(FuncReadVaInto, err)
	}
	return f.ReadAtInto(p, off)
}

func (f *File) ReadStringVa(va uint32, maxlen int) (string, error) {
	off, err := f.VaToOffset(va)
	if err != nil {
		return "", Error(FuncReadStringVa, err)
	}
	return f.ReadStringAt(off, maxlen)
}

// End File binary readers }}}1

// ReadAll parses pe/coff file reading all the data of the file into the memory
// Returns an error if any occured during the parsing
func (f *File) ReadAll() (err error) {
	if err = f.ReadHeaders(); err != nil {
		return Error(FuncReadAll, err)
	}
	if err = f.ReadSections(); err != nil {
		return Error(FuncReadAll, err)
	}
	if err = f.ReadDataDirs(); err != nil {
		return Error(FuncReadAll, err)
	}
	return
}

// WriteAll writes pe/coff file to `out`, and returns error if any
func (f *File) WriteAll(out io.Writer) error {
	return Error(FuncWriteAll, ErrNotImpl)
}

// VaToOffset returns a file offset which points to
// data pointed by `va` virtual address
func (f *File) VaToOffset(va uint32) (int64, error) {
	if f.Sections == nil {
		return 0, Error(FuncVaToOffset, ErrNotReady)
	}
	s := f.Sections.GetByVA(va)
	if s == nil {
		return 0, Error(FuncVaToOffset, ErrSectByVaNotFound)
	}
	return s.VaToFileOffset(va), nil
}

// === File offsets getters === {{{1
func (f *File) getDosHeaderOffset() int64 {
	return 0 //DOS Header is always in the beggining of the file (MZ)
}

func (f *File) getSignatureOffset() int64 {
	if f.DosHeader != nil {
		return int64(f.DosHeader.E_lfanew)
	} else {
		return 0
	}
}

func (f *File) getFileHeaderOffset() int64 {
	if f.DosHeader == nil {
		return 0
	} else {
		return f.getSignatureOffset() + int64(len(windef.PE_SIGN))
	}
}

func (f *File) getOptHeaderOffset() int64 {
	return f.getFileHeaderOffset() + int64(windef.SIZEOF_IMAGE_FILE_HEADER)
}

func (f *File) getSectionsHeadersOffset() int64 {
	return f.getOptHeaderOffset() + int64(f.FileHeader.SizeOfOptionalHeader)
}

// End File offsets getters }}}1
// === File checkers === {{{1

// Is64Bit returns true if Machine of file header equals to AMD64 or IA64
func (f *File) Is64Bit() (bool, error) {
	if f.FileHeader == nil {
		return false, Error(FuncIs64Bit, ErrNotReady)
	}
	return f.is64Bit(), nil
}

func (f *File) is64Bit() bool {
	return f.FileHeader.Machine == windef.IMAGE_FILE_MACHINE_AMD64 ||
		f.FileHeader.Machine == windef.IMAGE_FILE_MACHINE_IA64
}

func (f *File) IsPe32Plus() (bool, error) {
	if f.OptionalHeader == nil {
		return false, Error(FuncIsPe32Plus, ErrNotReady)
	}
	return f.isPe32Plus(), nil
}

func (f *File) isPe32Plus() bool {
	return f.OptionalHeader.Magic == windef.IMAGE_NT_OPTIONAL_HDR64_MAGIC
}

func (f *File) HasDosHeader() (bool, error) {
	// If DosHeader or DosSign has already been read, return true
	if f.DosHeader != nil {
		return true, nil
	}
	var sign [2]byte
	if err := f.ReadAtInto(&sign, f.getDosHeaderOffset()); err != nil {
		return false, Error(FuncHasDosHeader, err)
	}
	return sign == windef.MZ_SIGN, nil
}

func (f *File) IsValidPeSignature() bool {
	return f.Signature == windef.PE_SIGN
}

func (f *File) IsSupportedMachineType() (bool, error) {
	if f.FileHeader == nil {
		return false, Error(FuncIsSupportedMachineType, ErrNotReady)
	}
	for _, sm := range supportedMachineTypes {
		if sm == f.FileHeader.Machine {
			return true, nil
		}
	}
	return false, nil
}

// HasOptHeader returns true if OptionalHeader has been read or it can be read.
// Note: if FileHeader AND OptionalHeader hasn't been read, false is returned.
func (f *File) HasOptHeader() (bool, error) {
	if f.OptionalHeader != nil {
		return true, nil
	}
	if f.FileHeader == nil {
		return false, Error(FuncHasOptHeader, ErrNotReady)
	}
	return f.FileHeader.SizeOfOptionalHeader > 0, nil
}

// End File checkers }}}1
// === File headers readers === {{{1

// ReadHeaders reads:
//     - DosHeader (if it is presented)
//     - Signature (if it is presented), and validates it
//     - FileHeader
//     - OptionalHeader (if it is presented)
//     - Headers of sections
// Returns error if any
func (f *File) ReadHeaders() (err error) {
	hasDosHeader, err := f.HasDosHeader()
	if err != nil {
		return Error(FuncReadHeaders, err)
	}
	if hasDosHeader {
		if err = f.ReadDosHeader(); err != nil {
			return Error(FuncReadHeaders, err)
		}
		if err = f.ReadSignature(); err != nil {
			return Error(FuncReadHeaders, err)
		}
		if !f.IsValidPeSignature() {
			return Error(FuncReadHeaders, ErrInvPeSign)
		}
	}
	if err = f.ReadFileHeader(); err != nil {
		return Error(FuncReadHeaders, err)
	}
	suppMachineType, err := f.IsSupportedMachineType()
	if err != nil {
		return Error(FuncReadHeaders, err)
	}
	if !suppMachineType {
		return Error(FuncReadHeaders, ErrUnsuppMachType)
	}
	hasOptHdr, err := f.HasOptHeader()
	if err != nil {
		return Error(FuncReadHeaders, err)
	}
	if hasOptHdr {
		if err := f.ReadOptHeader(); err != nil {
			return Error(FuncReadHeaders, err)
		}
	}
	if err = f.ReadSectionsHeaders(); err != nil {
		return Error(FuncReadHeaders, err)
	}
	return nil
}

func (f *File) ReadDosHeader() error {
	if f.DosHeader != nil {
		return Error(FuncReadDosHeader, ErrAlrdyRead)
	}
	f.DosHeader = new(windef.DosHeader)
	return f.ReadAtInto(f.DosHeader, f.getDosHeaderOffset())
}

func (f *File) ReadSignature() error {
	if f.DosHeader == nil {
		return Error(FuncReadSignature, ErrNotReady)
	}
	return f.ReadAtInto(&f.Signature, int64(f.DosHeader.E_lfanew))
}

func (f *File) ReadFileHeader() error {
	if f.FileHeader != nil {
		return Error(FuncReadFileHeader, ErrAlrdyRead)
	}
	f.FileHeader = new(windef.FileHeader)
	return f.ReadAtInto(f.FileHeader, f.getFileHeaderOffset())
}

func (f *File) ReadOptHeader() error {
	if f.FileHeader == nil {
		return Error(FuncReadOptHeader, ErrNotReady)
	}
	if f.OptionalHeader != nil {
		return Error(FuncReadOptHeader, ErrAlrdyRead)
	}
	oh := new(OptionalHeader)
	switch f.FileHeader.SizeOfOptionalHeader {
	case windef.SIZEOF_IMAGE_OPTIONAL_HEADER32:
		var oh32 windef.OptionalHeader32
		if err := f.ReadAtInto(&oh32, f.getOptHeaderOffset()); err != nil {
			return Error(FuncReadOptHeader, err)
		}
		oh.Generalize32(&oh32)
	case windef.SIZEOF_IMAGE_OPTIONAL_HEADER64:
		var oh64 windef.OptionalHeader64
		if err := f.ReadAtInto(&oh64, f.getOptHeaderOffset()); err != nil {
			return Error(FuncReadOptHeader, err)
		}
		oh.Generalize64(&oh64)
	default:
		return Error(FuncReadOptHeader, ErrOptHdrUxSize)
	}
	f.OptionalHeader = oh
	return nil
}

func (f *File) ReadSectionsHeaders() error {
	if f.FileHeader == nil {
		return Error(FuncReadSectionsHeaders, ErrNotReady)
	}
	if f.Sections != nil {
		return Error(FuncReadSectionsHeaders, ErrAlrdyRead)
	}
	sections := make(Sections, int(f.FileHeader.NumberOfSections))
	for i := range sections {
		s := new(Section)
		if err := f.ReadAtInto(&s.SectionHeader, f.getSectionsHeadersOffset()+int64(i*windef.SIZEOF_IMAGE_SECTION_HEADER)); err != nil {
			return Error(FuncReadSectionsHeaders, err)
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
	sort.Sort(sections)
	f.Sections = sections
	return nil
}

// End File headers readers }}}1
// === File Sections contents readers === {{{1

func (f *File) ReadSections() error {
	if f.Sections == nil {
		return Error(FuncReadSections, ErrNotReady)
	}
	for _, s := range f.Sections {
		rawData := make([]byte, s.SizeOfRawData)
		if s.SizeOfRawData != 0 {
			if _, err := f.ReadAt(rawData, int64(s.PointerToRawData)); err != nil {
				return Error(FuncReadSections, err)
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
		return Error(FuncReadDataDirs, ErrNotReady)
	}
	//f.ReadDataDirExports()
	if err := f.ReadDataDirImports(); err != nil {
		return Error(FuncReadDataDirs, err)
	}
	//f.ReadDataDirResources()
	//f.ReadDataDirExceptions()
	//f.ReadDataDirSecurity()
	if err := f.ReadDataDirBaseRels(); err != nil {
		return Error(FuncReadDataDirs, err)
	}
	//f.ReadDataDirDebug()
	//f.ReadDataDirArchitecture()
	//f.ReadDataDirGlobalPtrs()
	//f.ReadDataDirTLS()
	//f.ReadDataDirLoadConfig()
	//f.ReadDataDirBoundImports()
	//f.ReadDataDirIAT()
	//f.ReadDataDirDelayImports()
	//f.ReadDataDirCOMDesc()
	return nil
}

func (f *File) ReadDataDirImports() (err error) {
	if f.OptionalHeader == nil {
		return Error(FuncReadDataDirImports, ErrNotReady)
	}
	if f.OptionalHeader.DataDirs.Imports != nil {
		return Error(FuncReadDataDirImports, ErrAlrdyRead)
	}
	imports := newImports(f.OptionalHeader.DataDirectory[windef.IMAGE_DIRECTORY_ENTRY_IMPORT])
	if imports.Size > 0 {
		imports.offset, err = f.VaToOffset(imports.VirtualAddress)
		if err != nil {
			return Error(FuncReadDataDirImports, err)
		}
		for {
			// Read ImportDescriptor
			i := imports.new()
			if err = f.ReadAtInto(&i.ImportDescriptor, i.offset); err != nil {
				return Error(FuncReadDataDirImports, err)
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
				return Error(FuncReadDataDirImports, err)
			}
			thunkOffset, err = f.VaToOffset(i.FirstThunk)
			if err != nil {
				return Error(FuncReadDataDirImports, err)
			}
			for {
				var t ImportThunk
				if f.isPe32Plus() {
					t = new(ImportThunk64)
				} else {
					t = new(ImportThunk32)
				}
				if err = f.ReadAtInto(t, thunkOffset); err != nil {
					return Error(FuncReadDataDirImports, err)
				}
				if t.IsNull() {
					break
				}
				var importFunc ImportFunc
				if !t.IsOrdinal() {
					err = f.ReadVaInto(&importFunc.Hint, t.HintRVA())
					if err != nil {
						return Error(FuncReadDataDirImports, err)
					}
					importFunc.Name, err = f.ReadStringVa(t.NameRVA(), -1)
					if err != nil {
						return Error(FuncReadDataDirImports, err)
					}
				} else {
					importFunc.Hint = t.Ordinal()
					importFunc.Name = fmt.Sprintf("#%d", t.Ordinal())
				}
				functions = append(functions, importFunc)
				thunkOffset += t.Size()
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
		return Error(FuncReadDataDirBaseRels, ErrNotReady)
	}
	baseRels := newBaseRels(f.OptionalHeader.DataDirectory[windef.IMAGE_DIRECTORY_ENTRY_BASERELOC])
	if baseRels.Size > 0 {
		baseRels.offset, err = f.VaToOffset(baseRels.VirtualAddress)
		if err != nil {
			return Error(FuncReadDataDirBaseRels, err)
		}
		for {
			block := baseRels.new()
			if err = f.ReadAtInto(&block.BaseRelocation, block.offset); err != nil {
				return Error(FuncReadDataDirBaseRels, err)
			}
			if block.SizeOfBlock == 0 {
				break
			}
			block.entries = make([]BaseRelocationEntry, block.calcEntryCount())
			if err = f.ReadAtInto(block.entries, block.offset+windef.SIZEOF_IMAGE_BASE_RELOCATION); err != nil {
				return Error(FuncReadDataDirBaseRels, err)
			}
			baseRels.append(block)
		}
	}
	f.OptionalHeader.DataDirs.BaseRelocations = baseRels
	return nil
}

// End File DataDirectory readers }}}1
