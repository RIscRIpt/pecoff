package pecoff

var (
	MZ_SIGN = [2]byte{'M', 'Z'}
	PE_SIGN = [4]byte{'P', 'E', 0, 0}
)

type DosHeader struct {
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for e_oeminfo)
	E_oeminfo  uint16     // OEM information; e_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   uint32     // File address of new exe header
}

const SIZEOF_IMAGE_DOS_HEADER = 64

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

const SIZEOF_IMAGE_FILE_HEADER = 20

type OptionalHeader_Standard struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
}

type OptionalHeader_Extension_FixedSize1 struct {
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
}

type OptionalHeader_Extension_FixedSize2 struct {
	LoaderFlags         uint32
	NumberOfRvaAndSizes uint32
}

type OptionalHeader32 struct {
	OptionalHeader_Standard
	BaseOfData uint32
	ImageBase  uint32
	OptionalHeader_Extension_FixedSize1
	SizeOfStackReserve uint32
	SizeOfStackCommit  uint32
	SizeOfHeapReserve  uint32
	SizeOfHeapCommit   uint32
	OptionalHeader_Extension_FixedSize2
	DataDirectoriesHeaders [16]DataDirectoryHeader
}

const SIZEOF_IMAGE_OPTIONAL_HEADER32 = 224

type OptionalHeader64 struct {
	OptionalHeader_Standard
	ImageBase uint64
	OptionalHeader_Extension_FixedSize1
	SizeOfStackReserve uint64
	SizeOfStackCommit  uint64
	SizeOfHeapReserve  uint64
	SizeOfHeapCommit   uint64
	OptionalHeader_Extension_FixedSize2
	DataDirectoriesHeaders [16]DataDirectoryHeader
}

const SIZEOF_IMAGE_OPTIONAL_HEADER64 = 240

type DataDirectoryHeader struct {
	VirtualAddress uint32
	Size           uint32
}

const SIZEOF_IMAGE_DATA_DIRECTORY_HEADER = 8

type SectionHeader struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

const SIZEOF_IMAGE_SECTION_HEADER = 40

type Relocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

const SIZEOF_IMAGE_RELOCATION = 10

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32 // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	Timestamp          uint32 // 0 if not bound, -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND) O.W. date/time stamp of DLL bound to (Old BIND)
	ForwarderChain     uint32 // -1 if no forwarders
	Name               uint32 // RVA of an ASCII string that contains the name of the DLL
	FirstThunk         uint32 // RVA to IAT (if bound this IAT has actual addresses)
}

const SIZEOF_IMAGE_IMPORT_DESCRIPTOR = 20

type ImageBaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

const SIZEOF_IMAGE_BASE_RELOCATION = 8
const SIZEOF_IMAGE_BASE_RELOCATION_ENTRY = 2

const (
	IMAGE_FILE_MACHINE_UNKNOWN   = 0x0
	IMAGE_FILE_MACHINE_AM33      = 0x1d3
	IMAGE_FILE_MACHINE_AMD64     = 0x8664
	IMAGE_FILE_MACHINE_ARM       = 0x1c0
	IMAGE_FILE_MACHINE_EBC       = 0xebc
	IMAGE_FILE_MACHINE_I386      = 0x14c
	IMAGE_FILE_MACHINE_IA64      = 0x200
	IMAGE_FILE_MACHINE_M32R      = 0x9041
	IMAGE_FILE_MACHINE_MIPS16    = 0x266
	IMAGE_FILE_MACHINE_MIPSFPU   = 0x366
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
	IMAGE_FILE_MACHINE_POWERPC   = 0x1f0
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
	IMAGE_FILE_MACHINE_R4000     = 0x166
	IMAGE_FILE_MACHINE_SH3       = 0x1a2
	IMAGE_FILE_MACHINE_SH3DSP    = 0x1a3
	IMAGE_FILE_MACHINE_SH4       = 0x1a6
	IMAGE_FILE_MACHINE_SH5       = 0x1a8
	IMAGE_FILE_MACHINE_THUMB     = 0x1c2
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
)

const (
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
)

const (
	IMAGE_REL_I386_ABSOLUTE = 0x0000 // Reference is absolute, no relocation is necessary
	IMAGE_REL_I386_DIR16    = 0x0001 // Direct 16-bit reference to the symbols virtual address
	IMAGE_REL_I386_REL16    = 0x0002 // PC-relative 16-bit reference to the symbols virtual address
	IMAGE_REL_I386_DIR32    = 0x0006 // Direct 32-bit reference to the symbols virtual address
	IMAGE_REL_I386_DIR32NB  = 0x0007 // Direct 32-bit reference to the symbols virtual address, base not included
	IMAGE_REL_I386_SEG12    = 0x0009 // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
	IMAGE_REL_I386_SECTION  = 0x000A
	IMAGE_REL_I386_SECREL   = 0x000B
	IMAGE_REL_I386_TOKEN    = 0x000C // clr token
	IMAGE_REL_I386_SECREL7  = 0x000D // 7 bit offset from base of section containing target
	IMAGE_REL_I386_REL32    = 0x0014 // PC-relative 32-bit reference to the symbols virtual address
)

const (
	IMAGE_REL_AMD64_ABSOLUTE = 0x0000 // Reference is absolute, no relocation is necessary
	IMAGE_REL_AMD64_ADDR64   = 0x0001 // 64-bit address (VA).
	IMAGE_REL_AMD64_ADDR32   = 0x0002 // 32-bit address (VA).
	IMAGE_REL_AMD64_ADDR32NB = 0x0003 // 32-bit address w/o image base (RVA).
	IMAGE_REL_AMD64_REL32    = 0x0004 // 32-bit relative address from byte following reloc
	IMAGE_REL_AMD64_REL32_1  = 0x0005 // 32-bit relative address from byte distance 1 from reloc
	IMAGE_REL_AMD64_REL32_2  = 0x0006 // 32-bit relative address from byte distance 2 from reloc
	IMAGE_REL_AMD64_REL32_3  = 0x0007 // 32-bit relative address from byte distance 3 from reloc
	IMAGE_REL_AMD64_REL32_4  = 0x0008 // 32-bit relative address from byte distance 4 from reloc
	IMAGE_REL_AMD64_REL32_5  = 0x0009 // 32-bit relative address from byte distance 5 from reloc
	IMAGE_REL_AMD64_SECTION  = 0x000A // Section index
	IMAGE_REL_AMD64_SECREL   = 0x000B // 32 bit offset from base of section containing target
	IMAGE_REL_AMD64_SECREL7  = 0x000C // 7 bit unsigned offset from base of section containing target
	IMAGE_REL_AMD64_TOKEN    = 0x000D // 32 bit metadata token
	IMAGE_REL_AMD64_SREL32   = 0x000E // 32 bit signed span-dependent value emitted into object
	IMAGE_REL_AMD64_PAIR     = 0x000F
	IMAGE_REL_AMD64_SSPAN32  = 0x0010 // 32 bit signed span-dependent value applied at link time
)

const (
	IMAGE_REL_BASED_ABSOLUTE           = 0
	IMAGE_REL_BASED_HIGH               = 1
	IMAGE_REL_BASED_LOW                = 2
	IMAGE_REL_BASED_HIGHLOW            = 3
	IMAGE_REL_BASED_HIGHADJ            = 4
	IMAGE_REL_BASED_MACHINE_SPECIFIC_5 = 5
	IMAGE_REL_BASED_RESERVED           = 6
	IMAGE_REL_BASED_MACHINE_SPECIFIC_7 = 7
	IMAGE_REL_BASED_MACHINE_SPECIFIC_8 = 8
	IMAGE_REL_BASED_MACHINE_SPECIFIC_9 = 9
	IMAGE_REL_BASED_DIR64              = 10
)
