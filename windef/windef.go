package windef

// Constant offsets within PE/COFF files
const (
	OFFSET_DOS_HEADER = 0 //If exists, DOS Header is always in the beggining of the file (MZ).

	OFFSET_COFF_FILE_HEADER = 0 //MS COFF always begins with FileHeader
)

// Sizes
const (
	SIZEOF_IMAGE_DOS_HEADER            = 64
	SIZEOF_IMAGE_FILE_HEADER           = 20
	SIZEOF_IMAGE_OPTIONAL_HEADER32     = 224
	SIZEOF_IMAGE_OPTIONAL_HEADER64     = 240
	SIZEOF_IMAGE_DATA_DIRECTORY_HEADER = 8
	SIZEOF_IMAGE_SECTION_HEADER        = 40
	SIZEOF_IMAGE_RELOCATION            = 10
	SIZEOF_IMAGE_IMPORT_DESCRIPTOR     = 20
	SIZEOF_IMAGE_BASE_RELOCATION       = 8
	SIZEOF_IMAGE_BASE_RELOCATION_ENTRY = 2
)

// Signatures
var (
	MZ_SIGN = [2]byte{'M', 'Z'}
	PE_SIGN = [4]byte{'P', 'E', 0, 0}
)

// PE/COFF types
type (
	// DOS Header
	DosHeader struct {
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

	// COFF File Header (presented in both Object and Image files)
	FileHeader struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	// Complete OptionalHeader for 32bit images
	OptionalHeader32 struct {
		Magic                       uint16
		MajorLinkerVersion          uint8
		MinorLinkerVersion          uint8
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint32
		ImageBase                   uint32
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
		SizeOfStackReserve          uint32
		SizeOfStackCommit           uint32
		SizeOfHeapReserve           uint32
		SizeOfHeapCommit            uint32
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               [16]DataDirectory
	}

	// Complete OptionalHeader for 64bit images
	OptionalHeader64 struct {
		Magic                       uint16
		MajorLinkerVersion          uint8
		MinorLinkerVersion          uint8
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		ImageBase                   uint64
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
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               [16]DataDirectory
	}

	// Complete OptionalHeader which can be used to contain any of OptionalHeader (32/64bit)
	OptionalHeaderCommon struct {
		Magic                       uint16
		MajorLinkerVersion          uint8
		MinorLinkerVersion          uint8
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint64
		ImageBase                   uint64
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
		SizeOfStackReserve          uint64
		SizeOfStackCommit           uint64
		SizeOfHeapReserve           uint64
		SizeOfHeapCommit            uint64
		LoaderFlags                 uint32
		NumberOfRvaAndSizes         uint32
		DataDirectory               [16]DataDirectory
	}

	// DataDirectory header
	DataDirectory struct {
		VirtualAddress uint32
		Size           uint32
	}

	SectionHeader struct {
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

	Relocation struct {
		VirtualAddress   uint32
		SymbolTableIndex uint32
		Type             uint16
	}

	ImportDescriptor struct {
		OriginalFirstThunk uint32 // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
		Timestamp          uint32 // 0 if not bound, -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND) O.W. date/time stamp of DLL bound to (Old BIND)
		ForwarderChain     uint32 // -1 if no forwarders
		Name               uint32 // RVA of an ASCII string that contains the name of the DLL
		FirstThunk         uint32 // RVA to IAT (if bound this IAT has actual addresses)
	}

	BaseRelocation struct {
		VirtualAddress uint32
		SizeOfBlock    uint32
	}
)

// Image file machine types
const (
	IMAGE_FILE_MACHINE_UNKNOWN   uint16 = 0x0
	IMAGE_FILE_MACHINE_AM33      uint16 = 0x1d3
	IMAGE_FILE_MACHINE_AMD64     uint16 = 0x8664
	IMAGE_FILE_MACHINE_ARM       uint16 = 0x1c0
	IMAGE_FILE_MACHINE_EBC       uint16 = 0xebc
	IMAGE_FILE_MACHINE_I386      uint16 = 0x14c
	IMAGE_FILE_MACHINE_IA64      uint16 = 0x200
	IMAGE_FILE_MACHINE_M32R      uint16 = 0x9041
	IMAGE_FILE_MACHINE_MIPS16    uint16 = 0x266
	IMAGE_FILE_MACHINE_MIPSFPU   uint16 = 0x366
	IMAGE_FILE_MACHINE_MIPSFPU16 uint16 = 0x466
	IMAGE_FILE_MACHINE_POWERPC   uint16 = 0x1f0
	IMAGE_FILE_MACHINE_POWERPCFP uint16 = 0x1f1
	IMAGE_FILE_MACHINE_R4000     uint16 = 0x166
	IMAGE_FILE_MACHINE_SH3       uint16 = 0x1a2
	IMAGE_FILE_MACHINE_SH3DSP    uint16 = 0x1a3
	IMAGE_FILE_MACHINE_SH4       uint16 = 0x1a6
	IMAGE_FILE_MACHINE_SH5       uint16 = 0x1a8
	IMAGE_FILE_MACHINE_THUMB     uint16 = 0x1c2
	IMAGE_FILE_MACHINE_WCEMIPSV2 uint16 = 0x169
)

var MAP_IMAGE_FILE_MACHINE = map[uint16]string{
	IMAGE_FILE_MACHINE_UNKNOWN:   "UNKNOWN",
	IMAGE_FILE_MACHINE_AM33:      "AM33",
	IMAGE_FILE_MACHINE_AMD64:     "AMD64",
	IMAGE_FILE_MACHINE_ARM:       "ARM",
	IMAGE_FILE_MACHINE_EBC:       "EBC",
	IMAGE_FILE_MACHINE_I386:      "I386",
	IMAGE_FILE_MACHINE_IA64:      "IA64",
	IMAGE_FILE_MACHINE_M32R:      "M32R",
	IMAGE_FILE_MACHINE_MIPS16:    "MIPS16",
	IMAGE_FILE_MACHINE_MIPSFPU:   "MIPSFPU",
	IMAGE_FILE_MACHINE_MIPSFPU16: "MIPSFPU16",
	IMAGE_FILE_MACHINE_POWERPC:   "POWERPC",
	IMAGE_FILE_MACHINE_POWERPCFP: "POWERPCFP",
	IMAGE_FILE_MACHINE_R4000:     "R4000",
	IMAGE_FILE_MACHINE_SH3:       "SH3",
	IMAGE_FILE_MACHINE_SH3DSP:    "SH3DSP",
	IMAGE_FILE_MACHINE_SH4:       "SH4",
	IMAGE_FILE_MACHINE_SH5:       "SH5",
	IMAGE_FILE_MACHINE_THUMB:     "THUMB",
	IMAGE_FILE_MACHINE_WCEMIPSV2: "WCEMIPSV2",
}

// File header characteristics
const (
	IMAGE_FILE_RELOCS_STRIPPED         = 0x0001 // Relocation info stripped from file.
	IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002 // File is executable  (i.e. no unresolved external references).
	IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004 // Line nunbers stripped from file.
	IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008 // Local symbols stripped from file.
	IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010 // Aggressively trim working set
	IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020 // App can handle >2gb addresses
	IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080 // Bytes of machine word are reversed.
	IMAGE_FILE_32BIT_MACHINE           = 0x0100 // 32 bit word machine.
	IMAGE_FILE_DEBUG_STRIPPED          = 0x0200 // Debugging info stripped from file in .DBG file
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 // If Image is on removable media, copy and run from the swap file.
	IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800 // If Image is on Net, copy and run from the swap file.
	IMAGE_FILE_SYSTEM                  = 0x1000 // System File.
	IMAGE_FILE_DLL                     = 0x2000 // File is a DLL.
	IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000 // File should only be run on a UP machine
	IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000 // Bytes of machine word are reversed.
)

// Magic values of an OptionalHeader
const (
	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
	IMAGE_ROM_OPTIONAL_HDR_MAGIC  = 0x107
)

// Subsystem values of an OptionalHeader
const (
	IMAGE_SUBSYSTEM_UNKNOWN                  = 0  // Unknown subsystem.
	IMAGE_SUBSYSTEM_NATIVE                   = 1  // Image doesn't require a subsystem.
	IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2  // Image runs in the Windows GUI subsystem.
	IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3  // Image runs in the Windows character subsystem.
	IMAGE_SUBSYSTEM_OS2_CUI                  = 5  // Image runs in the OS/2 character subsystem.
	IMAGE_SUBSYSTEM_POSIX_CUI                = 7  // Image runs in the Posix character subsystem.
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8  // Image is a native Win9x driver.
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9  // Image runs in the Windows CE subsystem.
	IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10 //
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11 //
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12 //
	IMAGE_SUBSYSTEM_EFI_ROM                  = 13
	IMAGE_SUBSYSTEM_XBOX                     = 14
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
)

// DllCharacteristics values of an OptionalHeader
const (
	IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA       = 0x0020 // Image can handle a high entropy 64-bit virtual address space.
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040 // DLL can move.
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080 // Code Integrity Image
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100 // Image is NX compatible
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200 // Image understands isolation and doesn't want it
	IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400 // Image does not use SEH.  No SE handler may reside in this image
	IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800 // Do not bind this image.
	IMAGE_DLLCHARACTERISTICS_APPCONTAINER          = 0x1000 // Image should execute in an AppContainer
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000 // Driver uses WDM model
	IMAGE_DLLCHARACTERISTICS_GUARD_CF              = 0x4000 // Image supports Control Flow Guard.
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
)

// DataDirectory entries of an OptionalHeader
const (
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
	IMAGE_DIRECTORY_ENTRY_RESERVED       = 15 // Must be zero
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES     = 16
)

var MAP_IMAGE_DIRECTORY_ENTRY = [...]string{
	/* IMAGE_DIRECTORY_ENTRY_EXPORT:        */ "EXPORT",
	/* IMAGE_DIRECTORY_ENTRY_IMPORT:        */ "IMPORT",
	/* IMAGE_DIRECTORY_ENTRY_RESOURCE:      */ "RESOURCE",
	/* IMAGE_DIRECTORY_ENTRY_EXCEPTION:     */ "EXCEPTION",
	/* IMAGE_DIRECTORY_ENTRY_SECURITY:      */ "SECURITY",
	/* IMAGE_DIRECTORY_ENTRY_BASERELOC:     */ "BASERELOC",
	/* IMAGE_DIRECTORY_ENTRY_DEBUG:         */ "DEBUG",
	/* IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:  */ "ARCHITECTURE",
	/* IMAGE_DIRECTORY_ENTRY_GLOBALPTR:     */ "GLOBALPTR",
	/* IMAGE_DIRECTORY_ENTRY_TLS:           */ "TLS",
	/* IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:   */ "LOAD_CONFIG",
	/* IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:  */ "BOUND_IMPORT",
	/* IMAGE_DIRECTORY_ENTRY_IAT:           */ "IAT",
	/* IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:  */ "DELAY_IMPORT",
	/* IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:*/ "COM_DESCRIPTOR",
	/* IMAGE_DIRECTORY_ENTRY_RESERVED:      */ "RESERVED",
}

// Section characteristics.
const (
	_IMAGE_SCN_TYPE_REG    = 0x00000000 // Reserved.
	_IMAGE_SCN_TYPE_DSECT  = 0x00000001 // Reserved.
	_IMAGE_SCN_TYPE_NOLOAD = 0x00000002 // Reserved.
	_IMAGE_SCN_TYPE_GROUP  = 0x00000004 // Reserved.
	IMAGE_SCN_TYPE_NO_PAD  = 0x00000008 // Reserved.
	_IMAGE_SCN_TYPE_COPY   = 0x00000010 // Reserved.

	IMAGE_SCN_CNT_CODE               = 0x00000020 // Section contains code.
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040 // Section contains initialized data.
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 // Section contains uninitialized data.

	IMAGE_SCN_LNK_OTHER  = 0x00000100 // Reserved.
	IMAGE_SCN_LNK_INFO   = 0x00000200 // Section contains comments or some other type of information.
	_IMAGE_SCN_TYPE_OVER = 0x00000400 // Reserved.
	IMAGE_SCN_LNK_REMOVE = 0x00000800 // Section contents will not become part of image.
	IMAGE_SCN_LNK_COMDAT = 0x00001000 // Section contents comdat.

	_IMAGE_SCN_RESERVED_00002000 = 0x00002000 // Reserved.
	_IMAGE_SCN_MEM_PROTECTED     = 0x00004000 // Obsolete
	IMAGE_SCN_NO_DEFER_SPEC_EXC  = 0x00004000 // Reset speculative exceptions handling bits in the TLB entries for this section.
	IMAGE_SCN_GPREL              = 0x00008000 // Section content can be accessed relative to GP
	IMAGE_SCN_MEM_FARDATA        = 0x00008000
	_IMAGE_SCN_MEM_SYSHEAP       = 0x00010000 // Obsolete
	IMAGE_SCN_MEM_PURGEABLE      = 0x00020000
	IMAGE_SCN_MEM_16BIT          = 0x00020000
	IMAGE_SCN_MEM_LOCKED         = 0x00040000
	IMAGE_SCN_MEM_PRELOAD        = 0x00080000

	IMAGE_SCN_ALIGN_1BYTES    = 0x00100000 //
	IMAGE_SCN_ALIGN_2BYTES    = 0x00200000 //
	IMAGE_SCN_ALIGN_4BYTES    = 0x00300000 //
	IMAGE_SCN_ALIGN_8BYTES    = 0x00400000 //
	IMAGE_SCN_ALIGN_16BYTES   = 0x00500000 // Default alignment if no others are specified.
	IMAGE_SCN_ALIGN_32BYTES   = 0x00600000 //
	IMAGE_SCN_ALIGN_64BYTES   = 0x00700000 //
	IMAGE_SCN_ALIGN_128BYTES  = 0x00800000 //
	IMAGE_SCN_ALIGN_256BYTES  = 0x00900000 //
	IMAGE_SCN_ALIGN_512BYTES  = 0x00A00000 //
	IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000 //
	IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000 //
	IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000 //
	IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000 //
	IMAGE_SCN_ALIGN_MASK      = 0x00F00000

	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000 // Section contains extended relocations.
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000 // Section can be discarded.
	IMAGE_SCN_MEM_NOT_CACHED  = 0x04000000 // Section is not cachable.
	IMAGE_SCN_MEM_NOT_PAGED   = 0x08000000 // Section is not pageable.
	IMAGE_SCN_MEM_SHARED      = 0x10000000 // Section is shareable.
	IMAGE_SCN_MEM_EXECUTE     = 0x20000000 // Section is executable.
	IMAGE_SCN_MEM_READ        = 0x40000000 // Section is readable.
	IMAGE_SCN_MEM_WRITE       = 0x80000000 // Section is writeable.
)

// Section I386 relocations
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

// Section AMD64 relocations
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

// Base relocations
const (
	IMAGE_REL_BASED_ABSOLUTE       = 0  // The base relocation is skipped. This type can be used to pad a block.
	IMAGE_REL_BASED_HIGH           = 1  // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
	IMAGE_REL_BASED_LOW            = 2  // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
	IMAGE_REL_BASED_HIGHLOW        = 3  // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
	IMAGE_REL_BASED_HIGHADJ        = 4  // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
	IMAGE_REL_BASED_MIPS_JMPADDR   = 5  // The base relocation applies to a MIPS jump instruction.
	IMAGE_REL_BASED_ARM_MOV32A     = 5  // The base relocation applies the difference to the 32-bit value encoded in the immediate fields of a contiguous MOVW+MOVT pair in ARM mode at offset.
	IMAGE_REL_BASED_RESERVED       = 6  // shouldn't be set
	IMAGE_REL_BASED_ARM_MOV32T     = 7  // The base relocation applies the difference to the 32-bit value encoded in the immediate fields of a contiguous MOVW+MOVT pair in Thumb mode at offset.
	IMAGE_REL_BASED_UNKNOWN        = 8  // ???
	IMAGE_REL_BASED_MIPS_JMPADDR16 = 9  // The base relocation applies to a MIPS16 jump instruction.
	IMAGE_REL_BASED_DIR64          = 10 // The base relocation applies the difference to the 64-bit field at offset.
	IMAGE_NUMBEROF_IMAGE_REL_BASED = 11
)

var MAP_IMAGE_REL_BASED = [...]string{
	/* IMAGE_REL_BASED_ABSOLUTE                  */ "ABSOLUTE",
	/* IMAGE_REL_BASED_HIGH                      */ "HIGH",
	/* IMAGE_REL_BASED_LOW                       */ "LOW",
	/* IMAGE_REL_BASED_HIGHLOW                   */ "HIGHLOW",
	/* IMAGE_REL_BASED_HIGHADJ                   */ "HIGHADJ",
	/* IMAGE_REL_BASED_MIPS_JMPADDR / ARM_MOV32A */ "MIPS_JMPADDR / ARM_MOV32A",
	/* IMAGE_REL_BASED_RESERVED                  */ "RESERVED",
	/* IMAGE_REL_BASED_ARM_MOV32T                */ "ARM_MOV32T",
	/* IMAGE_REL_BASED_UNKNOWN                   */ "UNKNOWN",
	/* IMAGE_REL_BASED_MIPS_JMPADDR16            */ "MIPS_JMPADDR16",
	/* IMAGE_REL_BASED_DIR64                     */ "DIR64",
}
