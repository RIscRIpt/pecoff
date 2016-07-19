package dumper

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/windef"
)

type FileDumper struct {
	File   *pecoff.File
	Writer io.Writer
}

func New(file *pecoff.File, w io.Writer) *FileDumper {
	return &FileDumper{
		File:   file,
		Writer: w,
	}
}

func (fd *FileDumper) DumpAll() error {
	if err := fd.File.ReadAll(); err != nil {
		return err
	}
	fd.DumpHeaders()
	return nil
}

func (fd *FileDumper) DumpHeaders() {
	fmt.Fprintln(fd.Writer, "DosHeader:")
	//fd.Writer.Indent()
	fd.DumpDosHeader()
	fmt.Fprintln(fd.Writer)
	//fd.Writer.Unindent()

	fmt.Fprintln(fd.Writer, "FileHeader:")
	//fd.Writer.Indent()
	fd.DumpFileHeader()
	fmt.Fprintln(fd.Writer)
	//fd.Writer.Unindent()

	fmt.Fprintln(fd.Writer, "OptionalHeader:")
	//fd.Writer.Indent()
	fd.DumpOptionalHeader()
	fmt.Fprintln(fd.Writer)
	//fd.Writer.Unindent()

	fmt.Fprintln(fd.Writer, "SectionsHeaders:")
	// fd.Writer.Indent()
	fd.DumpSectionsHeaders()
	fmt.Fprintln(fd.Writer)
	// fd.Writer.Unindent()

	fmt.Fprintln(fd.Writer, "DataDirectories:")
	// fd.Writer.Indent()
	fd.DumpDataDirectories()
	fmt.Fprintln(fd.Writer)
	// fd.Writer.Unindent()

	//fd.Writer.Flush()
}

func (fd *FileDumper) DumpDosHeader() {
	if fd.File.DosHeader == nil {
		return
	}
	//fd.Writer.SetColumns(fd.Writer.GetIndent() + 3)
	fmt.Fprintf(fd.Writer, "e_magic   \t%04X\tMagic number                    \n", fd.File.DosHeader.E_magic)
	fmt.Fprintf(fd.Writer, "e_cblp    \t%04X\tBytes on last page of file      \n", fd.File.DosHeader.E_cblp)
	fmt.Fprintf(fd.Writer, "e_cp      \t%04X\tPages in file                   \n", fd.File.DosHeader.E_cp)
	fmt.Fprintf(fd.Writer, "e_crlc    \t%04X\tRelocations                     \n", fd.File.DosHeader.E_crlc)
	fmt.Fprintf(fd.Writer, "e_cparhdr \t%04X\tSize of header in paragraphs    \n", fd.File.DosHeader.E_cparhdr)
	fmt.Fprintf(fd.Writer, "e_minalloc\t%04X\tMinimum extra paragraphs needed \n", fd.File.DosHeader.E_minalloc)
	fmt.Fprintf(fd.Writer, "e_maxalloc\t%04X\tMaximum extra paragraphs needed \n", fd.File.DosHeader.E_maxalloc)
	fmt.Fprintf(fd.Writer, "e_ss      \t%04X\tInitial (relative) SS value     \n", fd.File.DosHeader.E_ss)
	fmt.Fprintf(fd.Writer, "e_sp      \t%04X\tInitial SP value                \n", fd.File.DosHeader.E_sp)
	fmt.Fprintf(fd.Writer, "e_csum    \t%04X\tChecksum                        \n", fd.File.DosHeader.E_csum)
	fmt.Fprintf(fd.Writer, "e_ip      \t%04X\tInitial IP value                \n", fd.File.DosHeader.E_ip)
	fmt.Fprintf(fd.Writer, "e_cs      \t%04X\tInitial (relative) CS value     \n", fd.File.DosHeader.E_cs)
	fmt.Fprintf(fd.Writer, "e_lfarlc  \t%04X\tFile address of relocation table\n", fd.File.DosHeader.E_lfarlc)
	fmt.Fprintf(fd.Writer, "e_ovno    \t%04X\tOverlay number                  \n", fd.File.DosHeader.E_ovno)
	fmt.Fprintf(fd.Writer, "e_res     \t    \tReserved words                  \n")
	//fd.Writer.Indent()
	for _, v := range fd.File.DosHeader.E_res {
		fmt.Fprintf(fd.Writer, "%04X\n", v)
	}
	//fd.Writer.Unindent()
	fmt.Fprintf(fd.Writer, "e_oemid   \t%04X\tOEM identifier (for e_oeminfo)   \n", fd.File.DosHeader.E_oemid)
	fmt.Fprintf(fd.Writer, "e_oeminfo \t%04X\tOEM information; e_oemid specific\n", fd.File.DosHeader.E_oeminfo)
	fmt.Fprintf(fd.Writer, "e_res2    \t    \tReserved words                   \n")
	//fd.Writer.Indent()
	for _, v := range fd.File.DosHeader.E_res2 {
		fmt.Fprintf(fd.Writer, "%04X\n", v)
	}
	//fd.Writer.Unindent()
	fmt.Fprintf(fd.Writer, "e_lfanew  \t%08X\tFile address of new exe header   \n", fd.File.DosHeader.E_lfanew)
}

func (fd *FileDumper) DumpFileHeader() {
	if fd.File.FileHeader == nil {
		return
	}
	//fd.Writer.SetColumns(fd.Writer.GetIndent() + 3)
	MachineString, ok := windef.MAP_IMAGE_FILE_MACHINE[fd.File.FileHeader.Machine]
	if !ok {
		MachineString = windef.MAP_IMAGE_FILE_MACHINE[windef.IMAGE_FILE_MACHINE_UNKNOWN]
	}
	TimeDateStamp := time.Unix(int64(fd.File.FileHeader.TimeDateStamp), 0)
	fmt.Fprintf(fd.Writer, "Machine             \t%04X\t%s\n", fd.File.FileHeader.Machine, MachineString)
	fmt.Fprintf(fd.Writer, "NumberOfSections    \t%04X\n", fd.File.FileHeader.NumberOfSections)
	fmt.Fprintf(fd.Writer, "TimeDateStamp       \t%08X\t%s\n", fd.File.FileHeader.TimeDateStamp, TimeDateStamp)
	fmt.Fprintf(fd.Writer, "PointerToSymbolTable\t%08X\n", fd.File.FileHeader.PointerToSymbolTable)
	fmt.Fprintf(fd.Writer, "NumberOfSymbols     \t%08X\n", fd.File.FileHeader.NumberOfSymbols)
	fmt.Fprintf(fd.Writer, "SizeOfOptionalHeader\t%04X\n", fd.File.FileHeader.SizeOfOptionalHeader)
	fmt.Fprintf(fd.Writer, "Characteristics     \t%04X\n", fd.File.FileHeader.Characteristics)
	//fd.Writer.Indent()
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_RELOCS_STRIPPED != 0 {
		fmt.Fprintf(fd.Writer, "RELOCS_STRIPPED         \tRelocation info stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
		fmt.Fprintf(fd.Writer, "EXECUTABLE_IMAGE        \tFile is executable  (i.e. no unresolved external references).\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LINE_NUMS_STRIPPED != 0 {
		fmt.Fprintf(fd.Writer, "LINE_NUMS_STRIPPED      \tLine nunbers stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 {
		fmt.Fprintf(fd.Writer, "LOCAL_SYMS_STRIPPED     \tLocal symbols stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_AGGRESIVE_WS_TRIM != 0 {
		fmt.Fprintf(fd.Writer, "AGGRESIVE_WS_TRIM       \tAggressively trim working set\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
		fmt.Fprintf(fd.Writer, "LARGE_ADDRESS_AWARE     \tApp can handle >2gb addresses\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_BYTES_REVERSED_LO != 0 {
		fmt.Fprintf(fd.Writer, "BYTES_REVERSED_LO       \tBytes of machine word are reversed.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_32BIT_MACHINE != 0 {
		fmt.Fprintf(fd.Writer, "32BIT_MACHINE           \t32 bit word machine.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_DEBUG_STRIPPED != 0 {
		fmt.Fprintf(fd.Writer, "DEBUG_STRIPPED          \tDebugging info stripped from file in .DBG file\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP != 0 {
		fmt.Fprintf(fd.Writer, "REMOVABLE_RUN_FROM_SWAP \tIf Image is on removable media, copy and run from the swap file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_NET_RUN_FROM_SWAP != 0 {
		fmt.Fprintf(fd.Writer, "NET_RUN_FROM_SWAP       \tIf Image is on Net, copy and run from the swap file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_SYSTEM != 0 {
		fmt.Fprintf(fd.Writer, "SYSTEM                  \tSystem File.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_DLL != 0 {
		fmt.Fprintf(fd.Writer, "DLL                     \tFile is a DLL.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_UP_SYSTEM_ONLY != 0 {
		fmt.Fprintf(fd.Writer, "UP_SYSTEM_ONLY          \tFile should only be run on a UP machine\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_BYTES_REVERSED_HI != 0 {
		fmt.Fprintf(fd.Writer, "BYTES_REVERSED_HI       \tBytes of machine word are reversed.\n")
	}
	//fd.Writer.Unindent()
}

func (fd *FileDumper) DumpOptionalHeader() {
	if fd.File.OptionalHeader == nil {
		return
	}
	//fd.Writer.SetColumns(fd.Writer.GetIndent() + 3)
	// Standard fields
	var magicString string
	switch fd.File.OptionalHeader.Magic {
	case windef.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		magicString = "PE32"
	case windef.IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		magicString = "PE32+"
	case windef.IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		magicString = "ROM"
	default:
		magicString = "Unknown"
	}
	fmt.Fprintf(fd.Writer, "Magic                   \t%04X\t(%s)\n", fd.File.OptionalHeader.Magic, magicString)
	fmt.Fprintf(fd.Writer, "MajorLinkerVersion      \t%02X\n", fd.File.OptionalHeader.MajorLinkerVersion)
	fmt.Fprintf(fd.Writer, "MinorLinkerVersion      \t%02X\n", fd.File.OptionalHeader.MinorLinkerVersion)
	fmt.Fprintf(fd.Writer, "SizeOfCode              \t%08X\n", fd.File.OptionalHeader.SizeOfCode)
	fmt.Fprintf(fd.Writer, "SizeOfInitializedData   \t%08X\n", fd.File.OptionalHeader.SizeOfInitializedData)
	fmt.Fprintf(fd.Writer, "SizeOfUninitializedData \t%08X\n", fd.File.OptionalHeader.SizeOfUninitializedData)
	fmt.Fprintf(fd.Writer, "AddressOfEntryPoint     \t%08X\n", fd.File.OptionalHeader.AddressOfEntryPoint)
	fmt.Fprintf(fd.Writer, "BaseOfCode              \t%08X\n", fd.File.OptionalHeader.BaseOfCode)

	isPe32Plus, _ := fd.File.IsPe32Plus()
	if !isPe32Plus {
		fmt.Fprintf(fd.Writer, "BaseOfCode              \t%08X\n", fd.File.OptionalHeader.BaseOfData)
	}

	// Variable size fields (part 1)
	if !isPe32Plus {
		fmt.Fprintf(fd.Writer, "ImageBase               \t%08X\n", fd.File.OptionalHeader.ImageBase)
	} else {
		fmt.Fprintf(fd.Writer, "ImageBase               \t%016X\n", fd.File.OptionalHeader.ImageBase)
	}

	// Extension fields (part 1)
	fmt.Fprintf(fd.Writer, "SectionAlignment            \t%08X\n", fd.File.OptionalHeader.SectionAlignment)
	fmt.Fprintf(fd.Writer, "FileAlignment               \t%08X\n", fd.File.OptionalHeader.FileAlignment)
	fmt.Fprintf(fd.Writer, "MajorOperatingSystemVersion \t%04X\n", fd.File.OptionalHeader.MajorOperatingSystemVersion)
	fmt.Fprintf(fd.Writer, "MinorOperatingSystemVersion \t%04X\n", fd.File.OptionalHeader.MinorOperatingSystemVersion)
	fmt.Fprintf(fd.Writer, "MajorImageVersion           \t%04X\n", fd.File.OptionalHeader.MajorImageVersion)
	fmt.Fprintf(fd.Writer, "MinorImageVersion           \t%04X\n", fd.File.OptionalHeader.MinorImageVersion)
	fmt.Fprintf(fd.Writer, "MajorSubsystemVersion       \t%04X\n", fd.File.OptionalHeader.MajorSubsystemVersion)
	fmt.Fprintf(fd.Writer, "MinorSubsystemVersion       \t%04X\n", fd.File.OptionalHeader.MinorSubsystemVersion)
	fmt.Fprintf(fd.Writer, "Win32VersionValue           \t%08X\n", fd.File.OptionalHeader.Win32VersionValue)
	fmt.Fprintf(fd.Writer, "SizeOfImage                 \t%08X\n", fd.File.OptionalHeader.SizeOfImage)
	fmt.Fprintf(fd.Writer, "SizeOfHeaders               \t%08X\n", fd.File.OptionalHeader.SizeOfHeaders)
	fmt.Fprintf(fd.Writer, "CheckSum                    \t%08X\n", fd.File.OptionalHeader.CheckSum)
	fmt.Fprintf(fd.Writer, "Subsystem                   \t%04X\n", fd.File.OptionalHeader.Subsystem)
	//fd.Writer.Indent()
	switch fd.File.OptionalHeader.Subsystem {
	default:
	case windef.IMAGE_SUBSYSTEM_UNKNOWN:
		fmt.Fprintf(fd.Writer, "UNKNOWN                  \tUnknown subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_NATIVE:
		fmt.Fprintf(fd.Writer, "NATIVE                   \tImage doesn't require a subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		fmt.Fprintf(fd.Writer, "WINDOWS_GUI              \tImage runs in the Windows GUI subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		fmt.Fprintf(fd.Writer, "WINDOWS_CUI              \tImage runs in the Windows character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_OS2_CUI:
		fmt.Fprintf(fd.Writer, "OS2_CUI                  \tImage runs in the OS/2 character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_POSIX_CUI:
		fmt.Fprintf(fd.Writer, "POSIX_CUI                \tImage runs in the Posix character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		fmt.Fprintf(fd.Writer, "NATIVE_WINDOWS           \tImage is a native Win9x driver.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		fmt.Fprintf(fd.Writer, "WINDOWS_CE_GUI           \tImage runs in the Windows CE subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		fmt.Fprintf(fd.Writer, "EFI_APPLICATION\n")
	case windef.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		fmt.Fprintf(fd.Writer, "EFI_BOOT_SERVICE_DRIVER\n")
	case windef.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		fmt.Fprintf(fd.Writer, "EFI_RUNTIME_DRIVER\n")
	case windef.IMAGE_SUBSYSTEM_EFI_ROM:
		fmt.Fprintf(fd.Writer, "EFI_ROM\n")
	case windef.IMAGE_SUBSYSTEM_XBOX:
		fmt.Fprintf(fd.Writer, "XBOX\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		fmt.Fprintf(fd.Writer, "WINDOWS_BOOT_APPLICATION\n")
	}
	//fd.Writer.Unindent()
	fmt.Fprintf(fd.Writer, "DllCharacteristics          \t%04X\n", fd.File.OptionalHeader.DllCharacteristics)
	//fd.Writer.Indent()
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
		fmt.Fprintf(fd.Writer, "HIGH_ENTROPY_VA       \tImage can handle a high entropy 64-bit virtual address space.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		fmt.Fprintf(fd.Writer, "DYNAMIC_BASE          \tDLL can move.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
		fmt.Fprintf(fd.Writer, "FORCE_INTEGRITY       \tCode Integrity Image\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		fmt.Fprintf(fd.Writer, "NX_COMPAT             \tImage is NX compatible\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 {
		fmt.Fprintf(fd.Writer, "NO_ISOLATION          \tImage understands isolation and doesn't want it\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
		fmt.Fprintf(fd.Writer, "NO_SEH                \tImage does not use SEH.  No SE handler may reside in this image\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
		fmt.Fprintf(fd.Writer, "NO_BIND               \tDo not bind this image.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
		fmt.Fprintf(fd.Writer, "APPCONTAINER          \tImage should execute in an AppContainer\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
		fmt.Fprintf(fd.Writer, "WDM_DRIVER            \tDriver uses WDM model\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
		fmt.Fprintf(fd.Writer, "GUARD_CF              \tImage supports Control Flow Guard.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
		fmt.Fprintf(fd.Writer, "TERMINAL_SERVER_AWARE\n")
	}
	fmt.Fprintf(fd.Writer, "DataDirectories:\n")
	for i, dd := range fd.File.OptionalHeader.DataDirectory {
		fmt.Fprintln(fd.Writer, windef.MAP_IMAGE_DIRECTORY_ENTRY[i])
		fmt.Fprintf(fd.Writer, "VirtualAddress: %08X\n", dd.VirtualAddress)
		fmt.Fprintf(fd.Writer, "Size:           %08X\n", dd.Size)
	}
	//fd.Writer.Unindent()
}

func (fd *FileDumper) DumpSectionsHeaders() {
	if fd.File.Sections == nil {
		return
	}
	for i, s := range fd.File.Sections {
		fmt.Fprintf(fd.Writer, "Section #%d\n", i)
		nullIndex := bytes.IndexByte(s.Name[:], 0)
		if nullIndex == -1 {
			nullIndex = len(s.Name)
		}
		fmt.Fprintf(fd.Writer, "Name                \t%s\n", string(s.Name[:nullIndex]))
		fmt.Fprintf(fd.Writer, "VirtualSize         \t%08X\n", s.VirtualSize)
		fmt.Fprintf(fd.Writer, "VirtualAddress      \t%08X\n", s.VirtualAddress)
		fmt.Fprintf(fd.Writer, "SizeOfRawData       \t%08X\n", s.SizeOfRawData)
		fmt.Fprintf(fd.Writer, "PointerToRawData    \t%08X\n", s.PointerToRawData)
		fmt.Fprintf(fd.Writer, "PointerToRelocations\t%08X\n", s.PointerToRelocations)
		fmt.Fprintf(fd.Writer, "PointerToLineNumbers\t%08X\n", s.PointerToLineNumbers)
		fmt.Fprintf(fd.Writer, "NumberOfRelocations \t%04X\n", s.NumberOfRelocations)
		fmt.Fprintf(fd.Writer, "NumberOfLineNumbers \t%04X\n", s.NumberOfLineNumbers)
		fmt.Fprintf(fd.Writer, "Characteristics     \t%08X\n", s.Characteristics)
		if s.Characteristics&windef.IMAGE_SCN_CNT_CODE != 0 {
			fmt.Fprintf(fd.Writer, "CNT_CODE              \tSection contains code.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
			fmt.Fprintf(fd.Writer, "CNT_INITIALIZED_DATA  \tSection contains initialized data.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
			fmt.Fprintf(fd.Writer, "CNT_UNINITIALIZED_DATA\tSection contains uninitialized data.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_INFO != 0 {
			fmt.Fprintf(fd.Writer, "LNK_INFO              \tSection contains comments or some other type of information.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_REMOVE != 0 {
			fmt.Fprintf(fd.Writer, "LNK_REMOVE            \tSection contents will not become part of image.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_COMDAT != 0 {
			fmt.Fprintf(fd.Writer, "LNK_COMDAT            \tSection contents comdat.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_NO_DEFER_SPEC_EXC != 0 {
			fmt.Fprintf(fd.Writer, "NO_DEFER_SPEC_EXC     \tReset speculative exceptions handling bits in the TLB entries for this section.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_GPREL != 0 {
			fmt.Fprintf(fd.Writer, "GPREL                 \tSection content can be accessed relative to GP\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_FARDATA != 0 {
			fmt.Fprintf(fd.Writer, "MEM_FARDATA           \t\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_PURGEABLE != 0 {
			fmt.Fprintf(fd.Writer, "MEM_PURGEABLE         \t\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_16BIT != 0 {
			fmt.Fprintf(fd.Writer, "MEM_16BIT             \t\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_LOCKED != 0 {
			fmt.Fprintf(fd.Writer, "MEM_LOCKED            \t\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_PRELOAD != 0 {
			fmt.Fprintf(fd.Writer, "MEM_PRELOAD           \t\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
			fmt.Fprintf(fd.Writer, "LNK_NRELOC_OVFL       \tSection contains extended relocations.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_DISCARDABLE != 0 {
			fmt.Fprintf(fd.Writer, "MEM_DISCARDABLE       \tSection can be discarded.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_NOT_CACHED != 0 {
			fmt.Fprintf(fd.Writer, "MEM_NOT_CACHED        \tSection is not cachable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_NOT_PAGED != 0 {
			fmt.Fprintf(fd.Writer, "MEM_NOT_PAGED         \tSection is not pageable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_SHARED != 0 {
			fmt.Fprintf(fd.Writer, "MEM_SHARED            \tSection is shareable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_EXECUTE != 0 {
			fmt.Fprintf(fd.Writer, "MEM_EXECUTE           \tSection is executable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_READ != 0 {
			fmt.Fprintf(fd.Writer, "MEM_READ              \tSection is readable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_WRITE != 0 {
			fmt.Fprintf(fd.Writer, "MEM_WRITE             \tSection is writeable.\n")
		}
		switch s.Characteristics & windef.IMAGE_SCN_ALIGN_MASK {
		case windef.IMAGE_SCN_ALIGN_1BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_1BYTES   \n")
		case windef.IMAGE_SCN_ALIGN_2BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_2BYTES   \n")
		case windef.IMAGE_SCN_ALIGN_4BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_4BYTES   \n")
		case windef.IMAGE_SCN_ALIGN_8BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_8BYTES   \n")
		default:
			fallthrough //default is 16byte alignment
		case windef.IMAGE_SCN_ALIGN_16BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_16BYTES  \n")
		case windef.IMAGE_SCN_ALIGN_32BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_32BYTES  \n")
		case windef.IMAGE_SCN_ALIGN_64BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_64BYTES  \n")
		case windef.IMAGE_SCN_ALIGN_128BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_128BYTES \n")
		case windef.IMAGE_SCN_ALIGN_256BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_256BYTES \n")
		case windef.IMAGE_SCN_ALIGN_512BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_512BYTES \n")
		case windef.IMAGE_SCN_ALIGN_1024BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_1024BYTES\n")
		case windef.IMAGE_SCN_ALIGN_2048BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_2048BYTES\n")
		case windef.IMAGE_SCN_ALIGN_4096BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_4096BYTES\n")
		case windef.IMAGE_SCN_ALIGN_8192BYTES:
			fmt.Fprintf(fd.Writer, "ALIGN_8192BYTES\n")
		}
		fmt.Fprintln(fd.Writer)
	}
}

func (fd *FileDumper) DumpDataDirectories() {
	if fd.File.OptionalHeader == nil {
		return
	}
	dataDirs := fd.File.OptionalHeader.DataDirs
	if dataDirs.Imports != nil && dataDirs.Imports.Size > 0 {
		fmt.Fprintln(fd.Writer, "Imports:")
		// fd.Writer.Indent()
		fd.DumpImports()
		fmt.Fprintln(fd.Writer)
		// fd.Writer.Unindent()
	}

	if dataDirs.BaseRelocations != nil && dataDirs.BaseRelocations.Size > 0 {
		fmt.Fprintln(fd.Writer, "BaseRelocations:")
		// fd.Writer.Indent()
		fd.DumpBaseRelocations()
		fmt.Fprintln(fd.Writer)
		// fd.Writer.Unindent()
	}
}

func (fd *FileDumper) DumpImports() {
	if fd.File.OptionalHeader == nil {
		return
	}
	imports := fd.File.OptionalHeader.DataDirs.Imports
	for _, imp := range imports.Get() {
		fmt.Fprintf(fd.Writer, "OriginalFirstThunk\t%08X\tRVA to original unbound IAT (PIMAGE_THUNK_DATA)         \n", imp.OriginalFirstThunk)
		fmt.Fprintf(fd.Writer, "Timestamp         \t%08X\t0 if not bound, -1 if bound, or real date/time stamp    \n", imp.Timestamp)
		fmt.Fprintf(fd.Writer, "ForwarderChain    \t%08X\t-1 if no forwarders                                     \n", imp.ForwarderChain)
		fmt.Fprintf(fd.Writer, "Name              \t%08X\t(%s)\tRVA of an ASCII string that contains the name of the DLL\n", imp.Name, imp.Library())
		fmt.Fprintf(fd.Writer, "FirstThunk        \t%08X\tRVA to IAT (if bound this IAT has actual addresses)     \n", imp.FirstThunk)
		fmt.Fprintf(fd.Writer, "Functions:\n")
		for _, f := range imp.Functions() {
			fmt.Fprintf(fd.Writer, "%02X\t%s\n", f.Hint, f.Name)
		}
	}
}

func (fd *FileDumper) DumpBaseRelocations() {
	if fd.File.OptionalHeader == nil {
		return
	}
	baseRels := fd.File.OptionalHeader.DataDirs.BaseRelocations
	for _, brel := range baseRels.Get() {
		fmt.Fprintf(fd.Writer, "VirtualAddress\t%08X\n", brel.VirtualAddress)
		fmt.Fprintf(fd.Writer, "SizeOfBlock   \t%08X\n", brel.SizeOfBlock)
		fmt.Fprintf(fd.Writer, "Entries:\n")
		for _, e := range brel.Entries() {
			var typeName string
			if e.Type() < len(windef.MAP_IMAGE_REL_BASED) {
				typeName = windef.MAP_IMAGE_REL_BASED[e.Type()]
			} else {
				typeName = fmt.Sprintf("Unknown (%02X)", e.Type())
			}
			fmt.Fprintf(fd.Writer, "%08X\t%s\n", e.Offset(), typeName)
		}
	}
}
