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

	indentation []byte
}

func New(file *pecoff.File, w io.Writer) *FileDumper {
	return &FileDumper{
		File:   file,
		Writer: w,
	}
}

func (fd *FileDumper) indent() {
	fd.indentation = append(fd.indentation, ' ', ' ')
}

func (fd *FileDumper) unindent() {
	if len(fd.indentation) > 0 {
		fd.indentation = fd.indentation[:len(fd.indentation)-2]
	}
}

func (fd *FileDumper) dump(format string, a ...interface{}) {
	if _, err := fd.Writer.Write(fd.indentation); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(fd.Writer, format, a...); err != nil {
		panic(err)
	}
}

func (fd *FileDumper) DumpAll() {
	fd.DumpHeaders()
}

func (fd *FileDumper) DumpHeaders() {
	fd.dump("DosHeader:\n")
	fd.indent()
	fd.DumpDosHeader()
	fd.unindent()
	fd.dump("\n")

	fd.dump("FileHeader:\n")
	fd.indent()
	fd.DumpFileHeader()
	fd.unindent()
	fd.dump("\n")

	fd.dump("OptionalHeader:\n")
	fd.indent()
	fd.DumpOptionalHeader()
	fd.unindent()
	fd.dump("\n")

	fd.dump("SectionsHeaders:\n")
	fd.indent()
	fd.DumpSectionsHeaders()
	fd.unindent()
	fd.dump("\n")

	fd.dump("DataDirectories:\n")
	fd.indent()
	fd.DumpDataDirectories()
	fd.unindent()
	fd.dump("\n")
}

func (fd *FileDumper) DumpDosHeader() {
	if fd.File.DosHeader == nil {
		return
	}
	fd.dump("e_magic    %04X      Magic number                    \n", fd.File.DosHeader.E_magic)
	fd.dump("e_cblp     %04X      Bytes on last page of file      \n", fd.File.DosHeader.E_cblp)
	fd.dump("e_cp       %04X      Pages in file                   \n", fd.File.DosHeader.E_cp)
	fd.dump("e_crlc     %04X      Relocations                     \n", fd.File.DosHeader.E_crlc)
	fd.dump("e_cparhdr  %04X      Size of header in paragraphs    \n", fd.File.DosHeader.E_cparhdr)
	fd.dump("e_minalloc %04X      Minimum extra paragraphs needed \n", fd.File.DosHeader.E_minalloc)
	fd.dump("e_maxalloc %04X      Maximum extra paragraphs needed \n", fd.File.DosHeader.E_maxalloc)
	fd.dump("e_ss       %04X      Initial (relative) SS value     \n", fd.File.DosHeader.E_ss)
	fd.dump("e_sp       %04X      Initial SP value                \n", fd.File.DosHeader.E_sp)
	fd.dump("e_csum     %04X      Checksum                        \n", fd.File.DosHeader.E_csum)
	fd.dump("e_ip       %04X      Initial IP value                \n", fd.File.DosHeader.E_ip)
	fd.dump("e_cs       %04X      Initial (relative) CS value     \n", fd.File.DosHeader.E_cs)
	fd.dump("e_lfarlc   %04X      File address of relocation table\n", fd.File.DosHeader.E_lfarlc)
	fd.dump("e_ovno     %04X      Overlay number                  \n", fd.File.DosHeader.E_ovno)
	fd.dump("e_res[4]             Reserved words                  \n")
	for _, v := range fd.File.DosHeader.E_res {
		fd.dump("           %04X\n", v)
	}
	fd.dump("e_oemid    %04X     OEM identifier (for e_oeminfo)   \n", fd.File.DosHeader.E_oemid)
	fd.dump("e_oeminfo  %04X     OEM information; e_oemid specific\n", fd.File.DosHeader.E_oeminfo)
	fd.dump("e_res2[10]          Reserved words                   \n")
	for _, v := range fd.File.DosHeader.E_res2 {
		fd.dump("           %04X\n", v)
	}
	fd.dump("e_lfanew   %08X File address of new exe header   \n", fd.File.DosHeader.E_lfanew)
}

func (fd *FileDumper) DumpFileHeader() {
	if fd.File.FileHeader == nil {
		return
	}
	MachineString, ok := windef.MAP_IMAGE_FILE_MACHINE[fd.File.FileHeader.Machine]
	if !ok {
		MachineString = windef.MAP_IMAGE_FILE_MACHINE[windef.IMAGE_FILE_MACHINE_UNKNOWN]
	}
	TimeDateStamp := time.Unix(int64(fd.File.FileHeader.TimeDateStamp), 0)
	fd.dump("Machine              %04X     (%s)\n", fd.File.FileHeader.Machine, MachineString)
	fd.dump("NumberOfSections     %04X\n", fd.File.FileHeader.NumberOfSections)
	fd.dump("TimeDateStamp        %08X (%s)\n", fd.File.FileHeader.TimeDateStamp, TimeDateStamp)
	fd.dump("PointerToSymbolTable %08X\n", fd.File.FileHeader.PointerToSymbolTable)
	fd.dump("NumberOfSymbols      %08X\n", fd.File.FileHeader.NumberOfSymbols)
	fd.dump("SizeOfOptionalHeader %04X\n", fd.File.FileHeader.SizeOfOptionalHeader)
	fd.dump("Characteristics      %04X\n", fd.File.FileHeader.Characteristics)
	fd.indent()
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_RELOCS_STRIPPED != 0 {
		fd.dump("RELOCS_STRIPPED             Relocation info stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
		fd.dump("EXECUTABLE_IMAGE            File is executable  (i.e. no unresolved external references).\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LINE_NUMS_STRIPPED != 0 {
		fd.dump("LINE_NUMS_STRIPPED          Line nunbers stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0 {
		fd.dump("LOCAL_SYMS_STRIPPED         Local symbols stripped from file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_AGGRESIVE_WS_TRIM != 0 {
		fd.dump("AGGRESIVE_WS_TRIM           Aggressively trim working set\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_LARGE_ADDRESS_AWARE != 0 {
		fd.dump("LARGE_ADDRESS_AWARE         App can handle >2gb addresses\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_BYTES_REVERSED_LO != 0 {
		fd.dump("BYTES_REVERSED_LO           Bytes of machine word are reversed.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_32BIT_MACHINE != 0 {
		fd.dump("32BIT_MACHINE               32 bit word machine.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_DEBUG_STRIPPED != 0 {
		fd.dump("DEBUG_STRIPPED              Debugging info stripped from file in .DBG file\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP != 0 {
		fd.dump("REMOVABLE_RUN_FROM_SWAP     If Image is on removable media, copy and run from the swap file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_NET_RUN_FROM_SWAP != 0 {
		fd.dump("NET_RUN_FROM_SWAP           If Image is on Net, copy and run from the swap file.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_SYSTEM != 0 {
		fd.dump("SYSTEM                      System File.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_DLL != 0 {
		fd.dump("DLL                         File is a DLL.\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_UP_SYSTEM_ONLY != 0 {
		fd.dump("UP_SYSTEM_ONLY              File should only be run on a UP machine\n")
	}
	if fd.File.FileHeader.Characteristics&windef.IMAGE_FILE_BYTES_REVERSED_HI != 0 {
		fd.dump("BYTES_REVERSED_HI           Bytes of machine word are reversed.\n")
	}
	fd.unindent()
}

func (fd *FileDumper) DumpOptionalHeader() {
	if fd.File.OptionalHeader == nil {
		return
	}
	// Standard fields
	magicString, ok := windef.MAP_IMAGE_OPTIONAL_HDR_MAGIC[fd.File.OptionalHeader.Magic]
	if !ok {
		magicString = "Unknown"
	}
	fd.dump("Magic                       %04X             (%s)\n", fd.File.OptionalHeader.Magic, magicString)
	fd.dump("MajorLinkerVersion          %02X\n", fd.File.OptionalHeader.MajorLinkerVersion)
	fd.dump("MinorLinkerVersion          %02X\n", fd.File.OptionalHeader.MinorLinkerVersion)
	fd.dump("SizeOfCode                  %08X\n", fd.File.OptionalHeader.SizeOfCode)
	fd.dump("SizeOfInitializedData       %08X\n", fd.File.OptionalHeader.SizeOfInitializedData)
	fd.dump("SizeOfUninitializedData     %08X\n", fd.File.OptionalHeader.SizeOfUninitializedData)
	fd.dump("AddressOfEntryPoint         %08X\n", fd.File.OptionalHeader.AddressOfEntryPoint)
	fd.dump("BaseOfCode                  %08X\n", fd.File.OptionalHeader.BaseOfCode)

	isPe32Plus, _ := fd.File.IsPe32Plus()
	if !isPe32Plus {
		fd.dump("BaseOfData                  %08X\n", fd.File.OptionalHeader.BaseOfData)
	}

	// Variable size fields (part 1)
	if !isPe32Plus {
		fd.dump("ImageBase                   %08X\n", fd.File.OptionalHeader.ImageBase)
	} else {
		fd.dump("ImageBase                   %016X\n", fd.File.OptionalHeader.ImageBase)
	}

	// Extension fields (part 1)
	fd.dump("SectionAlignment            %08X\n", fd.File.OptionalHeader.SectionAlignment)
	fd.dump("FileAlignment               %08X\n", fd.File.OptionalHeader.FileAlignment)
	fd.dump("MajorOperatingSystemVersion %04X\n", fd.File.OptionalHeader.MajorOperatingSystemVersion)
	fd.dump("MinorOperatingSystemVersion %04X\n", fd.File.OptionalHeader.MinorOperatingSystemVersion)
	fd.dump("MajorImageVersion           %04X\n", fd.File.OptionalHeader.MajorImageVersion)
	fd.dump("MinorImageVersion           %04X\n", fd.File.OptionalHeader.MinorImageVersion)
	fd.dump("MajorSubsystemVersion       %04X\n", fd.File.OptionalHeader.MajorSubsystemVersion)
	fd.dump("MinorSubsystemVersion       %04X\n", fd.File.OptionalHeader.MinorSubsystemVersion)
	fd.dump("Win32VersionValue           %08X\n", fd.File.OptionalHeader.Win32VersionValue)
	fd.dump("SizeOfImage                 %08X\n", fd.File.OptionalHeader.SizeOfImage)
	fd.dump("SizeOfHeaders               %08X\n", fd.File.OptionalHeader.SizeOfHeaders)
	fd.dump("CheckSum                    %08X\n", fd.File.OptionalHeader.CheckSum)
	fd.dump("Subsystem                   %04X\n", fd.File.OptionalHeader.Subsystem)
	fd.indent()
	switch fd.File.OptionalHeader.Subsystem {
	default:
	case windef.IMAGE_SUBSYSTEM_UNKNOWN:
		fd.dump("UNKNOWN                                    Unknown subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_NATIVE:
		fd.dump("NATIVE                                     Image doesn't require a subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		fd.dump("WINDOWS_GUI                                Image runs in the Windows GUI subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		fd.dump("WINDOWS_CUI                                Image runs in the Windows character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_OS2_CUI:
		fd.dump("OS2_CUI                                    Image runs in the OS/2 character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_POSIX_CUI:
		fd.dump("POSIX_CUI                                  Image runs in the Posix character subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
		fd.dump("NATIVE_WINDOWS                             Image is a native Win9x driver.\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		fd.dump("WINDOWS_CE_GUI                             Image runs in the Windows CE subsystem.\n")
	case windef.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		fd.dump("EFI_APPLICATION\n")
	case windef.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		fd.dump("EFI_BOOT_SERVICE_DRIVER\n")
	case windef.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		fd.dump("EFI_RUNTIME_DRIVER\n")
	case windef.IMAGE_SUBSYSTEM_EFI_ROM:
		fd.dump("EFI_ROM\n")
	case windef.IMAGE_SUBSYSTEM_XBOX:
		fd.dump("XBOX\n")
	case windef.IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
		fd.dump("WINDOWS_BOOT_APPLICATION\n")
	}
	fd.unindent()
	fd.dump("DllCharacteristics          %04X\n", fd.File.OptionalHeader.DllCharacteristics)
	fd.indent()
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
		fd.dump("HIGH_ENTROPY_VA                            Image can handle a high entropy 64-bit virtual address space.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
		fd.dump("DYNAMIC_BASE                               DLL can move.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
		fd.dump("FORCE_INTEGRITY                            Code Integrity Image\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
		fd.dump("NX_COMPAT                                  Image is NX compatible\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 {
		fd.dump("NO_ISOLATION                               Image understands isolation and doesn't want it\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
		fd.dump("NO_SEH                                     Image does not use SEH.  No SE handler may reside in this image\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
		fd.dump("NO_BIND                                    Do not bind this image.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
		fd.dump("APPCONTAINER                               Image should execute in an AppContainer\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
		fd.dump("WDM_DRIVER                                 Driver uses WDM model\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
		fd.dump("GUARD_CF                                   Image supports Control Flow Guard.\n")
	}
	if fd.File.OptionalHeader.DllCharacteristics&windef.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
		fd.dump("TERMINAL_SERVER_AWARE\n")
	}
	fd.unindent()
	// Variable size fields (part 2)
	if !isPe32Plus {
		fd.dump("SizeOfStackReserve          %08X\n", fd.File.OptionalHeader.SizeOfStackReserve)
		fd.dump("SizeOfStackCommit           %08X\n", fd.File.OptionalHeader.SizeOfStackCommit)
		fd.dump("SizeOfHeapReserve           %08X\n", fd.File.OptionalHeader.SizeOfHeapReserve)
		fd.dump("SizeOfHeapCommit            %08X\n", fd.File.OptionalHeader.SizeOfHeapCommit)
	} else {
		fd.dump("SizeOfStackReserve          %016X\n", fd.File.OptionalHeader.SizeOfStackReserve)
		fd.dump("SizeOfStackCommit           %016X\n", fd.File.OptionalHeader.SizeOfStackCommit)
		fd.dump("SizeOfHeapReserve           %016X\n", fd.File.OptionalHeader.SizeOfHeapReserve)
		fd.dump("SizeOfHeapCommit            %016X\n", fd.File.OptionalHeader.SizeOfHeapCommit)
	}
	// Extension fields (part 2)
	fd.dump("LoaderFlags                 %08X\n", fd.File.OptionalHeader.LoaderFlags)
	fd.dump("NumberOfRvaAndSizes         %08X\n", fd.File.OptionalHeader.NumberOfRvaAndSizes)
	// Data directories
	fd.dump("DataDirectories:\n")
	for i, dd := range fd.File.OptionalHeader.DataDirectory {
		fd.dump("  %s\n", windef.MAP_IMAGE_DIRECTORY_ENTRY[i])
		fd.dump("    VirtualAddress: %08X\n", dd.VirtualAddress)
		fd.dump("    Size:           %08X\n", dd.Size)
	}
	fd.unindent()
}

func (fd *FileDumper) DumpSectionsHeaders() {
	if fd.File.Sections == nil {
		return
	}
	for i, s := range fd.File.Sections {
		fd.dump("Section #%d\n", i)
		fd.indent()
		nullIndex := bytes.IndexByte(s.Name[:], 0)
		if nullIndex == -1 {
			nullIndex = len(s.Name)
		}
		fd.dump("Name                 %s $ %s\n", string(s.Name[:nullIndex]), s.NameString())
		fd.dump("VirtualSize          %08X\n", s.VirtualSize)
		fd.dump("VirtualAddress       %08X\n", s.VirtualAddress)
		fd.dump("SizeOfRawData        %08X\n", s.SizeOfRawData)
		fd.dump("PointerToRawData     %08X\n", s.PointerToRawData)
		fd.dump("PointerToRelocations %08X\n", s.PointerToRelocations)
		fd.dump("PointerToLineNumbers %08X\n", s.PointerToLineNumbers)
		fd.dump("NumberOfRelocations  %04X\n", s.NumberOfRelocations)
		fd.dump("NumberOfLineNumbers  %04X\n", s.NumberOfLineNumbers)
		fd.dump("Characteristics      %08X\n", s.Characteristics)
		fd.indent()
		if s.Characteristics&windef.IMAGE_SCN_CNT_CODE != 0 {
			fd.dump("CNT_CODE                    Section contains code.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
			fd.dump("CNT_INITIALIZED_DATA        Section contains initialized data.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
			fd.dump("CNT_UNINITIALIZED_DATA      Section contains uninitialized data.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_INFO != 0 {
			fd.dump("LNK_INFO                    Section contains comments or some other type of information.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_REMOVE != 0 {
			fd.dump("LNK_REMOVE                  Section contents will not become part of image.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_COMDAT != 0 {
			fd.dump("LNK_COMDAT                  Section contents comdat.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_NO_DEFER_SPEC_EXC != 0 {
			fd.dump("NO_DEFER_SPEC_EXC           Reset speculative exceptions handling bits in the TLB entries for this section.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_GPREL != 0 {
			fd.dump("GPREL                       Section content can be accessed relative to GP\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_FARDATA != 0 {
			fd.dump("MEM_FARDATA                 \n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_PURGEABLE != 0 {
			fd.dump("MEM_PURGEABLE               \n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_16BIT != 0 {
			fd.dump("MEM_16BIT                   \n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_LOCKED != 0 {
			fd.dump("MEM_LOCKED                  \n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_PRELOAD != 0 {
			fd.dump("MEM_PRELOAD                 \n")
		}
		if s.Characteristics&windef.IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
			fd.dump("LNK_NRELOC_OVFL             Section contains extended relocations.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_DISCARDABLE != 0 {
			fd.dump("MEM_DISCARDABLE             Section can be discarded.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_NOT_CACHED != 0 {
			fd.dump("MEM_NOT_CACHED              Section is not cachable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_NOT_PAGED != 0 {
			fd.dump("MEM_NOT_PAGED               Section is not pageable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_SHARED != 0 {
			fd.dump("MEM_SHARED                  Section is shareable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_EXECUTE != 0 {
			fd.dump("MEM_EXECUTE                 Section is executable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_READ != 0 {
			fd.dump("MEM_READ                    Section is readable.\n")
		}
		if s.Characteristics&windef.IMAGE_SCN_MEM_WRITE != 0 {
			fd.dump("MEM_WRITE                   Section is writeable.\n")
		}
		switch s.Characteristics & windef.IMAGE_SCN_ALIGN_MASK {
		case windef.IMAGE_SCN_ALIGN_1BYTES:
			fd.dump("ALIGN_1BYTES\n")
		case windef.IMAGE_SCN_ALIGN_2BYTES:
			fd.dump("ALIGN_2BYTES\n")
		case windef.IMAGE_SCN_ALIGN_4BYTES:
			fd.dump("ALIGN_4BYTES\n")
		case windef.IMAGE_SCN_ALIGN_8BYTES:
			fd.dump("ALIGN_8BYTES\n")
		default:
			fallthrough //default is 16byte alignment
		case windef.IMAGE_SCN_ALIGN_16BYTES:
			fd.dump("ALIGN_16BYTES\n")
		case windef.IMAGE_SCN_ALIGN_32BYTES:
			fd.dump("ALIGN_32BYTES\n")
		case windef.IMAGE_SCN_ALIGN_64BYTES:
			fd.dump("ALIGN_64BYTES\n")
		case windef.IMAGE_SCN_ALIGN_128BYTES:
			fd.dump("ALIGN_128BYTES\n")
		case windef.IMAGE_SCN_ALIGN_256BYTES:
			fd.dump("ALIGN_256BYTES\n")
		case windef.IMAGE_SCN_ALIGN_512BYTES:
			fd.dump("ALIGN_512BYTES\n")
		case windef.IMAGE_SCN_ALIGN_1024BYTES:
			fd.dump("ALIGN_1024BYTES\n")
		case windef.IMAGE_SCN_ALIGN_2048BYTES:
			fd.dump("ALIGN_2048BYTES\n")
		case windef.IMAGE_SCN_ALIGN_4096BYTES:
			fd.dump("ALIGN_4096BYTES\n")
		case windef.IMAGE_SCN_ALIGN_8192BYTES:
			fd.dump("ALIGN_8192BYTES\n")
		}
		fd.unindent()
		fd.unindent()
		fd.dump("\n")
	}
}

func (fd *FileDumper) DumpDataDirectories() {
	if fd.File.OptionalHeader == nil {
		return
	}
	dataDirs := fd.File.OptionalHeader.DataDirs
	if dataDirs.Imports != nil && dataDirs.Imports.Size > 0 {
		fd.dump("Imports:\n")
		fd.indent()
		fd.DumpImports()
		fd.unindent()
		fd.dump("\n")
	}

	if dataDirs.BaseRelocations != nil && dataDirs.BaseRelocations.Size > 0 {
		fd.dump("BaseRelocations:\n")
		fd.indent()
		fd.DumpBaseRelocations()
		fd.unindent()
		fd.dump("\n")
	}
}

func (fd *FileDumper) DumpImports() {
	if fd.File.OptionalHeader == nil {
		return
	}
	imports := fd.File.OptionalHeader.DataDirs.Imports
	for _, imp := range imports.Get() {
		fd.dump("%s:\n", imp.Library())
		fd.indent()
		fd.dump("OriginalFirstThunk %08X RVA to original unbound IAT (PIMAGE_THUNK_DATA)         \n", imp.OriginalFirstThunk)
		fd.dump("Timestamp          %08X 0 if not bound, -1 if bound, or real date/time stamp    \n", imp.Timestamp)
		fd.dump("ForwarderChain     %08X -1 if no forwarders                                     \n", imp.ForwarderChain)
		fd.dump("Name               %08X RVA of an ASCII string that contains the name of the DLL\n", imp.Name)
		fd.dump("FirstThunk         %08X RVA to IAT (if bound this IAT has actual addresses)     \n", imp.FirstThunk)
		fd.dump("Functions:\n")
		fd.indent()
		for _, f := range imp.Functions() {
			fd.dump("%04X    %s\n", f.Hint, f.Name)
		}
		fd.unindent()
		fd.unindent()
	}
}

func (fd *FileDumper) DumpBaseRelocations() {
	if fd.File.OptionalHeader == nil {
		return
	}
	baseRels := fd.File.OptionalHeader.DataDirs.BaseRelocations
	for _, brel := range baseRels.Get() {
		fd.dump("[%08X - %08X]:\n", brel.VirtualAddress, brel.VirtualAddress+0x1000)
		fd.indent()
		fd.dump("VirtualAddress %08X\n", brel.VirtualAddress)
		fd.dump("SizeOfBlock    %08X\n", brel.SizeOfBlock)
		fd.dump("Entries:\n")
		fd.indent()
		for _, e := range brel.Entries() {
			var typeName string
			if e.Type() < len(windef.MAP_IMAGE_REL_BASED) {
				typeName = windef.MAP_IMAGE_REL_BASED[e.Type()]
			} else {
				typeName = fmt.Sprintf("Unknown (%02X)", e.Type())
			}
			fd.dump("%s %08X (%08X)\n", typeName, e.Offset(), brel.VirtualAddress+e.Offset())
		}
		fd.unindent()
		fd.unindent()
	}
}
