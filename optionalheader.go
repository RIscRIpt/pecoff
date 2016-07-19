package pecoff

import "github.com/RIscRIpt/pecoff/windef"

type OptionalHeader struct {
	windef.OptionalHeaderCommon
	DataDirs DataDirs
}

func (oh *OptionalHeader) Generalize32(oh32 *windef.OptionalHeader32) {
	oh.OptionalHeaderCommon = windef.OptionalHeaderCommon{
		Magic:                       oh32.Magic,
		MajorLinkerVersion:          oh32.MajorLinkerVersion,
		MinorLinkerVersion:          oh32.MinorLinkerVersion,
		SizeOfCode:                  oh32.SizeOfCode,
		SizeOfInitializedData:       oh32.SizeOfInitializedData,
		SizeOfUninitializedData:     oh32.SizeOfUninitializedData,
		AddressOfEntryPoint:         oh32.AddressOfEntryPoint,
		BaseOfCode:                  oh32.BaseOfCode,
		BaseOfData:                  uint64(oh32.BaseOfData),
		ImageBase:                   uint64(oh32.ImageBase),
		SectionAlignment:            oh32.SectionAlignment,
		FileAlignment:               oh32.FileAlignment,
		MajorOperatingSystemVersion: oh32.MajorOperatingSystemVersion,
		MinorOperatingSystemVersion: oh32.MinorOperatingSystemVersion,
		MajorImageVersion:           oh32.MajorImageVersion,
		MinorImageVersion:           oh32.MinorImageVersion,
		MajorSubsystemVersion:       oh32.MajorSubsystemVersion,
		MinorSubsystemVersion:       oh32.MinorSubsystemVersion,
		Win32VersionValue:           oh32.Win32VersionValue,
		SizeOfImage:                 oh32.SizeOfImage,
		SizeOfHeaders:               oh32.SizeOfHeaders,
		CheckSum:                    oh32.CheckSum,
		Subsystem:                   oh32.Subsystem,
		DllCharacteristics:          oh32.DllCharacteristics,
		SizeOfStackReserve:          uint64(oh32.SizeOfStackReserve),
		SizeOfStackCommit:           uint64(oh32.SizeOfStackCommit),
		SizeOfHeapReserve:           uint64(oh32.SizeOfHeapReserve),
		SizeOfHeapCommit:            uint64(oh32.SizeOfHeapCommit),
		LoaderFlags:                 oh32.LoaderFlags,
		NumberOfRvaAndSizes:         oh32.NumberOfRvaAndSizes,
		DataDirectory:               oh32.DataDirectory,
	}
}

func (oh *OptionalHeader) Generalize64(oh64 *windef.OptionalHeader64) {
	oh.OptionalHeaderCommon = windef.OptionalHeaderCommon{
		Magic:                       oh64.Magic,
		MajorLinkerVersion:          oh64.MajorLinkerVersion,
		MinorLinkerVersion:          oh64.MinorLinkerVersion,
		SizeOfCode:                  oh64.SizeOfCode,
		SizeOfInitializedData:       oh64.SizeOfInitializedData,
		SizeOfUninitializedData:     oh64.SizeOfUninitializedData,
		AddressOfEntryPoint:         oh64.AddressOfEntryPoint,
		BaseOfCode:                  oh64.BaseOfCode,
		BaseOfData:                  uint64(0),
		ImageBase:                   uint64(oh64.ImageBase),
		SectionAlignment:            oh64.SectionAlignment,
		FileAlignment:               oh64.FileAlignment,
		MajorOperatingSystemVersion: oh64.MajorOperatingSystemVersion,
		MinorOperatingSystemVersion: oh64.MinorOperatingSystemVersion,
		MajorImageVersion:           oh64.MajorImageVersion,
		MinorImageVersion:           oh64.MinorImageVersion,
		MajorSubsystemVersion:       oh64.MajorSubsystemVersion,
		MinorSubsystemVersion:       oh64.MinorSubsystemVersion,
		Win32VersionValue:           oh64.Win32VersionValue,
		SizeOfImage:                 oh64.SizeOfImage,
		SizeOfHeaders:               oh64.SizeOfHeaders,
		CheckSum:                    oh64.CheckSum,
		Subsystem:                   oh64.Subsystem,
		DllCharacteristics:          oh64.DllCharacteristics,
		SizeOfStackReserve:          uint64(oh64.SizeOfStackReserve),
		SizeOfStackCommit:           uint64(oh64.SizeOfStackCommit),
		SizeOfHeapReserve:           uint64(oh64.SizeOfHeapReserve),
		SizeOfHeapCommit:            uint64(oh64.SizeOfHeapCommit),
		LoaderFlags:                 oh64.LoaderFlags,
		NumberOfRvaAndSizes:         oh64.NumberOfRvaAndSizes,
		DataDirectory:               oh64.DataDirectory,
	}
}
