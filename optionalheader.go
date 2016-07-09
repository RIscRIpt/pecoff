package pecoff

import "fmt"

type OptionalHeader struct {
	*OptionalHeaderCommon
	DataDirectories *DataDirectories
}

func NewOptionalHeader(file *File, size uint16) (oh *OptionalHeader) {
	oh = new(OptionalHeader)
	switch size {
	case SIZEOF_IMAGE_OPTIONAL_HEADER32:
		var oh32 OptionalHeader32
		file.ReadAtInto(file.getOptHeaderOffset(), &oh32)
		oh.OptionalHeaderCommon = generalizeOptHeader32(&oh32)
	case SIZEOF_IMAGE_OPTIONAL_HEADER64:
		var oh64 OptionalHeader64
		file.ReadAtInto(file.getOptHeaderOffset(), &oh64)
		oh.OptionalHeaderCommon = generalizeOptHeader64(&oh64)
	default:
		panic(fmt.Errorf("Unknown SizeOfOptionalHeader = %d", file.FileHeader.SizeOfOptionalHeader))
	}
	oh.DataDirectories = NewDataDirectories(file)
	return
}

func generalizeOptHeader32(oh32 *OptionalHeader32) *OptionalHeaderCommon {
	return &OptionalHeaderCommon{
		OptionalHeader_Standard:             oh32.OptionalHeader_Standard,
		BaseOfData:                          uint64(oh32.BaseOfData),
		ImageBase:                           uint64(oh32.ImageBase),
		OptionalHeader_Extension_FixedSize1: oh32.OptionalHeader_Extension_FixedSize1,
		SizeOfStackReserve:                  uint64(oh32.SizeOfStackReserve),
		SizeOfStackCommit:                   uint64(oh32.SizeOfStackCommit),
		SizeOfHeapReserve:                   uint64(oh32.SizeOfHeapReserve),
		SizeOfHeapCommit:                    uint64(oh32.SizeOfHeapCommit),
		OptionalHeader_Extension_FixedSize2: oh32.OptionalHeader_Extension_FixedSize2,
		DataDirectoriesHeaders:              oh32.DataDirectoriesHeaders,
	}
}

func generalizeOptHeader64(oh64 *OptionalHeader64) *OptionalHeaderCommon {
	return &OptionalHeaderCommon{
		OptionalHeader_Standard:             oh64.OptionalHeader_Standard,
		BaseOfData:                          uint64(0),
		ImageBase:                           uint64(oh64.ImageBase),
		OptionalHeader_Extension_FixedSize1: oh64.OptionalHeader_Extension_FixedSize1,
		SizeOfStackReserve:                  uint64(oh64.SizeOfStackReserve),
		SizeOfStackCommit:                   uint64(oh64.SizeOfStackCommit),
		SizeOfHeapReserve:                   uint64(oh64.SizeOfHeapReserve),
		SizeOfHeapCommit:                    uint64(oh64.SizeOfHeapCommit),
		OptionalHeader_Extension_FixedSize2: oh64.OptionalHeader_Extension_FixedSize2,
		DataDirectoriesHeaders:              oh64.DataDirectoriesHeaders,
	}
}
