package pecoff

import "github.com/RIscRIpt/pecoff/windef"

type Section struct {
	windef.SectionHeader
	nameString string
	rawData    []byte
	//relocations []windef.Relocation
}

func (s *Section) NameString() string {
	return s.nameString
}

func (s *Section) VaToSectionOffset(va uint32) int64 {
	return int64(va - s.VirtualAddress)
}

func (s *Section) VaToFileOffset(va uint32) int64 {
	return s.VaToSectionOffset(va) + int64(s.PointerToRawData)
}

// RawData returns slice of bytes ([]byte) which contains raw data of a section.
// If SizeOfRawData in the section's header equals to 0, nil is returned.
func (s *Section) RawData() []byte {
	if s.rawData == nil {
		return nil
	}
	bytes := make([]byte, len(s.rawData))
	copy(bytes, s.rawData)
	return bytes
}

func (s *Section) SetRawData(bytes []byte) {
	s.rawData = make([]byte, len(bytes))
	copy(s.rawData, bytes)
	s.SizeOfRawData = uint32(len(bytes))
}

func (s *Section) Relocations() []windef.Relocation {
	panic("Not implemented")
}

// func (s *Section) ApplyBaseRelocation(baseDest, baseSrc uint32, relocation BaseRelocation) {
// 	offset := s.VaToSectionOffset(baseSrc) + int64(relocation.Offset())
// 	switch relocation.Type() {
// 	//case IMAGE_REL_BASED_HIGH:
// 	//case IMAGE_REL_BASED_LOW:
// 	case IMAGE_REL_BASED_HIGHLOW:
// 		(*(*uint32)(&s.rawData[offset])) += uint32(baseDest - s.VirtualAddress)
// 	//case IMAGE_REL_BASED_HIGHADJ:
// 	//case IMAGE_REL_BASED_DIR64:
// 	default:
// 		panic("Unsupported relocation type!")
// 	}
// }

// func (s *Section) WriteAt(offset int64, data interface{}) {
// 	binary.Write(s.RawDataBuffer(), binary.LittleEndian, data)
// }

// func (s *Section) WriteVa(va uint32, data interface{}) {
// 	s.WriteAt(s.VaToSectionOffset(va), data)
// }
