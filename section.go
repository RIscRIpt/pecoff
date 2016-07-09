package pecoff

import (
	"bytes"
	"encoding/binary"
)

type Section struct {
	file *File

	Header        SectionHeader
	rawData       []byte
	rawDataBuffer *bytes.Buffer
	//relocations []Relocation
}

func NewSection(file *File, index int) (s *Section) {
	s = &Section{
		file: file,
	}
	file.ReadAtInto(file.getSectionsHeadersOffset()+int64(index*SIZEOF_IMAGE_SECTION_HEADER), &s.Header)
	return
}

func (s *Section) VaToSectionOffset(va uint32) int64 {
	return int64(va - s.Header.VirtualAddress)
}

func (s *Section) VaToFileOffset(va uint32) int64 {
	return s.VaToSectionOffset(va) + int64(s.Header.PointerToRawData)
}

// Returns true if SizeOfRawData in the header of the section is > 0
func (s *Section) HasRawData() bool { return s.Header.SizeOfRawData > 0 }

// Returns true if s.rawData != nil
func (s *Section) IsRawDataRead() bool { return s.rawData != nil }

func (s *Section) mustRawData() {
	if s.HasRawData() && !s.IsRawDataRead() {
		s.rawData = make([]byte, s.Header.SizeOfRawData)
		s.file.ReadAtInto(int64(s.Header.PointerToRawData), s.rawData)
		s.rawDataBuffer = bytes.NewBuffer(s.rawData)
	}
}

// RawData returns slice of bytes ([]byte) which contains raw data of a section.
// If SizeOfRawData in the section's header equals to 0, nil is returned.
func (s *Section) RawData() []byte {
	s.mustRawData()
	return s.rawData
}

// RawDataBuffer returns bytes.Buffer which contains raw data of a section.
// If SizeOfRawData in the section's header equals to 0, nil is returned.
func (s *Section) RawDataBuffer() *bytes.Buffer {
	s.mustRawData()
	return s.rawDataBuffer
}

func (s *Section) Parse() {}

func (s *Section) Relocations() []Relocation {
	panic("Not implemented")
}

// func (s *Section) ApplyBaseRelocation(baseDest, baseSrc uint32, relocation BaseRelocation) {
// 	offset := s.VaToSectionOffset(baseSrc) + int64(relocation.Offset())
// 	switch relocation.Type() {
// 	//case IMAGE_REL_BASED_HIGH:
// 	//case IMAGE_REL_BASED_LOW:
// 	case IMAGE_REL_BASED_HIGHLOW:
// 		(*(*uint32)(&s.rawData[offset])) += uint32(baseDest - s.Header.VirtualAddress)
// 	//case IMAGE_REL_BASED_HIGHADJ:
// 	//case IMAGE_REL_BASED_DIR64:
// 	default:
// 		panic("Unsupported relocation type!")
// 	}
// }

func (s *Section) WriteAt(offset int64, data interface{}) {
	binary.Write(s.RawDataBuffer(), binary.LittleEndian, data)
}

func (s *Section) WriteVa(va uint32, data interface{}) {
	s.WriteAt(s.VaToSectionOffset(va), data)
}
