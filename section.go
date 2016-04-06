package pecoff

import "encoding/binary"

type Section struct {
	file *File

	Header  SectionHeader
	rawData []byte
	//relocations []Relocation
}

func NewSection(file *File, index int) (s *Section) {
	s = &Section{
		file:    file,
		rawData: nil,
	}
	file.read_at_into(file.get_sections_headers_offset()+int64(index*binary.Size(s.Header)), &s.Header)
	return
}

func (s *Section) RawData() []byte {
	if s.Header.SizeOfRawData != 0 && s.rawData == nil {
		s.rawData = make([]byte, s.Header.SizeOfRawData)
		s.file.read_at_into(int64(s.Header.PointerToRawData), s.rawData)
	}
	return s.rawData
}

func (s *Section) Relocations() []Relocation {
	panic("Not implemented")
}
