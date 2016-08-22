package pecoff

import "github.com/RIscRIpt/pecoff/windef"

// Section embedds a windef.SectionHeader struct
// and stores unexported fields of parsed data of a section,
// such as string represntation of the section name, raw data, and etc...
type Section struct {
	id int
	windef.SectionHeader
	nameString  string
	rawData     []byte
	relocations []windef.Relocation
}

// ID returns a real id of a section inside a PE/COFF file.
func (s *Section) ID() int {
	return s.id
}

// NameString returns string represntation of a SectionHeader.Name field.
func (s *Section) NameString() string {
	return s.nameString
}

// VaToSectionOffset converts virtual address to the offset within section.
func (s *Section) VaToSectionOffset(va uint32) int64 {
	return int64(va - s.VirtualAddress)
}

// VaToFileOffset converts virtual address to the file offset.
func (s *Section) VaToFileOffset(va uint32) int64 {
	return s.VaToSectionOffset(va) + int64(s.PointerToRawData)
}

// RawData returns slice of bytes ([]byte) which contains raw data of a section.
func (s *Section) RawData() []byte {
	return s.rawData
}

// Relocations returns a slice of relocations of the section.
func (s *Section) Relocations() []windef.Relocation {
	return s.relocations
}
