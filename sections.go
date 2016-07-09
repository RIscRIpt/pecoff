package pecoff

import "sort"

// Sections is a slice of pointers to the Section.
// Implements a sort.Interface, and can be sorted ascending by Section.VirtualAddress.
type Sections []*Section

// Returns new sorted Sections
func NewSections(file *File, numberOfSections uint16) Sections {
	sections := make(Sections, int(numberOfSections))
	for i := 0; i < len(sections); i++ {
		sections[i] = NewSection(file, i)
	}
	sort.Sort(sections)
	return sections
}

// Len returns len(Sections)
func (s Sections) Len() int {
	return len(s)
}

// Less returns true if VirtualAddress of section[i] is
// less that VirtualAddress of section[j]
func (s Sections) Less(i, j int) bool {
	return s[i].Header.VirtualAddress < s[j].Header.VirtualAddress
}

// Swap swaps sections
func (s Sections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// GetByVA returns a pointer to Section, which has `va` in it, if any, else nil.
func (s Sections) GetByVA(va uint32) *Section {
	i := sort.Search(s.Len(), func(i int) bool {
		return s[i].Header.VirtualAddress+s[i].Header.VirtualSize >= va
	})
	if i >= s.Len() {
		return nil
	}
	return s[i]
}
