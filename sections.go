package pecoff

import "sort"

// Sections is a slice of pointers to Sections.
// Implements a sort.Interface, and can be sorted ascending by Section.VirtualAddress.
type Sections []*Section

// Len returns len(Sections)
func (s Sections) Len() int {
	return len(s)
}

// Less returns true if VirtualAddress of section[i] is
// less that VirtualAddress of section[j]
func (s Sections) Less(i, j int) bool {
	return s[i].VirtualAddress < s[j].VirtualAddress
}

// Swap swaps sections
func (s Sections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// GetByVA returns a pointer to Section, which has `va` in it, if any, else nil.
func (s Sections) GetByVA(va uint32) *Section {
	i := sort.Search(s.Len(), func(i int) bool {
		return s[i].VirtualAddress+s[i].VirtualSize >= va
	})
	if i >= s.Len() {
		return nil
	}
	return s[i]
}
