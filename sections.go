package pecoff

import (
	"errors"
	"sort"
)

// List of errors {{{1
var (
	ErrSectionsNoIndexMap = errors.New("pecoff: sections are sorted, but no indexMap was set")
	ErrSectionsNotSorted  = errors.New("pecoff: sections array is not sorted")
	ErrSectionNotFound    = errors.New("pecoff: section was not found")
)

// End List of errors }}}1

// Sections contains unexpected fields.
// Implements a sort.Interface, and can be sorted ascending by Section.VirtualAddress.
type Sections struct {
	array    []*Section
	indexMap []int
	sorted   bool
}

func newSections(count int) *Sections {
	return &Sections{
		array:    make([]*Section, count),
		indexMap: nil,
		sorted:   false,
	}
}

// Array returns a slice of (pointers to) sections.
// Returned slice must not be modified directly!
func (s *Sections) Array() []*Section {
	return s.array
}

// Len returns count of sections
// This method is required to implement the sort.Interface
func (s *Sections) Len() int {
	return len(s.array)
}

// Less returns true if VirtualAddress of section[i] is
// less that VirtualAddress of section[j]
// This method is required to implement the sort.Interface
func (s *Sections) Less(i, j int) bool {
	return s.array[i].VirtualAddress < s.array[j].VirtualAddress
}

// Swap swaps sections
// This method is required to implement the sort.Interface
func (s *Sections) Swap(i, j int) {
	s.array[i], s.array[j] = s.array[j], s.array[i]
}

func (s *Sections) sort() {
	sort.Sort(s)
	s.indexMap = make([]int, s.Len())
	for id, section := range s.array {
		s.indexMap[id] = section.id
	}
	s.sorted = true
}

// GetByID returns a section with specified **1-based** id number.
// The reason for 1-based indices is that all the sections numbers
// according to the PE/COFF file specification are 1-based.
// If an id is outside a valid range, an error ErrSectionNotFound is returned.
func (s *Sections) GetByID(id int16) (*Section, error) {
	if !s.sorted {
		panic(ErrSectionsNotSorted)
	}
	if s.indexMap == nil {
		panic(ErrSectionsNoIndexMap)
	}
	id--
	if id < 0 || int(id) >= len(s.array) {
		return nil, ErrSectionNotFound
	}
	return s.array[s.indexMap[id]], nil
}

// GetByVA returns a (pointer to) Section, which has specified
// virtual address in its address range.
// If no such section exist, nil and an error ErrSectionNotFound are returned.
func (s Sections) GetByVA(va uint32) (*Section, error) {
	if !s.sorted {
		panic(ErrSectionsNotSorted)
	}
	i := sort.Search(s.Len(), func(i int) bool {
		return s.array[i].VirtualAddress+s.array[i].VirtualSize >= va
	})
	if i >= s.Len() {
		return nil, ErrSectionNotFound
	}
	return s.array[i], nil
}
