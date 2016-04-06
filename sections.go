package pecoff

type Sections []*Section

func (s Sections) Len() int {
	return len(s)
}

func (s Sections) Less(i, j int) bool {
	return s[i].Header.VirtualAddress < s[j].Header.VirtualAddress
}

func (s Sections) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
