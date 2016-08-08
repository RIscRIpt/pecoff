package pecoff

import "github.com/RIscRIpt/pecoff/windef"

type Symbol struct {
	windef.Symbol
	nameString string
}

func (s *Symbol) NameString() string {
	return s.nameString
}
