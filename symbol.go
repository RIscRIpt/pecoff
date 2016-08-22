package pecoff

import "github.com/RIscRIpt/pecoff/windef"

// Symbol embedds a windef.Symbol struct
// and stores unexported fields of parsed data of a symbol.
type Symbol struct {
	windef.Symbol
	nameString string
}

// NameString returns a string represntation of the field `Name`.
func (s *Symbol) NameString() string {
	return s.nameString
}
