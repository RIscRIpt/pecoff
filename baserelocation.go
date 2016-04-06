package pecoff

// BaseRelocation Entry (16 bits)
type BaseRelocation uint16

// Type can be any of IMAGE_REL_BASED_* constant.
func (r BaseRelocation) Type() int { return int(r >> 12) }

// Offset from the starting address that wasspecified in the Page RVA field for the block
// specifies where the base relocation is to be applied.
func (r BaseRelocation) Offset() uint32 { return uint32(r & 0xFFF) }
