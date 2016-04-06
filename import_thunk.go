package pecoff

type Thunk interface {
	IsNull() bool
	IsOrdinal() bool

	Ordinal() uint16
	NameRVA() uint32
}

type Thunk32 uint32
type Thunk64 uint64

func (t Thunk32) IsNull() bool { return t == 0 }
func (t Thunk64) IsNull() bool { return t == 0 }

func (t Thunk32) IsOrdinal() bool { return (t & 0x80000000) != 0 }
func (t Thunk64) IsOrdinal() bool { return (t & 0x8000000000000000) != 0 }

func (t Thunk32) Ordinal() uint16 { return uint16(t & 0xFFFF) }
func (t Thunk64) Ordinal() uint16 { return uint16(t & 0xFFFF) }

func (t Thunk32) NameRVA() uint32 { return uint32(t) }
func (t Thunk64) NameRVA() uint32 { return uint32(t) }
