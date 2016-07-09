package pecoff

type ImportThunk interface {
	IsNull() bool
	IsOrdinal() bool

	Ordinal() uint16
	HintRVA() uint32
	NameRVA() uint32

	Size() int64
}

type ImportThunk32 uint32
type ImportThunk64 uint64

func (t ImportThunk32) IsNull() bool { return t == 0 }
func (t ImportThunk64) IsNull() bool { return t == 0 }

func (t ImportThunk32) IsOrdinal() bool { return (t & 0x80000000) != 0 }
func (t ImportThunk64) IsOrdinal() bool { return (t & 0x8000000000000000) != 0 }

func (t ImportThunk32) Ordinal() uint16 { return uint16(t & 0xFFFF) }
func (t ImportThunk64) Ordinal() uint16 { return uint16(t & 0xFFFF) }

func (t ImportThunk32) HintRVA() uint32 { return uint32(t) }
func (t ImportThunk64) HintRVA() uint32 { return uint32(t) }
func (t ImportThunk32) NameRVA() uint32 { return uint32(t) + 2 }
func (t ImportThunk64) NameRVA() uint32 { return uint32(t) + 2 }

func (t ImportThunk32) Size() int64 { return 4 }
func (t ImportThunk64) Size() int64 { return 8 }
