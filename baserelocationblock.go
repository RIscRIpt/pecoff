package pecoff

type BaseRelocationBlock struct {
	file   *File
	offset int64

	ImageBaseRelocation

	entries []BaseRelocation
}

func NewBaseRelocationBlock(file *File, offset int64) (brb *BaseRelocationBlock) {
	brb = &BaseRelocationBlock{
		file:   file,
		offset: offset,
	}
	file.read_at_into(offset, &brb.ImageBaseRelocation)
	if !brb.IsEmpty() {
		return brb
	} else {
		return nil
	}
}

func (brb *BaseRelocationBlock) IsEmpty() bool {
	return brb.ImageBaseRelocation == ImageBaseRelocation{}
}

func (brb *BaseRelocationBlock) Entries() []BaseRelocation {
	if brb.SizeOfBlock > 0 && brb.entries == nil {
		brb.entries = make([]BaseRelocation, (brb.SizeOfBlock-SIZEOF_IMAGE_BASE_RELOCATION)/SIZEOF_IMAGE_BASE_RELOCATION_ENTRY)
		brb.file.read_at_into(brb.offset+SIZEOF_IMAGE_BASE_RELOCATION, brb.entries)
	}
	return brb.entries
}
