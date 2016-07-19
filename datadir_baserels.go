package pecoff

import "github.com/RIscRIpt/pecoff/windef"

// DdBaseRelocations {{{1
type DdBaseRelocations struct {
	windef.DataDirectory
	offset     int64
	blocksSize int64
	blocks     []*BaseRelocationBlock
}

func newBaseRels(dd windef.DataDirectory) *DdBaseRelocations {
	return &DdBaseRelocations{
		DataDirectory: dd,
	}
}

// new returns a newBaseRelocationBlock which must be discarded,
// or passed to the append method afterwards.
func (r *DdBaseRelocations) new() *BaseRelocationBlock {
	return newBaseRelocationBlock(r.offset + r.blocksSize)
}

// append a BaseRelocationBlock returned from the method new
func (r *DdBaseRelocations) append(block *BaseRelocationBlock) {
	r.blocks = append(r.blocks, block)
	r.blocksSize += int64(block.SizeOfBlock)
}

func (r *DdBaseRelocations) Get() []*BaseRelocationBlock {
	return r.blocks
}

// End DdBaseRelocations }}}1
// BaseRelocationBlock {{{1
type BaseRelocationBlock struct {
	windef.BaseRelocation
	offset  int64
	entries []BaseRelocationEntry
}

func newBaseRelocationBlock(offset int64) *BaseRelocationBlock {
	return &BaseRelocationBlock{
		offset: offset,
	}
}

func (brb *BaseRelocationBlock) calcEntryCount() int {
	return int((brb.SizeOfBlock - windef.SIZEOF_IMAGE_BASE_RELOCATION) / windef.SIZEOF_IMAGE_BASE_RELOCATION_ENTRY)
}

func (brb *BaseRelocationBlock) Entries() []BaseRelocationEntry {
	return brb.entries
}

// End BaseRelocationBlock }}}1
// BaseRelocation Entry (16 bits) {{{1
type BaseRelocationEntry uint16

// Type can be any of IMAGE_REL_BASED_* constant.
func (r BaseRelocationEntry) Type() int { return int(r >> 12) }

// Offset from the starting address that wasspecified in the Page RVA field for the block
// specifies where the base relocation is to be applied.
func (r BaseRelocationEntry) Offset() uint32 { return uint32(r & 0xFFF) }

// End BaseRelocationEntry }}}1
