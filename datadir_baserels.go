package pecoff

import (
	"errors"
	"sort"

	"github.com/RIscRIpt/pecoff/windef"
)

// List of errors
var (
	ErrBaseRelNotFound   = errors.New("pecoff: base relocation not found")
	ErrBaseRelsNotSorted = errors.New("pecoff: base relocations are not sorted")
)

// DdBaseRelocations is a base relocations data directory wrapper which holds
// a (sorted ascending by VirtualAddress) slice of (pointers to) BaseRelocationBlock-s
type DdBaseRelocations struct {
	windef.DataDirectory
	offset     int64
	blocksSize int64
	blocks     []*BaseRelocationBlock

	// `sorted` is true if items of the slice `blocks`
	// are sorted ascending by their VirtualAddress-es.
	// Practically the vast majority of PE files store
	// base relocations blocks in an ascending order,
	// but it's not strictly documented, so we should ensure this
	// so some methods (such as GetFromInterval) could take advantage
	// of the sorted slice `blocks`.
	sorted bool
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
	r.sorted = false
	r.blocks = append(r.blocks, block)
	r.blocksSize += int64(block.SizeOfBlock)
}

// Get returns a slice of (pointers to) base relocation blocks.
// Returned slice must not be modified directly!
func (r *DdBaseRelocations) Get() []*BaseRelocationBlock {
	return r.blocks
}

// Len returns a count of base relocation blocks
// This method is required to implement the sort.Interface
func (r *DdBaseRelocations) Len() int {
	return len(r.blocks)
}

// Less returns true if VirtualAddress of blocks[i] is
// less that VirtualAddress of blocks[j]
// This method is required to implement the sort.Interface
func (r *DdBaseRelocations) Less(i, j int) bool {
	return r.blocks[i].VirtualAddress < r.blocks[j].VirtualAddress
}

// Swap swaps blocks
// This method is required to implement the sort.Interface
func (r *DdBaseRelocations) Swap(i, j int) {
	r.blocks[i], r.blocks[j] = r.blocks[j], r.blocks[i]
}

func (r *DdBaseRelocations) sort() {
	sort.Sort(r)
	r.sorted = true
}

// GetIDByVA uses a binary search (sort.Search) to find
// an id of a block which contains virtual address `va`.
// If such block doesn't exist an error ErrBaseRelNotFound is returned.
// This method requires a slice of blocks to be sorted,
// otherwise an error ErrBaseRelsNotSorted is returned.
func (r *DdBaseRelocations) GetIDByVA(va uint32) (int, error) {
	if !r.sorted {
		return -1, ErrBaseRelsNotSorted
	}
	i := sort.Search(r.Len(), func(i int) bool {
		return r.blocks[i].VirtualAddress+windef.IMAGE_REL_BASED_BLOCK_MAX_VA >= va
	})
	if i >= r.Len() {
		return -1, ErrBaseRelNotFound
	}
	return i, nil
}

// GetByVA is a wrapper method of GetIDByVA,
// which returns a (pointer to the) block instead of an id.
func (r *DdBaseRelocations) GetByVA(va uint32) (*BaseRelocationBlock, error) {
	id, err := r.GetIDByVA(va)
	if err != nil {
		return nil, err
	}
	return r.blocks[id], nil
}

// GetFromInterval returns a 'sliced' slice `blocks`
// of (pointers to) BaseRelocationBlock-s,
// which have VirtualAddress in the specified interval [begin; end).
// This method assumes a slice of blocks to be sorted
// according to the specification of DdBaseRelocations struct.
func (r *DdBaseRelocations) GetFromInterval(begin, end uint32) ([]*BaseRelocationBlock, error) {
	beginID, err := r.GetIDByVA(begin)
	if err != nil {
		return nil, err
	}
	endID := beginID
	for r.blocks[endID].VirtualAddress+windef.IMAGE_REL_BASED_BLOCK_MAX_VA < end {
		endID++
	}
	return r.blocks[beginID : endID+1], nil
}

// BaseRelocationBlock embedds windef.BaseRelocation, and holds its
// parsed base relocation entries.
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

// Entries returns a slice of base relcation entries of this block.
// Returned slice must not be modified directly!
func (brb *BaseRelocationBlock) Entries() []BaseRelocationEntry {
	return brb.entries
}

// BaseRelocationEntry is a 16 bit value (according to the pecoff specification)
// which has bitfields: Type (4 H.O. bits) and Offset (12 L.O. bits).
type BaseRelocationEntry uint16

// Type returns a value, which can be any of IMAGE_REL_BASED_* constant.
func (r BaseRelocationEntry) Type() int { return int(r >> 12) }

// Offset from the starting address that was specified
// in the Page RVA field for the block (BaseRelocationBlock.VirtualAddress)
// It specifies where the base relocation is to be applied.
func (r BaseRelocationEntry) Offset() uint32 { return uint32(r & 0xFFF) }
