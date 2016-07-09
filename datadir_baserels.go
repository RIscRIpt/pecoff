package pecoff

type DdBaseRelocations struct {
	DataDirectory
	blocks []*BaseRelocationBlock
}

func NewDdBaseRelocations(file *File, ddh DataDirectoryHeader) *DdBaseRelocations {
	return &DdBaseRelocations{
		DataDirectory: DataDirectory{
			file:   file,
			Header: ddh,
		},
	}
}

func (r *DdBaseRelocations) Get() []*BaseRelocationBlock {
	if r.Header.Size > 0 && r.blocks == nil {
		block_offset := r.file.VaToOffset(r.Header.VirtualAddress)
		for {
			newBlock := NewBaseRelocationBlock(r.file, block_offset)
			if newBlock == nil {
				break
			}
			r.blocks = append(r.blocks, newBlock)
			block_offset += int64(newBlock.SizeOfBlock)
		}
	}
	return r.blocks
}
