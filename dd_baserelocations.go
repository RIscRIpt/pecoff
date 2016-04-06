package pecoff

type DD_BaseRelocations struct {
	DataDirectory
	blocks []*BaseRelocationBlock
}

func NewBaseRelocations(file *File, ddh DataDirectoryHeader) *DD_BaseRelocations {
	return &DD_BaseRelocations{
		DataDirectory: DataDirectory{
			file:   file,
			Header: ddh,
		},
	}
}

func (r *DD_BaseRelocations) Get() []*BaseRelocationBlock {
	if r.Header.Size > 0 && r.blocks == nil {
		block_offset := r.file.va_to_offset(r.Header.VirtualAddress)
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
