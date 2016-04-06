package pecoff

type IOptionalHeader interface {
	DD_Headers() [16]DataDirectoryHeader
}

func (oh *OptionalHeader32) DD_Headers() [16]DataDirectoryHeader {
	return oh.DataDirectoriesHeaders
}

func (oh *OptionalHeader64) DD_Headers() [16]DataDirectoryHeader {
	return oh.DataDirectoriesHeaders
}
