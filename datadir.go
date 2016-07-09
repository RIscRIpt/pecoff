package pecoff

type DataDirectory struct {
	file   *File
	Header DataDirectoryHeader
}
