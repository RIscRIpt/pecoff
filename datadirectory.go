package pecoff

type IDataDirectory interface {
}

type DataDirectory struct {
	file *File

	Header DataDirectoryHeader
}
