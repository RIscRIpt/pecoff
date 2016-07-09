package pecoff

import (
	"fmt"
)

type DataDirectories struct {
	file *File
	// Exports         *DdExports
	Imports *DdImports
	// Resources       *DdResources
	// Exceptions      *DdExceptions
	// Security        *DdSecurity
	BaseRelocations *DdBaseRelocations
	// Debug           *DdDebug
	// Architecture    *DdArchitecture
	// GlobalPtrs      *DdGlobalPtrs
	// TLS             *DdTLS
	// LoadConfig      *DdLoadConfig
	// BoundImports    *DdBoundImport
	// IAT             *DdIAT
	// DelayImports    *DdDelayImports
	// COMDescriptors  *DdCOMDescriptors
}

func NewDataDirectories(file *File) *DataDirectories {
	return &DataDirectories{
		file: file,
	}
}

func (dds *DataDirectories) Parse() {
	//dds.Exports        = NewDdExports(dds.file        , dds.Header(IMAGE_DIRECTORY_ENTRY_EXPORT))
	dds.Imports = NewDdImports(dds.file, dds.Header(IMAGE_DIRECTORY_ENTRY_IMPORT))
	//dds.Resources      = NewDdResources(dds.file      , dds.Header(IMAGE_DIRECTORY_ENTRY_RESOURCE))
	//dds.Exceptions     = NewDdExceptions(dds.file     , dds.Header(IMAGE_DIRECTORY_ENTRY_EXCEPTION))
	//dds.Security       = NewDdSecurity(dds.file       , dds.Header(IMAGE_DIRECTORY_ENTRY_SECURITY))
	dds.BaseRelocations = NewDdBaseRelocations(dds.file, dds.Header(IMAGE_DIRECTORY_ENTRY_BASERELOC))
	//dds.Debug          = NewDdDebug(dds.file          , dds.Header(IMAGE_DIRECTORY_ENTRY_DEBUG))
	//dds.Architecture   = NewDdArchitecture(dds.file   , dds.Header(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE))
	//dds.GlobalPtrs     = NewDdGlobalPtrs(dds.file     , dds.Header(IMAGE_DIRECTORY_ENTRY_GLOBALPTR))
	//dds.TLS            = NewDdTLS(dds.file            , dds.Header(IMAGE_DIRECTORY_ENTRY_TLS))
	//dds.LoadConfig     = NewDdLoadConfig(dds.file     , dds.Header(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG))
	//dds.BoundImports   = NewDdBoundImports(dds.file   , dds.Header(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT))
	//dds.IAT            = NewDdIAT(dds.file            , dds.Header(IMAGE_DIRECTORY_ENTRY_IAT))
	//dds.DelayImports   = NewDdDelayImports(dds.file   , dds.Header(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT))
	//dds.COMDescriptors = NewDdCOMDescriptors(dds.file , dds.Header(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR))
}

func (dds *DataDirectories) Header(id int) DataDirectoryHeader {
	if id < 0 || id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES {
		panic(fmt.Errorf("Invalid DataDirectory index %d", id))
	}
	return dds.file.OptionalHeader.DataDirectoriesHeaders[id]
}
