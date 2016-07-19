package pecoff

type DataDirs struct {
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
