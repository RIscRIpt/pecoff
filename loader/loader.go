package loader

import (
	"github.com/RIscRIpt/pecoff"
)

// Loader allows to read PE/COFF file, apply relocations and get raw data of sections.
type Loader struct {
	*pecoff.File
}

// New constructs new PE/COFF file Loader
func New(filename string) (l *Loader, err error) {
	file, err := pecoff.Open(filename)
	if err != nil {
		return
	}
	// Read all required data to avoid panics later
	if err = file.ReadAll(); err != nil {
		return
	}
	return &Loader{
		File: file,
	}, nil
}

// EntryPoint returns virtual address of the entry point
func (l *Loader) EntryPoint() uint32 {
	return l.OptionalHeader.EntryPoint()
}

// Imports returns map of slice of function names as strings, where key is import library name
func (l *Loader) Imports() (imports map[string][]string) {
	imports = make(map[string][]string)
	for _, i := range l.Imports.Get() {
		imports[i.Library()] = i.Functions()
	}
	return
}

// Sections returns map of sections' raw data ([]bytes) with a key of virtual address
func (l *Loader) Sections() (sections map[uint32][]byte) {
	sections = make(map[uint32][]byte)
	for _, s := range l.Sections {
		sections[s.Header.VirtualAddress] = s.RawData()
	}
	return
}

// RelocateBase applies base relocations
func (l *Loader) RelocateBase(base uint64) {
	for _, relBlock := range l.BaseRelocations.Get() {
		s := l.File.Sections.GetByVA(relBlock.VirtualAddress)
		if s == nil {
			panic("Must not happen")
		}
		for _, relEntry := range relBlock.Entries() {
			s.ApplyBaseRelocation(base, relBlock.VirtualAddress, relEntry)
		}
	}
}

// DefineImports sets up import table with specified addresses
func (l *Loader) DefineImports(imports map[string]map[string]uint64) {
	for _, i := range l.Imports.Get() {
		i.SetAddresses(imports[i.Library()])
	}
}
