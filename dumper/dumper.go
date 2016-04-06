package dumper

import (
	"io"

	. "github.com/RIscRIpt/pecoff"
	"github.com/davecgh/go-spew/spew"
)

type FileDumper struct {
	*File
}

func New(filename string) (*FileDumper, error) {
	f, err := Open(filename)
	if err != nil {
		return nil, err
	}
	return &FileDumper{
		File: f,
	}, nil
}

func (fd *FileDumper) Close() error {
	return fd.File.Close()
}

func (fd *FileDumper) DumpAll(w io.Writer) error {
	if err := fd.ReadAll(); err != nil {
		return err
	}
	fd.DumpHeaders(w)
	fd.DumpDataDirectories(w)
	return nil
}

func (fd *FileDumper) DumpHeaders(w io.Writer) {
	fd.dump_dos_header(w)
	fd.dump_coff_header(w)
	fd.dump_opt_header(w)
	fd.dump_sections_headers(w)
}

func (fd *FileDumper) dump_dos_header(w io.Writer) {
	if fd.DosHeader != nil {
		spew.Fdump(w, fd.DosHeader)
	}
}

func (fd *FileDumper) dump_coff_header(w io.Writer) {
	spew.Fdump(w, fd.FileHeader)
}

func (fd *FileDumper) dump_opt_header(w io.Writer) {
	if fd.OptionalHeader != nil {
		spew.Fdump(w, fd.OptionalHeader)
	}
}

func (fd *FileDumper) dump_sections_headers(w io.Writer) {
	for i := range fd.Sections {
		spew.Fdump(w, fd.Sections[i].Header)
	}
}

func (fd *FileDumper) DumpDataDirectories(w io.Writer) {
	fd.DumpImports(w)
	fd.DumpBaseRelocations(w)
}

func (fd *FileDumper) DumpImports(w io.Writer) {
	if fd.Imports == nil {
		return
	}
	for _, imp := range fd.Imports.Get() {
		spew.Fdump(w, imp.ImageImportDescriptor)
		spew.Fdump(w, imp.Library())
		spew.Fdump(w, imp.Functions())
	}
}

func (fd *FileDumper) DumpBaseRelocations(w io.Writer) {
	if fd.BaseRelocations == nil {
		return
	}
	for _, block := range fd.BaseRelocations.Get() {
		spew.Fdump(w, block.ImageBaseRelocation)
		spew.Fdump(w, block.Entries())
	}
}
