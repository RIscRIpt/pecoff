# pecoff
[![Build Status](https://travis-ci.org/RIscRIpt/pecoff.svg?branch=master)](https://travis-ci.org/RIscRIpt/pecoff)
[![Coverage](https://gocover.io/_badge/github.com/RIscRIpt/pecoff?1)](https://gocover.io/github.com/RIscRIpt/pecoff)
[![Go Report Card](https://goreportcard.com/badge/github.com/RIscRIpt/pecoff)](https://goreportcard.com/report/github.com/RIscRIpt/pecoff)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](http://godoc.org/github.com/RIscRIpt/pecoff)
[![License](https://img.shields.io/badge/license-gnu%20gpl%20v3-663366.svg)](https://github.com/RIscRIpt/pecoff/blob/master/LICENSE)

This package implements access to PE (Microsoft Windows Portable Executable) and MS-COFF (Microsoft Common Object File Format) files in [Go programming language](https://golang.org/).

In contrast to the [`debug.pe`](https://golang.org/pkg/debug/pe/) package from the standard library of Go, this implementation gives you access to much more file contents, such as:
  - Dos header;
  - File header;
  - Optional header;
  - Data directories of an optional header;
  - Headers of sections;
  - Relocations of sections;
  - String table of a COFF file;
  - and others...

### Example
The following example shows you how to check `MachineType` field inside a `FileHeader`
```go
func Example_MachineType() {
    file, _ := os.Open(testDir + "exe_32_fasm+1-71-39_aslr")
    defer file.Close()
    // Creating PE/COFF File
    pe := pecoff.Explore(binutil.WrapReaderAt(file))
    // Reading DosHeader to get offset to the file header
    pe.ReadDosHeader()
    // Reading FileHeader
    pe.ReadFileHeader()
    // Releasing resources (i.e. file)
    pe.Seal()
    // Priting string represntation of the MachineType
    fmt.Println(windef.MAP_IMAGE_FILE_MACHINE[pe.FileHeader.Machine])
    // Output:
    // I386
}
```
More usage examples can be found in the [tests](https://github.com/RIscRIpt/pecoff/blob/master/file_test.go)

### Limitations
This package can fully parse only PE/COFF files
which are compiled for the following two architectures:
  - AMD64 `IMAGE_FILE_MACHINE_AMD64`
  - I386  `IMAGE_FILE_MACHINE_I386`

### Thread safety
This package is **not** thread safe.
Calling `Read*` methods must be done from a single thread, otherwise the consistency and correctness of the parsed data **cannot** be guaranteed.
But all other operations, which don't modify the contents of the `File` can be safely performed from a multiple goroutines (i.e. accessing the `File` object and its fields).

### TODO
Add support for the following data directories of an optional header:
  - Exports
  - Resources
  - Exceptions
  - Security
  - Debug
  - Architecture
  - GlobalPtrs
  - TLS
  - LoadConfig
  - BoundImports
  - IAT
  - DelayImports
  - COMDescriptors

### License
[GNU General Public License v3.0](https://github.com/RIscRIpt/pecoff/blob/master/LICENSE)

