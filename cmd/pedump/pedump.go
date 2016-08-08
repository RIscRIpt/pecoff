package main

import (
	"fmt"
	"os"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/dumper"
)

// Exit codes
const (
	_ = 256 - iota
	ECinvalidUsage
	ECcannotOpenFile
	ECfailReadAll
	ECfailDump
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s pecoff[.exe|.dll|.obj]\n", os.Args[0])
		os.Exit(ECinvalidUsage)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(ECcannotOpenFile)
	}
	defer file.Close()

	pcfile := pecoff.NewFile(binutil.WrapReaderAt(file))
	if err := pcfile.ReadAll(); err != nil {
		fmt.Fprintln(os.Stderr, pecoff.ErrorFlatten(err))
		os.Exit(ECfailReadAll)
	}
	dumper := dumper.New(pcfile, os.Stdout)
	dumper.DumpAll()
}
