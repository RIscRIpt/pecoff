package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/RIscRIpt/pecoff"
	"github.com/RIscRIpt/pecoff/binutil"
	"github.com/RIscRIpt/pecoff/dumper"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s filename\n", os.Args[0])
		os.Exit(2)
	}

	file, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()

	pcfile := pecoff.NewFile(binutil.WrapReaderAt(file))

	dumper := dumper.New(pcfile, os.Stdout)
	if err := dumper.DumpAll(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		debug.PrintStack()
		os.Exit(-1)
	}
}
