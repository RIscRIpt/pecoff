package pecoff

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/RIscRIpt/pecoff/binutil"
)

const (
	testDir          string = "test_files/"
	shortTestMaxSize int64  = 16 * 1024
)

const (
	fnDelim            = "_"
	fnNrDetailType     = 0
	fnNrDetailBits     = 1
	fnNrDetailCompiler = 2
	fnNrDetailComment  = 3
)

func parseFile(t *testing.T, filename string) *File {
	rawFile, err := os.Open(testDir + filename)
	if err != nil {
		t.Errorf("Failed to open test file `%s`", filename)
		return nil
	}

	file := NewFile(binutil.WrapReaderAt(rawFile))
	err = file.ReadAll()
	if err != nil {
		if fe, ok := err.(*FileError); ok {
			err = fe.ToMultiError()
		}
		t.Errorf("Error occured while parsing file `%s`: %v", filename, err)
		return nil
	}
	return file
}

func getAllTestFiles(t *testing.T) []os.FileInfo {
	files, err := ioutil.ReadDir(testDir)
	if err != nil {
		t.Fatalf("ioutil.ReadDir failed: %s", err.Error())
	}
	// filter-out contents of test directory, leave only appropriate files
	filtered := files[:0]
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if testing.Short() && file.Size() >= shortTestMaxSize {
			continue
		}
		filtered = append(filtered, file)
	}
	return filtered
}

func TestParseAllParallel(t *testing.T) {
	var wg sync.WaitGroup
	for _, file := range getAllTestFiles(t) {
		wg.Add(1)
		go func(filename string) {
			defer wg.Done()
			parseFile(t, filename)
		}(file.Name())
	}
	wg.Wait()
}

func TestBitness(t *testing.T) {
	var wg sync.WaitGroup
	for _, file := range getAllTestFiles(t) {
		wg.Add(1)
		go func(file os.FileInfo) {
			defer wg.Done()
			filename := file.Name()
			fnDetails := strings.Split(filename, fnDelim)
			bits, err := strconv.Atoi(fnDetails[fnNrDetailBits])
			if err != nil {
				t.Errorf("Failed to read file bitness from its name (%s): %s", fnDetails[fnNrDetailBits], err.Error())
				return
			}
			parsedFile := parseFile(t, filename)
			if parsedFile.is64Bit() {
				if bits != 64 {
					t.Errorf("File bitness doesn't match. Expected %d, got %d (%s)", bits, 64, filename)
					return
				}
			} else { //must be 32bit
				if bits != 32 {
					t.Errorf("File bitness doesn't match. Expected %d, got %d (%s)", bits, 32, filename)
					return
				}
			}
		}(file)
	}
	wg.Wait()
}
