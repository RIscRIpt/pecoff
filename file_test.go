package pecoff

import (
	"io/ioutil"
	"os"
	"testing"
)

const (
	testDir          string = "test_files/"
	shortTestMaxSize int64  = 16 * 1024
)

func TestParseAllParallel(t *testing.T) {
	testFiles, err := ioutil.ReadDir(testDir)
	if err != nil {
		t.Fatalf("Failed to read test directory `%s`", testDir)
	}
	for _, file := range testFiles {
		if file.IsDir() {
			continue
		}
		if testing.Short() && file.Size() >= shortTestMaxSize {
			continue
		}
		go parseFile(t, file.Name())
	}
}

func parseFile(t *testing.T, filename string) bool {
	rawFile, err := os.Open(testDir + filename)
	if err != nil {
		t.Errorf("Failed to open test file `%s`", filename)
		return false
	}

	file := NewFile(rawFile)
	err = file.Parse()
	if err != nil {
		t.Errorf("Error occured while parsing file `%s`: %s", filename, err)
		return false
	}
	return true
}
