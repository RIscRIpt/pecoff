package binutil

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestByteSlice(t *testing.T) {
	var s struct {
		Len byte
		Str [14]byte
	}
	b := []byte("****_Hello, gophers")
	b[4] = byte(len(b) - 5)
	bs := WrapByteSlice(b)
	err := bs.ReadAtInto(&s, 4)
	if err != nil {
		t.Fatalf("ReadAtInto failed: %s\n", err)
	}
	if int(s.Len) != len(s.Str) {
		t.Fatalf("s.Len <%d> != Len(s.Str) <%d>\n", s.Len, len(s.Str))
	}
	sstr := string(s.Str[:])
	if sstr != "Hello, gophers" {
		t.Fatalf("unexpected string in s.Str : %s\n", sstr)
	}
}

func TestReaderAt(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "pecoff_binutil_TestReaderAt.tmp")
	if err != nil {
		t.Fatalf("ioutil.TempFile failed: %s\n", err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	var s struct {
		Len byte
		Str [14]byte
	}
	b := []byte("****_Hello, gophers")
	b[4] = byte(len(b) - 5)
	_, err = tmpfile.Write(b)
	if err != nil {
		t.Fatalf("tmpfile.Write failed: %s\n", err)
	}

	rat := WrapReaderAt(tmpfile)
	err = rat.ReadAtInto(&s, 4)
	if err != nil {
		t.Fatalf("ReadAtInto failed: %s\n", err)
	}
	if int(s.Len) != len(s.Str) {
		t.Fatalf("s.Len <%d> != Len(s.Str) <%d>\n", s.Len, len(s.Str))
	}
	sstr := string(s.Str[:])
	if sstr != "Hello, gophers" {
		t.Fatalf("unexpected string in s.Str : %s\n", sstr)
	}
}
