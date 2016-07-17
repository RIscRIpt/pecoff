package binary

// ReaderAtInto is the interface that wraps the ReadAtInto method.
//
// ReaderAtInto is an analogue to io.ReaderAt interface,
// which can read not only into byte slice ([]byte).
//
// ReadAtInto reads structured binary little-endian data into p
// starting at offset off in the underlying input source.
// p must be a pointer to a fixed-size value or a slice of fixed-size values.
//
// Clients of ReadAtInto can execute parallel ReadAtInto calls
// on the same input source.
//
// A basic implementation of ReaderAtInto can use "encoding/binary" package,
// and return errors directly from that package.
//
// Implementations must not retain p.
type ReaderAtInto interface {
	ReadAtInto(p interface{}, off int64) error
}
