package binary

import (
	"bytes"
	"encoding/binary"
)

// Encoder writes primitive values in big-endian order.
type Encoder struct {
	buf bytes.Buffer
}

// NewEncoder constructs an Encoder with a small pre-allocation.
func NewEncoder() *Encoder {
	return &Encoder{buf: *bytes.NewBuffer(make([]byte, 0, 128))}
}

func (e *Encoder) WriteU8(v byte) {
	_ = e.buf.WriteByte(v)
}

func (e *Encoder) WriteBool(v bool) {
	if v {
		e.WriteU8(1)
	} else {
		e.WriteU8(0)
	}
}

func (e *Encoder) WriteU16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, _ = e.buf.Write(b[:])
}

func (e *Encoder) WriteU32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, _ = e.buf.Write(b[:])
}

func (e *Encoder) WriteU64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = e.buf.Write(b[:])
}

func (e *Encoder) WriteBytes(b []byte) {
	_, _ = e.buf.Write(b)
}

func (e *Encoder) WriteVarBytes(b []byte) {
	e.WriteU32(uint32(len(b)))
	e.WriteBytes(b)
}

func (e *Encoder) WriteString(s string) {
	e.WriteVarBytes([]byte(s))
}

// Bytes returns the underlying buffer.
func (e *Encoder) Bytes() []byte {
	return e.buf.Bytes()
}
