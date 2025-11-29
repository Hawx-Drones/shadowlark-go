package binary

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// Decoder reads primitive values from a byte slice in big-endian order.
type Decoder struct {
	buf []byte
	pos int
}

func NewDecoder(buf []byte) *Decoder {
	return &Decoder{buf: buf, pos: 0}
}

func (d *Decoder) remaining() int {
	return len(d.buf) - d.pos
}

func (d *Decoder) readExact(n int) ([]byte, error) {
	if d.pos+n > len(d.buf) {
		return nil, errors.New("buffer underflow")
	}
	out := d.buf[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

func (d *Decoder) ReadU8() (byte, error) {
	b, err := d.readExact(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (d *Decoder) ReadBool() (bool, error) {
	b, err := d.ReadU8()
	if err != nil {
		return false, err
	}
	switch b {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("invalid bool value")
	}
}

func (d *Decoder) ReadU16() (uint16, error) {
	b, err := d.readExact(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (d *Decoder) ReadU32() (uint32, error) {
	b, err := d.readExact(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (d *Decoder) ReadU64() (uint64, error) {
	b, err := d.readExact(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (d *Decoder) ReadBytes(n int) ([]byte, error) {
	return d.readExact(n)
}

func (d *Decoder) ReadVarBytes() ([]byte, error) {
	l, err := d.ReadU32()
	if err != nil {
		return nil, err
	}
	return d.readExact(int(l))
}

func (d *Decoder) ReadString() (string, error) {
	b, err := d.ReadVarBytes()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errors.New("invalid utf-8")
	}
	return string(b), nil
}

// Remaining returns unread bytes count.
func (d *Decoder) Remaining() int {
	return d.remaining()
}
