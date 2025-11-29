package frame

import (
	"errors"

	"github.com/Hawx-Drones/shadowlark-go/binary"
)

const (
	Version       = 1
	MsgHeartbeat  = 0x03
	maxPayloadLen = 16 * 1024 * 1024
)

// Frame is the outer transport envelope.
type Frame struct {
	Version byte
	MsgType byte
	Flags   byte
	Payload []byte
}

func New(msgType, flags byte, payload []byte) Frame {
	return Frame{
		Version: Version,
		MsgType: msgType,
		Flags:   flags,
		Payload: payload,
	}
}

func (f Frame) Encode(enc *binary.Encoder) {
	enc.WriteU8(f.Version)
	enc.WriteU8(f.MsgType)
	enc.WriteU8(f.Flags)
	enc.WriteU32(uint32(len(f.Payload)))
	enc.WriteBytes(f.Payload)
}

func Decode(dec *binary.Decoder) (Frame, error) {
	version, err := dec.ReadU8()
	if err != nil {
		return Frame{}, err
	}
	if version != Version {
		return Frame{}, errors.New("unsupported frame version")
	}

	msgType, err := dec.ReadU8()
	if err != nil {
		return Frame{}, err
	}
	flags, err := dec.ReadU8()
	if err != nil {
		return Frame{}, err
	}
	payloadLen, err := dec.ReadU32()
	if err != nil {
		return Frame{}, err
	}
	if payloadLen > maxPayloadLen {
		return Frame{}, errors.New("payload too large")
	}
	payload, err := dec.ReadBytes(int(payloadLen))
	if err != nil {
		return Frame{}, err
	}

	return Frame{
		Version: version,
		MsgType: msgType,
		Flags:   flags,
		Payload: payload,
	}, nil
}
