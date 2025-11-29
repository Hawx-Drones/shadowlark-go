package handshake

import (
	"crypto/rand"
	"errors"

	"github.com/shadowlark/shadowlark-go/binary"
	"github.com/shadowlark/shadowlark-go/transport/frame"
)

const (
	MsgHandshakeInit byte = 1
	MsgHandshakeAck  byte = 2
)

type Nonce32 [32]byte

// Init mirrors the Rust HandshakeInit struct.
type Init struct {
	Version     byte
	ClientNonce Nonce32
	Features    uint32
}

func NewInit(features uint32) (Init, error) {
	var nonce Nonce32
	if _, err := rand.Read(nonce[:]); err != nil {
		return Init{}, err
	}
	return Init{
		Version:     frame.Version,
		ClientNonce: nonce,
		Features:    features,
	}, nil
}

func (h Init) Encode(enc *binary.Encoder) {
	enc.WriteU8(h.Version)
	enc.WriteBytes(h.ClientNonce[:])
	enc.WriteU32(h.Features)
}

func DecodeInit(dec *binary.Decoder) (Init, error) {
	version, err := dec.ReadU8()
	if err != nil {
		return Init{}, err
	}
	if version != frame.Version {
		return Init{}, errors.New("handshake init: unsupported version")
	}
	nonceBytes, err := dec.ReadBytes(32)
	if err != nil {
		return Init{}, err
	}
	var nonce Nonce32
	copy(nonce[:], nonceBytes)
	features, err := dec.ReadU32()
	if err != nil {
		return Init{}, err
	}
	return Init{
		Version:     version,
		ClientNonce: nonce,
		Features:    features,
	}, nil
}

func (h Init) ToFrame() frame.Frame {
	enc := binary.NewEncoder()
	h.Encode(enc)
	return frame.New(MsgHandshakeInit, 0, enc.Bytes())
}

func InitFromFrame(f frame.Frame) (Init, error) {
	if f.MsgType != MsgHandshakeInit {
		return Init{}, errors.New("expected HANDSHAKE_INIT")
	}
	dec := binary.NewDecoder(f.Payload)
	return DecodeInit(dec)
}

// Ack mirrors the Rust HandshakeAck struct.
type Ack struct {
	Version          byte
	ServerNonce      Nonce32
	AcceptedFeatures uint32
}

func NewAck(acceptedFeatures uint32) (Ack, error) {
	var nonce Nonce32
	if _, err := rand.Read(nonce[:]); err != nil {
		return Ack{}, err
	}
	return Ack{
		Version:          frame.Version,
		ServerNonce:      nonce,
		AcceptedFeatures: acceptedFeatures,
	}, nil
}

func (h Ack) Encode(enc *binary.Encoder) {
	enc.WriteU8(h.Version)
	enc.WriteBytes(h.ServerNonce[:])
	enc.WriteU32(h.AcceptedFeatures)
}

func DecodeAck(dec *binary.Decoder) (Ack, error) {
	version, err := dec.ReadU8()
	if err != nil {
		return Ack{}, err
	}
	if version != frame.Version {
		return Ack{}, errors.New("handshake ack: unsupported version")
	}
	nonceBytes, err := dec.ReadBytes(32)
	if err != nil {
		return Ack{}, err
	}
	var nonce Nonce32
	copy(nonce[:], nonceBytes)
	features, err := dec.ReadU32()
	if err != nil {
		return Ack{}, err
	}
	return Ack{
		Version:          version,
		ServerNonce:      nonce,
		AcceptedFeatures: features,
	}, nil
}

func (h Ack) ToFrame() frame.Frame {
	enc := binary.NewEncoder()
	h.Encode(enc)
	return frame.New(MsgHandshakeAck, 0, enc.Bytes())
}

func AckFromFrame(f frame.Frame) (Ack, error) {
	if f.MsgType != MsgHandshakeAck {
		return Ack{}, errors.New("expected HANDSHAKE_ACK")
	}
	dec := binary.NewDecoder(f.Payload)
	return DecodeAck(dec)
}
