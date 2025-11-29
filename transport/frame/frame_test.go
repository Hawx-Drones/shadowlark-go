package frame

import (
	"testing"

	"github.com/Hawx-Drones/shadowlark-go/binary"
)

func TestFrameRoundtrip(t *testing.T) {
	f := New(2, 0, []byte("hello"))
	enc := binary.NewEncoder()
	f.Encode(enc)

	dec := binary.NewDecoder(enc.Bytes())
	decoded, err := Decode(dec)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if decoded.Version != Version || decoded.MsgType != 2 || decoded.Flags != 0 {
		t.Fatalf("unexpected header: %+v", decoded)
	}
	if string(decoded.Payload) != "hello" {
		t.Fatalf("unexpected payload %q", decoded.Payload)
	}
}
