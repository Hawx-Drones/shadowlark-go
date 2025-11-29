package crypto

import (
	"testing"

	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	var key SessionKey
	for i := 0; i < 32; i++ {
		key[i] = byte(i + 1)
	}
	original := frame.New(9, 0, []byte("shadowlark-test"))

	enc, err := EncryptFrame(original, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc.Flags&FlagEncrypted == 0 {
		t.Fatalf("expected encrypted flag set")
	}
	if string(enc.Payload) == string(original.Payload) {
		t.Fatalf("ciphertext should differ from plaintext")
	}

	dec, err := DecryptFrame(enc, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec.Payload) != string(original.Payload) {
		t.Fatalf("roundtrip mismatch: %q", dec.Payload)
	}
}
