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
	plain := frame.New(9, 0, []byte("shadowlark-test"))
	nonce := DeriveNonce(0x0102030405060708, key, 0x01, 0)
	aad := BuildAAD(plain, 0, 0)

	encrypted, err := EncryptFrame(plain, key, nonce, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if encrypted.Flags&FlagEncrypted == 0 {
		t.Fatalf("expected encrypted flag set")
	}
	if string(encrypted.Payload) == string(plain.Payload) {
		t.Fatalf("ciphertext should differ from plaintext")
	}

	decrypted, err := DecryptFrame(encrypted, key, nonce, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted.Payload) != string(plain.Payload) {
		t.Fatalf("roundtrip mismatch: %q", decrypted.Payload)
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	var key SessionKey
	for i := 0; i < 32; i++ {
		key[i] = byte(255 - i)
	}
	plain := frame.New(0x33, 0, []byte("tamper-check"))
	nonce := DeriveNonce(0x8877665544332211, key, 0x01, 7)
	aad := BuildAAD(plain, 2, 7)
	encrypted, err := EncryptFrame(plain, key, nonce, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encrypted.Payload[len(encrypted.Payload)-1] ^= 0x01
	if _, err := DecryptFrame(encrypted, key, nonce, aad); err == nil {
		t.Fatalf("expected tampered ciphertext to fail")
	}
}
