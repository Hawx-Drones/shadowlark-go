package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
)

const FlagEncrypted byte = 0x01

type SessionKey [32]byte

func DeriveSessionKey(client, server [32]byte) SessionKey {
	var out SessionKey
	for i := 0; i < 32; i++ {
		out[i] = client[i] ^ server[i]
	}
	return out
}

func DeriveNonce(sessionID uint64, key SessionKey, direction byte, sequence uint64) [12]byte {
	h := sha256.New()
	h.Write([]byte("SHADOWLARK_NONCE_PREFIX"))
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], sessionID)
	h.Write(sid[:])
	h.Write([]byte{direction})
	h.Write(key[:])
	digest := h.Sum(nil)

	var nonce [12]byte
	copy(nonce[0:4], digest[0:4])
	binary.BigEndian.PutUint64(nonce[4:12], sequence)
	return nonce
}

func BuildAAD(f frame.Frame, epoch uint32, sequence uint64) [16]byte {
	var aad [16]byte
	aad[0] = f.Version
	aad[1] = f.MsgType
	aad[2] = f.Flags | FlagEncrypted
	binary.BigEndian.PutUint32(aad[3:7], epoch)
	binary.BigEndian.PutUint64(aad[7:15], sequence)
	aad[15] = 0
	return aad
}

func RekeyMaterial(key SessionKey, sessionID uint64, direction byte) SessionKey {
	h := sha256.New()
	h.Write([]byte("SHADOWLARK_REKEY"))
	var sid [8]byte
	binary.BigEndian.PutUint64(sid[:], sessionID)
	h.Write(sid[:])
	h.Write([]byte{direction})
	h.Write(key[:])
	digest := h.Sum(nil)

	var out SessionKey
	copy(out[:], digest[0:32])
	return out
}

func EncryptFrame(f frame.Frame, key SessionKey, nonce [12]byte, aad [16]byte) (frame.Frame, error) {
	if f.Flags&FlagEncrypted != 0 {
		return frame.Frame{}, errors.New("encrypt_frame: already encrypted")
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return frame.Frame{}, err
	}
	ciphertext := aead.Seal(nil, nonce[:], f.Payload, aad[:])
	return frame.Frame{
		Version: f.Version,
		MsgType: f.MsgType,
		Flags:   f.Flags | FlagEncrypted,
		Payload: ciphertext,
	}, nil
}

func DecryptFrame(f frame.Frame, key SessionKey, nonce [12]byte, aad [16]byte) (frame.Frame, error) {
	if f.Flags&FlagEncrypted == 0 {
		return frame.Frame{}, errors.New("decrypt_frame: frame not encrypted")
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return frame.Frame{}, err
	}
	plaintext, err := aead.Open(nil, nonce[:], f.Payload, aad[:])
	if err != nil {
		return frame.Frame{}, err
	}
	return frame.Frame{
		Version: f.Version,
		MsgType: f.MsgType,
		Flags:   f.Flags &^ FlagEncrypted,
		Payload: plaintext,
	}, nil
}
