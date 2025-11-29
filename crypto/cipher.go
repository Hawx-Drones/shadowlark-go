package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

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

func deriveNonce(_ frame.Frame) [12]byte {
	return [12]byte{}
}

func EncryptFrame(f frame.Frame, key SessionKey) (frame.Frame, error) {
	if f.Flags&FlagEncrypted != 0 {
		return frame.Frame{}, errors.New("encrypt_frame: already encrypted")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return frame.Frame{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return frame.Frame{}, err
	}

	nonce := deriveNonce(f)
	payload := aead.Seal(nil, nonce[:], f.Payload, nil)

	return frame.Frame{
		Version: f.Version,
		MsgType: f.MsgType,
		Flags:   f.Flags | FlagEncrypted,
		Payload: payload,
	}, nil
}

func DecryptFrame(f frame.Frame, key SessionKey) (frame.Frame, error) {
	if f.Flags&FlagEncrypted == 0 {
		return frame.Frame{}, errors.New("decrypt_frame: frame not encrypted")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return frame.Frame{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return frame.Frame{}, err
	}

	nonce := deriveNonce(f)
	plaintext, err := aead.Open(nil, nonce[:], f.Payload, nil)
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
