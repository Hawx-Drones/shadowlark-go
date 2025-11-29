package session

import (
	"time"

	"github.com/Hawx-Drones/shadowlark-go/crypto"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/handshake"
)

type State struct {
	ClientNonce [32]byte
	ServerNonce [32]byte
	SessionKey  crypto.SessionKey
	LastSeen    time.Time
}

func FromHandshake(init handshake.Init, ack handshake.Ack) State {
	key := crypto.DeriveSessionKey(init.ClientNonce, ack.ServerNonce)
	return State{
		ClientNonce: init.ClientNonce,
		ServerNonce: ack.ServerNonce,
		SessionKey:  key,
		LastSeen:    time.Now(),
	}
}

func New(clientNonce, serverNonce [32]byte, key crypto.SessionKey) State {
	return State{
		ClientNonce: clientNonce,
		ServerNonce: serverNonce,
		SessionKey:  key,
		LastSeen:    time.Now(),
	}
}

func (s *State) Touch() {
	s.LastSeen = time.Now()
}

func (s *State) IsTimedOut(timeout time.Duration) bool {
	return time.Since(s.LastSeen) >= timeout
}

func (s *State) EncryptFrame(f frame.Frame) (frame.Frame, error) {
	return crypto.EncryptFrame(f, s.SessionKey)
}

func (s *State) DecryptFrame(f frame.Frame) (frame.Frame, error) {
	return crypto.DecryptFrame(f, s.SessionKey)
}

func (s *State) IsEncrypted(f frame.Frame) bool {
	return f.Flags&crypto.FlagEncrypted != 0
}
