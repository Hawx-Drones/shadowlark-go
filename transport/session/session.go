package session

import (
	"errors"
	"math"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/crypto"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/handshake"
)

const udpReplayWindowSize = 1024
const udpReplayWindowWords = udpReplayWindowSize / 64

type ReplayMode byte

const (
	ReplayModeOrderedTCP ReplayMode = 1
	ReplayModeSlidingUDP ReplayMode = 2
)

type RekeyReason byte

const (
	RekeyReasonTime   RekeyReason = 1
	RekeyReasonBytes  RekeyReason = 2
	RekeyReasonManual RekeyReason = 3
)

type udpReplayWindow struct {
	initialized bool
	highestSeen uint64
	bits        [udpReplayWindowWords]uint64
}

func (w *udpReplayWindow) validateCandidate(sequence uint64) error {
	if !w.initialized {
		return nil
	}
	if sequence > w.highestSeen {
		return nil
	}
	distance := int(w.highestSeen - sequence)
	if distance >= udpReplayWindowSize {
		return errors.New("replay rejected: sequence is outside UDP replay window")
	}
	if w.contains(distance) {
		return errors.New("replay rejected: duplicate UDP sequence")
	}
	return nil
}

func (w *udpReplayWindow) markSeen(sequence uint64) {
	if !w.initialized {
		w.initialized = true
		w.highestSeen = sequence
		w.clear()
		w.set(0)
		return
	}

	if sequence > w.highestSeen {
		shift := int(sequence - w.highestSeen)
		w.shiftWindow(shift)
		w.highestSeen = sequence
		w.set(0)
		return
	}

	distance := int(w.highestSeen - sequence)
	if distance < udpReplayWindowSize {
		w.set(distance)
	}
}

func (w *udpReplayWindow) clear() {
	for i := range w.bits {
		w.bits[i] = 0
	}
}

func (w *udpReplayWindow) contains(bitIndex int) bool {
	word := bitIndex / 64
	bit := bitIndex % 64
	return (w.bits[word] & (1 << bit)) != 0
}

func (w *udpReplayWindow) set(bitIndex int) {
	word := bitIndex / 64
	bit := bitIndex % 64
	w.bits[word] |= 1 << bit
}

func (w *udpReplayWindow) shiftWindow(shift int) {
	if shift >= udpReplayWindowSize {
		w.clear()
		return
	}
	if shift == 0 {
		return
	}

	wordShift := shift / 64
	bitShift := shift % 64
	var next [udpReplayWindowWords]uint64
	for dst := udpReplayWindowWords - 1; dst >= 0; dst-- {
		if dst < wordShift {
			continue
		}
		src := dst - wordShift
		value := w.bits[src] << bitShift
		if bitShift != 0 && src > 0 {
			value |= w.bits[src-1] >> (64 - bitShift)
		}
		next[dst] = value
	}
	w.bits = next
}

type State struct {
	Role            handshake.EndpointRole
	SessionID       uint64
	TxKey           crypto.SessionKey
	RxKey           crypto.SessionKey
	TxEpoch         uint32
	RxEpoch         uint32
	TxSequence      uint64
	RxSequence      uint64
	LastSeen        time.Time
	ReplayMode      ReplayMode
	TxBytesInEpoch  uint64
	TxEpochStarted  time.Time
	RekeyMaxBytes   uint64
	RekeyMaxAge     time.Duration
	rekeyRequired   bool
	rekeyReason     *RekeyReason
	udpReplayWindow udpReplayWindow
}

func FromHandshakeOutput(output handshake.HandshakeOutput) State {
	now := time.Now()
	return State{
		Role:           output.Role,
		SessionID:      output.SessionID,
		TxKey:          output.TxKey,
		RxKey:          output.RxKey,
		TxEpoch:        0,
		RxEpoch:        0,
		TxSequence:     0,
		RxSequence:     0,
		LastSeen:       now,
		ReplayMode:     ReplayModeOrderedTCP,
		TxBytesInEpoch: 0,
		TxEpochStarted: now,
		RekeyMaxBytes:  maxUint64(output.MaxRekeyBytes, 1),
		RekeyMaxAge:    maxDuration(time.Duration(output.MaxRekeySeconds)*time.Second, time.Second),
	}
}

func (s *State) Touch() {
	s.LastSeen = time.Now()
}

func (s *State) IsTimedOut(timeout time.Duration) bool {
	return time.Since(s.LastSeen) >= timeout
}

func (s *State) SetReplayMode(mode ReplayMode) {
	s.ReplayMode = mode
	if mode == ReplayModeSlidingUDP {
		s.udpReplayWindow = udpReplayWindow{}
	}
}

func (s *State) SetRekeyPolicy(maxBytes uint64, maxAge time.Duration) {
	s.RekeyMaxBytes = maxUint64(maxBytes, 1)
	s.RekeyMaxAge = maxDuration(maxAge, time.Second)
}

func (s *State) IsRekeyRequired() bool {
	return s.rekeyRequired
}

func (s *State) RekeyReason() (RekeyReason, bool) {
	if s.rekeyReason == nil {
		return 0, false
	}
	return *s.rekeyReason, true
}

func (s *State) MarkRekeyManual() {
	reason := RekeyReasonManual
	s.rekeyRequired = true
	s.rekeyReason = &reason
}

func (s *State) EncryptFrame(f frame.Frame) (frame.Frame, error) {
	if f.Flags&crypto.FlagEncrypted != 0 {
		return frame.Frame{}, errors.New("frame already encrypted")
	}
	if s.TxSequence == math.MaxUint64 {
		return frame.Frame{}, errors.New("outbound counter overflow")
	}

	nonce := crypto.DeriveNonce(s.SessionID, s.TxKey, s.txDirection(), s.TxSequence)
	aad := crypto.BuildAAD(f, s.TxEpoch, s.TxSequence)
	encrypted, err := crypto.EncryptFrame(f, s.TxKey, nonce, aad)
	if err != nil {
		return frame.Frame{}, err
	}

	s.TxSequence++
	s.TxBytesInEpoch += uint64(len(encrypted.Payload))
	s.refreshRekeyTrigger()
	s.Touch()
	return encrypted, nil
}

func (s *State) DecryptFrame(f frame.Frame) (frame.Frame, error) {
	if f.Flags&crypto.FlagEncrypted == 0 {
		return frame.Frame{}, errors.New("frame is not encrypted")
	}
	if s.ReplayMode != ReplayModeOrderedTCP {
		return frame.Frame{}, errors.New("ordered decrypt requires ordered replay mode")
	}
	if s.RxSequence == math.MaxUint64 {
		return frame.Frame{}, errors.New("inbound counter overflow")
	}

	nonce := crypto.DeriveNonce(s.SessionID, s.RxKey, s.rxDirection(), s.RxSequence)
	aad := crypto.BuildAAD(f, s.RxEpoch, s.RxSequence)
	decrypted, err := crypto.DecryptFrame(f, s.RxKey, nonce, aad)
	if err != nil {
		return frame.Frame{}, errors.New("decrypt failed or replay/out-of-order record")
	}

	s.RxSequence++
	s.Touch()
	return decrypted, nil
}

func (s *State) DecryptFrameUDP(f frame.Frame, sequence uint64) (frame.Frame, error) {
	if f.Flags&crypto.FlagEncrypted == 0 {
		return frame.Frame{}, errors.New("frame is not encrypted")
	}
	if s.ReplayMode != ReplayModeSlidingUDP {
		return frame.Frame{}, errors.New("udp decrypt requires sliding UDP replay mode")
	}
	if err := s.udpReplayWindow.validateCandidate(sequence); err != nil {
		return frame.Frame{}, err
	}

	nonce := crypto.DeriveNonce(s.SessionID, s.RxKey, s.rxDirection(), sequence)
	aad := crypto.BuildAAD(f, s.RxEpoch, sequence)
	decrypted, err := crypto.DecryptFrame(f, s.RxKey, nonce, aad)
	if err != nil {
		return frame.Frame{}, errors.New("decrypt failed")
	}

	s.udpReplayWindow.markSeen(sequence)
	s.Touch()
	return decrypted, nil
}

func (s *State) RekeyOutbound() {
	s.TxKey = crypto.RekeyMaterial(s.TxKey, s.SessionID, s.txDirection())
	s.TxEpoch++
	s.TxSequence = 0
	s.TxBytesInEpoch = 0
	s.TxEpochStarted = time.Now()
	s.rekeyRequired = false
	s.rekeyReason = nil
}

func (s *State) RekeyInbound() {
	s.RxKey = crypto.RekeyMaterial(s.RxKey, s.SessionID, s.rxDirection())
	s.RxEpoch++
	s.RxSequence = 0
	s.udpReplayWindow = udpReplayWindow{}
}

func (s *State) IsEncrypted(f frame.Frame) bool {
	return f.Flags&crypto.FlagEncrypted != 0
}

func (s *State) refreshRekeyTrigger() {
	if s.rekeyRequired {
		return
	}
	if s.TxBytesInEpoch >= s.RekeyMaxBytes {
		reason := RekeyReasonBytes
		s.rekeyRequired = true
		s.rekeyReason = &reason
		return
	}
	if time.Since(s.TxEpochStarted) >= s.RekeyMaxAge {
		reason := RekeyReasonTime
		s.rekeyRequired = true
		s.rekeyReason = &reason
	}
}

func (s *State) txDirection() byte {
	if s.Role == handshake.EndpointRoleInitiator {
		return 0x01
	}
	return 0x02
}

func (s *State) rxDirection() byte {
	if s.Role == handshake.EndpointRoleInitiator {
		return 0x02
	}
	return 0x01
}

func maxUint64(v uint64, minimum uint64) uint64 {
	if v < minimum {
		return minimum
	}
	return v
}

func maxDuration(v time.Duration, minimum time.Duration) time.Duration {
	if v < minimum {
		return minimum
	}
	return v
}
