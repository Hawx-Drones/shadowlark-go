package session

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/handshake"
)

type vectorFixture struct {
	SessionIDHex      string `json:"session_id_hex"`
	InitiatorTxKeyHex string `json:"initiator_tx_key_hex"`
	InitiatorRxKeyHex string `json:"initiator_rx_key_hex"`
	TransportRecords  []struct {
		FrameHex string `json:"frame_hex"`
	} `json:"transport_records"`
}

func TestSecureSessionEncryptDecryptRoundtrip(t *testing.T) {
	initiator, responder := pairedSessionsFromVector(t)
	plain := frame.New(0x42, 0, []byte("vector-frame-payload"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	decrypted, err := responder.DecryptFrame(encrypted)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted.Payload) != string(plain.Payload) {
		t.Fatalf("payload mismatch")
	}
	if decrypted.MsgType != plain.MsgType {
		t.Fatalf("msg type mismatch")
	}
}

func TestSecureSessionVectorFrameMatchesCoreArtifact(t *testing.T) {
	fixture := loadFixture(t)
	initiator, _ := pairedSessionsFromFixture(t, fixture)
	plain := frame.New(0x42, 0, []byte("vector-frame-payload"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(fixture.TransportRecords) == 0 {
		t.Fatalf("vector missing transport records")
	}
	expectedBytes, err := hex.DecodeString(fixture.TransportRecords[0].FrameHex)
	if err != nil {
		t.Fatalf("decode frame hex: %v", err)
	}
	actual := encodeFrameBytes(t, encrypted)
	if string(actual) != string(expectedBytes) {
		t.Fatalf("frame vector mismatch\nexpected=%x\nactual=%x", expectedBytes, actual)
	}
}

func TestSecureSessionReplayRejectedOrdered(t *testing.T) {
	initiator, responder := pairedSessionsFromVector(t)
	plain := frame.New(0x20, 0, []byte("ordered-replay"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := responder.DecryptFrame(encrypted); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if _, err := responder.DecryptFrame(encrypted); err == nil {
		t.Fatalf("expected second decrypt to fail")
	}
}

func TestSecureSessionReplayRejectedSlidingUDP(t *testing.T) {
	initiator, responder := pairedSessionsFromVector(t)
	responder.SetReplayMode(ReplayModeSlidingUDP)

	plain := frame.New(0x21, 0, []byte("udp-replay"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := responder.DecryptFrameUDP(encrypted, 0); err != nil {
		t.Fatalf("first udp decrypt: %v", err)
	}
	if _, err := responder.DecryptFrameUDP(encrypted, 0); err == nil {
		t.Fatalf("expected duplicate UDP sequence rejection")
	}
}

func TestRekeyTriggerByBytesAndClearAfterRekey(t *testing.T) {
	initiator, responder := pairedSessionsFromVector(t)
	initiator.SetRekeyPolicy(32, time.Hour)

	plain := frame.New(0x20, 0, []byte("bytes-trigger-01234567890123456789"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := responder.DecryptFrame(encrypted); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !initiator.IsRekeyRequired() {
		t.Fatalf("expected rekey requirement by bytes")
	}
	reason, ok := initiator.RekeyReason()
	if !ok || reason != RekeyReasonBytes {
		t.Fatalf("unexpected rekey reason: %v %v", reason, ok)
	}

	initiator.RekeyOutbound()
	if initiator.IsRekeyRequired() {
		t.Fatalf("expected rekey requirement cleared")
	}
}

func TestRekeyTriggerByTime(t *testing.T) {
	initiator, responder := pairedSessionsFromVector(t)
	initiator.SetRekeyPolicy(^uint64(0), 5*time.Millisecond)
	initiator.TxEpochStarted = time.Now().Add(-time.Second)

	plain := frame.New(0x20, 0, []byte("time-trigger"))
	encrypted, err := initiator.EncryptFrame(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := responder.DecryptFrame(encrypted); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !initiator.IsRekeyRequired() {
		t.Fatalf("expected rekey requirement by time")
	}
	reason, ok := initiator.RekeyReason()
	if !ok || reason != RekeyReasonTime {
		t.Fatalf("unexpected rekey reason: %v %v", reason, ok)
	}
}

func pairedSessionsFromVector(t *testing.T) (*State, *State) {
	t.Helper()
	fixture := loadFixture(t)
	return pairedSessionsFromFixture(t, fixture)
}

func pairedSessionsFromFixture(t *testing.T, fixture vectorFixture) (*State, *State) {
	t.Helper()
	sessionIDBytes, err := hex.DecodeString(fixture.SessionIDHex)
	if err != nil {
		t.Fatalf("decode session id: %v", err)
	}
	if len(sessionIDBytes) != 8 {
		t.Fatalf("unexpected session id length: %d", len(sessionIDBytes))
	}
	sessionID := uint64(sessionIDBytes[0])<<56 |
		uint64(sessionIDBytes[1])<<48 |
		uint64(sessionIDBytes[2])<<40 |
		uint64(sessionIDBytes[3])<<32 |
		uint64(sessionIDBytes[4])<<24 |
		uint64(sessionIDBytes[5])<<16 |
		uint64(sessionIDBytes[6])<<8 |
		uint64(sessionIDBytes[7])

	txKeyBytes, err := hex.DecodeString(fixture.InitiatorTxKeyHex)
	if err != nil {
		t.Fatalf("decode initiator tx key: %v", err)
	}
	rxKeyBytes, err := hex.DecodeString(fixture.InitiatorRxKeyHex)
	if err != nil {
		t.Fatalf("decode initiator rx key: %v", err)
	}
	if len(txKeyBytes) != 32 || len(rxKeyBytes) != 32 {
		t.Fatalf("unexpected key lengths tx=%d rx=%d", len(txKeyBytes), len(rxKeyBytes))
	}

	var initiatorTx [32]byte
	copy(initiatorTx[:], txKeyBytes)
	var initiatorRx [32]byte
	copy(initiatorRx[:], rxKeyBytes)

	initiatorOut := handshake.HandshakeOutput{
		Role:                    handshake.EndpointRoleInitiator,
		SessionID:               sessionID,
		TxKey:                   initiatorTx,
		RxKey:                   initiatorRx,
		NegotiatedCapabilityBit: 0x0000000F,
		NegotiatedMaxPayload:    524288,
		MaxRekeyBytes:           1_073_741_824,
		MaxRekeySeconds:         900,
	}
	responderOut := handshake.HandshakeOutput{
		Role:                    handshake.EndpointRoleResponder,
		SessionID:               sessionID,
		TxKey:                   initiatorRx,
		RxKey:                   initiatorTx,
		NegotiatedCapabilityBit: 0x0000000F,
		NegotiatedMaxPayload:    524288,
		MaxRekeyBytes:           1_073_741_824,
		MaxRekeySeconds:         900,
	}

	initiator := FromHandshakeOutput(initiatorOut)
	responder := FromHandshakeOutput(responderOut)
	return &initiator, &responder
}

func encodeFrameBytes(t *testing.T, f frame.Frame) []byte {
	t.Helper()
	enc := binary.NewEncoder()
	f.Encode(enc)
	out := make([]byte, len(enc.Bytes()))
	copy(out, enc.Bytes())
	return out
}

func loadFixture(t *testing.T) vectorFixture {
	t.Helper()
	paths := []string{
		"../shadowlark-core/notes/SHADOWLARK_TEST_VECTORS.json",
		"../../shadowlark-core/notes/SHADOWLARK_TEST_VECTORS.json",
		"../../../shadowlark-core/notes/SHADOWLARK_TEST_VECTORS.json",
		"/Users/jonathan/Desktop/Hawx/Shadowlark/shadowlark-core/notes/SHADOWLARK_TEST_VECTORS.json",
	}

	var payload []byte
	var err error
	for _, path := range paths {
		payload, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if payload == nil {
		t.Fatalf("failed to read vector artifact: %v", err)
	}

	var fixture vectorFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("decode vector json: %v", err)
	}
	return fixture
}
