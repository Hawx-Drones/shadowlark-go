package handshake

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
)

type vectorData struct {
	Initiator struct {
		X25519StaticPrivateHex    string `json:"x25519_static_private_hex"`
		X25519EphemeralPrivateHex string `json:"x25519_ephemeral_private_hex"`
		IdentityBundleHex         string `json:"identity_bundle_hex"`
	} `json:"initiator"`
	Responder struct {
		X25519StaticPrivateHex    string `json:"x25519_static_private_hex"`
		X25519EphemeralPrivateHex string `json:"x25519_ephemeral_private_hex"`
		IdentityBundleHex         string `json:"identity_bundle_hex"`
	} `json:"responder"`
	HandshakeRecordsHex []string `json:"handshake_records_hex"`
	TranscriptHashHex   string   `json:"transcript_hash_hex"`
	SessionIDHex        string   `json:"session_id_hex"`
	InitiatorTxKeyHex   string   `json:"initiator_tx_key_hex"`
	InitiatorRxKeyHex   string   `json:"initiator_rx_key_hex"`
}

func TestIdentityBundleRoundtripAndValidation(t *testing.T) {
	identity, err := GenerateIdentityKeypair()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	now := uint64(1_700_000_000)
	bundle, err := SignedIdentityBundle("peer-1", now-60, now+60, identity)
	if err != nil {
		t.Fatalf("signed bundle: %v", err)
	}
	bytes, err := bundle.ToBytes()
	if err != nil {
		t.Fatalf("bundle bytes: %v", err)
	}
	decoded, err := IdentityBundleFromBytes(bytes)
	if err != nil {
		t.Fatalf("bundle decode: %v", err)
	}
	trust := StrictTrustStore()
	trust.Pin(decoded.Ed25519Public)
	if err := decoded.Validate(trust, now); err != nil {
		t.Fatalf("bundle validate: %v", err)
	}
}

func TestSecureHandshakeRoundtrip(t *testing.T) {
	now := uint64(1_700_000_000)
	initiatorID, err := GenerateIdentityKeypair()
	if err != nil {
		t.Fatalf("generate initiator: %v", err)
	}
	responderID, err := GenerateIdentityKeypair()
	if err != nil {
		t.Fatalf("generate responder: %v", err)
	}

	initiatorBundle, err := SignedIdentityBundle("initiator", now-60, now+300, initiatorID)
	if err != nil {
		t.Fatalf("bundle initiator: %v", err)
	}
	responderBundle, err := SignedIdentityBundle("responder", now-60, now+300, responderID)
	if err != nil {
		t.Fatalf("bundle responder: %v", err)
	}

	initiatorTrust := StrictTrustStore()
	initiatorTrust.Pin(responderBundle.Ed25519Public)
	responderTrust := StrictTrustStore()
	responderTrust.Pin(initiatorBundle.Ed25519Public)

	initiator, err := NewSecureInitiator(initiatorID, initiatorBundle, initiatorTrust, DefaultHandshakePolicy())
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	responder, err := NewSecureResponder(responderID, responderBundle, responderTrust, DefaultHandshakePolicy())
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	clientHello, err := initiator.BuildClientHello()
	if err != nil {
		t.Fatalf("build client hello: %v", err)
	}
	serverHello, err := responder.HandleClientHello(clientHello, now)
	if err != nil {
		t.Fatalf("handle client hello: %v", err)
	}
	if err := initiator.HandleServerHello(serverHello, now); err != nil {
		t.Fatalf("handle server hello: %v", err)
	}
	clientFinish, err := initiator.BuildClientFinish()
	if err != nil {
		t.Fatalf("build client finish: %v", err)
	}
	responderOut, err := responder.HandleClientFinish(clientFinish)
	if err != nil {
		t.Fatalf("handle client finish: %v", err)
	}
	initiatorOut, err := initiator.Finalize()
	if err != nil {
		t.Fatalf("finalize initiator: %v", err)
	}

	if initiatorOut.SessionID != responderOut.SessionID {
		t.Fatalf("session id mismatch")
	}
	if initiatorOut.TxKey != responderOut.RxKey {
		t.Fatalf("initiator tx != responder rx")
	}
	if initiatorOut.RxKey != responderOut.TxKey {
		t.Fatalf("initiator rx != responder tx")
	}
}

func TestSecureHandshakeRejectsUnknownIdentity(t *testing.T) {
	now := uint64(1_700_000_000)
	initiatorID, _ := GenerateIdentityKeypair()
	responderID, _ := GenerateIdentityKeypair()
	initiatorBundle, _ := SignedIdentityBundle("initiator", now-60, now+300, initiatorID)
	responderBundle, _ := SignedIdentityBundle("responder", now-60, now+300, responderID)

	initiatorTrust := StrictTrustStore()
	responderTrust := StrictTrustStore()
	responderTrust.Pin(initiatorBundle.Ed25519Public)

	initiator, _ := NewSecureInitiator(initiatorID, initiatorBundle, initiatorTrust, DefaultHandshakePolicy())
	responder, _ := NewSecureResponder(responderID, responderBundle, responderTrust, DefaultHandshakePolicy())

	clientHello, _ := initiator.BuildClientHello()
	serverHello, err := responder.HandleClientHello(clientHello, now)
	if err != nil {
		t.Fatalf("server hello failed unexpectedly: %v", err)
	}
	if err := initiator.HandleServerHello(serverHello, now); err == nil {
		t.Fatalf("expected unknown-identity rejection")
	}
}

func TestClientHelloTrailingBytesRejected(t *testing.T) {
	bundle := IdentityBundle{
		BundleVersion:      IdentityBundleVersion,
		SigAlg:             IdentityBundleSigAlgEd25519,
		KeyID:              "peer",
		NotBeforeUnix:      0,
		NotAfterUnix:       10,
		X25519StaticPublic: [32]byte{1},
		Ed25519Public:      [32]byte{2},
		Signature:          [64]byte{3},
	}
	hello := ClientHello{
		CapabilityBits:      1,
		RequestedMaxPayload: 1024,
		EphPublic:           [32]byte{7},
		IdentityBundle:      bundle,
	}
	f, err := hello.ToFrame()
	if err != nil {
		t.Fatalf("to frame: %v", err)
	}
	f.Payload = append(f.Payload, 0xAA)
	if _, err := ClientHelloFromFrame(f); err == nil {
		t.Fatalf("expected trailing wrapper bytes rejection")
	}
}

func TestDeterministicHandshakeVectorsFromCoreArtifact(t *testing.T) {
	vector := loadVector(t)

	initiatorStaticPrivate := mustHex32(t, vector.Initiator.X25519StaticPrivateHex)
	responderStaticPrivate := mustHex32(t, vector.Responder.X25519StaticPrivateHex)
	initiatorStaticPublic, err := x25519PublicFromPrivate(initiatorStaticPrivate)
	if err != nil {
		t.Fatalf("initiator static public: %v", err)
	}
	responderStaticPublic, err := x25519PublicFromPrivate(responderStaticPrivate)
	if err != nil {
		t.Fatalf("responder static public: %v", err)
	}

	initiatorEphPrivate := mustHex32(t, vector.Initiator.X25519EphemeralPrivateHex)
	responderEphPrivate := mustHex32(t, vector.Responder.X25519EphemeralPrivateHex)
	initiatorEphPublic, err := x25519PublicFromPrivate(initiatorEphPrivate)
	if err != nil {
		t.Fatalf("initiator eph public: %v", err)
	}
	responderEphPublic, err := x25519PublicFromPrivate(responderEphPrivate)
	if err != nil {
		t.Fatalf("responder eph public: %v", err)
	}

	clientBundleBytes, _ := hex.DecodeString(vector.Initiator.IdentityBundleHex)
	serverBundleBytes, _ := hex.DecodeString(vector.Responder.IdentityBundleHex)
	clientBundle, err := IdentityBundleFromBytes(clientBundleBytes)
	if err != nil {
		t.Fatalf("client bundle: %v", err)
	}
	serverBundle, err := IdentityBundleFromBytes(serverBundleBytes)
	if err != nil {
		t.Fatalf("server bundle: %v", err)
	}
	if clientBundle.X25519StaticPublic != initiatorStaticPublic {
		t.Fatalf("client bundle static public mismatch")
	}
	if serverBundle.X25519StaticPublic != responderStaticPublic {
		t.Fatalf("server bundle static public mismatch")
	}

	clientHello := ClientHello{
		CapabilityBits:      0x000000FF,
		RequestedMaxPayload: 1_048_576,
		EphPublic:           initiatorEphPublic,
		IdentityBundle:      clientBundle,
	}
	serverHello := ServerHello{
		AcceptedCapabilityBits: 0x0000000F,
		AcceptedMaxPayload:     524_288,
		EphPublic:              responderEphPublic,
		IdentityBundle:         serverBundle,
		TranscriptSignature:    [64]byte{0xC3},
	}
	for i := range serverHello.TranscriptSignature {
		serverHello.TranscriptSignature[i] = 0xC3
	}
	clientFinish := ClientFinish{
		MaxRekeyBytes:       1_073_741_824,
		MaxRekeySeconds:     900,
		RoleHint:            RoleHintDuplex,
		TranscriptSignature: [64]byte{},
	}
	for i := range clientFinish.TranscriptSignature {
		clientFinish.TranscriptSignature[i] = 0xD4
	}

	chFrame, _ := clientHello.ToFrame()
	shFrame, _ := serverHello.ToFrame()
	cfFrame, _ := clientFinish.ToFrame()

	assertHexEqual(t, encodeFrame(chFrame), vector.HandshakeRecordsHex[0])
	assertHexEqual(t, encodeFrame(shFrame), vector.HandshakeRecordsHex[1])
	assertHexEqual(t, encodeFrame(cfFrame), vector.HandshakeRecordsHex[2])

	transcriptHash, err := handshakeTranscriptHash(clientHello, serverHello)
	if err != nil {
		t.Fatalf("transcript hash: %v", err)
	}
	assertHexEqual(t, transcriptHash[:], vector.TranscriptHashHex)

	ee, _ := x25519Shared(initiatorEphPrivate, responderEphPublic)
	es, _ := x25519Shared(initiatorEphPrivate, responderStaticPublic)
	se, _ := x25519Shared(initiatorStaticPrivate, responderEphPublic)
	ss, _ := x25519Shared(initiatorStaticPrivate, responderStaticPublic)

	sessionIDi, txI, rxI, err := deriveTransportKeys(EndpointRoleInitiator, transcriptHash, ee, es, se, ss)
	if err != nil {
		t.Fatalf("derive initiator keys: %v", err)
	}
	sessionIDr, txR, rxR, err := deriveTransportKeys(EndpointRoleResponder, transcriptHash, ee, es, se, ss)
	if err != nil {
		t.Fatalf("derive responder keys: %v", err)
	}
	if sessionIDi != sessionIDr {
		t.Fatalf("session id mismatch")
	}
	if txI != rxR || rxI != txR {
		t.Fatalf("directional keys mismatch")
	}

	assertHexEqual(t, uint64ToBytes(sessionIDi), vector.SessionIDHex)
	assertHexEqual(t, txI[:], vector.InitiatorTxKeyHex)
	assertHexEqual(t, rxI[:], vector.InitiatorRxKeyHex)
}

func encodeFrame(f frame.Frame) []byte {
	enc := binary.NewEncoder()
	f.Encode(enc)
	out := make([]byte, len(enc.Bytes()))
	copy(out, enc.Bytes())
	return out
}

func assertHexEqual(t *testing.T, actual []byte, expectedHex string) {
	t.Helper()
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("decode expected hex: %v", err)
	}
	if string(actual) != string(expected) {
		t.Fatalf("hex mismatch\nexpected=%x\nactual=%x", expected, actual)
	}
}

func mustHex32(t *testing.T, hexValue string) [32]byte {
	t.Helper()
	buf, err := hex.DecodeString(hexValue)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if len(buf) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(buf))
	}
	var out [32]byte
	copy(out[:], buf)
	return out
}

func uint64ToBytes(v uint64) []byte {
	return []byte{
		byte(v >> 56),
		byte(v >> 48),
		byte(v >> 40),
		byte(v >> 32),
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

func loadVector(t *testing.T) vectorData {
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
		t.Fatalf("read vector file: %v", err)
	}

	var out vectorData
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("decode vector json: %v", err)
	}
	if len(out.HandshakeRecordsHex) < 3 {
		t.Fatalf("vector missing handshake records")
	}
	return out
}
