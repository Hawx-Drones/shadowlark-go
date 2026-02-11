package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	stdbinary "encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
)

const (
	MsgHandshakeInit byte = 1
	MsgHandshakeAck  byte = 2
	MsgClientFinish  byte = 3

	MsgClientHello byte = MsgHandshakeInit
	MsgServerHello byte = MsgHandshakeAck

	HandshakePayloadInit     byte = 1
	HandshakePayloadResponse byte = 2
	HandshakePayloadFinish   byte = 3

	NoiseProfile = "Noise_XX_25519_ChaChaPoly_SHA256"
)

type RoleHint byte

const (
	RoleHintUnspecified RoleHint = 0
	RoleHintProducer    RoleHint = 1
	RoleHintConsumer    RoleHint = 2
	RoleHintDuplex      RoleHint = 3
)

func roleHintFromByte(v byte) (RoleHint, error) {
	switch RoleHint(v) {
	case RoleHintUnspecified, RoleHintProducer, RoleHintConsumer, RoleHintDuplex:
		return RoleHint(v), nil
	default:
		return RoleHintUnspecified, fmt.Errorf("invalid role hint %d", v)
	}
}

type EndpointRole byte

const (
	EndpointRoleInitiator EndpointRole = 1
	EndpointRoleResponder EndpointRole = 2
)

type IdentityKeypair struct {
	ed25519Private ed25519.PrivateKey
	ed25519Public  [32]byte
	x25519Private  [32]byte
	x25519Public   [32]byte
}

func GenerateIdentityKeypair() (IdentityKeypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return IdentityKeypair{}, err
	}

	var edPub [32]byte
	copy(edPub[:], pub)

	var xPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, xPriv[:]); err != nil {
		return IdentityKeypair{}, err
	}
	xPub, err := x25519PublicFromPrivate(xPriv)
	if err != nil {
		return IdentityKeypair{}, err
	}

	return IdentityKeypair{
		ed25519Private: priv,
		ed25519Public:  edPub,
		x25519Private:  xPriv,
		x25519Public:   xPub,
	}, nil
}

func IdentityKeypairFromSeeds(ed25519Seed [32]byte, x25519Private [32]byte) (IdentityKeypair, error) {
	priv := ed25519.NewKeyFromSeed(ed25519Seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	var edPub [32]byte
	copy(edPub[:], pub)

	xPub, err := x25519PublicFromPrivate(x25519Private)
	if err != nil {
		return IdentityKeypair{}, err
	}

	return IdentityKeypair{
		ed25519Private: priv,
		ed25519Public:  edPub,
		x25519Private:  x25519Private,
		x25519Public:   xPub,
	}, nil
}

func (k IdentityKeypair) Ed25519Public() [32]byte {
	return k.ed25519Public
}

func (k IdentityKeypair) X25519Public() [32]byte {
	return k.x25519Public
}

func (k IdentityKeypair) X25519Private() [32]byte {
	return k.x25519Private
}

func (k IdentityKeypair) SignEd25519(message []byte) ([64]byte, error) {
	if len(k.ed25519Private) == 0 {
		return [64]byte{}, errors.New("missing ed25519 private key")
	}
	sig := ed25519.Sign(k.ed25519Private, message)
	var out [64]byte
	copy(out[:], sig)
	return out, nil
}

func VerifyEd25519(publicKey [32]byte, message []byte, signature [64]byte) error {
	if !ed25519.Verify(ed25519.PublicKey(publicKey[:]), message, signature[:]) {
		return errors.New("ed25519 verification failed")
	}
	return nil
}

func (k IdentityKeypair) X25519SharedSecret(peerPublic [32]byte) ([32]byte, error) {
	return x25519Shared(k.x25519Private, peerPublic)
}

type TrustStore struct {
	pinned map[[32]byte]struct{}
}

func StrictTrustStore() TrustStore {
	return TrustStore{
		pinned: make(map[[32]byte]struct{}),
	}
}

func (t *TrustStore) Pin(publicKey [32]byte) {
	if t.pinned == nil {
		t.pinned = make(map[[32]byte]struct{})
	}
	t.pinned[publicKey] = struct{}{}
}

func (t TrustStore) IsTrusted(publicKey [32]byte) bool {
	_, ok := t.pinned[publicKey]
	return ok
}

type IdentityBundle struct {
	BundleVersion      byte
	SigAlg             byte
	KeyID              string
	NotBeforeUnix      uint64
	NotAfterUnix       uint64
	X25519StaticPublic [32]byte
	Ed25519Public      [32]byte
	Signature          [64]byte
}

const (
	IdentityBundleVersion       byte = 1
	IdentityBundleSigAlgEd25519      = 1
)

func SignedIdentityBundle(
	keyID string,
	notBeforeUnix uint64,
	notAfterUnix uint64,
	identity IdentityKeypair,
) (IdentityBundle, error) {
	bundle := IdentityBundle{
		BundleVersion:      IdentityBundleVersion,
		SigAlg:             IdentityBundleSigAlgEd25519,
		KeyID:              keyID,
		NotBeforeUnix:      notBeforeUnix,
		NotAfterUnix:       notAfterUnix,
		X25519StaticPublic: identity.X25519Public(),
		Ed25519Public:      identity.Ed25519Public(),
	}
	input, err := bundle.signatureInput()
	if err != nil {
		return IdentityBundle{}, err
	}
	sig, err := identity.SignEd25519(input)
	if err != nil {
		return IdentityBundle{}, err
	}
	bundle.Signature = sig
	return bundle, nil
}

func (b IdentityBundle) Encode(enc *binary.Encoder) error {
	if len(b.KeyID) > int(^uint16(0)) {
		return errors.New("key_id too large")
	}
	enc.WriteU8(b.BundleVersion)
	enc.WriteU8(b.SigAlg)
	enc.WriteU16(uint16(len(b.KeyID)))
	enc.WriteBytes([]byte(b.KeyID))
	enc.WriteU64(b.NotBeforeUnix)
	enc.WriteU64(b.NotAfterUnix)
	enc.WriteBytes(b.X25519StaticPublic[:])
	enc.WriteBytes(b.Ed25519Public[:])
	enc.WriteBytes(b.Signature[:])
	return nil
}

func DecodeIdentityBundle(dec *binary.Decoder) (IdentityBundle, error) {
	bundleVersion, err := dec.ReadU8()
	if err != nil {
		return IdentityBundle{}, err
	}
	sigAlg, err := dec.ReadU8()
	if err != nil {
		return IdentityBundle{}, err
	}
	keyIDLen, err := dec.ReadU16()
	if err != nil {
		return IdentityBundle{}, err
	}
	keyIDBytes, err := dec.ReadBytes(int(keyIDLen))
	if err != nil {
		return IdentityBundle{}, err
	}
	notBeforeUnix, err := dec.ReadU64()
	if err != nil {
		return IdentityBundle{}, err
	}
	notAfterUnix, err := dec.ReadU64()
	if err != nil {
		return IdentityBundle{}, err
	}

	x25519StaticPublicBytes, err := dec.ReadBytes(32)
	if err != nil {
		return IdentityBundle{}, err
	}
	ed25519PublicBytes, err := dec.ReadBytes(32)
	if err != nil {
		return IdentityBundle{}, err
	}
	sigBytes, err := dec.ReadBytes(64)
	if err != nil {
		return IdentityBundle{}, err
	}

	var x25519StaticPublic [32]byte
	copy(x25519StaticPublic[:], x25519StaticPublicBytes)
	var ed25519Public [32]byte
	copy(ed25519Public[:], ed25519PublicBytes)
	var signature [64]byte
	copy(signature[:], sigBytes)

	return IdentityBundle{
		BundleVersion:      bundleVersion,
		SigAlg:             sigAlg,
		KeyID:              string(keyIDBytes),
		NotBeforeUnix:      notBeforeUnix,
		NotAfterUnix:       notAfterUnix,
		X25519StaticPublic: x25519StaticPublic,
		Ed25519Public:      ed25519Public,
		Signature:          signature,
	}, nil
}

func (b IdentityBundle) ToBytes() ([]byte, error) {
	enc := binary.NewEncoder()
	if err := b.Encode(enc); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func IdentityBundleFromBytes(payload []byte) (IdentityBundle, error) {
	dec := binary.NewDecoder(payload)
	bundle, err := DecodeIdentityBundle(dec)
	if err != nil {
		return IdentityBundle{}, err
	}
	if dec.Remaining() != 0 {
		return IdentityBundle{}, errors.New("trailing bytes in identity bundle")
	}
	return bundle, nil
}

func (b IdentityBundle) Validate(trust TrustStore, nowUnix uint64) error {
	if b.BundleVersion != IdentityBundleVersion {
		return fmt.Errorf("unsupported bundle version %d", b.BundleVersion)
	}
	if b.SigAlg != IdentityBundleSigAlgEd25519 {
		return fmt.Errorf("unsupported signature algorithm %d", b.SigAlg)
	}
	if nowUnix < b.NotBeforeUnix || nowUnix > b.NotAfterUnix {
		return errors.New("identity bundle outside validity window")
	}
	if !trust.IsTrusted(b.Ed25519Public) {
		return errors.New("peer identity is not trusted")
	}
	input, err := b.signatureInput()
	if err != nil {
		return err
	}
	if err := VerifyEd25519(b.Ed25519Public, input, b.Signature); err != nil {
		return fmt.Errorf("identity bundle signature verification failed: %w", err)
	}
	return nil
}

func (b IdentityBundle) signatureInput() ([]byte, error) {
	if len(b.KeyID) > int(^uint16(0)) {
		return nil, errors.New("key_id too large")
	}
	enc := binary.NewEncoder()
	enc.WriteBytes([]byte("SHADOWLARK_ID_BUNDLE"))
	enc.WriteU8(b.BundleVersion)
	enc.WriteU8(b.SigAlg)
	enc.WriteU16(uint16(len(b.KeyID)))
	enc.WriteBytes([]byte(b.KeyID))
	enc.WriteU64(b.NotBeforeUnix)
	enc.WriteU64(b.NotAfterUnix)
	enc.WriteBytes(b.X25519StaticPublic[:])
	enc.WriteBytes(b.Ed25519Public[:])
	return enc.Bytes(), nil
}

type ClientHello struct {
	CapabilityBits      uint32
	RequestedMaxPayload uint32
	EphPublic           [32]byte
	IdentityBundle      IdentityBundle
}

func (h ClientHello) encodeBody(enc *binary.Encoder) error {
	bundle, err := h.IdentityBundle.ToBytes()
	if err != nil {
		return err
	}
	if len(bundle) > int(^uint16(0)) {
		return errors.New("identity bundle too large")
	}
	enc.WriteU32(h.CapabilityBits)
	enc.WriteU32(h.RequestedMaxPayload)
	enc.WriteBytes(h.EphPublic[:])
	enc.WriteU16(uint16(len(bundle)))
	enc.WriteBytes(bundle)
	return nil
}

func decodeClientHelloBody(dec *binary.Decoder) (ClientHello, error) {
	capabilityBits, err := dec.ReadU32()
	if err != nil {
		return ClientHello{}, err
	}
	requestedMaxPayload, err := dec.ReadU32()
	if err != nil {
		return ClientHello{}, err
	}
	ephPublicBytes, err := dec.ReadBytes(32)
	if err != nil {
		return ClientHello{}, err
	}
	bundleLen, err := dec.ReadU16()
	if err != nil {
		return ClientHello{}, err
	}
	bundlePayload, err := dec.ReadBytes(int(bundleLen))
	if err != nil {
		return ClientHello{}, err
	}
	bundle, err := IdentityBundleFromBytes(bundlePayload)
	if err != nil {
		return ClientHello{}, err
	}
	var ephPublic [32]byte
	copy(ephPublic[:], ephPublicBytes)
	return ClientHello{
		CapabilityBits:      capabilityBits,
		RequestedMaxPayload: requestedMaxPayload,
		EphPublic:           ephPublic,
		IdentityBundle:      bundle,
	}, nil
}

func (h ClientHello) transcriptBytes() ([]byte, error) {
	enc := binary.NewEncoder()
	if err := h.encodeBody(enc); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func (h ClientHello) ToFrame() (frame.Frame, error) {
	bodyEnc := binary.NewEncoder()
	if err := h.encodeBody(bodyEnc); err != nil {
		return frame.Frame{}, err
	}
	body := bodyEnc.Bytes()
	if len(body) > int(^uint16(0)) {
		return frame.Frame{}, errors.New("client hello body too large")
	}

	wrapper := binary.NewEncoder()
	wrapper.WriteU8(HandshakePayloadInit)
	wrapper.WriteU8(0)
	wrapper.WriteU16(uint16(len(body)))
	wrapper.WriteBytes(body)

	return frame.New(MsgClientHello, 0, wrapper.Bytes()), nil
}

func ClientHelloFromFrame(f frame.Frame) (ClientHello, error) {
	if f.MsgType != MsgClientHello {
		return ClientHello{}, errors.New("expected MSG_CLIENT_HELLO")
	}
	dec := binary.NewDecoder(f.Payload)
	kind, err := dec.ReadU8()
	if err != nil {
		return ClientHello{}, err
	}
	if kind != HandshakePayloadInit {
		return ClientHello{}, errors.New("invalid payload kind for client hello")
	}
	if _, err := dec.ReadU8(); err != nil {
		return ClientHello{}, err
	}
	bodyLen, err := dec.ReadU16()
	if err != nil {
		return ClientHello{}, err
	}
	body, err := dec.ReadBytes(int(bodyLen))
	if err != nil {
		return ClientHello{}, err
	}
	if dec.Remaining() != 0 {
		return ClientHello{}, errors.New("trailing bytes in client hello wrapper")
	}
	bodyDec := binary.NewDecoder(body)
	hello, err := decodeClientHelloBody(bodyDec)
	if err != nil {
		return ClientHello{}, err
	}
	if bodyDec.Remaining() != 0 {
		return ClientHello{}, errors.New("trailing bytes in client hello body")
	}
	return hello, nil
}

type ServerHello struct {
	AcceptedCapabilityBits uint32
	AcceptedMaxPayload     uint32
	EphPublic              [32]byte
	IdentityBundle         IdentityBundle
	TranscriptSignature    [64]byte
}

func (h ServerHello) encodeBody(enc *binary.Encoder) error {
	bundle, err := h.IdentityBundle.ToBytes()
	if err != nil {
		return err
	}
	if len(bundle) > int(^uint16(0)) {
		return errors.New("identity bundle too large")
	}
	enc.WriteU32(h.AcceptedCapabilityBits)
	enc.WriteU32(h.AcceptedMaxPayload)
	enc.WriteBytes(h.EphPublic[:])
	enc.WriteU16(uint16(len(bundle)))
	enc.WriteBytes(bundle)
	enc.WriteBytes(h.TranscriptSignature[:])
	return nil
}

func decodeServerHelloBody(dec *binary.Decoder) (ServerHello, error) {
	acceptedCapabilityBits, err := dec.ReadU32()
	if err != nil {
		return ServerHello{}, err
	}
	acceptedMaxPayload, err := dec.ReadU32()
	if err != nil {
		return ServerHello{}, err
	}
	ephPublicBytes, err := dec.ReadBytes(32)
	if err != nil {
		return ServerHello{}, err
	}
	bundleLen, err := dec.ReadU16()
	if err != nil {
		return ServerHello{}, err
	}
	bundlePayload, err := dec.ReadBytes(int(bundleLen))
	if err != nil {
		return ServerHello{}, err
	}
	bundle, err := IdentityBundleFromBytes(bundlePayload)
	if err != nil {
		return ServerHello{}, err
	}
	sigBytes, err := dec.ReadBytes(64)
	if err != nil {
		return ServerHello{}, err
	}

	var ephPublic [32]byte
	copy(ephPublic[:], ephPublicBytes)
	var transcriptSig [64]byte
	copy(transcriptSig[:], sigBytes)

	return ServerHello{
		AcceptedCapabilityBits: acceptedCapabilityBits,
		AcceptedMaxPayload:     acceptedMaxPayload,
		EphPublic:              ephPublic,
		IdentityBundle:         bundle,
		TranscriptSignature:    transcriptSig,
	}, nil
}

func (h ServerHello) transcriptBytesWithoutSignature() ([]byte, error) {
	bundle, err := h.IdentityBundle.ToBytes()
	if err != nil {
		return nil, err
	}
	if len(bundle) > int(^uint16(0)) {
		return nil, errors.New("identity bundle too large")
	}
	enc := binary.NewEncoder()
	enc.WriteU32(h.AcceptedCapabilityBits)
	enc.WriteU32(h.AcceptedMaxPayload)
	enc.WriteBytes(h.EphPublic[:])
	enc.WriteU16(uint16(len(bundle)))
	enc.WriteBytes(bundle)
	return enc.Bytes(), nil
}

func (h ServerHello) ToFrame() (frame.Frame, error) {
	bodyEnc := binary.NewEncoder()
	if err := h.encodeBody(bodyEnc); err != nil {
		return frame.Frame{}, err
	}
	body := bodyEnc.Bytes()
	if len(body) > int(^uint16(0)) {
		return frame.Frame{}, errors.New("server hello body too large")
	}

	wrapper := binary.NewEncoder()
	wrapper.WriteU8(HandshakePayloadResponse)
	wrapper.WriteU8(0)
	wrapper.WriteU16(uint16(len(body)))
	wrapper.WriteBytes(body)

	return frame.New(MsgServerHello, 0, wrapper.Bytes()), nil
}

func ServerHelloFromFrame(f frame.Frame) (ServerHello, error) {
	if f.MsgType != MsgServerHello {
		return ServerHello{}, errors.New("expected MSG_SERVER_HELLO")
	}
	dec := binary.NewDecoder(f.Payload)
	kind, err := dec.ReadU8()
	if err != nil {
		return ServerHello{}, err
	}
	if kind != HandshakePayloadResponse {
		return ServerHello{}, errors.New("invalid payload kind for server hello")
	}
	if _, err := dec.ReadU8(); err != nil {
		return ServerHello{}, err
	}
	bodyLen, err := dec.ReadU16()
	if err != nil {
		return ServerHello{}, err
	}
	body, err := dec.ReadBytes(int(bodyLen))
	if err != nil {
		return ServerHello{}, err
	}
	if dec.Remaining() != 0 {
		return ServerHello{}, errors.New("trailing bytes in server hello wrapper")
	}
	bodyDec := binary.NewDecoder(body)
	hello, err := decodeServerHelloBody(bodyDec)
	if err != nil {
		return ServerHello{}, err
	}
	if bodyDec.Remaining() != 0 {
		return ServerHello{}, errors.New("trailing bytes in server hello body")
	}
	return hello, nil
}

type ClientFinish struct {
	MaxRekeyBytes       uint64
	MaxRekeySeconds     uint32
	RoleHint            RoleHint
	TranscriptSignature [64]byte
}

func (f ClientFinish) encodeBody(enc *binary.Encoder) {
	enc.WriteU64(f.MaxRekeyBytes)
	enc.WriteU32(f.MaxRekeySeconds)
	enc.WriteU8(byte(f.RoleHint))
	enc.WriteU8(0)
	enc.WriteU16(0)
	enc.WriteBytes(f.TranscriptSignature[:])
}

func decodeClientFinishBody(dec *binary.Decoder) (ClientFinish, error) {
	maxRekeyBytes, err := dec.ReadU64()
	if err != nil {
		return ClientFinish{}, err
	}
	maxRekeySeconds, err := dec.ReadU32()
	if err != nil {
		return ClientFinish{}, err
	}
	roleHintByte, err := dec.ReadU8()
	if err != nil {
		return ClientFinish{}, err
	}
	roleHint, err := roleHintFromByte(roleHintByte)
	if err != nil {
		return ClientFinish{}, err
	}
	if _, err := dec.ReadU8(); err != nil {
		return ClientFinish{}, err
	}
	if _, err := dec.ReadU16(); err != nil {
		return ClientFinish{}, err
	}
	sigBytes, err := dec.ReadBytes(64)
	if err != nil {
		return ClientFinish{}, err
	}
	var sig [64]byte
	copy(sig[:], sigBytes)
	return ClientFinish{
		MaxRekeyBytes:       maxRekeyBytes,
		MaxRekeySeconds:     maxRekeySeconds,
		RoleHint:            roleHint,
		TranscriptSignature: sig,
	}, nil
}

func (f ClientFinish) ToFrame() (frame.Frame, error) {
	bodyEnc := binary.NewEncoder()
	f.encodeBody(bodyEnc)
	body := bodyEnc.Bytes()
	if len(body) > int(^uint16(0)) {
		return frame.Frame{}, errors.New("client finish body too large")
	}

	wrapper := binary.NewEncoder()
	wrapper.WriteU8(HandshakePayloadFinish)
	wrapper.WriteU8(0)
	wrapper.WriteU16(uint16(len(body)))
	wrapper.WriteBytes(body)

	return frame.New(MsgClientFinish, 0, wrapper.Bytes()), nil
}

func ClientFinishFromFrame(f frame.Frame) (ClientFinish, error) {
	if f.MsgType != MsgClientFinish {
		return ClientFinish{}, errors.New("expected MSG_CLIENT_FINISH")
	}
	dec := binary.NewDecoder(f.Payload)
	kind, err := dec.ReadU8()
	if err != nil {
		return ClientFinish{}, err
	}
	if kind != HandshakePayloadFinish {
		return ClientFinish{}, errors.New("invalid payload kind for client finish")
	}
	if _, err := dec.ReadU8(); err != nil {
		return ClientFinish{}, err
	}
	bodyLen, err := dec.ReadU16()
	if err != nil {
		return ClientFinish{}, err
	}
	body, err := dec.ReadBytes(int(bodyLen))
	if err != nil {
		return ClientFinish{}, err
	}
	if dec.Remaining() != 0 {
		return ClientFinish{}, errors.New("trailing bytes in client finish wrapper")
	}
	bodyDec := binary.NewDecoder(body)
	finish, err := decodeClientFinishBody(bodyDec)
	if err != nil {
		return ClientFinish{}, err
	}
	if bodyDec.Remaining() != 0 {
		return ClientFinish{}, errors.New("trailing bytes in client finish body")
	}
	return finish, nil
}

type HandshakePolicy struct {
	CapabilityBits  uint32
	MaxPayload      uint32
	MaxRekeyBytes   uint64
	MaxRekeySeconds uint32
}

func DefaultHandshakePolicy() HandshakePolicy {
	return HandshakePolicy{
		CapabilityBits:  0xFFFF_FFFF,
		MaxPayload:      4_194_304,
		MaxRekeyBytes:   1_073_741_824,
		MaxRekeySeconds: 900,
	}
}

type HandshakeOutput struct {
	Role                    EndpointRole
	SessionID               uint64
	TxKey                   [32]byte
	RxKey                   [32]byte
	PeerIdentity            IdentityBundle
	NegotiatedCapabilityBit uint32
	NegotiatedMaxPayload    uint32
	MaxRekeyBytes           uint64
	MaxRekeySeconds         uint32
}

type SecureInitiator struct {
	localIdentity IdentityKeypair
	localBundle   IdentityBundle
	trustStore    TrustStore
	policy        HandshakePolicy
	ephPrivate    [32]byte
	ephPublic     [32]byte
	clientHello   *ClientHello
	serverHello   *ServerHello
}

func NewSecureInitiator(
	localIdentity IdentityKeypair,
	localBundle IdentityBundle,
	trustStore TrustStore,
	policy HandshakePolicy,
) (*SecureInitiator, error) {
	ephPrivate, err := random32()
	if err != nil {
		return nil, err
	}
	ephPublic, err := x25519PublicFromPrivate(ephPrivate)
	if err != nil {
		return nil, err
	}
	return &SecureInitiator{
		localIdentity: localIdentity,
		localBundle:   localBundle,
		trustStore:    trustStore,
		policy:        policy,
		ephPrivate:    ephPrivate,
		ephPublic:     ephPublic,
	}, nil
}

func (s *SecureInitiator) BuildClientHello() (frame.Frame, error) {
	hello := ClientHello{
		CapabilityBits:      s.policy.CapabilityBits,
		RequestedMaxPayload: s.policy.MaxPayload,
		EphPublic:           s.ephPublic,
		IdentityBundle:      s.localBundle,
	}
	s.clientHello = &hello
	return hello.ToFrame()
}

func (s *SecureInitiator) HandleServerHello(f frame.Frame, nowUnix uint64) error {
	serverHello, err := ServerHelloFromFrame(f)
	if err != nil {
		return err
	}
	if err := serverHello.IdentityBundle.Validate(s.trustStore, nowUnix); err != nil {
		return err
	}
	if s.clientHello == nil {
		return errors.New("client hello not built")
	}

	intersection := s.clientHello.CapabilityBits & serverHello.AcceptedCapabilityBits
	if intersection == 0 {
		return errors.New("no common capability bits")
	}
	if serverHello.AcceptedMaxPayload == 0 || serverHello.AcceptedMaxPayload > s.policy.MaxPayload {
		return errors.New("invalid accepted max payload")
	}

	transcriptHash, err := handshakeTranscriptHash(*s.clientHello, serverHello)
	if err != nil {
		return err
	}
	message, err := serverSignatureMessage(
		transcriptHash,
		s.clientHello.EphPublic,
		serverHello.EphPublic,
		s.localBundle.X25519StaticPublic,
		serverHello.IdentityBundle.X25519StaticPublic,
	)
	if err != nil {
		return err
	}
	if err := VerifyEd25519(serverHello.IdentityBundle.Ed25519Public, message, serverHello.TranscriptSignature); err != nil {
		return fmt.Errorf("server transcript signature verification failed: %w", err)
	}

	s.serverHello = &serverHello
	return nil
}

func (s *SecureInitiator) BuildClientFinish() (frame.Frame, error) {
	if s.clientHello == nil {
		return frame.Frame{}, errors.New("client hello not built")
	}
	if s.serverHello == nil {
		return frame.Frame{}, errors.New("server hello not processed")
	}

	transcriptHash, err := handshakeTranscriptHash(*s.clientHello, *s.serverHello)
	if err != nil {
		return frame.Frame{}, err
	}
	message, err := clientSignatureMessage(
		transcriptHash,
		s.clientHello.EphPublic,
		s.serverHello.EphPublic,
		s.localBundle.X25519StaticPublic,
		s.serverHello.IdentityBundle.X25519StaticPublic,
	)
	if err != nil {
		return frame.Frame{}, err
	}
	sig, err := s.localIdentity.SignEd25519(message)
	if err != nil {
		return frame.Frame{}, err
	}

	finish := ClientFinish{
		MaxRekeyBytes:       s.policy.MaxRekeyBytes,
		MaxRekeySeconds:     s.policy.MaxRekeySeconds,
		RoleHint:            RoleHintDuplex,
		TranscriptSignature: sig,
	}
	return finish.ToFrame()
}

func (s *SecureInitiator) Finalize() (HandshakeOutput, error) {
	if s.clientHello == nil {
		return HandshakeOutput{}, errors.New("client hello missing")
	}
	if s.serverHello == nil {
		return HandshakeOutput{}, errors.New("server hello missing")
	}

	transcriptHash, err := handshakeTranscriptHash(*s.clientHello, *s.serverHello)
	if err != nil {
		return HandshakeOutput{}, err
	}

	initiatorStaticPrivate := s.localIdentity.X25519Private()
	ee, err := x25519Shared(s.ephPrivate, s.serverHello.EphPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	es, err := x25519Shared(s.ephPrivate, s.serverHello.IdentityBundle.X25519StaticPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	se, err := x25519Shared(initiatorStaticPrivate, s.serverHello.EphPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	ss, err := x25519Shared(initiatorStaticPrivate, s.serverHello.IdentityBundle.X25519StaticPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}

	sessionID, txKey, rxKey, err := deriveTransportKeys(EndpointRoleInitiator, transcriptHash, ee, es, se, ss)
	if err != nil {
		return HandshakeOutput{}, err
	}

	return HandshakeOutput{
		Role:                    EndpointRoleInitiator,
		SessionID:               sessionID,
		TxKey:                   txKey,
		RxKey:                   rxKey,
		PeerIdentity:            s.serverHello.IdentityBundle,
		NegotiatedCapabilityBit: s.clientHello.CapabilityBits & s.serverHello.AcceptedCapabilityBits,
		NegotiatedMaxPayload:    s.serverHello.AcceptedMaxPayload,
		MaxRekeyBytes:           s.policy.MaxRekeyBytes,
		MaxRekeySeconds:         s.policy.MaxRekeySeconds,
	}, nil
}

type SecureResponder struct {
	localIdentity IdentityKeypair
	localBundle   IdentityBundle
	trustStore    TrustStore
	policy        HandshakePolicy
	ephPrivate    [32]byte
	ephPublic     [32]byte
	clientHello   *ClientHello
	serverHello   *ServerHello
}

func NewSecureResponder(
	localIdentity IdentityKeypair,
	localBundle IdentityBundle,
	trustStore TrustStore,
	policy HandshakePolicy,
) (*SecureResponder, error) {
	ephPrivate, err := random32()
	if err != nil {
		return nil, err
	}
	ephPublic, err := x25519PublicFromPrivate(ephPrivate)
	if err != nil {
		return nil, err
	}
	return &SecureResponder{
		localIdentity: localIdentity,
		localBundle:   localBundle,
		trustStore:    trustStore,
		policy:        policy,
		ephPrivate:    ephPrivate,
		ephPublic:     ephPublic,
	}, nil
}

func (s *SecureResponder) HandleClientHello(f frame.Frame, nowUnix uint64) (frame.Frame, error) {
	clientHello, err := ClientHelloFromFrame(f)
	if err != nil {
		return frame.Frame{}, err
	}
	if err := clientHello.IdentityBundle.Validate(s.trustStore, nowUnix); err != nil {
		return frame.Frame{}, err
	}

	acceptedCapabilityBits := clientHello.CapabilityBits & s.policy.CapabilityBits
	if acceptedCapabilityBits == 0 {
		return frame.Frame{}, errors.New("no common capability bits")
	}

	acceptedMaxPayload := clientHello.RequestedMaxPayload
	if acceptedMaxPayload > s.policy.MaxPayload {
		acceptedMaxPayload = s.policy.MaxPayload
	}
	if acceptedMaxPayload == 0 {
		return frame.Frame{}, errors.New("invalid negotiated max payload")
	}

	serverHello := ServerHello{
		AcceptedCapabilityBits: acceptedCapabilityBits,
		AcceptedMaxPayload:     acceptedMaxPayload,
		EphPublic:              s.ephPublic,
		IdentityBundle:         s.localBundle,
	}
	transcriptHash, err := handshakeTranscriptHash(clientHello, serverHello)
	if err != nil {
		return frame.Frame{}, err
	}
	sigMessage, err := serverSignatureMessage(
		transcriptHash,
		clientHello.EphPublic,
		serverHello.EphPublic,
		clientHello.IdentityBundle.X25519StaticPublic,
		s.localBundle.X25519StaticPublic,
	)
	if err != nil {
		return frame.Frame{}, err
	}
	sig, err := s.localIdentity.SignEd25519(sigMessage)
	if err != nil {
		return frame.Frame{}, err
	}
	serverHello.TranscriptSignature = sig

	s.clientHello = &clientHello
	s.serverHello = &serverHello
	return serverHello.ToFrame()
}

func (s *SecureResponder) HandleClientFinish(f frame.Frame) (HandshakeOutput, error) {
	finish, err := ClientFinishFromFrame(f)
	if err != nil {
		return HandshakeOutput{}, err
	}
	if s.clientHello == nil {
		return HandshakeOutput{}, errors.New("client hello missing")
	}
	if s.serverHello == nil {
		return HandshakeOutput{}, errors.New("server hello missing")
	}

	transcriptHash, err := handshakeTranscriptHash(*s.clientHello, *s.serverHello)
	if err != nil {
		return HandshakeOutput{}, err
	}
	message, err := clientSignatureMessage(
		transcriptHash,
		s.clientHello.EphPublic,
		s.serverHello.EphPublic,
		s.clientHello.IdentityBundle.X25519StaticPublic,
		s.localBundle.X25519StaticPublic,
	)
	if err != nil {
		return HandshakeOutput{}, err
	}
	if err := VerifyEd25519(s.clientHello.IdentityBundle.Ed25519Public, message, finish.TranscriptSignature); err != nil {
		return HandshakeOutput{}, fmt.Errorf("client transcript signature verification failed: %w", err)
	}

	responderStaticPrivate := s.localIdentity.X25519Private()
	ee, err := x25519Shared(s.ephPrivate, s.clientHello.EphPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	es, err := x25519Shared(responderStaticPrivate, s.clientHello.EphPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	se, err := x25519Shared(s.ephPrivate, s.clientHello.IdentityBundle.X25519StaticPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}
	ss, err := x25519Shared(responderStaticPrivate, s.clientHello.IdentityBundle.X25519StaticPublic)
	if err != nil {
		return HandshakeOutput{}, err
	}

	sessionID, txKey, rxKey, err := deriveTransportKeys(EndpointRoleResponder, transcriptHash, ee, es, se, ss)
	if err != nil {
		return HandshakeOutput{}, err
	}

	return HandshakeOutput{
		Role:                    EndpointRoleResponder,
		SessionID:               sessionID,
		TxKey:                   txKey,
		RxKey:                   rxKey,
		PeerIdentity:            s.clientHello.IdentityBundle,
		NegotiatedCapabilityBit: s.serverHello.AcceptedCapabilityBits,
		NegotiatedMaxPayload:    s.serverHello.AcceptedMaxPayload,
		MaxRekeyBytes:           finish.MaxRekeyBytes,
		MaxRekeySeconds:         finish.MaxRekeySeconds,
	}, nil
}

func handshakeTranscriptHash(clientHello ClientHello, serverHello ServerHello) ([32]byte, error) {
	clientTranscript, err := clientHello.transcriptBytes()
	if err != nil {
		return [32]byte{}, err
	}
	serverTranscript, err := serverHello.transcriptBytesWithoutSignature()
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("SHADOWLARK_XX_TRANSCRIPT"))
	h.Write(clientTranscript)
	h.Write(serverTranscript)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func serverSignatureMessage(
	transcriptHash [32]byte,
	clientEph [32]byte,
	serverEph [32]byte,
	clientStatic [32]byte,
	serverStatic [32]byte,
) ([]byte, error) {
	enc := binary.NewEncoder()
	enc.WriteBytes([]byte("SHADOWLARK_SERVER_HELLO_SIG"))
	enc.WriteBytes(transcriptHash[:])
	enc.WriteBytes(clientEph[:])
	enc.WriteBytes(serverEph[:])
	enc.WriteBytes(clientStatic[:])
	enc.WriteBytes(serverStatic[:])
	return enc.Bytes(), nil
}

func clientSignatureMessage(
	transcriptHash [32]byte,
	clientEph [32]byte,
	serverEph [32]byte,
	clientStatic [32]byte,
	serverStatic [32]byte,
) ([]byte, error) {
	enc := binary.NewEncoder()
	enc.WriteBytes([]byte("SHADOWLARK_CLIENT_FINISH_SIG"))
	enc.WriteBytes(transcriptHash[:])
	enc.WriteBytes(clientEph[:])
	enc.WriteBytes(serverEph[:])
	enc.WriteBytes(clientStatic[:])
	enc.WriteBytes(serverStatic[:])
	return enc.Bytes(), nil
}

func deriveTransportKeys(
	role EndpointRole,
	transcriptHash [32]byte,
	ee [32]byte,
	es [32]byte,
	se [32]byte,
	ss [32]byte,
) (uint64, [32]byte, [32]byte, error) {
	var ikm [128]byte
	copy(ikm[0:32], ee[:])
	copy(ikm[32:64], es[:])
	copy(ikm[64:96], se[:])
	copy(ikm[96:128], ss[:])

	saltHasher := sha256.New()
	saltHasher.Write([]byte("SHADOWLARK_HANDSHAKE_SALT"))
	saltHasher.Write(transcriptHash[:])
	salt := saltHasher.Sum(nil)

	hkdfReader := hkdf.New(sha256.New, ikm[:], salt, []byte("SHADOWLARK_TRANSPORT_KEYS"))
	var keys [64]byte
	if _, err := io.ReadFull(hkdfReader, keys[:]); err != nil {
		return 0, [32]byte{}, [32]byte{}, fmt.Errorf("hkdf expand failed: %w", err)
	}

	var initiatorToResponder [32]byte
	copy(initiatorToResponder[:], keys[0:32])
	var responderToInitiator [32]byte
	copy(responderToInitiator[:], keys[32:64])

	var txKey [32]byte
	var rxKey [32]byte
	if role == EndpointRoleInitiator {
		txKey = initiatorToResponder
		rxKey = responderToInitiator
	} else {
		txKey = responderToInitiator
		rxKey = initiatorToResponder
	}

	sidHasher := sha256.New()
	sidHasher.Write([]byte("SHADOWLARK_SESSION_ID"))
	sidHasher.Write(transcriptHash[:])
	sidDigest := sidHasher.Sum(nil)
	sessionID := stdbinary.BigEndian.Uint64(sidDigest[0:8])
	if sessionID == 0 {
		sessionID = 1
	}

	return sessionID, txKey, rxKey, nil
}

func random32() ([32]byte, error) {
	var out [32]byte
	_, err := io.ReadFull(rand.Reader, out[:])
	return out, err
}

func x25519PublicFromPrivate(private [32]byte) ([32]byte, error) {
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], pub)
	return out, nil
}

func x25519Shared(private [32]byte, peerPublic [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(private[:], peerPublic[:])
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], shared)
	return out, nil
}
