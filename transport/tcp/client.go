package tcp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/app"
	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/handshake"
	"github.com/Hawx-Drones/shadowlark-go/transport/router"
	"github.com/Hawx-Drones/shadowlark-go/transport/session"
)

const (
	heartbeatInterval              = 5 * time.Second
	heartbeatTimeout               = 20 * time.Second
	defaultIdentityValiditySeconds = uint64(86400)
)

const (
	identityEdSeedEnv   = "SHADOWLARK_IDENTITY_ED25519_SEED_HEX"
	identityXPrivEnv    = "SHADOWLARK_IDENTITY_X25519_PRIVATE_HEX"
	identityKeyIDEnv    = "SHADOWLARK_IDENTITY_KEY_ID"
	identityValidityEnv = "SHADOWLARK_IDENTITY_VALIDITY_S"
	trustPinsEnv        = "SHADOWLARK_TRUST_ED25519_HEX"
)

type Client struct {
	conn              net.Conn
	Session           *session.State
	LastHeartbeatSent time.Time
	localIdentity     *handshake.IdentityKeypair
	localBundle       *handshake.IdentityBundle
	trustStore        handshake.TrustStore
	trustConfigured   bool
	policy            handshake.HandshakePolicy
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	trust := handshake.StrictTrustStore()
	return &Client{
		conn:              conn,
		Session:           nil,
		LastHeartbeatSent: time.Now(),
		trustStore:        trust,
		trustConfigured:   false,
		policy:            handshake.DefaultHandshakePolicy(),
	}, nil
}

func (c *Client) SetSecureIdentity(localIdentity handshake.IdentityKeypair, localBundle handshake.IdentityBundle) {
	identity := localIdentity
	bundle := localBundle
	c.localIdentity = &identity
	c.localBundle = &bundle
}

func (c *Client) SetTrustStore(trustStore handshake.TrustStore) {
	c.trustStore = trustStore
	c.trustConfigured = true
}

func (c *Client) SetHandshakePolicy(policy handshake.HandshakePolicy) {
	c.policy = policy
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Handshake(_ *router.FrameRouter) error {
	identity, bundle, err := c.ensureIdentityBundle()
	if err != nil {
		return err
	}

	trust := c.trustStore
	if !c.trustConfigured {
		trust, err = buildTrustStoreFromEnv()
		if err != nil {
			return err
		}
		c.trustStore = trust
		c.trustConfigured = true
	}

	return c.handshakeSecure(identity, bundle, trust, c.policy)
}

func (c *Client) HandshakeSecure(
	localIdentity handshake.IdentityKeypair,
	localBundle handshake.IdentityBundle,
	trustStore handshake.TrustStore,
	policy handshake.HandshakePolicy,
) error {
	return c.handshakeSecure(localIdentity, localBundle, trustStore, policy)
}

func (c *Client) handshakeSecure(
	localIdentity handshake.IdentityKeypair,
	localBundle handshake.IdentityBundle,
	trustStore handshake.TrustStore,
	policy handshake.HandshakePolicy,
) error {
	initiator, err := handshake.NewSecureInitiator(localIdentity, localBundle, trustStore, policy)
	if err != nil {
		return err
	}

	clientHello, err := initiator.BuildClientHello()
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, clientHello); err != nil {
		return err
	}

	serverHello, err := readFrame(c.conn)
	if err != nil {
		return err
	}
	if serverHello.MsgType != handshake.MsgServerHello {
		return fmt.Errorf("expected MSG_SERVER_HELLO, got %d", serverHello.MsgType)
	}
	if err := initiator.HandleServerHello(serverHello, uint64(time.Now().Unix())); err != nil {
		return err
	}

	clientFinish, err := initiator.BuildClientFinish()
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, clientFinish); err != nil {
		return err
	}

	output, err := initiator.Finalize()
	if err != nil {
		return err
	}
	sess := session.FromHandshakeOutput(output)
	c.Session = &sess
	return nil
}

func (c *Client) ensureIdentityBundle() (handshake.IdentityKeypair, handshake.IdentityBundle, error) {
	if c.localIdentity != nil && c.localBundle != nil {
		return *c.localIdentity, *c.localBundle, nil
	}

	identity, err := buildIdentityFromEnv()
	if err != nil {
		return handshake.IdentityKeypair{}, handshake.IdentityBundle{}, err
	}
	now := uint64(time.Now().Unix())
	keyID := os.Getenv(identityKeyIDEnv)
	if strings.TrimSpace(keyID) == "" {
		keyID = "shadowlark-go-client"
	}
	validity, err := parseOptionalUint64Env(identityValidityEnv)
	if err != nil {
		return handshake.IdentityKeypair{}, handshake.IdentityBundle{}, err
	}
	if validity == 0 {
		validity = defaultIdentityValiditySeconds
	}

	bundle, err := handshake.SignedIdentityBundle(keyID, now-60, now+validity, identity)
	if err != nil {
		return handshake.IdentityKeypair{}, handshake.IdentityBundle{}, err
	}
	c.SetSecureIdentity(identity, bundle)
	return identity, bundle, nil
}

func buildIdentityFromEnv() (handshake.IdentityKeypair, error) {
	edSeedHex := strings.TrimSpace(os.Getenv(identityEdSeedEnv))
	xPrivHex := strings.TrimSpace(os.Getenv(identityXPrivEnv))

	if edSeedHex == "" && xPrivHex == "" {
		return handshake.IdentityKeypair{}, fmt.Errorf(
			"%s and %s must be set",
			identityEdSeedEnv,
			identityXPrivEnv,
		)
	}
	if edSeedHex == "" || xPrivHex == "" {
		return handshake.IdentityKeypair{}, fmt.Errorf("%s and %s must be set together", identityEdSeedEnv, identityXPrivEnv)
	}

	edSeedBytes, err := parseHexBytes(identityEdSeedEnv, edSeedHex)
	if err != nil {
		return handshake.IdentityKeypair{}, err
	}
	xPrivBytes, err := parseHexBytes(identityXPrivEnv, xPrivHex)
	if err != nil {
		return handshake.IdentityKeypair{}, err
	}
	if len(edSeedBytes) != 32 {
		return handshake.IdentityKeypair{}, fmt.Errorf("%s expected 32 bytes, got %d", identityEdSeedEnv, len(edSeedBytes))
	}
	if len(xPrivBytes) != 32 {
		return handshake.IdentityKeypair{}, fmt.Errorf("%s expected 32 bytes, got %d", identityXPrivEnv, len(xPrivBytes))
	}

	var edSeed [32]byte
	copy(edSeed[:], edSeedBytes)
	var xPriv [32]byte
	copy(xPriv[:], xPrivBytes)

	return handshake.IdentityKeypairFromSeeds(edSeed, xPriv)
}

func buildTrustStoreFromEnv() (handshake.TrustStore, error) {
	raw := strings.TrimSpace(os.Getenv(trustPinsEnv))
	if raw == "" {
		return handshake.TrustStore{}, fmt.Errorf(
			"%s must be set to one or more comma-separated Ed25519 public key pins",
			trustPinsEnv,
		)
	}

	trust := handshake.StrictTrustStore()
	pinCount := 0
	for idx, token := range strings.Split(raw, ",") {
		pinHex := strings.TrimSpace(token)
		if pinHex == "" {
			continue
		}

		pinBytes, err := parseHexBytes(trustPinsEnv, pinHex)
		if err != nil {
			return handshake.TrustStore{}, fmt.Errorf("%s pin %d invalid: %w", trustPinsEnv, idx, err)
		}
		if len(pinBytes) != 32 {
			return handshake.TrustStore{}, fmt.Errorf("%s pin %d expected 32 bytes, got %d", trustPinsEnv, idx, len(pinBytes))
		}

		var key [32]byte
		copy(key[:], pinBytes)
		trust.Pin(key)
		pinCount++
	}

	if pinCount == 0 {
		return handshake.TrustStore{}, fmt.Errorf(
			"%s must include at least one valid 32-byte Ed25519 public key pin",
			trustPinsEnv,
		)
	}

	return trust, nil
}

func parseOptionalUint64Env(name string) (uint64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned integer: %w", name, err)
	}
	return value, nil
}

func parseHexBytes(name string, value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("%s must have even-length hex", name)
	}
	out, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s contains invalid hex: %w", name, err)
	}
	return out, nil
}

func (c *Client) MaybeSendHeartbeat() error {
	if time.Since(c.LastHeartbeatSent) < heartbeatInterval {
		return nil
	}
	hb := frame.New(frame.MsgHeartbeat, 0, nil)
	if err := writeFrame(c.conn, hb); err != nil {
		return err
	}
	c.LastHeartbeatSent = time.Now()
	return nil
}

func (c *Client) CheckTimeout() error {
	if c.Session == nil {
		return errors.New("no session established")
	}
	if c.Session.IsTimedOut(heartbeatTimeout) {
		return errors.New("session heartbeat timeout")
	}
	return nil
}

func (c *Client) SendEncrypted(f frame.Frame) error {
	if c.Session == nil {
		return errors.New("no secure session established")
	}
	enc, err := c.Session.EncryptFrame(f)
	if err != nil {
		return err
	}
	if err := writeFrame(c.conn, enc); err != nil {
		return err
	}
	return c.MaybeSendHeartbeat()
}

func (c *Client) ReadEncrypted(r *router.FrameRouter) (frame.Frame, error) {
	if c.Session == nil {
		return frame.Frame{}, errors.New("no secure session established")
	}
	for {
		raw, err := readFrame(c.conn)
		if err != nil {
			return frame.Frame{}, err
		}
		if raw.MsgType == frame.MsgHeartbeat {
			_ = r.Dispatch(raw, &c.Session)
			_ = c.MaybeSendHeartbeat()
			continue
		}
		dec, err := c.Session.DecryptFrame(raw)
		if err != nil {
			return frame.Frame{}, err
		}
		return dec, nil
	}
}

func writeFrame(w io.Writer, f frame.Frame) error {
	enc := binary.NewEncoder()
	f.Encode(enc)
	_, err := w.Write(enc.Bytes())
	return err
}

func readFrame(r io.Reader) (frame.Frame, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(r, header); err != nil {
		return frame.Frame{}, err
	}
	dec := binary.NewDecoder(header)
	version, err := dec.ReadU8()
	if err != nil {
		return frame.Frame{}, err
	}
	msgType, err := dec.ReadU8()
	if err != nil {
		return frame.Frame{}, err
	}
	flags, err := dec.ReadU8()
	if err != nil {
		return frame.Frame{}, err
	}
	length, err := dec.ReadU32()
	if err != nil {
		return frame.Frame{}, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return frame.Frame{}, err
	}
	return frame.Frame{
		Version: version,
		MsgType: msgType,
		Flags:   flags,
		Payload: payload,
	}, nil
}

func NewAppRouter(inbox app.Inbox) *router.FrameRouter {
	return router.WithAppDefaults(inbox)
}
