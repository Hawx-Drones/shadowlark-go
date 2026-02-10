package tcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/app"
	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/handshake"
	"github.com/Hawx-Drones/shadowlark-go/transport/router"
	"github.com/Hawx-Drones/shadowlark-go/transport/session"
)

const (
	heartbeatInterval = 5 * time.Second
	heartbeatTimeout  = 20 * time.Second
)

type Client struct {
	conn              net.Conn
	Session           *session.State
	LastHeartbeatSent time.Time
	localIdentity     *handshake.IdentityKeypair
	localBundle       *handshake.IdentityBundle
	trustStore        handshake.TrustStore
	policy            handshake.HandshakePolicy
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	trust := handshake.AllowAnyTrustStore()
	return &Client{
		conn:              conn,
		Session:           nil,
		LastHeartbeatSent: time.Now(),
		trustStore:        trust,
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
	return c.handshakeSecure(identity, bundle, c.trustStore, c.policy)
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

	identity, err := handshake.GenerateIdentityKeypair()
	if err != nil {
		return handshake.IdentityKeypair{}, handshake.IdentityBundle{}, err
	}
	now := uint64(time.Now().Unix())
	bundle, err := handshake.SignedIdentityBundle("shadowlark-go-client", now-60, now+86400, identity)
	if err != nil {
		return handshake.IdentityKeypair{}, handshake.IdentityBundle{}, err
	}
	c.SetSecureIdentity(identity, bundle)
	return identity, bundle, nil
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
