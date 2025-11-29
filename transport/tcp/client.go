package tcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/shadowlark/shadowlark-go/app"
	"github.com/shadowlark/shadowlark-go/binary"
	"github.com/shadowlark/shadowlark-go/transport/frame"
	"github.com/shadowlark/shadowlark-go/transport/handshake"
	"github.com/shadowlark/shadowlark-go/transport/router"
	"github.com/shadowlark/shadowlark-go/transport/session"
)

const (
	heartbeatInterval = 5 * time.Second
	heartbeatTimeout  = 20 * time.Second
)

// Client is a blocking TCP client that speaks the Shadowlark V1 protocol.
type Client struct {
	conn              net.Conn
	Session           *session.State
	LastHeartbeatSent time.Time
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:              conn,
		Session:           nil,
		LastHeartbeatSent: time.Now(),
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// Handshake performs the INIT/ACK exchange and populates Session.
func (c *Client) Handshake(r *router.FrameRouter) error {
	init, err := handshake.NewInit(0x01)
	if err != nil {
		return err
	}
	initFrame := init.ToFrame()
	if err := writeFrame(c.conn, initFrame); err != nil {
		return err
	}
	if err := r.Dispatch(initFrame, &c.Session); err != nil {
		return err
	}

	ackFrame, err := readFrame(c.conn)
	if err != nil {
		return err
	}
	if ackFrame.MsgType != handshake.MsgHandshakeAck {
		return fmt.Errorf("expected HANDSHAKE_ACK, got %d", ackFrame.MsgType)
	}
	if err := r.Dispatch(ackFrame, &c.Session); err != nil {
		return err
	}
	return nil
}

// MaybeSendHeartbeat writes a heartbeat if the interval elapsed.
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
		return errors.New("no session key yet")
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
		return frame.Frame{}, errors.New("no session key yet")
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

// writeFrame writes the frame header + payload.
func writeFrame(w io.Writer, f frame.Frame) error {
	enc := binary.NewEncoder()
	f.Encode(enc)
	_, err := w.Write(enc.Bytes())
	return err
}

// readFrame reads a complete frame from the stream.
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

// NewAppRouter builds a router with default handlers + app inbox.
func NewAppRouter(inbox app.Inbox) *router.FrameRouter {
	return router.WithAppDefaults(inbox)
}
