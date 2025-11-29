package router

import (
	"fmt"

	"github.com/shadowlark/shadowlark-go/app"
	"github.com/shadowlark/shadowlark-go/crypto"
	"github.com/shadowlark/shadowlark-go/transport/frame"
	"github.com/shadowlark/shadowlark-go/transport/handshake"
	"github.com/shadowlark/shadowlark-go/transport/session"
)

type FrameHandler interface {
	Handle(f frame.Frame, sess **session.State) error
}

type FrameRouter struct {
	handlers map[byte]FrameHandler
}

func New() *FrameRouter {
	return &FrameRouter{
		handlers: make(map[byte]FrameHandler),
	}
}

func WithDefaults() *FrameRouter {
	r := New()
	r.RegisterHandler(handshake.MsgHandshakeInit, HandshakeInitHandler{})
	r.RegisterHandler(handshake.MsgHandshakeAck, HandshakeAckHandler{})
	r.RegisterHandler(frame.MsgHeartbeat, HeartbeatHandler{})
	return r
}

func WithAppDefaults(inbox app.Inbox) *FrameRouter {
	r := WithDefaults()
	r.RegisterHandler(app.MsgAppMessage, AppMessageHandler{Inbox: inbox})
	return r
}

func (r *FrameRouter) RegisterHandler(msgType byte, handler FrameHandler) {
	r.handlers[msgType] = handler
}

func (r *FrameRouter) Dispatch(f frame.Frame, sess **session.State) error {
	h, ok := r.handlers[f.MsgType]
	if !ok {
		return fmt.Errorf("no handler registered for msg_type %d", f.MsgType)
	}
	return h.Handle(f, sess)
}

// -------------------------
// Built-in handlers
// -------------------------

type HandshakeInitHandler struct{}

func (HandshakeInitHandler) Handle(f frame.Frame, sess **session.State) error {
	init, err := handshake.InitFromFrame(f)
	if err != nil {
		return err
	}
	state := session.New(init.ClientNonce, [32]byte{}, [32]byte{})
	*sess = &state
	return nil
}

type HandshakeAckHandler struct{}

func (HandshakeAckHandler) Handle(f frame.Frame, sess **session.State) error {
	if sess == nil {
		return fmt.Errorf("nil session pointer")
	}
	ack, err := handshake.AckFromFrame(f)
	if err != nil {
		return err
	}
	if *sess == nil {
		return fmt.Errorf("received HANDSHAKE_ACK before HANDSHAKE_INIT")
	}
	s := *sess
	s.ServerNonce = ack.ServerNonce
	s.SessionKey = crypto.DeriveSessionKey(s.ClientNonce, ack.ServerNonce)
	s.Touch()
	*sess = s
	return nil
}

type AppMessageHandler struct {
	Inbox app.Inbox
}

func (h AppMessageHandler) Handle(f frame.Frame, sess **session.State) error {
	msg, err := app.FromFrame(f)
	if err != nil {
		return err
	}
	h.Inbox.Push(msg)
	if s := *sess; s != nil {
		s.Touch()
	}
	return nil
}

type HeartbeatHandler struct{}

func (HeartbeatHandler) Handle(_ frame.Frame, sess **session.State) error {
	if s := *sess; s != nil {
		s.Touch()
	}
	return nil
}
