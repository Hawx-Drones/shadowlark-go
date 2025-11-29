package router

import (
	"testing"

	"github.com/shadowlark/shadowlark-go/app"
	"github.com/shadowlark/shadowlark-go/transport/handshake"
	"github.com/shadowlark/shadowlark-go/transport/session"
)

func TestRouterHandshakeFlow(t *testing.T) {
	r := WithDefaults()

	init, _ := handshake.NewInit(1)
	initFrame := init.ToFrame()

	var sess *session.State
	if err := r.Dispatch(initFrame, &sess); err != nil {
		t.Fatalf("dispatch init: %v", err)
	}
	if sess == nil {
		t.Fatalf("session not created")
	}

	ack, _ := handshake.NewAck(1)
	ackFrame := ack.ToFrame()
	if err := r.Dispatch(ackFrame, &sess); err != nil {
		t.Fatalf("dispatch ack: %v", err)
	}
	if sess.SessionKey == ([32]byte{}) {
		t.Fatalf("session key not derived")
	}
}

func TestAppHandlerBuffers(t *testing.T) {
	inbox := app.NewInbox()
	r := WithAppDefaults(inbox)

	msg := app.NewMessage(0, 1, 9, []byte("hello"))
	frame := msg.ToFrame()

	var sess *session.State
	if err := r.Dispatch(frame, &sess); err != nil {
		t.Fatalf("dispatch app: %v", err)
	}
	if inbox.Len() != 1 {
		t.Fatalf("expected inbox len 1, got %d", inbox.Len())
	}
}
