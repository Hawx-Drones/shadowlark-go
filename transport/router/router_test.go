package router

import (
	"testing"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/app"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/session"
)

func TestAppHandlerBuffers(t *testing.T) {
	inbox := app.NewInbox()
	r := WithAppDefaults(inbox)

	msg := app.NewMessage(0, 1, 9, []byte("hello"))
	appFrame := msg.ToFrame()

	var sess *session.State
	if err := r.Dispatch(appFrame, &sess); err != nil {
		t.Fatalf("dispatch app: %v", err)
	}
	if inbox.Len() != 1 {
		t.Fatalf("expected inbox len 1, got %d", inbox.Len())
	}
}

func TestHeartbeatTouchesSession(t *testing.T) {
	r := WithDefaults()
	s := &session.State{LastSeen: time.Now().Add(-5 * time.Minute)}
	previous := s.LastSeen

	hb := frame.New(frame.MsgHeartbeat, 0, nil)
	if err := r.Dispatch(hb, &s); err != nil {
		t.Fatalf("dispatch heartbeat: %v", err)
	}
	if !s.LastSeen.After(previous) {
		t.Fatalf("expected heartbeat to refresh session timestamp")
	}
}
