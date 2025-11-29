package session

import (
	"testing"
	"time"

	"github.com/shadowlark/shadowlark-go/crypto"
	"github.com/shadowlark/shadowlark-go/transport/frame"
	"github.com/shadowlark/shadowlark-go/transport/handshake"
)

func TestSessionKeyDerivation(t *testing.T) {
	init, _ := handshake.NewInit(1)
	ack, _ := handshake.NewAck(1)

	sess := FromHandshake(init, ack)
	for i := 0; i < 32; i++ {
		if sess.SessionKey[i] != init.ClientNonce[i]^ack.ServerNonce[i] {
			t.Fatalf("key mismatch at %d", i)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	init, _ := handshake.NewInit(1)
	ack, _ := handshake.NewAck(1)
	sess := FromHandshake(init, ack)

	orig := frame.New(10, 0, []byte("hello-shadowlark"))
	enc, err := sess.EncryptFrame(orig)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !sess.IsEncrypted(enc) {
		t.Fatalf("expected encrypted flag")
	}
	dec, err := sess.DecryptFrame(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(dec.Payload) != "hello-shadowlark" {
		t.Fatalf("payload mismatch")
	}
}

func TestTimeoutDetection(t *testing.T) {
	var zero crypto.SessionKey
	sess := New([32]byte{}, [32]byte{}, zero)
	sess.LastSeen = time.Now().Add(-30 * time.Second)

	if !sess.IsTimedOut(20 * time.Second) {
		t.Fatalf("expected timeout")
	}
	if sess.IsTimedOut(40 * time.Second) {
		t.Fatalf("did not expect timeout")
	}
}
