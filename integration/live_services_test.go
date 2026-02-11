//go:build integration

package integration_test

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/app"
	slbinary "github.com/Hawx-Drones/shadowlark-go/binary"
	coreframe "github.com/Hawx-Drones/shadowlark-go/transport/frame"
	"github.com/Hawx-Drones/shadowlark-go/transport/router"
	"github.com/Hawx-Drones/shadowlark-go/transport/tcp"
)

const (
	msgStreamEncrypted = 0x70
	msgHello           = 0x01
	msgHelloAck        = 0x02
)

func TestMessagingInteropWithLiveService(t *testing.T) {
	requireLiveInterop(t)

	shadowlarkRoot := resolveShadowlarkRoot(t)
	bindAddr := reserveTCPAddr(t)
	startRustService(
		t,
		filepath.Join(shadowlarkRoot, "shadowlark-messaging"),
		"shadowlark-messaging",
		"SHADOWLARK_BIND",
		bindAddr,
	)

	clientA, err := tcp.Dial(bindAddr)
	if err != nil {
		t.Fatalf("dial client A: %v", err)
	}
	defer clientA.Close()

	clientB, err := tcp.Dial(bindAddr)
	if err != nil {
		t.Fatalf("dial client B: %v", err)
	}
	defer clientB.Close()

	r := router.WithDefaults()
	if err := clientA.Handshake(r); err != nil {
		t.Fatalf("client A handshake: %v", err)
	}
	if err := clientB.Handshake(r); err != nil {
		t.Fatalf("client B handshake: %v", err)
	}

	// Subscribe both peers before sending the target payload.
	subscribeA := app.NewMessage(9001, 0, app.AppTypeAck, []byte{0, 0, 0, 0}).ToFrame()
	subscribeB := app.NewMessage(9001, 0, app.AppTypeAck, []byte{0, 0, 0, 0}).ToFrame()
	if err := clientA.SendEncrypted(subscribeA); err != nil {
		t.Fatalf("client A channel subscribe: %v", err)
	}
	if err := clientB.SendEncrypted(subscribeB); err != nil {
		t.Fatalf("client B channel subscribe: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	message := app.NewMessage(9001, 2, app.AppTypeData, []byte("go-live-integration")).ToFrame()
	if err := clientA.SendEncrypted(message); err != nil {
		t.Fatalf("client A send encrypted: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for forwarded payload on receiver")
		}
		remaining := time.Until(deadline)
		received, err := readEncryptedWithTimeout(clientB, r, remaining)
		if err != nil {
			t.Fatalf("client B read encrypted: %v", err)
		}

		decoded, err := app.FromFrame(received)
		if err != nil {
			continue
		}
		if decoded.ChannelID == 9001 && decoded.MsgType == app.AppTypeData && string(decoded.Payload) == "go-live-integration" {
			break
		}
	}
}

func TestStreamingInteropWithLiveService(t *testing.T) {
	requireLiveInterop(t)

	shadowlarkRoot := resolveShadowlarkRoot(t)
	bindAddr := reserveTCPAddr(t)
	startRustService(
		t,
		filepath.Join(shadowlarkRoot, "shadowlark-streaming"),
		"shadowlark-streaming",
		"STREAM_BIND",
		bindAddr,
	)

	client, err := tcp.Dial(bindAddr)
	if err != nil {
		t.Fatalf("dial streaming service: %v", err)
	}
	defer client.Close()

	r := router.WithDefaults()
	if err := client.Handshake(r); err != nil {
		t.Fatalf("streaming secure handshake: %v", err)
	}

	streamHelloPayload := []byte{0x02, 0x03}
	streamHelloFrame := encodeStreamFrame(msgHello, 0x00, 77, streamHelloPayload)
	corePlain := coreframe.New(msgStreamEncrypted, 0, streamHelloFrame)

	if err := client.SendEncrypted(corePlain); err != nil {
		t.Fatalf("send secure streaming hello: %v", err)
	}

	coreAck, err := readEncryptedWithTimeout(client, r, 5*time.Second)
	if err != nil {
		t.Fatalf("read secure streaming ack: %v", err)
	}
	if coreAck.MsgType != msgStreamEncrypted {
		t.Fatalf("unexpected core secure msg type: got %d want %d", coreAck.MsgType, msgStreamEncrypted)
	}

	msgType, _, channelID, payload, err := decodeStreamFrame(coreAck.Payload)
	if err != nil {
		t.Fatalf("decode inner stream frame: %v", err)
	}
	if msgType != msgHelloAck {
		t.Fatalf("unexpected stream msg type: got %d want %d", msgType, msgHelloAck)
	}
	if channelID != 77 {
		t.Fatalf("unexpected stream channel id: got %d want %d", channelID, 77)
	}
	if len(payload) != 4 {
		t.Fatalf("unexpected hello ack payload length: got %d want %d", len(payload), 4)
	}

	clientID := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if clientID == 0 {
		t.Fatalf("expected non-zero hello ack client id")
	}
}

func requireLiveInterop(t *testing.T) {
	t.Helper()
	if os.Getenv("SHADOWLARK_LIVE_INTEGRATION") != "1" {
		t.Skip("set SHADOWLARK_LIVE_INTEGRATION=1 to run live service integration tests")
	}
}

func resolveShadowlarkRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to resolve current file path")
	}
	goRepoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	return filepath.Dir(goRepoRoot)
}

func reserveTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve addr: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func startRustService(t *testing.T, workdir string, binName string, envName string, bindAddr string) {
	t.Helper()

	cmd := exec.Command("cargo", "run", "--quiet", "--bin", binName)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%s", envName, bindAddr))

	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("start rust service in %s: %v", workdir, err)
	}

	if err := waitForTCP(bindAddr, 30*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("service did not bind %s: %v\nlogs:\n%s", bindAddr, err, logs.String())
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("service logs (%s):\n%s", workdir, logs.String())
		}
	})
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func readEncryptedWithTimeout(client *tcp.Client, r *router.FrameRouter, timeout time.Duration) (coreframe.Frame, error) {
	type result struct {
		frame coreframe.Frame
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		frame, err := client.ReadEncrypted(r)
		ch <- result{frame: frame, err: err}
	}()

	select {
	case out := <-ch:
		return out.frame, out.err
	case <-time.After(timeout):
		return coreframe.Frame{}, errors.New("timed out waiting for encrypted frame")
	}
}

func encodeStreamFrame(msgType byte, flags byte, channelID uint32, payload []byte) []byte {
	enc := slbinary.NewEncoder()
	enc.WriteU8(1)
	enc.WriteU8(msgType)
	enc.WriteU8(flags)
	enc.WriteU32(channelID)
	enc.WriteU32(uint32(len(payload)))
	enc.WriteBytes(payload)
	out := make([]byte, len(enc.Bytes()))
	copy(out, enc.Bytes())
	return out
}

func decodeStreamFrame(payload []byte) (msgType byte, flags byte, channelID uint32, inner []byte, err error) {
	dec := slbinary.NewDecoder(payload)

	version, err := dec.ReadU8()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if version != 1 {
		return 0, 0, 0, nil, fmt.Errorf("unexpected stream frame version %d", version)
	}

	msgType, err = dec.ReadU8()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	flags, err = dec.ReadU8()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	channelID, err = dec.ReadU32()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	length, err := dec.ReadU32()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	inner, err = dec.ReadBytes(int(length))
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if dec.Remaining() != 0 {
		return 0, 0, 0, nil, fmt.Errorf("trailing bytes in stream frame")
	}

	return msgType, flags, channelID, inner, nil
}
