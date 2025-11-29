package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Hawx-Drones/shadowlark-go/app"
	"github.com/Hawx-Drones/shadowlark-go/transport/tcp"
)

// A tiny demo client that connects to a Shadowlark relay, handshakes,
// sends one message, and prints the next inbound app message.
func main() {
	addr := os.Getenv("SHADOWLARK_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}

	inbox := app.NewInbox()
	router := tcp.NewAppRouter(inbox)

	client, err := tcp.Dial(addr)
	if err != nil {
		panic(fmt.Sprintf("dial failed: %v", err))
	}
	defer client.Close()

	if err := client.Handshake(router); err != nil {
		panic(fmt.Sprintf("handshake failed: %v", err))
	}

	messenger := app.NewMessenger()
	_, frame := messenger.BuildFrame(1, app.AppTypeData, []byte("hi from go"))
	if err := client.SendEncrypted(frame); err != nil {
		panic(fmt.Sprintf("send failed: %v", err))
	}

	// Read until we get an app message; push into inbox via router.
	done := time.After(3 * time.Second)
	for {
		select {
		case <-done:
			fmt.Println("no response within 3s")
			return
		default:
			f, err := client.ReadEncrypted(router)
			if err != nil {
				fmt.Printf("read failed: %v\n", err)
				return
			}
			if err := router.Dispatch(f, &client.Session); err != nil {
				fmt.Printf("dispatch error: %v\n", err)
				return
			}
			if msg, ok := inbox.Pop(); ok {
				fmt.Printf("received channel=%d seq=%d type=0x%04x payload=%q\n",
					msg.ChannelID, msg.Seq, msg.MsgType, string(msg.Payload))
				return
			}
		}
	}
}
