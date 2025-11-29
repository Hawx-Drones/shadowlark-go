package app

import "testing"

func TestMessageRoundtrip(t *testing.T) {
	msg := NewMessage(7, 42, 9, []byte("hello-app"))
	frame := msg.ToFrame()

	parsed, err := FromFrame(frame)
	if err != nil {
		t.Fatalf("from frame: %v", err)
	}
	if parsed.ChannelID != 7 || parsed.Seq != 42 || parsed.MsgType != 9 {
		t.Fatalf("unexpected header: %+v", parsed)
	}
	if string(parsed.Payload) != "hello-app" {
		t.Fatalf("payload mismatch: %q", parsed.Payload)
	}
}

func TestAckRoundtrip(t *testing.T) {
	ack := NewAck(3, 99)
	msg, err := ack.ToMessage(7)
	if err != nil {
		t.Fatalf("to message: %v", err)
	}
	frame := msg.ToFrame()

	parsedMsg, err := FromFrame(frame)
	if err != nil {
		t.Fatalf("from frame: %v", err)
	}
	parsedAck, err := AckFromMessage(parsedMsg)
	if err != nil {
		t.Fatalf("ack parse: %v", err)
	}
	if parsedAck.ChannelID != 3 || parsedAck.AckedSeq != 99 || parsedAck.IsNak {
		t.Fatalf("unexpected ack: %+v", parsedAck)
	}
}

func TestChunkRoundtrip(t *testing.T) {
	chunk := Chunk{
		ChannelID:  4,
		Seq:        1,
		ChunkIndex: 0,
		ChunkTotal: 2,
		Payload:    []byte("chunk-data"),
	}
	msg, err := chunk.ToMessage()
	if err != nil {
		t.Fatalf("chunk to message: %v", err)
	}
	frame := msg.ToFrame()

	parsedMsg, err := FromFrame(frame)
	if err != nil {
		t.Fatalf("from frame: %v", err)
	}
	parsedChunk, err := ChunkFromMessage(parsedMsg)
	if err != nil {
		t.Fatalf("chunk parse: %v", err)
	}
	if parsedChunk.ChannelID != 4 || parsedChunk.Seq != 1 || parsedChunk.Payload == nil {
		t.Fatalf("unexpected chunk: %+v", parsedChunk)
	}
}

func TestMessengerSequences(t *testing.T) {
	m := NewMessenger()
	seqA0, _ := m.BuildFrame(10, 1, []byte("a0"))
	seqB0, _ := m.BuildFrame(11, 1, []byte("b0"))
	seqA1, _ := m.BuildFrame(10, 1, []byte("a1"))

	if seqA0 != 0 || seqB0 != 0 || seqA1 != 1 {
		t.Fatalf("unexpected seqs: %d %d %d", seqA0, seqB0, seqA1)
	}
}

func TestInboxFiltering(t *testing.T) {
	inbox := NewInbox()
	inbox.Push(NewMessage(1, 0, 1, []byte("c1-0")))
	inbox.Push(NewMessage(2, 0, 1, []byte("c2-0")))
	inbox.Push(NewMessage(1, 1, 1, []byte("c1-1")))

	found, ok := inbox.PopChannel(2)
	if !ok {
		t.Fatalf("expected message on channel 2")
	}
	if found.ChannelID != 2 || string(found.Payload) != "c2-0" {
		t.Fatalf("unexpected message: %+v", found)
	}
	if inbox.Len() != 2 {
		t.Fatalf("expected len 2, got %d", inbox.Len())
	}
}
