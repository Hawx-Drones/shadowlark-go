package app

import (
	"errors"
	"sort"
	"sync"

	"github.com/Hawx-Drones/shadowlark-go/binary"
	"github.com/Hawx-Drones/shadowlark-go/transport/frame"
)

const (
	MsgAppMessage byte = 0x10

	AppTypeData  uint16 = 0x01
	AppTypeAck   uint16 = 0x02
	AppTypeNak   uint16 = 0x03
	AppTypeChunk uint16 = 0x10
)

type Message struct {
	ChannelID uint32
	Seq       uint32
	MsgType   uint16
	Payload   []byte
}

func NewMessage(channelID, seq uint32, msgType uint16, payload []byte) Message {
	return Message{
		ChannelID: channelID,
		Seq:       seq,
		MsgType:   msgType,
		Payload:   payload,
	}
}

func (m Message) Encode(enc *binary.Encoder) {
	enc.WriteU32(m.ChannelID)
	enc.WriteU32(m.Seq)
	enc.WriteU16(m.MsgType)
	enc.WriteU32(uint32(len(m.Payload)))
	enc.WriteBytes(m.Payload)
}

func Decode(dec *binary.Decoder) (Message, error) {
	channelID, err := dec.ReadU32()
	if err != nil {
		return Message{}, err
	}
	seq, err := dec.ReadU32()
	if err != nil {
		return Message{}, err
	}
	msgType, err := dec.ReadU16()
	if err != nil {
		return Message{}, err
	}
	length, err := dec.ReadU32()
	if err != nil {
		return Message{}, err
	}
	if length > 8*1024*1024 {
		return Message{}, errors.New("app payload too large")
	}
	payload, err := dec.ReadBytes(int(length))
	if err != nil {
		return Message{}, err
	}
	return Message{
		ChannelID: channelID,
		Seq:       seq,
		MsgType:   msgType,
		Payload:   payload,
	}, nil
}

func (m Message) ToFrame() frame.Frame {
	enc := binary.NewEncoder()
	m.Encode(enc)
	return frame.New(MsgAppMessage, 0, enc.Bytes())
}

func FromFrame(f frame.Frame) (Message, error) {
	if f.MsgType != MsgAppMessage {
		return Message{}, errors.New("expected APP_MESSAGE frame")
	}
	dec := binary.NewDecoder(f.Payload)
	return Decode(dec)
}

type Ack struct {
	ChannelID uint32
	AckedSeq  uint32
	IsNak     bool
}

func NewAck(channelID, ackedSeq uint32) Ack {
	return Ack{ChannelID: channelID, AckedSeq: ackedSeq, IsNak: false}
}

func NewNak(channelID, ackedSeq uint32) Ack {
	return Ack{ChannelID: channelID, AckedSeq: ackedSeq, IsNak: true}
}

func (a Ack) ToMessage(seq uint32) (Message, error) {
	enc := binary.NewEncoder()
	enc.WriteU32(a.AckedSeq)
	msgType := AppTypeAck
	if a.IsNak {
		msgType = AppTypeNak
	}
	return Message{
		ChannelID: a.ChannelID,
		Seq:       seq,
		MsgType:   msgType,
		Payload:   enc.Bytes(),
	}, nil
}

func AckFromMessage(msg Message) (Ack, error) {
	if msg.MsgType != AppTypeAck && msg.MsgType != AppTypeNak {
		return Ack{}, errors.New("not an ACK/NAK message")
	}
	dec := binary.NewDecoder(msg.Payload)
	acked, err := dec.ReadU32()
	if err != nil {
		return Ack{}, err
	}
	return Ack{
		ChannelID: msg.ChannelID,
		AckedSeq:  acked,
		IsNak:     msg.MsgType == AppTypeNak,
	}, nil
}

type Chunk struct {
	ChannelID  uint32
	Seq        uint32
	ChunkIndex uint32
	ChunkTotal uint32
	Payload    []byte
}

func (c Chunk) ToMessage() (Message, error) {
	enc := binary.NewEncoder()
	enc.WriteU32(c.ChunkIndex)
	enc.WriteU32(c.ChunkTotal)
	enc.WriteU32(uint32(len(c.Payload)))
	enc.WriteBytes(c.Payload)

	return Message{
		ChannelID: c.ChannelID,
		Seq:       c.Seq,
		MsgType:   AppTypeChunk,
		Payload:   enc.Bytes(),
	}, nil
}

func ChunkFromMessage(msg Message) (Chunk, error) {
	if msg.MsgType != AppTypeChunk {
		return Chunk{}, errors.New("not a CHUNK message")
	}
	dec := binary.NewDecoder(msg.Payload)
	idx, err := dec.ReadU32()
	if err != nil {
		return Chunk{}, err
	}
	total, err := dec.ReadU32()
	if err != nil {
		return Chunk{}, err
	}
	length, err := dec.ReadU32()
	if err != nil {
		return Chunk{}, err
	}
	payload, err := dec.ReadBytes(int(length))
	if err != nil {
		return Chunk{}, err
	}
	return Chunk{
		ChannelID:  msg.ChannelID,
		Seq:        msg.Seq,
		ChunkIndex: idx,
		ChunkTotal: total,
		Payload:    payload,
	}, nil
}

type inboxState struct {
	mu    sync.Mutex
	queue []Message
}

// Inbox is a simple mutex-protected queue for received app messages.
// It is copy-safe: all copies share the same underlying state.
type Inbox struct {
	state *inboxState
}

func NewInbox() Inbox {
	return Inbox{
		state: &inboxState{queue: make([]Message, 0)},
	}
}

func (i Inbox) Push(m Message) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	i.state.queue = append(i.state.queue, m)
}

func (i Inbox) Pop() (Message, bool) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	if len(i.state.queue) == 0 {
		return Message{}, false
	}
	m := i.state.queue[0]
	i.state.queue = i.state.queue[1:]
	return m, true
}

func (i Inbox) PopChannel(channelID uint32) (Message, bool) {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	for idx, msg := range i.state.queue {
		if msg.ChannelID == channelID {
			i.state.queue = append(i.state.queue[:idx], i.state.queue[idx+1:]...)
			return msg, true
		}
	}
	return Message{}, false
}

func (i Inbox) Len() int {
	i.state.mu.Lock()
	defer i.state.mu.Unlock()
	return len(i.state.queue)
}

// Messenger tracks per-channel sequence counters and builds frames.
type Messenger struct {
	nextSeq map[uint32]uint32
	inbox   Inbox
}

func NewMessenger() Messenger {
	return Messenger{
		nextSeq: make(map[uint32]uint32),
		inbox:   NewInbox(),
	}
}

func NewMessengerWithInbox(inbox Inbox) Messenger {
	return Messenger{
		nextSeq: make(map[uint32]uint32),
		inbox:   inbox,
	}
}

func (m *Messenger) allocSeq(channelID uint32) uint32 {
	seq := m.nextSeq[channelID]
	m.nextSeq[channelID] = seq + 1
	return seq
}

func (m *Messenger) BuildFrame(channelID uint32, msgType uint16, payload []byte) (uint32, frame.Frame) {
	seq := m.allocSeq(channelID)
	msg := NewMessage(channelID, seq, msgType, payload)
	return seq, msg.ToFrame()
}

func (m *Messenger) InboxLen() int {
	return m.inbox.Len()
}

func (m *Messenger) TryRecv() (Message, bool) {
	return m.inbox.Pop()
}

func (m *Messenger) TryRecvChannel(channelID uint32) (Message, bool) {
	return m.inbox.PopChannel(channelID)
}

func (m *Messenger) Inbox() Inbox {
	return m.inbox
}

// StableSubscriberSet tracks channel subscribers similar to the Rust relay.
type StableSubscriberSet struct {
	mu   sync.Mutex
	subs map[uint32][]uint32
}

func NewStableSubscriberSet() *StableSubscriberSet {
	return &StableSubscriberSet{subs: make(map[uint32][]uint32)}
}

func (s *StableSubscriberSet) Add(channelID uint32, clientID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := append(s.subs[channelID], clientID)
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	list = dedupe(list)
	s.subs[channelID] = list
}

func (s *StableSubscriberSet) Remove(channelID uint32, clientID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.subs[channelID]
	out := list[:0]
	for _, id := range list {
		if id != clientID {
			out = append(out, id)
		}
	}
	s.subs[channelID] = out
}

func (s *StableSubscriberSet) Subscribers(channelID uint32) []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.subs[channelID]
	out := make([]uint32, len(src))
	copy(out, src)
	return out
}

func dedupe(in []uint32) []uint32 {
	if len(in) == 0 {
		return in
	}
	out := []uint32{in[0]}
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}
