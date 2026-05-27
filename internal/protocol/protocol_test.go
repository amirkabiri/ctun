package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"ctun/internal/conf"
	"ctun/internal/tnet"
)

func sampleMessage(flags Flags, payload []byte) *Message {
	return &Message{
		SessionID: 0xDEADBEEF,
		Sequence:  0x0123456789ABCDEF,
		Flags:     flags,
		Payload:   payload,
	}
}

func TestRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		flags   Flags
		payload []byte
	}{
		{"hello empty", FlagHello, nil},
		{"hello small", FlagHello, []byte("hi")},
		{"hello_ack", FlagHelloAck, []byte{1, 2, 3, 4}},
		{"data empty", FlagData, []byte{}},
		{"data large", FlagData, bytes.Repeat([]byte{0xAB}, 1024)},
		{"data max", FlagData, bytes.Repeat([]byte{0xCD}, MaxPayloadSize)},
		{"keepalive", FlagKeepalive, []byte{PPING}},
		{"close", FlagClose, []byte("bye")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := sampleMessage(c.flags, c.payload)
			wire, err := Marshal(in)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if len(wire) != HeaderSize+len(c.payload) {
				t.Fatalf("wire length %d, want %d", len(wire), HeaderSize+len(c.payload))
			}
			out, err := Unmarshal(wire)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if out.SessionID != in.SessionID {
				t.Errorf("SessionID got %x want %x", out.SessionID, in.SessionID)
			}
			if out.Sequence != in.Sequence {
				t.Errorf("Sequence got %x want %x", out.Sequence, in.Sequence)
			}
			if out.Flags != in.Flags {
				t.Errorf("Flags got %d want %d", out.Flags, in.Flags)
			}
			if !bytes.Equal(out.Payload, in.Payload) && !(len(out.Payload) == 0 && len(in.Payload) == 0) {
				t.Errorf("Payload mismatch")
			}
		})
	}
}

func TestMarshal_Deterministic(t *testing.T) {
	m := sampleMessage(FlagData, []byte("hello, ctun"))
	a, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal a: %v", err)
	}
	b, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("Marshal is not deterministic:\n a=%x\n b=%x", a, b)
	}
}

func TestUnmarshal_Truncated(t *testing.T) {
	// Shorter than HeaderSize.
	for n := 0; n < HeaderSize; n++ {
		_, err := Unmarshal(make([]byte, n))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("len=%d: got %v, want ErrTruncated", n, err)
		}
	}
	// Header says Length=10 but only 5 payload bytes follow.
	buf := make([]byte, HeaderSize+5)
	buf[12] = byte(FlagData)
	binary.BigEndian.PutUint16(buf[13:15], 10)
	if _, err := Unmarshal(buf); !errors.Is(err, ErrTruncated) {
		t.Fatalf("partial payload: got %v, want ErrTruncated", err)
	}
}

func TestUnmarshal_LengthMismatch(t *testing.T) {
	// Header says Length=5 but the buffer has 6 payload bytes.
	buf := make([]byte, HeaderSize+6)
	buf[12] = byte(FlagData)
	binary.BigEndian.PutUint16(buf[13:15], 5)
	if _, err := Unmarshal(buf); !errors.Is(err, ErrLengthMismatch) {
		t.Fatalf("got %v, want ErrLengthMismatch", err)
	}
}

func TestUnmarshal_UnknownFlags(t *testing.T) {
	buf := make([]byte, HeaderSize)
	buf[12] = 255
	binary.BigEndian.PutUint16(buf[13:15], 0)
	if _, err := Unmarshal(buf); !errors.Is(err, ErrUnknownFlags) {
		t.Fatalf("got %v, want ErrUnknownFlags", err)
	}
	// Also check 5, the first invalid value just past FlagClose.
	buf[12] = 5
	if _, err := Unmarshal(buf); !errors.Is(err, ErrUnknownFlags) {
		t.Fatalf("flag=5: got %v, want ErrUnknownFlags", err)
	}
}

func TestUnmarshal_PayloadTooLarge_OnMarshal(t *testing.T) {
	m := &Message{Flags: FlagData, Payload: make([]byte, MaxPayloadSize+1)}
	if _, err := Marshal(m); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Marshal: got %v, want ErrPayloadTooLarge", err)
	}
	buf := make([]byte, HeaderSize+MaxPayloadSize+1)
	if _, err := MarshalTo(buf, m); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("MarshalTo: got %v, want ErrPayloadTooLarge", err)
	}
}

func TestMarshalTo_Buffer_TooSmall(t *testing.T) {
	m := sampleMessage(FlagData, []byte("data"))
	// HeaderSize + 4 needed; give one less.
	buf := make([]byte, HeaderSize+3)
	if _, err := MarshalTo(buf, m); !errors.Is(err, ErrBufferTooSmall) {
		t.Fatalf("got %v, want ErrBufferTooSmall", err)
	}
	// Zero-sized buf is also too small.
	if _, err := MarshalTo(nil, m); !errors.Is(err, ErrBufferTooSmall) {
		t.Fatalf("nil buf: got %v, want ErrBufferTooSmall", err)
	}
}

func TestReadMessage_RoundTrip(t *testing.T) {
	in := sampleMessage(FlagData, []byte("over a stream"))
	var b bytes.Buffer
	if err := WriteMessage(&b, in); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	out, err := ReadMessage(&b)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if out.SessionID != in.SessionID || out.Sequence != in.Sequence ||
		out.Flags != in.Flags || !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("round trip mismatch:\n in=%#v\n out=%#v", in, out)
	}
}

func TestReadMessage_ShortHeader(t *testing.T) {
	_, err := ReadMessage(bytes.NewReader([]byte{1, 2, 3}))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
}

func TestReadMessage_ShortPayload(t *testing.T) {
	// Build a header declaring Length=10 but supply only 3 payload bytes.
	buf := make([]byte, HeaderSize+3)
	buf[12] = byte(FlagData)
	binary.BigEndian.PutUint16(buf[13:15], 10)
	_, err := ReadMessage(bytes.NewReader(buf))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated (wrapped); chain: %v", err, err)
	}
}

func TestReadMessage_UnknownFlags(t *testing.T) {
	buf := make([]byte, HeaderSize)
	buf[12] = 99
	binary.BigEndian.PutUint16(buf[13:15], 0)
	_, err := ReadMessage(bytes.NewReader(buf))
	if !errors.Is(err, ErrUnknownFlags) {
		t.Fatalf("got %v, want ErrUnknownFlags", err)
	}
}

func TestReadMessage_EOFOnEmpty(t *testing.T) {
	_, err := ReadMessage(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

func BenchmarkMarshalTo(b *testing.B) {
	m := &Message{
		SessionID: 0xDEADBEEF,
		Sequence:  1,
		Flags:     FlagData,
		Payload:   bytes.Repeat([]byte{0xAB}, 256),
	}
	buf := make([]byte, HeaderSize+len(m.Payload))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := MarshalTo(buf, m); err != nil {
			b.Fatal(err)
		}
		m.Sequence++
	}
}

func TestMarshalTo_ZeroAlloc(t *testing.T) {
	m := &Message{
		SessionID: 1,
		Sequence:  1,
		Flags:     FlagData,
		Payload:   bytes.Repeat([]byte{0xAB}, 256),
	}
	buf := make([]byte, HeaderSize+len(m.Payload))
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := MarshalTo(buf, m); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("MarshalTo allocated %.2f times/op; want 0", allocs)
	}
}

// --- Stream-control sub-frame tests ----------------------------------------

func TestProto_RoundTrip_PingPong(t *testing.T) {
	for _, pt := range []PType{PPING, PPONG} {
		in := &Proto{Type: pt}
		var b bytes.Buffer
		if err := in.Write(&b); err != nil {
			t.Fatalf("write 0x%02x: %v", pt, err)
		}
		out := &Proto{}
		if err := out.Read(&b); err != nil {
			t.Fatalf("read 0x%02x: %v", pt, err)
		}
		if out.Type != in.Type {
			t.Fatalf("type mismatch: got 0x%02x want 0x%02x", out.Type, in.Type)
		}
	}
}

func TestProto_RoundTrip_TCPF(t *testing.T) {
	in := &Proto{Type: PTCPF, TCPF: []conf.TCPF{
		{SYN: true},
		{PSH: true, ACK: true},
		{FIN: true, ACK: true},
		{NS: true, CWR: true, ECE: true, URG: true, ACK: true, PSH: true, RST: true, SYN: true, FIN: true},
	}}
	var b bytes.Buffer
	if err := in.Write(&b); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := &Proto{}
	if err := out.Read(&b); err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Type != PTCPF {
		t.Fatalf("type mismatch: %d", out.Type)
	}
	if len(out.TCPF) != len(in.TCPF) {
		t.Fatalf("len mismatch: got %d want %d", len(out.TCPF), len(in.TCPF))
	}
	for i := range in.TCPF {
		if out.TCPF[i] != in.TCPF[i] {
			t.Errorf("TCPF[%d] mismatch: got %#v want %#v", i, out.TCPF[i], in.TCPF[i])
		}
	}
}

func TestProto_RoundTrip_TCPF_Empty(t *testing.T) {
	in := &Proto{Type: PTCPF, TCPF: nil}
	var b bytes.Buffer
	if err := in.Write(&b); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := &Proto{}
	if err := out.Read(&b); err != nil {
		t.Fatalf("read: %v", err)
	}
	if out.Type != PTCPF || len(out.TCPF) != 0 {
		t.Fatalf("empty PTCPF round trip failed: %#v", out)
	}
}

func TestProto_RoundTrip_Addr(t *testing.T) {
	for _, pt := range []PType{PTCP, PUDP} {
		in := &Proto{Type: pt, Addr: &tnet.Addr{Host: "example.com", Port: 443}}
		var b bytes.Buffer
		if err := in.Write(&b); err != nil {
			t.Fatalf("write 0x%02x: %v", pt, err)
		}
		out := &Proto{}
		if err := out.Read(&b); err != nil {
			t.Fatalf("read 0x%02x: %v", pt, err)
		}
		if out.Type != pt || out.Addr == nil {
			t.Fatalf("decoded shape wrong: %#v", out)
		}
		if out.Addr.Host != in.Addr.Host || out.Addr.Port != in.Addr.Port {
			t.Errorf("addr mismatch: got %#v want %#v", out.Addr, in.Addr)
		}
	}
}

func TestProto_Addr_IPv6(t *testing.T) {
	in := &Proto{Type: PTCP, Addr: &tnet.Addr{Host: "2001:db8::1", Port: 80}}
	var b bytes.Buffer
	if err := in.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := &Proto{}
	if err := out.Read(&b); err != nil {
		t.Fatal(err)
	}
	if out.Addr.Host != in.Addr.Host || out.Addr.Port != in.Addr.Port {
		t.Errorf("ipv6 mismatch: %#v vs %#v", out.Addr, in.Addr)
	}
}

func TestProto_DecodeRejectsBadInputs(t *testing.T) {
	// Empty payload.
	_, err := DecodeProto(&Message{Flags: FlagData, Payload: nil})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("empty payload: got %v", err)
	}
	// Unknown PType.
	_, err = DecodeProto(&Message{Flags: FlagData, Payload: []byte{0xFF}})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("unknown PType: got %v", err)
	}
	// Wrong flag for PPING.
	_, err = DecodeProto(&Message{Flags: FlagData, Payload: []byte{PPING}})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("PPING with FlagData: got %v", err)
	}
	// PTCPF count mismatch.
	bad := []byte{PTCPF, 2, 0x00, 0x01} // claims 2 entries, but body has only 1
	_, err = DecodeProto(&Message{Flags: FlagData, Payload: bad})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("PTCPF count mismatch: got %v", err)
	}
	// PTCPF reserved bits set.
	bad = []byte{PTCPF, 1, 0xFE, 0x00} // bit 9..15 set
	_, err = DecodeProto(&Message{Flags: FlagData, Payload: bad})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("PTCPF reserved bits: got %v", err)
	}
	// PTCP truncated body.
	bad = []byte{PTCP, 4, 'a', 'b'} // hostLen=4 but only 2 host bytes provided
	_, err = DecodeProto(&Message{Flags: FlagData, Payload: bad})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("PTCP truncated: got %v", err)
	}
}

func TestProto_EncodeRejectsBadInputs(t *testing.T) {
	// PTCP without Addr.
	_, err := EncodeProto(&Proto{Type: PTCP})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("nil addr: got %v", err)
	}
	// Out-of-range port.
	_, err = EncodeProto(&Proto{Type: PTCP, Addr: &tnet.Addr{Host: "h", Port: -1}})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("negative port: got %v", err)
	}
	_, err = EncodeProto(&Proto{Type: PTCP, Addr: &tnet.Addr{Host: "h", Port: 70000}})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("port too large: got %v", err)
	}
	// Host too long.
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'x'
	}
	_, err = EncodeProto(&Proto{Type: PTCP, Addr: &tnet.Addr{Host: string(long), Port: 80}})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("long host: got %v", err)
	}
	// PTCPF count too large.
	tooMany := make([]conf.TCPF, 256)
	_, err = EncodeProto(&Proto{Type: PTCPF, TCPF: tooMany})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("PTCPF count overflow: got %v", err)
	}
	// Unknown PType.
	_, err = EncodeProto(&Proto{Type: 0x99})
	if !errors.Is(err, ErrInvalidSubFrame) {
		t.Fatalf("unknown PType: got %v", err)
	}
}
