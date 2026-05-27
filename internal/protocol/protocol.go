// Package protocol implements ctun's wire format — the fixed-layout binary
// frame that replaces paqet's gob-based serialisation.
//
// # Wire layout (plaintext, before any outer AEAD)
//
//	+------------+-------------+----------+-----------------+-------------+
//	| SessionID  | Sequence    | Flags    | Length          | Payload     |
//	| 4 bytes BE | 8 bytes BE  | 1 byte   | 2 bytes BE      | N bytes     |
//	+------------+-------------+----------+-----------------+-------------+
//
// The header is exactly 15 bytes for every frame. Length is the payload
// length (max 65535) and excludes the header itself.
//
// # Flag values
//
//   - FlagHello     (0) — initial client→server handshake (T3.3).
//   - FlagHelloAck  (1) — server→client handshake acknowledgement (T3.3).
//   - FlagData      (2) — application data (smux/KCP segments and the
//     in-stream control sub-frames inventoried below).
//   - FlagKeepalive (3) — liveness probe / heartbeat.
//   - FlagClose     (4) — session teardown.
//
// # Stream-control sub-frames inside FlagData / FlagKeepalive
//
// paqet's legacy `gob`-encoded Proto messages do not map 1:1 to the outer
// 5-flag set above — they are smux stream-level control messages, not
// transport frames. They are folded into the new frame format by setting
// Flags to the closest semantic match and emitting a sub-type byte at the
// start of Payload:
//
//	PPING (0x01) — Flags=FlagKeepalive  Payload=[0x01]
//	PPONG (0x02) — Flags=FlagKeepalive  Payload=[0x02]
//	PTCPF (0x03) — Flags=FlagData       Payload=[0x03][Count:1][TCPF:Count*2]
//	PTCP  (0x04) — Flags=FlagData       Payload=[0x04][AddrLen:1][Addr][Port:2 BE]
//	PUDP  (0x05) — Flags=FlagData       Payload=[0x05][AddrLen:1][Addr][Port:2 BE]
//
// PTCPF's TCPF block packs the 9 boolean TCP flags into a 2-byte little-endian
// bitfield (FIN=bit0, SYN=bit1, RST=bit2, PSH=bit3, ACK=bit4, URG=bit5,
// ECE=bit6, CWR=bit7, NS=bit8). The remaining 7 bits are reserved and MUST be
// zero on the wire; receivers reject non-zero reserved bits.
//
// SessionID and Sequence are placeholders at this layer; they are populated
// by the session manager (T3.2) and the anti-replay window (T3.4). Until
// those land, stream call-sites pass zero values — this is wire-compatible
// because the outer AEAD nonce is independent.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Flags is the 1-byte frame-type field of the ctun wire format.
type Flags uint8

// The set of valid Flags values. Anything outside this set is rejected by
// Unmarshal with ErrUnknownFlags.
const (
	FlagHello     Flags = 0
	FlagHelloAck  Flags = 1
	FlagData      Flags = 2
	FlagKeepalive Flags = 3
	FlagClose     Flags = 4
)

// HeaderSize is the fixed length of the ctun frame header in bytes.
const HeaderSize = 15

// MaxPayloadSize is the largest payload that fits in the 2-byte Length field.
const MaxPayloadSize = 65535

// Message is the in-memory representation of one ctun frame.
type Message struct {
	SessionID uint32
	Sequence  uint64
	Flags     Flags
	Payload   []byte
}

// Typed sentinels exposed for errors.Is callers.
var (
	// ErrPayloadTooLarge is returned when a payload exceeds MaxPayloadSize.
	ErrPayloadTooLarge = errors.New("protocol: payload exceeds MaxPayloadSize")
	// ErrTruncated is returned when the input buffer is shorter than the
	// header or shorter than the declared payload length.
	ErrTruncated = errors.New("protocol: truncated input")
	// ErrLengthMismatch is returned when the Length field disagrees with the
	// number of bytes remaining in the buffer (extra trailing bytes).
	ErrLengthMismatch = errors.New("protocol: length field disagrees with buffer size")
	// ErrUnknownFlags is returned when the Flags byte is not one of the five
	// defined values.
	ErrUnknownFlags = errors.New("protocol: unknown flags value")
	// ErrBufferTooSmall is returned by MarshalTo when the supplied buffer
	// cannot hold HeaderSize + len(Payload) bytes.
	ErrBufferTooSmall = errors.New("protocol: buffer too small")
)

// validFlag reports whether f is one of the five defined Flags values.
func validFlag(f Flags) bool {
	return f <= FlagClose
}

// Marshal serialises m into a freshly-allocated byte slice. It returns
// ErrPayloadTooLarge if len(m.Payload) > MaxPayloadSize.
func Marshal(m *Message) ([]byte, error) {
	if len(m.Payload) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	buf := make([]byte, HeaderSize+len(m.Payload))
	n, err := MarshalTo(buf, m)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// MarshalTo serialises m into buf and returns the number of bytes written.
// buf must hold at least HeaderSize+len(m.Payload) bytes; otherwise
// ErrBufferTooSmall is returned. ErrPayloadTooLarge is returned if the
// payload exceeds MaxPayloadSize.
//
// MarshalTo performs no allocations on the hot path — see BenchmarkMarshalTo.
func MarshalTo(buf []byte, m *Message) (int, error) {
	if len(m.Payload) > MaxPayloadSize {
		return 0, ErrPayloadTooLarge
	}
	need := HeaderSize + len(m.Payload)
	if len(buf) < need {
		return 0, ErrBufferTooSmall
	}
	binary.BigEndian.PutUint32(buf[0:4], m.SessionID)
	binary.BigEndian.PutUint64(buf[4:12], m.Sequence)
	buf[12] = byte(m.Flags)
	binary.BigEndian.PutUint16(buf[13:15], uint16(len(m.Payload)))
	copy(buf[HeaderSize:need], m.Payload)
	return need, nil
}

// Unmarshal parses one Message from buf. It returns:
//   - ErrTruncated if buf is shorter than HeaderSize or shorter than the
//     declared payload length.
//   - ErrLengthMismatch if buf contains bytes after the declared payload
//     (the wire is one message per outer frame; trailing bytes signal a bug
//     or attack).
//   - ErrUnknownFlags if the Flags byte is outside the defined set.
//
// The returned Message owns its Payload slice (a copy of the input bytes).
func Unmarshal(buf []byte) (*Message, error) {
	if len(buf) < HeaderSize {
		return nil, ErrTruncated
	}
	length := int(binary.BigEndian.Uint16(buf[13:15]))
	if len(buf) < HeaderSize+length {
		return nil, ErrTruncated
	}
	if len(buf) > HeaderSize+length {
		return nil, ErrLengthMismatch
	}
	flags := Flags(buf[12])
	if !validFlag(flags) {
		return nil, ErrUnknownFlags
	}
	m := &Message{
		SessionID: binary.BigEndian.Uint32(buf[0:4]),
		Sequence:  binary.BigEndian.Uint64(buf[4:12]),
		Flags:     flags,
	}
	if length > 0 {
		m.Payload = make([]byte, length)
		copy(m.Payload, buf[HeaderSize:HeaderSize+length])
	}
	return m, nil
}

// ReadMessage reads exactly one Message from r. It first reads the
// 15-byte header, then reads the declared payload bytes. Errors from r are
// returned wrapped with the wire-level context (truncated header vs body).
//
// It is the stream-oriented counterpart to Unmarshal for callers that
// exchange Messages over an io.Reader (e.g. smux streams).
func ReadMessage(r io.Reader) (*Message, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: short header: %w", ErrTruncated, err)
		}
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(hdr[13:15]))
	flags := Flags(hdr[12])
	if !validFlag(flags) {
		return nil, ErrUnknownFlags
	}
	m := &Message{
		SessionID: binary.BigEndian.Uint32(hdr[0:4]),
		Sequence:  binary.BigEndian.Uint64(hdr[4:12]),
		Flags:     flags,
	}
	if length > 0 {
		m.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, m.Payload); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, fmt.Errorf("%w: short payload: %w", ErrTruncated, err)
			}
			return nil, err
		}
	}
	return m, nil
}

// WriteMessage marshals m and writes it to w in one shot. The buffer is
// allocated per call; for the per-packet hot path use MarshalTo with a
// pooled buffer.
func WriteMessage(w io.Writer, m *Message) error {
	buf, err := Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}
