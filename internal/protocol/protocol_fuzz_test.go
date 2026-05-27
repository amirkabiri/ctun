package protocol

import (
	"bytes"
	"testing"
)

// FuzzProtocolUnmarshal exercises Unmarshal with arbitrary inputs. The
// invariant under fuzz is that Unmarshal never panics for any input shape.
func FuzzProtocolUnmarshal(f *testing.F) {
	// Seed: truncated header.
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize-1))
	// Seed: header only, length=0 for every valid flag.
	for _, fl := range []Flags{FlagHello, FlagHelloAck, FlagData, FlagKeepalive, FlagClose} {
		seed, err := Marshal(&Message{Flags: fl})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(seed)
	}
	// Seed: a valid Data message with a small payload.
	seed, err := Marshal(&Message{
		SessionID: 0x11223344,
		Sequence:  0x55667788AABBCCDD,
		Flags:     FlagData,
		Payload:   []byte("ping"),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	// Seed: a max-size payload.
	f.Add(append(seed, bytes.Repeat([]byte{0xFF}, 32)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. The returned error/Message is intentionally unused —
		// the assertion is solely about robustness.
		_, _ = Unmarshal(data)
	})
}
