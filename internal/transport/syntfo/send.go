// SYN-side TCP option layout for the SYN-TFO transport, plus the sequence
// number derivation T0.3 routed here from internal/socket/send_handle.go.
//
// This file is the "send logic" home referenced by T1.2's DoD. It deliberately
// stays a pure leaf: the only imports are gopacket's layers package (for the
// TCPOption type the builder hands back to the lower-level pcap writer) and
// stdlib. internal/socket/send_handle.go imports this package to assemble the
// final SYN; nothing here imports socket, so the dependency graph remains
// acyclic (socket -> syntfo only).

package syntfo

import (
	"encoding/binary"

	"github.com/gopacket/gopacket/layers"
)

// TFOOptionKind is the IANA-assigned TCP option kind for TCP Fast Open
// (RFC 7413 §2). gopacket's layers package does not define a named constant
// for it (it stops at Kind=30 / Multipath TCP), so we declare our own to
// avoid sprinkling magic numbers through the send path.
const TFOOptionKind layers.TCPOptionKind = 34

// TFOOptionLength is the on-wire length of the TFO option for ctun's profile:
// 1 byte Kind + 1 byte Length + 8 bytes cookie = 10 bytes. RFC 7413 permits
// 4 / 6 / 10 / 12 / 16 / 18 byte cookies; ctun fixes 8 bytes (matching the
// HMAC truncation point T3.2 will use).
const TFOOptionLength uint8 = 2 + CookieSize

// MSSValue is the Maximum Segment Size advertised on every ctun SYN. 0x05b4
// (= 1460) is the standard Ethernet-MSS default and matches what paqet
// originally emitted; keeping it pinned makes the send path independent of
// per-interface MTU discovery, which is fine because KCP runs its own
// fragmentation logic above.
var MSSValue = []byte{0x05, 0xb4}

// WindowScaleShift is the value advertised by the WindowScale option (Kind=3).
// 8 means "scale receive window by 2^8 = 256"; this matches the value the
// pre-T1.2 send path emitted and what most modern Linux/macOS stacks
// advertise on initial SYNs, so middleboxes that scrutinise WS shouldn't
// flag the ctun SYN as anomalous.
const WindowScaleShift = 8

// SYNHeaderSize is the size in bytes of the serialized TCP header (including
// options) produced by BuildSYNOptions. It is exported so callers can assert
// alignment without re-deriving it, and so tests can sanity-check that
// changes to the option list preserve the 4-byte alignment requirement.
//
//	TCP fixed header  : 20 bytes
//	MSS               :  4 bytes
//	SACK-permitted    :  2 bytes
//	Timestamps        : 10 bytes
//	NOP               :  1 byte
//	WindowScale       :  3 bytes
//	NOP               :  1 byte
//	NOP               :  1 byte
//	TFO (Kind=34)     : 10 bytes
//	------------------------------
//	Total             : 52 bytes  (header 20 + options 32)
//
// 52 is a multiple of 4 — the TCP DataOffset field expresses header length
// in 32-bit words, so any non-multiple-of-4 total is illegal. The two NOPs
// at positions 6 and 7 in the option list are the alignment pad: removing
// them would yield a 30-byte option block (50-byte header), which gopacket
// would silently zero-pad to 32 — burning the chance for any observer to
// see the alignment intent at parse time.
const SYNHeaderSize = 20 + 32

// BuildSYNOptions returns the TCP option list a SYN-TFO SYN should carry. It
// is a pure function: every call allocates a fresh option slice and the
// 8-byte Timestamps payload, so the caller is free to mutate the returned
// slices without disturbing other goroutines.
//
// Arguments:
//   - cookie: the 8-byte TFO cookie produced by a CookieProvider. The bytes
//     are copied verbatim into the option payload.
//   - tsVal:  the Timestamps TSval field (4 bytes, big-endian). The send
//     path derives this from a monotonic counter; the option-builder takes
//     it as a parameter so the test can pin a deterministic value.
//
// TSecr is left as zero — RFC 7323 requires TSecr=0 on the initial SYN
// because no peer timestamp has been observed yet, and this matches what
// paqet emitted before T1.2.
//
// The option order — MSS, SACK-perm, Timestamps, NOP, WindowScale, NOP, NOP,
// TFO — is chosen so the short 1-byte NOPs land adjacent to the 3-byte
// WindowScale (placing it on a 4-byte boundary by chance is not the goal —
// alignment of the *whole* option block to 4 bytes is what TCP requires) and
// the longer TFO option lands last, making it easy to eyeball in a packet
// capture. The two NOPs at indices 5 and 6 are the alignment pad described
// above SYNHeaderSize.
func BuildSYNOptions(cookie [CookieSize]byte, tsVal uint32) []layers.TCPOption {
	tsData := make([]byte, 8)
	binary.BigEndian.PutUint32(tsData[0:4], tsVal)
	// TSecr is zero on initial SYNs (RFC 7323 §3.2); leave tsData[4:8] = 0.

	cookieData := make([]byte, CookieSize)
	copy(cookieData, cookie[:])

	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: MSSValue},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: tsData},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{WindowScaleShift}},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: TFOOptionKind, OptionLength: TFOOptionLength, OptionData: cookieData},
	}
}

// SYNSeq derives the TCP sequence number for an outgoing SYN. T0.3 found that
// the pre-T1.2 derivation (`tcp.Seq = 1 + (counter & 0x7)`) only produced 8
// distinct sequence numbers, which any receiver doing SYN-flood mitigation
// or duplicate-detection would treat as retransmissions and silently drop —
// the single biggest behavioural risk for SYN-only mode.
//
// We are NOT a normal kernel TCP stack here: ctun forges the entire SYN,
// including Seq, and the upper-layer reliability (KCP) does not rely on TCP
// sequence semantics — every KCP datagram becomes a fresh outgoing SYN with
// a fresh sequence number. The only constraint on Seq is that intermediate
// stacks should not coalesce or drop our packets, which requires the value
// to vary enough that the 4-tuple+seq key is unique across a short window.
//
// The non-SYN branch in the pre-T1.2 send path used `time + (counter << 7)`
// — adapted here to produce a full 32-bit value. Per-flow uniqueness (a
// per-destination counter) is a refinement for a later task; a single shared
// counter is sufficient for T1.2's DoD ("full 32-bit entropy").
func SYNSeq(timeBase, counter uint32) uint32 {
	// (counter << 7) shifts the counter into the high bits so consecutive
	// SYNs differ by 128 — well outside the 1-bit aliasing the old derivation
	// produced. Adding timeBase (a millisecond-since-process-start anchor)
	// randomises the absolute value across process restarts.
	return timeBase + (counter << 7)
}
