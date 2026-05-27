// Receive-side TFO option decoder for the SYN-TFO transport.
//
// T1.3 mirrors T1.2's send-side BuildSYNOptions with a receive-side
// DecodeTFO. The hot-path recv loop (internal/socket/recv_handle.go) runs
// every parsed packet through DecodeTFO; packets without a well-formed
// Kind=34 option are dropped silently (a counter is bumped — see
// counters.go), and packets with a well-formed option proceed to the
// upper-layer dispatch carrying the 8-byte cookie.
//
// Why a returned [CookieSize]byte array, not a slice? The hot-path caller
// runs once per inbound packet. Returning a slice would force the cookie
// bytes onto the heap (the slice header would escape with the call), which
// the DoD's "0 allocs/op" benchmark requirement forbids. Returning a value-
// type array keeps the cookie in a register/stack slot for the caller's
// (currently discarded — see T3.2) consumption. The array shape also matches
// what BuildSYNOptions on the send side accepts, so a future round-trip
// test can chain them without any conversion.
//
// Why is the option lookup positional-agnostic? The send-side option-order
// (MSS, SACK-perm, Timestamps, NOP, WindowScale, NOP, NOP, TFO) is one of
// many valid orderings; real-world middleboxes can re-order options as part
// of TFO-aware mangling, and any receiver in our position must accept the
// TFO option wherever it appears in the list. The decoder walks the slice
// once and returns on first valid match (see TestDecodeTFO_DuplicateTFO for
// the duplicate-option behaviour we lock in below).

package syntfo

import "github.com/gopacket/gopacket/layers"

// tfoStatus is the three-way result of classifyTFO: did the option list have
// a well-formed Kind=34 option, did it have one that was malformed, or none
// at all? The gate installed on the receive path uses this to decide which
// drop-counter to increment (no_tfo vs malformed_tfo); the public
// DecodeTFO collapses the two failure cases to a single ok=false because
// the hot-path caller only cares "should I forward this packet?".
type tfoStatus uint8

const (
	tfoStatusOK tfoStatus = iota
	tfoStatusMissing
	tfoStatusMalformed
)

// DecodeTFO scans the TCP options for the TFO option (Kind=34, Length=10),
// returning the 8-byte cookie and ok=true on success, or the zero cookie
// and ok=false otherwise.
//
// Semantics:
//   - ok=false when no Kind=34 option is present.
//   - ok=false when a Kind=34 option is present but malformed: wrong
//     OptionLength (must be exactly TFOOptionLength = 10), or OptionData
//     shorter than CookieSize = 8 bytes (truncated payload).
//   - ok=true when a well-formed Kind=34 option is present; cookie holds
//     the 8 bytes copied verbatim from OptionData[0:8].
//   - Duplicate TFO options: **first-wins**. We accept the first well-formed
//     Kind=34 and stop scanning; any subsequent occurrence is ignored. See
//     TestDecodeTFO_DuplicateTFO_FirstWins for the locked-in test. Rationale:
//     real Linux stacks reject duplicates outright, but pure first-wins lets
//     a TFO-aware middlebox that re-emits the option on rewrite still parse
//     cleanly. We pick the more-tolerant behaviour and document it here.
//   - Cookie validation (HMAC check) is NOT performed: T1.3 only enforces
//     option *shape*. The real validator lands in T3.2.
//
// Zero-allocation contract: this function does not allocate. It walks the
// caller's options slice in place, performs a fixed-size byte-by-byte copy
// into the returned array (a value copy, on the stack), and returns. No
// sub-slices, no `range` over OptionData, no string conversions. The
// BenchmarkDecodeTFO benchmark in recv_test.go enforces 0 allocs/op.
func DecodeTFO(options []layers.TCPOption) (cookie [CookieSize]byte, ok bool) {
	cookie, status := classifyTFO(options)
	return cookie, status == tfoStatusOK
}

// classifyTFO is the internal three-way variant of DecodeTFO. It performs
// exactly the same scan; the only difference is the richer return type that
// lets the receive-path gate distinguish "no TFO at all" from "malformed
// TFO present". DecodeTFO is the public hot-path surface; classifyTFO is
// the internal one the gate uses. Both share the same zero-allocation walk
// (see DecodeTFO's contract).
func classifyTFO(options []layers.TCPOption) (cookie [CookieSize]byte, status tfoStatus) {
	for i := 0; i < len(options); i++ {
		opt := &options[i]
		if opt.OptionType != TFOOptionKind {
			continue
		}
		// A Kind=34 option exists. From here on, "no match" downstream
		// becomes "malformed match" — we either accept it as the cookie or
		// reject the whole packet. Duplicate Kind=34 entries are first-wins:
		// the first well-formed one is returned; we never look further.
		if opt.OptionLength != TFOOptionLength {
			// Wrong length field — even if the data section happens to be 8
			// bytes, the on-wire length advertised by the option is wrong
			// and a correct receiver MUST reject (RFC 7413 §2). Treat as
			// malformed and short-circuit: we do not keep scanning for a
			// later "good" duplicate, because the first malformed one is
			// already enough evidence the sender is non-conforming.
			return [CookieSize]byte{}, tfoStatusMalformed
		}
		if len(opt.OptionData) < CookieSize {
			// Truncated payload: OptionLength claims 10 bytes (8 of cookie
			// + 2 of header), but gopacket only exposed fewer than 8 cookie
			// bytes. This can happen when a malformed packet has a length
			// that runs past the end of the option block. Reject.
			return [CookieSize]byte{}, tfoStatusMalformed
		}
		// Well-formed. Copy 8 bytes byte-by-byte into the return value. We
		// avoid `copy(cookie[:], opt.OptionData[:CookieSize])` not because
		// it would allocate — it wouldn't — but to keep the loop body's
		// escape analysis trivial; a manual unrolled assignment is what
		// most reliably stays stack-allocated across Go versions.
		cookie[0] = opt.OptionData[0]
		cookie[1] = opt.OptionData[1]
		cookie[2] = opt.OptionData[2]
		cookie[3] = opt.OptionData[3]
		cookie[4] = opt.OptionData[4]
		cookie[5] = opt.OptionData[5]
		cookie[6] = opt.OptionData[6]
		cookie[7] = opt.OptionData[7]
		return cookie, tfoStatusOK
	}
	return [CookieSize]byte{}, tfoStatusMissing
}
