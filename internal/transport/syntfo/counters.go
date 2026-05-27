// Drop-path counters for the SYN-TFO transport.
//
// T1.3 introduces a hot-path filter that rejects packets without a valid TFO
// option (Kind=34, length=10). Per the DoD, the drop path must NOT log
// per-packet — the only diagnostic surface is an atomic counter. This file
// is the home of those counters.
//
// Scope intentionally narrow: just the two counters T1.3 needs, plus the
// observation accessors tests rely on. The cross-cutting Metrics task (see
// docs/implementation-doc.md → "Cross-Cutting Concerns" → "Metrics") will
// later wire these (and the other dropped_* counters listed there) into a
// real metrics framework (expvar / prometheus). The structure here is chosen
// so that future wiring is a pure addition: callers already read by named
// accessor, not by struct-field address, so swapping the storage type is
// internal.
//
// TODO(metrics): once the Cross-Cutting Concerns "Metrics" task picks a
// framework, replace the bare atomic.Uint64 fields with framework-native
// counters (or register expvar/prometheus views on top of them). Keep the
// Load() accessor signatures stable so tests don't need to chase the
// rename. See docs/implementation-doc.md → "Cross-Cutting Concerns" →
// "Metrics" for the full counter list (dropped_no_tfo, dropped_bad_cookie,
// dropped_handshake_bad_hmac, dropped_replay, dropped_aead_open_fail).

package syntfo

import "sync/atomic"

// Counters holds the SYN-TFO transport's drop-path counters. One Counters
// value is owned by each Transport instance (returned via Transport.Counters);
// the gate closure installed on the receive path increments these in-place.
//
// All fields are safe for concurrent use without external locking — that is
// the entire point of atomic.Uint64 as the storage type. Tests poll the
// Load() accessors after constructing drop scenarios; production code does
// not read these directly (the future metrics scraper will).
type Counters struct {
	// droppedNoTFO is incremented when the recv path observes a packet whose
	// TCP options do not contain a TFO option (Kind=34) at all. Maps to the
	// design-doc / Cross-Cutting Concerns counter named "dropped_no_tfo".
	droppedNoTFO atomic.Uint64

	// droppedMalformedTFO is incremented when a TFO option (Kind=34) is
	// present but malformed — wrong OptionLength, truncated OptionData, or
	// otherwise unparsable. Distinguishing this from droppedNoTFO is the
	// recommended split called out in T1.3's brief: "TFO missing" vs "TFO
	// malformed" tell very different operational stories (a non-ctun
	// scanner sweeping the port, versus a partial implementation or a
	// corrupted middlebox).
	droppedMalformedTFO atomic.Uint64

	// droppedBadCookieValidator is incremented when a packet's TFO option
	// is well-formed (shape OK) but the cookie itself is rejected by the
	// session-table validator. T3.3 wires this counter: gateOptions calls
	// mgr.ValidateCookie on every non-HELLO inbound frame, and a mismatch
	// (unknown SessionID or wrong HMAC) bumps this counter and drops the
	// packet. The split between this counter and session.Counters.BadCookie
	// is the T3.3 brief's "DroppedBadCookieValidator distinguishes from
	// T1.3's DroppedNoTFO / DroppedMalformedTFO" guidance: the manager's
	// own counter still ticks (it is the source of truth for validator
	// outcomes), and this one ticks alongside so a syntfo-level metrics
	// scraper sees the drop in the syntfo counter inventory without
	// having to reach into the session package.
	droppedBadCookieValidator atomic.Uint64

	// droppedNonHelloZeroCookie is incremented when the gate observes a
	// non-HELLO frame stamped with the all-zero cookie sentinel. The
	// HELLO sentinel is reserved per design §8.4 for first-contact
	// handshake frames only; any other Flags value carrying the zero
	// cookie is either a buggy client or a probe and is dropped without
	// a session lookup (since there is no session yet, ValidateCookie
	// would also reject it, but the rejection path through this counter
	// is faster and more diagnostic than a no-op session lookup).
	droppedNonHelloZeroCookie atomic.Uint64

	// droppedMalformedFrame is incremented when the inner protocol
	// payload fails protocol.Unmarshal — truncated, length-mismatched, or
	// unknown Flags. A malformed inner frame is a sign of a corrupted
	// packet (or a probe carrying random bytes after a valid TFO option),
	// not a security event per se; it lives next to the cookie counters
	// because the gate is the first place we can detect it on the
	// receive path.
	droppedMalformedFrame atomic.Uint64

	// droppedAEADOpenFail is incremented by secureConn.ReadFrom when an
	// inbound payload's AEAD Open returns ErrAuthFailed (or any other
	// crypto-level rejection). The single most likely cause is a tampered
	// packet on the wire; secondary causes include a key-mismatch between
	// client and server (PSK drift) and a packet whose cookie validated
	// but whose AEAD ciphertext does not (a buggy attacker that managed to
	// forge a valid cookie but not the AEAD tag). Maps to the design-doc /
	// Cross-Cutting Concerns counter named "dropped_aead_open_fail".
	droppedAEADOpenFail atomic.Uint64

	// droppedUnknownSession is incremented by secureConn.ReadFrom when the
	// inner protocol frame's SessionID does not map to any registered
	// session. After a successful AEAD Open the SessionID is trusted (the
	// AEAD tag covers the header), so an unknown session here means
	// (a) the session was garbage-collected between Open and lookup, or
	// (b) the sender used a SessionID that was never minted in our table.
	// Either way the right action is silent drop + counter.
	droppedUnknownSession atomic.Uint64

	// droppedReplay is incremented by secureConn.ReadFrom when the inner
	// frame's Sequence fails the session's ReplayFilter.Check — duplicate
	// or out-of-window. Maps to the design-doc / Cross-Cutting Concerns
	// counter named "dropped_replay".
	droppedReplay atomic.Uint64
}

// NewCounters returns a Counters initialised to zero. Tests construct one
// directly; production code reaches the instance owned by a Transport via
// Transport.Counters().
func NewCounters() *Counters {
	return &Counters{}
}

// DroppedNoTFO returns the current value of the dropped_no_tfo counter.
// It is safe for concurrent use.
func (c *Counters) DroppedNoTFO() uint64 {
	return c.droppedNoTFO.Load()
}

// DroppedMalformedTFO returns the current value of the dropped_malformed_tfo
// counter. It is safe for concurrent use.
func (c *Counters) DroppedMalformedTFO() uint64 {
	return c.droppedMalformedTFO.Load()
}

// DroppedBadCookieValidator returns the current value of the
// dropped_bad_cookie_validator counter. T3.3 ticks this whenever a packet
// arrives with a well-formed TFO option whose cookie does not match any
// registered session.
func (c *Counters) DroppedBadCookieValidator() uint64 {
	return c.droppedBadCookieValidator.Load()
}

// DroppedNonHelloZeroCookie returns the current value of the
// dropped_non_hello_zero_cookie counter. T3.3 ticks this whenever a packet
// stamps the all-zero (HELLO) cookie sentinel but the inner frame's Flags
// is not FlagHello.
func (c *Counters) DroppedNonHelloZeroCookie() uint64 {
	return c.droppedNonHelloZeroCookie.Load()
}

// DroppedMalformedFrame returns the current value of the
// dropped_malformed_frame counter. T3.3 ticks this whenever the inner
// protocol payload fails Unmarshal.
func (c *Counters) DroppedMalformedFrame() uint64 {
	return c.droppedMalformedFrame.Load()
}

// incNoTFO increments the dropped_no_tfo counter. Package-private because
// only the receive-path gate has the authority to decide a packet should be
// dropped for missing TFO.
func (c *Counters) incNoTFO() {
	c.droppedNoTFO.Add(1)
}

// incMalformedTFO increments the dropped_malformed_tfo counter. Package-
// private for the same reason as incNoTFO.
func (c *Counters) incMalformedTFO() {
	c.droppedMalformedTFO.Add(1)
}

// incBadCookieValidator increments the dropped_bad_cookie_validator
// counter. Package-private.
func (c *Counters) incBadCookieValidator() {
	c.droppedBadCookieValidator.Add(1)
}

// incNonHelloZeroCookie increments the dropped_non_hello_zero_cookie
// counter. Package-private.
func (c *Counters) incNonHelloZeroCookie() {
	c.droppedNonHelloZeroCookie.Add(1)
}

// incMalformedFrame increments the dropped_malformed_frame counter.
// Package-private.
func (c *Counters) incMalformedFrame() {
	c.droppedMalformedFrame.Add(1)
}

// DroppedAEADOpenFail returns the current value of the
// dropped_aead_open_fail counter. T3.4 ticks this when secureConn.ReadFrom
// observes an AEAD Open failure (tag mismatch / wrong key / tampered
// ciphertext).
func (c *Counters) DroppedAEADOpenFail() uint64 {
	return c.droppedAEADOpenFail.Load()
}

// DroppedUnknownSession returns the current value of the
// dropped_unknown_session counter. T3.4 ticks this when secureConn.ReadFrom
// successfully opens a frame but its SessionID is not registered.
func (c *Counters) DroppedUnknownSession() uint64 {
	return c.droppedUnknownSession.Load()
}

// DroppedReplay returns the current value of the dropped_replay counter.
// T3.4 ticks this when an opened frame's Sequence fails the per-session
// anti-replay window check.
func (c *Counters) DroppedReplay() uint64 {
	return c.droppedReplay.Load()
}

// incAEADOpenFail increments the dropped_aead_open_fail counter.
// Package-private.
func (c *Counters) incAEADOpenFail() {
	c.droppedAEADOpenFail.Add(1)
}

// incUnknownSession increments the dropped_unknown_session counter.
// Package-private.
func (c *Counters) incUnknownSession() {
	c.droppedUnknownSession.Add(1)
}

// incReplay increments the dropped_replay counter. Package-private.
func (c *Counters) incReplay() {
	c.droppedReplay.Add(1)
}
