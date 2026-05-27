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
