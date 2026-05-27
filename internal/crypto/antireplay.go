package crypto

// This file implements ctun's anti-replay filter per design-doc §8.3:
// a 64-entry sliding window over recently observed sequence numbers, used to
// reject duplicate or too-old packets after AEAD decryption succeeds.
//
// T2.3 introduces this primitive but does NOT wire it onto the receive path.
// Phase 3 (T3.4) integrates it with the post-decrypt pipeline; for T2.3 the
// only deliverable is the data structure plus its concurrent-safety contract.

import "sync"

// windowSize is the width of the sliding replay window, in bits. It is also
// the inclusive upper bound on how far below the current top a sequence
// number may be and still be considered "in window". A seq exactly
// windowSize below top is out (one slot too old) — see Check for the
// boundary handling.
const windowSize = 64

// ReplayFilter detects duplicate or too-old sequence numbers within a
// sliding 64-entry window of the highest sequence seen so far. It is safe
// for concurrent use by many goroutines.
//
// Concurrency strategy: a single sync.Mutex guards both fields. The whole
// Check operation (compare, shift, set, return) executes under the lock,
// which makes concurrent Check calls linearizable in the order they acquire
// the mutex — any later observer agrees on which calls accepted and which
// rejected. A lock-free CAS variant is possible but unnecessary at the
// packet rates ctun expects (the lock is held for a handful of unsigned
// arithmetic ops and one branch); we prefer the simpler implementation.
//
// Window layout: `bitmap` is a 64-bit integer where bit i represents the
// "have I accepted seq (top - i)" flag. Bit 0 corresponds to `top` itself
// (always set once the filter has accepted anything); bit 63 corresponds
// to `top - 63`, the oldest slot still in window.
//
// Sequence-0 semantics: a freshly constructed filter has top=0 and
// bitmap=0. The first Check(0) computes top - seq = 0, reads bit 0 (clear),
// sets it, returns true. Subsequent Check(0) finds bit 0 set and returns
// false. This treats sequence 0 as a valid first sequence (option (a) from
// the T2.3 brief). Callers that prefer to reserve 0 for a sentinel can
// simply start their counters at 1.
type ReplayFilter struct {
	mu     sync.Mutex
	top    uint64 // highest sequence number accepted so far (0 until first accept)
	bitmap uint64 // bit i set <=> seq (top - i) has been accepted
}

// NewReplayFilter returns a fresh filter that has not yet accepted any
// sequence number. The zero value of ReplayFilter is also usable (top=0,
// bitmap=0, mu zero-valued); the constructor exists for callers that
// prefer pointer construction without relying on the zero-value contract.
func NewReplayFilter() *ReplayFilter {
	return &ReplayFilter{}
}

// Check returns true if seq has not been seen and is within the window
// (i.e. seq is strictly greater than the current top, or no more than 63
// below the current top and not yet recorded). Returns false for
// duplicates or for sequence numbers that are too old (more than 63 below
// the current window top).
//
// Calls from many goroutines are linearizable: each Check either accepts
// (returning true and updating the filter) or rejects in a total order
// that any later observer agrees with.
//
// Algorithm (matches design §8.3):
//
//   - seq > top: advance the window. Shift bitmap left by (seq - top) bits,
//     set bit 0 (the new top), update top. A shift >= 64 zeros the bitmap
//     cleanly (we special-case it because Go's `x << 64` on a uint64 is
//     undefined per the spec — and in practice silently leaves the bits
//     unchanged on common amd64/arm64 hardware).
//
//   - seq <= top: compute diff = top - seq. If diff >= 64 the slot has
//     fallen out of window, reject. Otherwise inspect bit `diff`; if set,
//     this is a duplicate and we reject; if clear, set it and accept.
//     The seq == top case (diff = 0) folds naturally into this branch:
//     bit 0 is always set once we have a top, so a second observation of
//     the current top is rejected as a duplicate.
//
// Note on the "just-too-old" boundary: a seq exactly 64 below top yields
// diff = 64, which is rejected because it cannot be represented in the
// 64-bit bitmap (only slots 0..63 are tracked).
func (f *ReplayFilter) Check(seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// First-ever accept: the zero value of the filter has top=0 and
	// bitmap=0. A Check(0) on that filter falls into the seq <= top branch
	// below (diff = 0, bit 0 clear -> set, accept) which is exactly the
	// semantics we want for "fresh filter accepts seq 0 once." Any seq > 0
	// on a fresh filter takes the advance branch and also works correctly
	// because the empty bitmap has no bits to lose during the shift.
	if seq > f.top {
		shift := seq - f.top
		if shift >= windowSize {
			// Far-future jump: every previously tracked slot has fallen
			// out of window. Zero the bitmap rather than relying on a
			// potentially-undefined large shift.
			f.bitmap = 0
		} else {
			f.bitmap <<= shift
		}
		f.top = seq
		f.bitmap |= 1 // record the new top
		return true
	}

	// seq <= f.top: either a duplicate, an in-window out-of-order accept,
	// or a too-old reject.
	diff := f.top - seq
	if diff >= windowSize {
		return false // too old: out of window
	}
	mask := uint64(1) << diff
	if f.bitmap&mask != 0 {
		return false // duplicate
	}
	f.bitmap |= mask
	return true
}
