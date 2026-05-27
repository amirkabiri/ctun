package crypto

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
)

// TestReplay_InOrder feeds the filter a monotonically increasing sequence
// 1..1000 and asserts every Check accepts. This is the cheapest possible
// confidence test that "happy path" forward progress works for the lifetime
// of a normal session, well beyond the 64-slot window.
func TestReplay_InOrder(t *testing.T) {
	f := NewReplayFilter()
	for i := uint64(1); i <= 1000; i++ {
		if !f.Check(i) {
			t.Fatalf("Check(%d) rejected, want accept", i)
		}
	}
}

// TestReplay_OutOfOrderWithinWindow exercises the reorder-within-window
// branch: a single advance (Check(10)) opens the window, then three
// in-window backfills land in arbitrary order, then a new advance lifts
// the top further, and finally a duplicate of a previously accepted
// in-window value is rejected.
func TestReplay_OutOfOrderWithinWindow(t *testing.T) {
	f := NewReplayFilter()
	cases := []struct {
		seq  uint64
		want bool
		why  string
	}{
		{10, true, "first accept advances top to 10"},
		{8, true, "in-window backfill"},
		{5, true, "in-window backfill, further back"},
		{11, true, "advance top to 11"},
		{8, false, "duplicate of an earlier in-window accept"},
	}
	for _, c := range cases {
		if got := f.Check(c.seq); got != c.want {
			t.Fatalf("Check(%d) = %v, want %v (%s)", c.seq, got, c.want, c.why)
		}
	}
}

// TestReplay_ExactDuplicate pins the most common attacker pattern:
// the same packet observed twice. The first is accepted, the second
// (at the current top) is rejected because bit 0 is already set.
func TestReplay_ExactDuplicate(t *testing.T) {
	f := NewReplayFilter()
	if !f.Check(42) {
		t.Fatalf("first Check(42) rejected, want accept")
	}
	if f.Check(42) {
		t.Fatalf("second Check(42) accepted, want reject (duplicate)")
	}
}

// TestReplay_JustTooOld pins the off-by-one boundary at the bottom edge of
// the window. With top=64 the in-window range covers seq 1..64 (slots 0..63);
// seq=0 would require slot 64, which is one beyond the bitmap, so it must
// reject. This is the test that catches a mis-typed >= vs > in the
// out-of-window branch.
func TestReplay_JustTooOld(t *testing.T) {
	f := NewReplayFilter()
	if !f.Check(64) {
		t.Fatalf("Check(64) rejected, want accept (sets top=64)")
	}
	if f.Check(0) {
		t.Fatalf("Check(0) accepted with top=64, want reject (diff=64 is out of window)")
	}
	// Sanity: the slot exactly at the window edge (top-63 = 1) must still
	// accept, to make sure we didn't over-tighten the boundary.
	if !f.Check(1) {
		t.Fatalf("Check(1) rejected with top=64, want accept (diff=63 is in window)")
	}
}

// TestReplay_FarFutureJump exercises the "shift >= 64 zeros the bitmap"
// branch. After accepting seq=1, a jump to seq=1<<32 must cleanly evict
// every previously tracked slot; a subsequent attempt to replay seq=2
// must reject as too old, proving the old bits did not survive the shift.
func TestReplay_FarFutureJump(t *testing.T) {
	f := NewReplayFilter()
	if !f.Check(1) {
		t.Fatalf("Check(1) rejected, want accept")
	}
	const jump = uint64(1) << 32
	if !f.Check(jump) {
		t.Fatalf("Check(%d) rejected, want accept", jump)
	}
	if f.Check(2) {
		t.Fatalf("Check(2) accepted after jump to %d, want reject (too old)", jump)
	}
}

// TestReplay_ZeroSeq documents the sequence-0 semantics: option (a) from
// the design brief. A fresh filter has top=0 and an empty bitmap, so
// Check(0) reads bit 0 (clear), sets it, accepts. The follow-up Check(0)
// finds bit 0 set and rejects as a duplicate. This is the only behaviour
// that makes "I have never seen anything" and "I have seen seq 0"
// distinguishable without a sentinel field.
func TestReplay_ZeroSeq(t *testing.T) {
	f := NewReplayFilter()
	if !f.Check(0) {
		t.Fatalf("Check(0) on fresh filter rejected, want accept")
	}
	if f.Check(0) {
		t.Fatalf("second Check(0) accepted, want reject (duplicate)")
	}
}

// TestReplay_NoPanicOnExtremeJumps stresses the unsigned-arithmetic edges:
// a leap from seq=0 to seq=^uint64(0) drives shift to the maximum possible
// value, after which a flurry of random seqs around the top must not
// panic. The test deliberately does not assert outcomes — it only asserts
// that the implementation survives without index-out-of-range, undefined
// shift behaviour, or arithmetic overflow.
func TestReplay_NoPanicOnExtremeJumps(t *testing.T) {
	f := NewReplayFilter()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on extreme-jump sequence: %v", r)
		}
	}()

	_ = f.Check(0)
	_ = f.Check(^uint64(0))
	// A handful of random follow-up calls clustered around the new top.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 100; i++ {
		// Random uint64 in the upper half so calls land at-or-near top.
		seq := ^uint64(0) - uint64(rng.Intn(128))
		_ = f.Check(seq)
	}
	// And a handful of small values that are now far too old.
	for i := 0; i < 100; i++ {
		_ = f.Check(uint64(rng.Intn(1024)))
	}
}

// TestReplay_ConcurrentStress launches many goroutines hammering Check
// with random sequences from a finite domain. The point is twofold:
//
//   - The race detector must see no data races (we run with -race).
//   - The total number of accepts must not exceed the number of distinct
//     sequence values, regardless of scheduling: every distinct seq can
//     legitimately accept at most once, so accepts > distinct would prove
//     a logic bug (e.g. a missing lock holdover allowing two writers to
//     both observe an empty slot and both set it).
//
// We deliberately do NOT assert an exact accept count: race-driven
// ordering can stall some goroutines until their seq has fallen out of
// window, which legitimately reduces the count below the theoretical
// maximum. Either bound on the count would be fragile.
func TestReplay_ConcurrentStress(t *testing.T) {
	const (
		goroutines = 1000
		opsEach    = 1000
		seqRange   = 4096 // distinct sequence values in play
	)

	f := NewReplayFilter()
	var accepts atomic.Uint64

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < opsEach; i++ {
				seq := uint64(rng.Intn(seqRange))
				if f.Check(seq) {
					accepts.Add(1)
				}
			}
		}(int64(g + 1))
	}
	wg.Wait()

	if got := accepts.Load(); got > seqRange {
		t.Fatalf("accepts = %d, want <= %d (distinct sequence values)", got, seqRange)
	}
}
