// Tests for the HELLO / HELLO_ACK handshake (T3.3, design §8.4).
//
// Scope:
//   - Build/Parse round-trips for both message types.
//   - HMAC happy paths and failure modes (wrong PSK, stale timestamp).
//   - RunClientHandshake retry schedule and ctx cancellation, exercised
//     against a recording Sender stub (no real transport).
//   - RunServerHandshake accept/reject paths, counter increments, and the
//     "zero outbound packets on reject" invariant.

package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// keyA / keyB are two distinct authKeys used by the "wrong PSK" tests.
// keyA matches manager_test.go's testAuthKey pattern (incrementing bytes);
// keyB is its bit-flipped twin so a copy/paste bug that uses one in place
// of the other surfaces immediately.
var (
	keyA = func() [32]byte {
		var k [32]byte
		for i := range k {
			k[i] = byte(i + 1)
		}
		return k
	}()
	keyB = func() [32]byte {
		var k [32]byte
		for i := range k {
			k[i] = byte(0xFF - (i + 1))
		}
		return k
	}()
)

// fixedNow is the wall-clock the build/validate happy-path tests pin so the
// HMAC bytes are reproducible across runs. Picked deliberately far from
// epoch and from any DST transition to avoid surprising timestamp math.
var fixedNow = time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)

func TestHandshake_HappyPath_BuildAndValidate(t *testing.T) {
	// Build HELLO with keyA, validate with keyA → accept.
	h := BuildHello(keyA, fixedNow)
	if err := ValidateHello(keyA, h, fixedNow, ClockSkewTolerance); err != nil {
		t.Fatalf("ValidateHello on freshly-built HELLO: %v", err)
	}

	// Marshal → Parse round trip must be lossless.
	buf := h.Marshal()
	if len(buf) != HelloPayloadSize {
		t.Fatalf("Marshal returned %d bytes, want %d", len(buf), HelloPayloadSize)
	}
	parsed, err := ParseHello(buf)
	if err != nil {
		t.Fatalf("ParseHello round-trip: %v", err)
	}
	if parsed != h {
		t.Fatalf("ParseHello round-trip mismatch:\n got  %+v\n want %+v", parsed, h)
	}

	// Build HELLO_ACK with same key + a sessionID, validate → accept.
	id := SessionID{0x01, 0x02, 0x03, 0x04}
	ack := BuildHelloAck(keyA, id)
	if err := ValidateHelloAck(keyA, ack); err != nil {
		t.Fatalf("ValidateHelloAck on freshly-built ACK: %v", err)
	}
	ackBuf := ack.Marshal()
	if len(ackBuf) != HelloAckPayloadSize {
		t.Fatalf("HelloAck Marshal returned %d bytes, want %d", len(ackBuf), HelloAckPayloadSize)
	}
	parsedAck, err := ParseHelloAck(ackBuf)
	if err != nil {
		t.Fatalf("ParseHelloAck round-trip: %v", err)
	}
	if parsedAck != ack {
		t.Fatalf("ParseHelloAck round-trip mismatch:\n got  %+v\n want %+v", parsedAck, ack)
	}
}

func TestHandshake_WrongPSK_Rejects(t *testing.T) {
	// Build HELLO with keyA, validate with keyB → reject (ErrHelloBadHMAC),
	// no panic.
	h := BuildHello(keyA, fixedNow)
	err := ValidateHello(keyB, h, fixedNow, ClockSkewTolerance)
	if !errors.Is(err, ErrHelloBadHMAC) {
		t.Fatalf("ValidateHello with wrong PSK: got %v, want ErrHelloBadHMAC", err)
	}

	// Same on the ACK side: built under keyA, validated under keyB.
	id := SessionID{0xAA, 0xBB, 0xCC, 0xDD}
	ack := BuildHelloAck(keyA, id)
	if err := ValidateHelloAck(keyB, ack); !errors.Is(err, ErrHelloAckBadHMAC) {
		t.Fatalf("ValidateHelloAck with wrong PSK: got %v, want ErrHelloAckBadHMAC", err)
	}
}

func TestHandshake_StaleTimestamp_Rejects(t *testing.T) {
	// Build HELLO with now-70s, validate at now with skew=60s → reject.
	skew := 60 * time.Second
	pastNow := fixedNow.Add(-70 * time.Second)
	h := BuildHello(keyA, pastNow)
	err := ValidateHello(keyA, h, fixedNow, skew)
	if !errors.Is(err, ErrHelloStaleTimestamp) {
		t.Fatalf("ValidateHello with stale timestamp: got %v, want ErrHelloStaleTimestamp", err)
	}

	// Boundary check: exactly at the skew is accepted (delta == skew → OK
	// because the rule is "more than ±skew rejects").
	atSkew := BuildHello(keyA, fixedNow.Add(-skew))
	if err := ValidateHello(keyA, atSkew, fixedNow, skew); err != nil {
		t.Fatalf("ValidateHello at exact skew boundary: got %v, want accept", err)
	}
}

func TestHandshake_FutureTimestamp_Rejects(t *testing.T) {
	// Build HELLO with now+70s, validate at now with skew=60s → reject.
	skew := 60 * time.Second
	futureNow := fixedNow.Add(70 * time.Second)
	h := BuildHello(keyA, futureNow)
	err := ValidateHello(keyA, h, fixedNow, skew)
	if !errors.Is(err, ErrHelloStaleTimestamp) {
		t.Fatalf("ValidateHello with future timestamp: got %v, want ErrHelloStaleTimestamp", err)
	}
}

func TestParseHello_BadLength(t *testing.T) {
	// Defensive: malformed inputs must return ErrHelloBadLength rather
	// than panicking. Covers both short and long inputs.
	for _, n := range []int{0, 1, HelloPayloadSize - 1, HelloPayloadSize + 1, 1024} {
		buf := make([]byte, n)
		if _, err := ParseHello(buf); !errors.Is(err, ErrHelloBadLength) {
			t.Errorf("ParseHello(len=%d): got %v, want ErrHelloBadLength", n, err)
		}
	}
}

func TestParseHello_UnsupportedVersion(t *testing.T) {
	// Build a valid-shaped payload, flip the version byte to a non-1 value,
	// confirm Parse rejects with the typed error (and does NOT mistakenly
	// return ErrHelloBadLength).
	h := BuildHello(keyA, fixedNow)
	buf := h.Marshal()
	buf[0] = 2 // bogus version
	_, err := ParseHello(buf)
	if !errors.Is(err, ErrHelloUnsupportedVersion) {
		t.Fatalf("ParseHello with version=2: got %v, want ErrHelloUnsupportedVersion", err)
	}
}

func TestParseHelloAck_BadLength(t *testing.T) {
	for _, n := range []int{0, 1, HelloAckPayloadSize - 1, HelloAckPayloadSize + 1, 1024} {
		buf := make([]byte, n)
		if _, err := ParseHelloAck(buf); !errors.Is(err, ErrHelloAckBadLength) {
			t.Errorf("ParseHelloAck(len=%d): got %v, want ErrHelloAckBadLength", n, err)
		}
	}
}

// --- Client-side retry tests -------------------------------------------------
//
// These tests drive RunClientHandshake against a recording Sender stub. The
// stub records every SendHello call (and its time-since-test-start) so the
// retry schedule can be asserted. nowFunc and sleepFunc are swapped to fake
// implementations so the test does not sleep wall-clock seconds.

// fakeClock is a monotonic time source: NowFn returns its internal "now" and
// SleepFn advances "now" by the requested delta (subject to ctx). This is
// the substitution used by retry-schedule tests so they exit in milliseconds
// instead of the real 7.75 s the production schedule would take.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Sleep advances the virtual clock by d immediately. ctx.Done short-
// circuits with ctx.Err() so cancellation tests can verify "promptly".
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

// withFakeClock installs c as the package-level time source for the
// duration of the test. Resets on cleanup so subsequent tests see the real
// clock again.
func withFakeClock(t *testing.T, c *fakeClock) {
	t.Helper()
	oldNow, oldSleep := nowFunc, sleepFunc
	nowFunc = c.Now
	sleepFunc = c.Sleep
	t.Cleanup(func() {
		nowFunc = oldNow
		sleepFunc = oldSleep
	})
}

// recordingSender captures every SendHello call with the virtual-time
// elapsed since constructor. ackFn (if non-nil) is invoked per attempt to
// decide what RecvHelloAck should return:
//   - ackFn returns (HelloAck, nil) → RecvHelloAck delivers it.
//   - ackFn returns (zero, non-nil) → RecvHelloAck returns the error.
//
// If ackFn is nil, RecvHelloAck behaves as if the server never replied: it
// blocks until ctx is cancelled and then returns ctx.Err(). This is the
// substitution used by the retry-schedule test which expects all 5
// attempts to fall through to the timeout path.
type recordingSender struct {
	clock *fakeClock
	start time.Time

	ackFn func(attempt int) (HelloAck, error)

	mu       sync.Mutex
	sendTs   []time.Duration // virtual-clock offset of each SendHello call
	attempts int
}

func (r *recordingSender) SendHello(_ context.Context, _ Hello) error {
	r.mu.Lock()
	r.sendTs = append(r.sendTs, r.clock.Now().Sub(r.start))
	r.attempts++
	r.mu.Unlock()
	return nil
}

func (r *recordingSender) RecvHelloAck(ctx context.Context) (HelloAck, error) {
	r.mu.Lock()
	attempt := r.attempts // 1-indexed: this is the attempt we just sent
	fn := r.ackFn
	r.mu.Unlock()

	if fn != nil {
		return fn(attempt)
	}
	// No ack callback: simulate "server never replied" by blocking until
	// ctx fires. With the fake clock, RunClientHandshake's between-attempt
	// sleep will advance virtual time and the outer for-loop will issue
	// the next SendHello — but RecvHelloAck has to return SOMETHING for
	// the loop to proceed. We return a non-ctx error to signal "this
	// attempt timed out, please retry"; the loop's err-handling path is
	// the one we want to exercise here.
	if ctx.Err() != nil {
		return HelloAck{}, ctx.Err()
	}
	return HelloAck{}, errors.New("recordingSender: no ack")
}

func (r *recordingSender) sends() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]time.Duration, len(r.sendTs))
	copy(out, r.sendTs)
	return out
}

func TestHandshake_RetrySchedule_Honors250msTo4s(t *testing.T) {
	// Drive RunClientHandshake with a Sender that never produces an ACK.
	// Assert all 5 attempts happen at the expected virtual-clock offsets.
	//
	// Tolerance: with the fake clock the virtual-time offsets are exact
	// (no scheduling noise), so we require exact equality to lock the
	// schedule in. If a future refactor switches to real-clock testing
	// the tolerance should be a few hundred ms to absorb CI noise — the
	// expected values themselves do not change.
	start := time.Now()
	clk := newFakeClock(start)
	withFakeClock(t, clk)

	rs := &recordingSender{clock: clk, start: start}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	id, err := RunClientHandshake(ctx, rs, keyA)
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Fatalf("RunClientHandshake: got err=%v id=%x, want ErrHandshakeTimeout", err, id)
	}
	if id != (SessionID{}) {
		t.Fatalf("RunClientHandshake on timeout: got id=%x, want zero", id)
	}

	got := rs.sends()
	want := []time.Duration{
		0,                       // attempt 1
		250 * time.Millisecond,  // attempt 2
		750 * time.Millisecond,  // attempt 3  (250+500)
		1750 * time.Millisecond, // attempt 4  (750+1000)
		3750 * time.Millisecond, // attempt 5  (1750+2000)
	}
	if len(got) != len(want) {
		t.Fatalf("attempts: got %d, want %d (delays: %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attempt %d: got %v, want %v", i+1, got[i], want[i])
		}
	}
}

func TestHandshake_RetryStopsOnAck(t *testing.T) {
	// Sender returns a valid HELLO_ACK on attempt 2; assert exactly two
	// sends and that the returned SessionID matches the one the ACK
	// carried. No further attempts must happen.
	start := time.Now()
	clk := newFakeClock(start)
	withFakeClock(t, clk)

	wantID := SessionID{0xDE, 0xAD, 0xBE, 0xEF}
	rs := &recordingSender{
		clock: clk,
		start: start,
		ackFn: func(attempt int) (HelloAck, error) {
			if attempt < 2 {
				return HelloAck{}, errors.New("not yet")
			}
			return BuildHelloAck(keyA, wantID), nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	id, err := RunClientHandshake(ctx, rs, keyA)
	if err != nil {
		t.Fatalf("RunClientHandshake: %v", err)
	}
	if id != wantID {
		t.Fatalf("returned SessionID = %x, want %x", id, wantID)
	}
	if got := rs.sends(); len(got) != 2 {
		t.Fatalf("got %d attempts, want exactly 2; delays=%v", len(got), got)
	}
}

func TestHandshake_RetryRespectsContext(t *testing.T) {
	// Cancel ctx before attempt 2 fires; RunClientHandshake must return
	// ctx.Err() promptly without waiting out the rest of the retry budget.
	start := time.Now()
	clk := newFakeClock(start)

	// Install a sleepFunc that returns ctx.Err() unconditionally — we
	// cancel ctx before the first inter-attempt sleep begins, so the
	// first sleep call sees the cancellation and returns immediately.
	oldNow, oldSleep := nowFunc, sleepFunc
	nowFunc = clk.Now
	sleepFunc = clk.Sleep
	t.Cleanup(func() {
		nowFunc = oldNow
		sleepFunc = oldSleep
	})

	rs := &recordingSender{clock: clk, start: start}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after the first SendHello but before the first sleep returns.
	rs.ackFn = func(attempt int) (HelloAck, error) {
		cancel()
		return HelloAck{}, context.Canceled
	}

	doneCh := make(chan struct{})
	var (
		id  SessionID
		err error
	)
	go func() {
		id, err = RunClientHandshake(ctx, rs, keyA)
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("RunClientHandshake did not return promptly on ctx cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RunClientHandshake: got err=%v, want context.Canceled", err)
	}
	if id != (SessionID{}) {
		t.Fatalf("RunClientHandshake on cancel: got id=%x, want zero", id)
	}
}

// --- Server-side handshake tests --------------------------------------------

// recordingServerSender captures every SendHelloAck call so tests can
// assert "exactly one outbound packet on accept" and "zero outbound packets
// on reject".
type recordingServerSender struct {
	mu   sync.Mutex
	acks []HelloAck
}

func (s *recordingServerSender) SendHelloAck(_ context.Context, a HelloAck) error {
	s.mu.Lock()
	s.acks = append(s.acks, a)
	s.mu.Unlock()
	return nil
}

func (s *recordingServerSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.acks)
}

func (s *recordingServerSender) last() HelloAck {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acks[len(s.acks)-1]
}

func TestServerHandshake_AcceptsValidHello_EmitsHelloAck_MintsSession(t *testing.T) {
	mgr := NewManager(keyA, keyA)
	sender := &recordingServerSender{}
	hello := BuildHello(keyA, fixedNow)

	sess, err := RunServerHandshake(context.Background(), hello, sender, mgr, keyA, fixedNow, ClockSkewTolerance)
	if err != nil {
		t.Fatalf("RunServerHandshake: %v", err)
	}
	if sess == nil {
		t.Fatalf("RunServerHandshake returned nil session")
	}
	if mgr.LookupSession(sess.ID) != sess {
		t.Fatalf("minted session not registered in manager table")
	}
	if got := sender.count(); got != 1 {
		t.Fatalf("SendHelloAck called %d times, want 1", got)
	}
	ack := sender.last()
	if ack.SessionID != sess.ID {
		t.Fatalf("HELLO_ACK SessionID = %x, want %x", ack.SessionID, sess.ID)
	}
	// And the ACK validates under the same key, of course.
	if err := ValidateHelloAck(keyA, ack); err != nil {
		t.Fatalf("emitted HELLO_ACK fails self-validation: %v", err)
	}
	// And no counter ticked.
	if got := mgr.Counters().HandshakeBadHMAC.Load(); got != 0 {
		t.Errorf("HandshakeBadHMAC = %d after accept, want 0", got)
	}
	if got := mgr.Counters().HandshakeStaleTimestamp.Load(); got != 0 {
		t.Errorf("HandshakeStaleTimestamp = %d after accept, want 0", got)
	}
}

func TestServerHandshake_RejectsBadHMAC_EmitsZeroPackets_IncrementsCounter(t *testing.T) {
	mgr := NewManager(keyA, keyA)
	sender := &recordingServerSender{}
	// Build HELLO under keyB so the HMAC fails under the server's keyA.
	hello := BuildHello(keyB, fixedNow)

	sess, err := RunServerHandshake(context.Background(), hello, sender, mgr, keyA, fixedNow, ClockSkewTolerance)
	if !errors.Is(err, ErrHelloBadHMAC) {
		t.Fatalf("RunServerHandshake: got err=%v, want ErrHelloBadHMAC", err)
	}
	if sess != nil {
		t.Fatalf("RunServerHandshake on reject returned non-nil session %p", sess)
	}
	if got := sender.count(); got != 0 {
		t.Fatalf("SendHelloAck called %d times on reject, want 0 (silent drop)", got)
	}
	if got := mgr.Counters().HandshakeBadHMAC.Load(); got != 1 {
		t.Fatalf("HandshakeBadHMAC = %d, want 1", got)
	}
	if got := mgr.Counters().HandshakeStaleTimestamp.Load(); got != 0 {
		t.Errorf("HandshakeStaleTimestamp = %d, want 0 (this was an HMAC failure, not a skew failure)", got)
	}
}

func TestServerHandshake_RejectsStaleHello_EmitsZeroPackets_IncrementsCounter(t *testing.T) {
	mgr := NewManager(keyA, keyA)
	sender := &recordingServerSender{}
	// Build HELLO with a timestamp 5 minutes in the past — well outside
	// the default ±60s skew.
	stale := BuildHello(keyA, fixedNow.Add(-5*time.Minute))

	sess, err := RunServerHandshake(context.Background(), stale, sender, mgr, keyA, fixedNow, ClockSkewTolerance)
	if !errors.Is(err, ErrHelloStaleTimestamp) {
		t.Fatalf("RunServerHandshake: got err=%v, want ErrHelloStaleTimestamp", err)
	}
	if sess != nil {
		t.Fatalf("RunServerHandshake on reject returned non-nil session %p", sess)
	}
	if got := sender.count(); got != 0 {
		t.Fatalf("SendHelloAck called %d times on reject, want 0 (silent drop)", got)
	}
	if got := mgr.Counters().HandshakeStaleTimestamp.Load(); got != 1 {
		t.Fatalf("HandshakeStaleTimestamp = %d, want 1", got)
	}
	if got := mgr.Counters().HandshakeBadHMAC.Load(); got != 0 {
		t.Errorf("HandshakeBadHMAC = %d, want 0 (this was a skew failure, not an HMAC failure)", got)
	}
}
