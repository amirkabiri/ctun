// Gate-level tests for the T3.3 handshake-aware receive path.
//
// These tests exercise Transport.gateOptions against synthetic SYN packets
// whose TFO cookie and inner protocol payload have been hand-crafted to
// drive every branch of the gate's decision tree (see syntfo.go's
// gateOptions doc). They do not spin up pcap; the gate is invoked directly
// with the byte slices it would otherwise receive from RecvHandle.Read.
//
// The T3.3 brief calls out four locked-in gate behaviours:
//   - TestGate_AcceptsHelloWithZeroCookie
//   - TestGate_RejectsNonHelloWithZeroCookie
//   - TestGate_AcceptsDataWithValidCookie
//   - TestGate_RejectsDataWithWrongCookie
//
// One extra test (TestGate_RejectsMalformedFrame) covers the
// "TFO-shape OK, inner Unmarshal fails" branch the gate added in T3.3;
// it is a guard against a future refactor that accidentally accepts
// random-bytes payloads as valid frames.

package syntfo

import (
	"context"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"

	"github.com/gopacket/gopacket/layers"

	"ctun/internal/protocol"
	"ctun/internal/session"
)

// gateAuthKey is the canonical authKey used by gate-level tests. Picked as
// "all 0xA5" so a buggy implementation that defaults to all-zero key surfaces
// immediately (the zero-key cookie pattern differs from the 0xA5-key one).
var gateAuthKey = func() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = 0xA5
	}
	return k
}()

// newGateTransport builds a syntfo.Transport stub wired with a session
// manager backed by gateAuthKey. The pcap handle is left nil because none
// of these tests reach the wire; only gateOptions is invoked.
func newGateTransport() *Transport {
	mgr := session.NewManager(gateAuthKey)
	return &Transport{
		counters: NewCounters(),
		mgr:      mgr,
	}
}

// makeFrame marshals a protocol.Message with the given fields. Centralised
// so tests below stay compact and any future header-layout change touches
// just this helper.
func makeFrame(t *testing.T, sessionID uint32, flags protocol.Flags, payload []byte) []byte {
	t.Helper()
	buf, err := protocol.Marshal(&protocol.Message{
		SessionID: sessionID,
		Flags:     flags,
		Payload:   payload,
	})
	if err != nil {
		t.Fatalf("protocol.Marshal: %v", err)
	}
	return buf
}

// optsWithCookie builds a SYN-options block carrying the supplied 8-byte
// cookie. Wraps BuildSYNOptions to keep the gate-test call sites tidy.
func optsWithCookie(cookie [CookieSize]byte) []layers.TCPOption {
	return BuildSYNOptions(cookie, 0)
}

// recordingHandler is a stub HelloHandler that records each invocation.
// It exists so the HELLO-routing tests can verify both "drop the frame at
// the gate level (return false)" AND "dispatch the frame to the handler"
// without spinning up a real handshake handler.
type recordingHandler struct {
	calls    atomic.Uint64
	lastM    atomic.Pointer[protocol.Message]
	lastFlag atomic.Uint64
}

func (r *recordingHandler) handle(_ context.Context, m *protocol.Message, _ net.Addr) {
	r.calls.Add(1)
	r.lastM.Store(m)
	if m != nil {
		r.lastFlag.Store(uint64(m.Flags))
	}
}

// TestGate_AcceptsHelloWithZeroCookie locks in the design §8.4 rule: a SYN
// stamped with the all-zero TFO cookie sentinel and an inner FlagHello
// frame is the candidate-handshake path. The gate must
//
//	(a) signal "drop" to the upper layer (HELLO never goes to KCP), and
//	(b) dispatch the parsed frame to the registered HelloHandler.
//
// "Accept" in the brief's wording ("gate accepts and routes to the HELLO
// handler") means "the HELLO is taken in and handled" — not that
// gateOptions itself returns true. Since the gate signals drop=false to
// the upper layer for HELLO (HELLO never goes to KCP), we assert both
// (a) gateOptions returns false AND (b) the handler was invoked once.
func TestGate_AcceptsHelloWithZeroCookie(t *testing.T) {
	tr := newGateTransport()
	h := &recordingHandler{}
	tr.SetHelloHandler(h.handle)

	// Build a minimal HELLO payload — we are testing the gate's routing,
	// not the handshake's HMAC. The handler in this test only records
	// the call.
	helloPayload := make([]byte, session.HelloPayloadSize)
	helloPayload[0] = session.HelloVersion
	frame := makeFrame(t, 0, protocol.FlagHello, helloPayload)
	zero := [CookieSize]byte{}

	if got := tr.gateOptions(optsWithCookie(zero), frame); got {
		t.Fatalf("gateOptions(HELLO,zero-cookie): got upper-layer accept (true), want drop (false; HELLO is handler-dispatched, not forwarded to KCP)")
	}
	if got := h.calls.Load(); got != 1 {
		t.Fatalf("HelloHandler invocations = %d, want 1 (HELLO must be dispatched)", got)
	}
	if got := protocol.Flags(h.lastFlag.Load()); got != protocol.FlagHello {
		t.Errorf("handler saw Flags=%d, want FlagHello=%d", got, protocol.FlagHello)
	}
	m := h.lastM.Load()
	if m == nil {
		t.Fatal("handler.lastM is nil; expected the parsed frame")
	}
	if m.SessionID != 0 {
		t.Errorf("handler saw SessionID=%d, want 0 (HELLO has no session yet)", m.SessionID)
	}
	// And no drop counter should have ticked on the HELLO accept path.
	if got := tr.counters.DroppedNoTFO(); got != 0 {
		t.Errorf("DroppedNoTFO = %d, want 0", got)
	}
	if got := tr.counters.DroppedNonHelloZeroCookie(); got != 0 {
		t.Errorf("DroppedNonHelloZeroCookie = %d, want 0 (this WAS a HELLO)", got)
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 0 {
		t.Errorf("DroppedBadCookieValidator = %d, want 0 (HELLO bypasses validator)", got)
	}
}

// TestGate_RejectsNonHelloWithZeroCookie locks in the negative half of the
// zero-cookie rule: zero cookie is reserved for HELLO. Any other Flags
// value with zero cookie is dropped (incNonHelloZeroCookie) and the
// HelloHandler is NOT invoked.
func TestGate_RejectsNonHelloWithZeroCookie(t *testing.T) {
	tr := newGateTransport()
	h := &recordingHandler{}
	tr.SetHelloHandler(h.handle)

	frame := makeFrame(t, 0, protocol.FlagData, []byte("not a hello"))
	zero := [CookieSize]byte{}
	if got := tr.gateOptions(optsWithCookie(zero), frame); got {
		t.Fatalf("gateOptions(DATA,zero-cookie): got accept, want drop")
	}
	if got := h.calls.Load(); got != 0 {
		t.Errorf("HelloHandler invocations = %d, want 0 (Flags was not FlagHello)", got)
	}
	if got := tr.counters.DroppedNonHelloZeroCookie(); got != 1 {
		t.Errorf("DroppedNonHelloZeroCookie = %d, want 1", got)
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 0 {
		t.Errorf("DroppedBadCookieValidator = %d, want 0 (zero-cookie path is its own counter)", got)
	}
}

// TestGate_AcceptsDataWithValidCookie covers the post-handshake happy
// path: a non-HELLO frame whose SessionID maps to a known session and
// whose TFO cookie matches the session's HMAC-derived cookie.
//
// "Accept" means gateOptions returns true so the upper layer (KCP today)
// receives the bytes. Neither the syntfo nor the session BadCookie
// counters tick on this path.
func TestGate_AcceptsDataWithValidCookie(t *testing.T) {
	tr := newGateTransport()
	sess := tr.mgr.NewSession()

	// Frame carries the session's ID; cookie is the session's cached
	// HMAC-derived cookie. This is precisely what the
	// SessionCookieProvider on the send side emits post-Bind.
	frame := makeFrame(t, sessionIDToUint32(sess.ID), protocol.FlagData, []byte("payload"))
	cookie := sess.Cookie()

	if got := tr.gateOptions(optsWithCookie(cookie), frame); !got {
		t.Fatalf("gateOptions(DATA,valid-cookie): got drop, want accept")
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 0 {
		t.Errorf("DroppedBadCookieValidator = %d, want 0", got)
	}
	if got := tr.mgr.Counters().BadCookie.Load(); got != 0 {
		t.Errorf("session.Counters.BadCookie = %d, want 0", got)
	}
}

// TestGate_RejectsDataWithWrongCookie locks in the bad-cookie reject path:
// a frame whose SessionID is registered but whose cookie does not match.
// Both the syntfo-level and the session-level counters must tick (they are
// the two halves of the brief's "DroppedBadCookieValidator distinguishes
// from T1.3's counters" guidance).
func TestGate_RejectsDataWithWrongCookie(t *testing.T) {
	tr := newGateTransport()
	sess := tr.mgr.NewSession()

	frame := makeFrame(t, sessionIDToUint32(sess.ID), protocol.FlagData, []byte("payload"))
	// Flip a bit in the session's real cookie to produce a wrong-but-not-
	// zero cookie. Using a totally random value would also work; this
	// keeps the failure proximal to the real cookie so a hex-diff in the
	// failure output is immediately legible.
	wrong := sess.Cookie()
	wrong[0] ^= 0x01

	if got := tr.gateOptions(optsWithCookie(wrong), frame); got {
		t.Fatalf("gateOptions(DATA,wrong-cookie): got accept, want drop")
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 1 {
		t.Errorf("syntfo.DroppedBadCookieValidator = %d, want 1", got)
	}
	if got := tr.mgr.Counters().BadCookie.Load(); got != 1 {
		t.Errorf("session.Counters.BadCookie = %d, want 1 (manager validator ticks too)", got)
	}
}

// TestGate_RejectsMalformedFrame guards the inner-Unmarshal branch added
// in T3.3: TFO is well-formed, cookie is non-zero, but the protocol
// payload fails Unmarshal. The gate drops the packet and ticks the
// dedicated DroppedMalformedFrame counter.
//
// This isn't in the T3.3 brief's locked-in tests but it falls out of the
// gate's decision tree — keeping it tested means a future refactor that
// accidentally accepts garbage payloads will fail this test rather than
// quietly poison the upper-layer dispatcher.
func TestGate_RejectsMalformedFrame(t *testing.T) {
	tr := newGateTransport()

	// 5 bytes — well short of HeaderSize = 15. protocol.Unmarshal returns
	// ErrTruncated; the gate maps that to incMalformedFrame.
	bogus := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	someCookie := [CookieSize]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}

	if got := tr.gateOptions(optsWithCookie(someCookie), bogus); got {
		t.Fatalf("gateOptions(malformed-frame): got accept, want drop")
	}
	if got := tr.counters.DroppedMalformedFrame(); got != 1 {
		t.Errorf("DroppedMalformedFrame = %d, want 1", got)
	}
}

// TestGate_EmptyPayload_Drops covers the explicit empty-payload branch.
// A TFO-OK packet with zero application bytes can't carry a protocol
// frame; treat as malformed.
func TestGate_EmptyPayload_Drops(t *testing.T) {
	tr := newGateTransport()
	someCookie := [CookieSize]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	if got := tr.gateOptions(optsWithCookie(someCookie), nil); got {
		t.Fatalf("gateOptions(empty payload): got accept, want drop")
	}
	if got := tr.counters.DroppedMalformedFrame(); got != 1 {
		t.Errorf("DroppedMalformedFrame = %d, want 1", got)
	}
}

// TestGate_NoSessionManager_PreservesT13Semantics confirms that the
// non-handshake fallback still works: when t.mgr is nil (legacy / test
// wiring), the gate accepts on TFO shape alone.
func TestGate_NoSessionManager_PreservesT13Semantics(t *testing.T) {
	tr := &Transport{counters: NewCounters()}
	opts := BuildSYNOptions(validCookie, 0)
	if !tr.gateOptions(opts, nil) {
		t.Fatalf("gateOptions(no-manager, valid TFO, nil payload): got drop, want accept")
	}
	// And again with an arbitrary payload — the no-manager branch must
	// not look at it.
	if !tr.gateOptions(opts, []byte("anything goes when no manager is wired")) {
		t.Fatalf("gateOptions(no-manager, valid TFO, garbage payload): got drop, want accept")
	}
}

// sessionIDToUint32 mirrors the byte ordering the gate uses to read
// frame.SessionID back into a [4]byte. Centralised so the test and the
// production code can't diverge silently. Equivalent to
// binary.BigEndian.Uint32 over the SessionID's bytes.
func sessionIDToUint32(id session.SessionID) uint32 {
	return binary.BigEndian.Uint32(id[:])
}
