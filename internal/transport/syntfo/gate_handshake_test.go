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

// gateEncKey is the paired AEAD key for gate-level tests (T3.4 widened
// NewManager to take encKey as its first argument). Distinct bytes from
// gateAuthKey so a regression that confused the two surfaces immediately.
var gateEncKey = func() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = 0x5A
	}
	return k
}()

// newGateTransport builds a syntfo.Transport stub wired with a session
// manager backed by gateAuthKey. The pcap handle is left nil because none
// of these tests reach the wire; only gateOptions is invoked.
func newGateTransport() *Transport {
	mgr := session.NewManager(gateEncKey, gateAuthKey)
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

	if got := tr.gateOptions(optsWithCookie(zero), frame, nil); got {
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
	if got := tr.gateOptions(optsWithCookie(zero), frame, nil); got {
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

	if got := tr.gateOptions(optsWithCookie(cookie), frame, nil); !got {
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

	if got := tr.gateOptions(optsWithCookie(wrong), frame, nil); got {
		t.Fatalf("gateOptions(DATA,wrong-cookie): got accept, want drop")
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 1 {
		t.Errorf("syntfo.DroppedBadCookieValidator = %d, want 1", got)
	}
	if got := tr.mgr.Counters().BadCookie.Load(); got != 1 {
		t.Errorf("session.Counters.BadCookie = %d, want 1 (manager validator ticks too)", got)
	}
}

// TestGate_RejectsMalformedFrame_NonZeroCookie_UnknownSession locks in the
// T3.4 reshape of the non-zero-cookie gate branch: with AEAD-wrapped data
// frames the gate no longer Unmarshals the inner payload (the bytes are
// AEAD ciphertext, not plaintext protocol frames). Instead, the gate
// performs a fast pre-decrypt reject by looking the session up by cookie
// via mgr.LookupByCookie. A bogus / unregistered cookie therefore drops
// with the DroppedBadCookieValidator counter, regardless of payload
// contents. Post-decrypt frame-shape validation lives in secureConn.
//
// This replaces T3.3's TestGate_RejectsMalformedFrame, which asserted the
// old behaviour (Unmarshal in the gate, DroppedMalformedFrame on shape
// failure). The new behaviour drops earlier and via a different counter.
func TestGate_RejectsMalformedFrame_NonZeroCookie_UnknownSession(t *testing.T) {
	tr := newGateTransport()

	// 5 bytes of garbage payload + an unregistered cookie. The gate must
	// reject on cookie lookup, never reach payload parsing.
	bogus := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	someCookie := [CookieSize]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}

	if got := tr.gateOptions(optsWithCookie(someCookie), bogus, nil); got {
		t.Fatalf("gateOptions(unregistered-cookie): got accept, want drop")
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 1 {
		t.Errorf("DroppedBadCookieValidator = %d, want 1", got)
	}
	// The payload was never Unmarshalled, so the malformed-frame counter
	// stays at zero — that counter is now secureConn's concern.
	if got := tr.counters.DroppedMalformedFrame(); got != 0 {
		t.Errorf("DroppedMalformedFrame = %d, want 0 (gate no longer parses non-zero-cookie payloads)", got)
	}
}

// TestGate_EmptyPayload_NonZeroCookie_UnknownSession covers the empty-payload
// branch under the same T3.4 reshape: empty payload + unregistered cookie
// drops on the cookie lookup, regardless of payload length. The previous
// "empty payload → malformed-frame" assertion no longer applies because the
// gate does not parse the payload on the non-zero-cookie path.
func TestGate_EmptyPayload_NonZeroCookie_UnknownSession(t *testing.T) {
	tr := newGateTransport()
	someCookie := [CookieSize]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
	if got := tr.gateOptions(optsWithCookie(someCookie), nil, nil); got {
		t.Fatalf("gateOptions(empty payload, unregistered cookie): got accept, want drop")
	}
	if got := tr.counters.DroppedBadCookieValidator(); got != 1 {
		t.Errorf("DroppedBadCookieValidator = %d, want 1", got)
	}
	if got := tr.counters.DroppedMalformedFrame(); got != 0 {
		t.Errorf("DroppedMalformedFrame = %d, want 0 (gate no longer parses non-zero-cookie payloads)", got)
	}
}

// TestGate_EmptyPayload_ZeroCookie_DropsAsMalformed locks in the remaining
// malformed-frame branch the gate still owns: zero-cookie packets must
// carry a plaintext HELLO payload. An empty payload on the zero-cookie
// HELLO path is still parsed by the gate (the HELLO frame is plaintext) and
// fails Unmarshal, ticking DroppedMalformedFrame.
func TestGate_EmptyPayload_ZeroCookie_DropsAsMalformed(t *testing.T) {
	tr := newGateTransport()
	zero := [CookieSize]byte{}
	if got := tr.gateOptions(optsWithCookie(zero), nil, nil); got {
		t.Fatalf("gateOptions(empty payload, zero cookie): got accept, want drop")
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
	if !tr.gateOptions(opts, nil, nil) {
		t.Fatalf("gateOptions(no-manager, valid TFO, nil payload): got drop, want accept")
	}
	// And again with an arbitrary payload — the no-manager branch must
	// not look at it.
	if !tr.gateOptions(opts, []byte("anything goes when no manager is wired"), nil) {
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
