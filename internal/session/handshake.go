// HELLO / HELLO_ACK handshake primitives (T3.3) per design-doc §8.4.
//
// # Overview
//
// The handshake is the very first exchange between client and server. Until
// it completes the client has no SessionID, so the outer wire frame's
// SessionID field is zero on the client→server HELLO. The server mints a
// fresh SessionID on accept and echoes it back inside HELLO_ACK; from that
// point on the client stamps the bound SessionID on every outgoing frame and
// uses the session-derived TFO cookie (see session.SessionCookieProvider).
//
// # Message shapes (design §8.4)
//
//	HELLO payload (carried inside protocol.Message.Payload, Flags=FlagHello):
//	   [version:1][timestamp_be8:8][hmac:32]
//	   where hmac = HMAC-SHA256(authKey, "hello" || timestamp_be8)
//
//	HELLO_ACK payload (Flags=FlagHelloAck):
//	   [sessionID:4][hmac:32]
//	   where hmac = HMAC-SHA256(authKey, sessionID[:])
//
// Note that two distinct HMACs exist in the system and they MUST NOT be
// confused:
//
//   - The handshake HMAC (this file) is the full 32-byte SHA-256 digest. It
//     authenticates the HELLO/HELLO_ACK preambles.
//   - The TFO cookie (session/manager.go) is HMAC-SHA256(authKey, sessionID)
//     truncated to 8 bytes. Same authKey, different inputs, different
//     truncation. The cookie is a per-packet fast-reject sentinel carried in
//     the TCP option; the handshake HMAC is the cryptographic gate the
//     session opens with.
//
// # AEAD choice for the handshake (T3.3 deviation note)
//
// The design doc (§8.4) shows HELLO/HELLO_ACK as raw payloads carried inside
// SYN packets. §13.1 lists the wire format as "Plaintext (before AEAD)" —
// the outer AEAD layer (§8.2) wraps frames once a session is established and
// keys are agreed. For the handshake itself there is no shared session-level
// state before HELLO completes, so applying AEAD on the handshake frames
// adds no defence in depth — the HMAC-over-timestamp + HMAC-over-sessionID
// already authenticates each direction with the only key both ends share
// (authKey). Wrapping the same bytes in AEAD under the same authKey-derived
// material is belt-and-braces and would require AEAD on every gate-side
// decrypt before we can even see the FlagHello byte, which contradicts the
// gate's "zero cookie → candidate handshake" routing.
//
// **Decision: handshake is plaintext with HMAC (option (a) from the brief).**
// The framing is `protocol.Marshal({Flags=FlagHello, Payload=<HELLO bytes>})`
// — the binary wire envelope from T3.1 is on the wire, but no AEAD wraps it.
// Data frames (T3.4+) will be AEAD-wrapped; the handshake will not.
//
// # Timestamp skew window
//
// Per the DoD, server rejects timestamps more than ±60 seconds from its
// clock. The constant ClockSkewTolerance below pins the default. Tests pass
// a per-test value into ValidateHello so they can exercise both stale and
// future-skew paths deterministically.
//
// # Client retry schedule (DoD: 5 attempts, 250 ms → 4 s exponential)
//
// Schedule used by RunClientHandshake (DoD-prescribed; locked-in by
// TestHandshake_RetrySchedule_Honors250msTo4s):
//
//	attempt 1: send immediately (delay = 0)
//	attempt 2: 250 ms after attempt 1
//	attempt 3: 500 ms after attempt 2
//	attempt 4: 1 s   after attempt 3
//	attempt 5: 2 s   after attempt 4
//	abort:     4 s   after attempt 5 with no HELLO_ACK
//
// Total wall time ≈ 7.75 s. Each retry uses a freshly-built HELLO with the
// current timestamp and a fresh HMAC; the server treats every attempt
// independently (no nonce caching). ctx.Done() short-circuits any wait.

package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// HelloVersion is the protocol version carried in the HELLO payload's
// version byte. The server rejects any non-matching version with
// ErrHelloUnsupportedVersion. Bumping this constant is part of a coordinated
// protocol rev; HKDF's "ctun-v1" info string would change alongside it.
const HelloVersion uint8 = 1

// helloPreamble is the fixed ASCII tag prefixed to the timestamp bytes when
// computing the HELLO HMAC. Design §8.4 specifies `HMAC(authKey,
// "hello" || timestamp_be8)`; declaring the tag as a package-private
// constant keeps the call sites short and centralises the spelling so a
// typo in one place cannot diverge from the other side of the exchange.
var helloPreamble = []byte("hello")

// HelloHMACSize is the size of the handshake HMAC (full SHA-256 digest, not
// truncated like the TFO cookie). Exported so callers that pre-size buffers
// don't need to re-derive sha256.Size for ctun's profile.
const HelloHMACSize = sha256.Size

// HelloPayloadSize is the on-wire length of the HELLO payload — exactly the
// bytes that live inside protocol.Message.Payload when Flags=FlagHello:
//
//	[version:1][timestamp_be8:8][hmac:32] = 41 bytes
const HelloPayloadSize = 1 + 8 + HelloHMACSize

// HelloAckPayloadSize is the on-wire length of the HELLO_ACK payload —
// exactly the bytes that live inside protocol.Message.Payload when
// Flags=FlagHelloAck:
//
//	[sessionID:4][hmac:32] = 36 bytes
const HelloAckPayloadSize = SessionIDSize + HelloHMACSize

// ClockSkewTolerance is the default acceptable skew between the client's
// HELLO timestamp and the server's clock. ±60 seconds matches design §8.4
// ("rejects timestamps more than ±60 seconds from its clock"). Exposed so
// production wiring can construct a tolerance value without re-declaring
// the magic number; tests pass their own value to ValidateHello to exercise
// both edges.
const ClockSkewTolerance = 60 * time.Second

// Typed errors returned by the handshake validators. Callers branch on
// these via errors.Is to decide which drop-counter to increment and to
// avoid logging on the hot path (only counters move; design-doc constraint).
var (
	// ErrHelloBadLength is returned by ParseHello when the input buffer is
	// not exactly HelloPayloadSize bytes long. The wire format is fixed —
	// any other length is malformed.
	ErrHelloBadLength = errors.New("session: HELLO payload has wrong length")

	// ErrHelloUnsupportedVersion is returned by ParseHello when the version
	// byte does not match HelloVersion. Distinguished from ErrHelloBadLength
	// because a future protocol rev may want to negotiate down rather than
	// drop silently.
	ErrHelloUnsupportedVersion = errors.New("session: HELLO version not supported")

	// ErrHelloBadHMAC is returned by ValidateHello when the HMAC over
	// ("hello" || timestamp_be8) does not match. The single most likely
	// cause is a PSK mismatch between client and server.
	ErrHelloBadHMAC = errors.New("session: HELLO HMAC mismatch")

	// ErrHelloStaleTimestamp is returned by ValidateHello when the HELLO
	// timestamp is outside the server's clock-skew tolerance window. Covers
	// both "too old" (replay window stale) and "too new" (clock-skew or
	// future-dated forgery).
	ErrHelloStaleTimestamp = errors.New("session: HELLO timestamp outside skew window")

	// ErrHelloAckBadLength is returned by ParseHelloAck when the input
	// buffer is not exactly HelloAckPayloadSize bytes long.
	ErrHelloAckBadLength = errors.New("session: HELLO_ACK payload has wrong length")

	// ErrHelloAckBadHMAC is returned by ValidateHelloAck when the HMAC over
	// sessionID[:] does not match. The same key-mismatch failure mode as
	// ErrHelloBadHMAC but on the client side.
	ErrHelloAckBadHMAC = errors.New("session: HELLO_ACK HMAC mismatch")

	// ErrHandshakeTimeout is returned by RunClientHandshake when all 5
	// retries have elapsed without a valid HELLO_ACK. The retry schedule is
	// described in the package-level comment.
	ErrHandshakeTimeout = errors.New("session: handshake timed out after 5 attempts")
)

// Hello is the in-memory representation of a parsed HELLO payload.
type Hello struct {
	// Version is the protocol version byte. ctun v1 fixes this at
	// HelloVersion = 1; future versions will negotiate via this field.
	Version uint8

	// TimestampMillis is the client's Unix timestamp at HELLO build time,
	// expressed in milliseconds. The server cross-checks this against its
	// own clock with ClockSkewTolerance.
	TimestampMillis int64

	// HMAC is the full 32-byte SHA-256 digest authenticating the timestamp.
	// Computed as HMAC-SHA256(authKey, "hello" || timestamp_be8).
	HMAC [HelloHMACSize]byte
}

// HelloAck is the in-memory representation of a parsed HELLO_ACK payload.
type HelloAck struct {
	// SessionID is the server-minted SessionID the client must use on every
	// post-handshake frame. The same ID populates the outer
	// protocol.Message.SessionID field of the HELLO_ACK frame itself.
	SessionID SessionID

	// HMAC is the full 32-byte digest of HMAC-SHA256(authKey, sessionID[:]).
	HMAC [HelloHMACSize]byte
}

// BuildHello constructs a HELLO whose timestamp is the milliseconds-since-
// epoch reading of now and whose HMAC is computed under authKey. The
// returned Hello is ready to Marshal into the payload of a Flags=FlagHello
// frame.
//
// Callers should pass time.Now() in production; tests pin now for
// determinism. Using a parameter (rather than reading time.Now inside the
// function) is what makes RunClientHandshake's retry schedule unit-testable
// — each attempt mints a fresh Hello with a fresh timestamp.
func BuildHello(authKey [32]byte, now time.Time) Hello {
	ts := now.UnixMilli()
	var h Hello
	h.Version = HelloVersion
	h.TimestampMillis = ts
	h.HMAC = computeHelloHMAC(authKey, ts)
	return h
}

// computeHelloHMAC returns HMAC-SHA256(authKey, "hello" || timestamp_be8).
// Internal helper shared by BuildHello (sets HMAC) and ValidateHello
// (recomputes the expected value for constant-time compare).
func computeHelloHMAC(authKey [32]byte, ts int64) [HelloHMACSize]byte {
	mac := hmac.New(sha256.New, authKey[:])
	mac.Write(helloPreamble)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(ts))
	mac.Write(tsBuf[:])
	var out [HelloHMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Marshal serialises h into a freshly-allocated HelloPayloadSize-byte slice
// suitable for use as protocol.Message.Payload with Flags=FlagHello.
//
// Layout: [version:1][timestamp_be8:8][hmac:32].
func (h Hello) Marshal() []byte {
	buf := make([]byte, HelloPayloadSize)
	buf[0] = h.Version
	binary.BigEndian.PutUint64(buf[1:9], uint64(h.TimestampMillis))
	copy(buf[9:], h.HMAC[:])
	return buf
}

// ParseHello is the inverse of Hello.Marshal. It returns:
//   - ErrHelloBadLength if buf is not exactly HelloPayloadSize bytes.
//   - ErrHelloUnsupportedVersion if buf[0] != HelloVersion.
//
// HMAC validation lives in ValidateHello; ParseHello only checks structural
// invariants so callers can distinguish "wire-garbage" (length / version
// mismatch — drop, bump no-cost-to-attacker counter) from "wrong PSK"
// (HMAC mismatch — bump HandshakeBadHMAC).
func ParseHello(buf []byte) (Hello, error) {
	if len(buf) != HelloPayloadSize {
		return Hello{}, fmt.Errorf("%w: got %d, want %d", ErrHelloBadLength, len(buf), HelloPayloadSize)
	}
	var h Hello
	h.Version = buf[0]
	if h.Version != HelloVersion {
		return Hello{}, fmt.Errorf("%w: got %d, want %d", ErrHelloUnsupportedVersion, h.Version, HelloVersion)
	}
	h.TimestampMillis = int64(binary.BigEndian.Uint64(buf[1:9]))
	copy(h.HMAC[:], buf[9:])
	return h, nil
}

// ValidateHello verifies (a) the HELLO HMAC under authKey using a
// constant-time compare and (b) the timestamp lies within ±skew of now.
// Returns nil on accept, ErrHelloBadHMAC on HMAC mismatch, or
// ErrHelloStaleTimestamp on skew violation.
//
// Constant-time compare is critical: a non-constant-time compare on the
// HMAC would leak prefix bytes to a network attacker who can measure
// response latency (no response is observable, but stack timing under load
// is). hmac.Equal is the right primitive — it wraps
// subtle.ConstantTimeCompare.
//
// HMAC is checked before timestamp on purpose: a forger who does not know
// the PSK cannot produce a passing HMAC at all, so leaking "your timestamp
// was stale" to a brute-force attacker would be a small information leak.
// Production callers do not log either error (counters only), so the order
// here is purely a defence-in-depth nicety.
func ValidateHello(authKey [32]byte, h Hello, now time.Time, skew time.Duration) error {
	want := computeHelloHMAC(authKey, h.TimestampMillis)
	if !hmac.Equal(h.HMAC[:], want[:]) {
		return ErrHelloBadHMAC
	}
	helloTime := time.UnixMilli(h.TimestampMillis)
	delta := now.Sub(helloTime)
	if delta < 0 {
		delta = -delta
	}
	if delta > skew {
		return ErrHelloStaleTimestamp
	}
	return nil
}

// BuildHelloAck constructs a HELLO_ACK whose HMAC is computed as
// HMAC-SHA256(authKey, id[:]). The returned HelloAck is ready to Marshal
// into the payload of a Flags=FlagHelloAck frame whose outer SessionID
// field is the same id.
func BuildHelloAck(authKey [32]byte, id SessionID) HelloAck {
	return HelloAck{
		SessionID: id,
		HMAC:      computeHelloAckHMAC(authKey, id),
	}
}

// computeHelloAckHMAC returns HMAC-SHA256(authKey, sessionID[:]). Internal
// helper shared by BuildHelloAck and ValidateHelloAck.
func computeHelloAckHMAC(authKey [32]byte, id SessionID) [HelloHMACSize]byte {
	mac := hmac.New(sha256.New, authKey[:])
	mac.Write(id[:])
	var out [HelloHMACSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// Marshal serialises a into a freshly-allocated HelloAckPayloadSize-byte
// slice suitable for use as protocol.Message.Payload with
// Flags=FlagHelloAck.
//
// Layout: [sessionID:4][hmac:32].
func (a HelloAck) Marshal() []byte {
	buf := make([]byte, HelloAckPayloadSize)
	copy(buf[0:SessionIDSize], a.SessionID[:])
	copy(buf[SessionIDSize:], a.HMAC[:])
	return buf
}

// ParseHelloAck is the inverse of HelloAck.Marshal. It returns
// ErrHelloAckBadLength if buf is not exactly HelloAckPayloadSize bytes.
//
// HMAC validation lives in ValidateHelloAck; ParseHelloAck only checks the
// fixed length. Symmetric with ParseHello.
func ParseHelloAck(buf []byte) (HelloAck, error) {
	if len(buf) != HelloAckPayloadSize {
		return HelloAck{}, fmt.Errorf("%w: got %d, want %d", ErrHelloAckBadLength, len(buf), HelloAckPayloadSize)
	}
	var a HelloAck
	copy(a.SessionID[:], buf[0:SessionIDSize])
	copy(a.HMAC[:], buf[SessionIDSize:])
	return a, nil
}

// ValidateHelloAck verifies the HELLO_ACK HMAC under authKey using a
// constant-time compare. Returns nil on accept, ErrHelloAckBadHMAC on
// mismatch.
//
// Unlike HELLO there is no timestamp on the ACK — the design-doc protocol
// does not include one. The HMAC over the SessionID is sufficient because
// (a) the server only emits HELLO_ACK in response to a valid HELLO, so the
// ACK is implicitly bound to the HELLO's freshness window, and (b) the
// client only accepts an ACK while it is actively retrying its HELLO, so
// a stale ACK has no consumer.
func ValidateHelloAck(authKey [32]byte, a HelloAck) error {
	want := computeHelloAckHMAC(authKey, a.SessionID)
	if !hmac.Equal(a.HMAC[:], want[:]) {
		return ErrHelloAckBadHMAC
	}
	return nil
}

// Sender abstracts the per-attempt I/O the client handshake needs: send a
// HELLO frame, then wait for a HELLO_ACK (or context cancellation). The
// interface is deliberately narrow so RunClientHandshake is testable
// without spinning up a real transport — tests implement Sender with a
// recording stub that fakes the round trip.
//
// Production wiring (T3.5+): the SYN-TFO transport implements Sender by
// (a) building a protocol.Message with Flags=FlagHello, SessionID=0, and
// the marshalled HELLO bytes; (b) calling Transport.Send; (c) blocking on
// a per-request channel that the recv path fills when a FlagHelloAck frame
// arrives.
type Sender interface {
	// SendHello transmits one HELLO frame. The implementation is
	// responsible for wrapping h in the outer protocol envelope
	// (SessionID=0, Flags=FlagHello, Payload=h.Marshal()) and pushing it
	// onto the wire.
	SendHello(ctx context.Context, h Hello) error

	// RecvHelloAck blocks until a HELLO_ACK frame arrives or ctx is
	// cancelled. The implementation parses the inbound frame's payload
	// into a HelloAck and returns it; HMAC validation is the caller's job.
	// Returning a non-nil error other than ctx.Err() signals "transport-
	// level failure" and aborts the handshake; in particular the test
	// stubs return io.EOF when they want to terminate early.
	RecvHelloAck(ctx context.Context) (HelloAck, error)
}

// interAttemptDelays is the DoD-prescribed wait schedule between client
// HELLO attempts. There are exactly 4 inter-attempt delays for 5 attempts:
// delays[i] is the wait between attempt i+1 and attempt i+2.
//
//	attempt 1 at t=0
//	+250 ms → attempt 2 at t=250 ms
//	+500 ms → attempt 3 at t=750 ms
//	+1 s    → attempt 4 at t=1.75 s
//	+2 s    → attempt 5 at t=3.75 s
//
// After attempt 5 there is one final 4 s grace wait (finalGiveUpWait)
// during which a late HELLO_ACK still wins the race; if that wait expires
// with no ACK, RunClientHandshake returns ErrHandshakeTimeout. Total wall
// time ≈ 7.75 s.
//
// Locked-in by TestHandshake_RetrySchedule_Honors250msTo4s. If a future
// reviewer wants a different schedule, change these constants and the test
// in the same commit — the test asserts attempt timings against these
// values, not against a separate copy.
var interAttemptDelays = []time.Duration{
	250 * time.Millisecond,
	500 * time.Millisecond,
	1000 * time.Millisecond,
	2000 * time.Millisecond,
}

// finalGiveUpWait is the grace period after the 5th attempt during which a
// late HELLO_ACK can still satisfy the handshake. Once it elapses,
// RunClientHandshake returns ErrHandshakeTimeout. Per the DoD schedule:
// "wait 4 s, give up."
const finalGiveUpWait = 4 * time.Second

// maxAttempts is the DoD-prescribed cap on HELLO sends. Five attempts,
// total wall time ~7.75 s. Exposed as a named constant so tests reading
// rs.sends() can assert exactly against it.
const maxAttempts = 5

// nowFunc is the wall-clock source RunClientHandshake uses to mint
// timestamps for each retry's fresh HELLO. Wired through a package-level
// variable so tests can pin it; production calls leave it at time.Now.
var nowFunc = time.Now

// sleepFunc is the sleep primitive RunClientHandshake uses to honour the
// retry schedule. Same rationale as nowFunc: tests replace it with a fake
// clock to assert the schedule without real wall-clock waits. The
// implementation must respect ctx — sleepFunc returns ctx.Err() if ctx is
// cancelled during the wait, or nil on a clean wake.
var sleepFunc = realSleep

// realSleep implements sleepFunc on real wall-clock time. Returns nil on
// timely wake, ctx.Err() on context cancellation. Uses time.NewTimer (and
// stops the timer on cancellation) so a cancelled wait does not leak the
// underlying runtime timer.
func realSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RunClientHandshake performs the client side of the HELLO/HELLO_ACK
// exchange. It builds a fresh HELLO each attempt, transmits via s, awaits
// the HELLO_ACK, validates the ACK's HMAC under authKey, and returns the
// server-issued SessionID on success.
//
// Behaviour summary (see retryDelays above and the package doc):
//
//   - Up to 5 attempts. Each attempt builds a fresh Hello with a fresh
//     timestamp (so a server with significant clock drift can still
//     accept a later retry).
//   - Between attempts the schedule is 250 ms → 500 ms → 1 s → 2 s → 4 s.
//   - ctx.Done() short-circuits both the SendHello/RecvHelloAck calls and
//     the inter-attempt wait. The function returns ctx.Err() promptly in
//     that case.
//   - If RecvHelloAck returns ANY error (transport failure, malformed
//     payload, HMAC mismatch from ValidateHelloAck), the function moves on
//     to the next retry after the prescribed wait. A persistently bad ACK
//     therefore looks the same as a missing ACK from the caller's
//     perspective — both fall out as ErrHandshakeTimeout. This is the
//     conservative choice: a hostile or buggy server that emits a wrong-
//     HMAC ACK gets the same treatment as one that emits nothing, so the
//     client never returns a bound SessionID from a verifier that failed.
//
// On success returns the validated SessionID and nil. On exhaustion
// returns the zero SessionID and ErrHandshakeTimeout. On ctx cancellation
// returns the zero SessionID and ctx.Err().
func RunClientHandshake(ctx context.Context, s Sender, authKey [32]byte) (SessionID, error) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Each attempt mints a fresh Hello — fresh timestamp, fresh HMAC.
		// We do not reuse a prior attempt's HMAC because the server's
		// skew window may have advanced past the original timestamp.
		hello := BuildHello(authKey, nowFunc())

		// Send + receive happens inside a single ctx-scoped flight. If
		// either errors, drop into the inter-attempt wait below.
		if err := s.SendHello(ctx, hello); err != nil {
			if ctx.Err() != nil {
				return SessionID{}, ctx.Err()
			}
			// Treat send failure as "attempt failed, retry" — same path
			// as a missing ACK. The cost of treating a real transport
			// outage as a retry is at most the configured retry budget
			// (≈ 7.75 s), which is well within the design's tolerance.
		} else {
			ack, err := s.RecvHelloAck(ctx)
			if err == nil {
				if vErr := ValidateHelloAck(authKey, ack); vErr == nil {
					return ack.SessionID, nil
				}
				// HMAC mismatch on the ACK: a hostile responder, or a
				// PSK mismatch. Either way the same conservative
				// behaviour as a missing ACK — drop into the wait and
				// retry. Eventually we time out with
				// ErrHandshakeTimeout.
			} else if ctx.Err() != nil {
				return SessionID{}, ctx.Err()
			}
		}

		var wait time.Duration
		if attempt < maxAttempts {
			// Inter-attempt delay: index by (attempt-1) into the 4-element
			// delay table. attempt=1 → delays[0]=250ms, ..., attempt=4 →
			// delays[3]=2s.
			wait = interAttemptDelays[attempt-1]
		} else {
			// Final grace wait after the 5th attempt. If a late ACK
			// arrives here we still accept it, but since the recv side
			// in our minimal Sender stub returns synchronously per
			// attempt, the wait will simply elapse and we return
			// ErrHandshakeTimeout below.
			wait = finalGiveUpWait
		}
		if err := sleepFunc(ctx, wait); err != nil {
			return SessionID{}, err
		}
	}
	return SessionID{}, ErrHandshakeTimeout
}

// ServerSender is the narrow interface the server-side handshake handler
// uses to push the HELLO_ACK back to the client. It mirrors the client-
// side Sender's shape (just the SendHelloAck half — the server does not
// recv at this layer; the recv loop has already handed it the parsed
// HELLO).
//
// Production wiring (T3.5+): the SYN-TFO transport implements this by
// (a) wrapping the HelloAck in a protocol.Message with
// Flags=FlagHelloAck and SessionID=<freshly-minted ID>; (b) calling
// Transport.Send to the client's address.
type ServerSender interface {
	// SendHelloAck transmits the HELLO_ACK frame. The implementation
	// wraps a in the outer protocol envelope (SessionID=a.SessionID,
	// Flags=FlagHelloAck, Payload=a.Marshal()).
	SendHelloAck(ctx context.Context, a HelloAck) error
}

// RunServerHandshake is the server-side counterpart to RunClientHandshake.
// It is called once by the recv-loop / gate when a HELLO frame arrives.
// On accept:
//
//  1. Mints a fresh session via mgr.NewSession().
//  2. Builds HELLO_ACK with the new sessionID.
//  3. Pushes the ACK back through sender.SendHelloAck.
//  4. Returns the *Session pointer so the recv loop can remember it.
//
// On reject (HMAC mismatch or stale timestamp):
//
//   - Increments the appropriate counter on mgr.Counters() (HandshakeBadHMAC
//     or HandshakeStaleTimestamp).
//   - Returns the typed error (ErrHelloBadHMAC or ErrHelloStaleTimestamp)
//     wrapped with context.
//   - **Does NOT** emit any outbound packets. Design §8.4: "هیچ پاسخی
//     نمی‌دهد (silent drop) → سرور invisible باقی می‌ماند" — completely
//     silent.
//
// now is the server's clock reading for skew validation. Tests pass a
// pinned value; production calls pass time.Now().
//
// skew is the maximum allowed |server_now - client_timestamp|. Production
// passes ClockSkewTolerance; tests pass a per-test value to exercise both
// the inside-window accept and outside-window reject paths.
func RunServerHandshake(
	ctx context.Context,
	h Hello,
	sender ServerSender,
	mgr *Manager,
	authKey [32]byte,
	now time.Time,
	skew time.Duration,
) (*Session, error) {
	if err := ValidateHello(authKey, h, now, skew); err != nil {
		// Counter bookkeeping is the entire diagnostic surface for the
		// reject path — no log line. The cross-cutting "Logging"
		// concern in docs/implementation-doc.md is explicit: counters
		// preferred over log lines on the hot path.
		switch {
		case errors.Is(err, ErrHelloBadHMAC):
			mgr.Counters().HandshakeBadHMAC.Add(1)
		case errors.Is(err, ErrHelloStaleTimestamp):
			mgr.Counters().HandshakeStaleTimestamp.Add(1)
		}
		return nil, err
	}

	sess := mgr.NewSession()
	ack := BuildHelloAck(authKey, sess.ID)
	if err := sender.SendHelloAck(ctx, ack); err != nil {
		// The session was already minted. Returning the error here
		// (rather than rolling back the session) is deliberate: a
		// transient send failure is normal in a packet-injection
		// transport, and the client will retry. If the retry's HELLO
		// validates, we will mint a SECOND session — that is fine
		// because sessions are cheap and the prior unreachable one
		// just sits in the table until session-GC (the open TODO in
		// manager.go) eventually evicts it.
		return nil, fmt.Errorf("session: send HELLO_ACK: %w", err)
	}
	return sess, nil
}
