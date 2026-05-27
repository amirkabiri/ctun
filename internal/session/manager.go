// Package session implements ctun's session manager: the source of truth for
// session identifiers, their HMAC-derived TFO cookies, and the per-session
// anti-replay window. T3.2 introduces the data structures, the manager's
// bookkeeping API, and the cookie derivation; the HELLO/HELLO_ACK exchange
// that actually populates the table arrives in T3.3, and the cookie validation
// in the recv gate (which depends on the AEAD layer landing on the receive
// path) follows in T3.3 as well.
//
// # Scope of T3.2
//
//   - Server-side: NewSession allocates a fresh random SessionID and seeds the
//     per-session table. LookupSession retrieves a registered session by ID.
//     ValidateCookie combines the lookup with a constant-time HMAC compare
//     and increments the BadCookie counter on mismatch.
//   - Client-side: BindSession records the SessionID echoed by the server in
//     HELLO_ACK so the post-handshake send path can stamp the right cookie.
//   - Each Session owns its own anti-replay filter (per design §8.3) and its
//     own cached cookie value (per design §8.4).
//
// # Out of scope (deferred)
//
//   - Session expiry / GC. Design-doc reserves the room for a lifetime sweep
//     but T3.2 does not start any background goroutines. See the TODO on
//     Manager for the follow-up.
//   - HELLO / HELLO_ACK exchange: this is T3.3. T3.2 only exposes the API
//     T3.3 will call.
//   - Cookie validation in the recv gate: this depends on AEAD-decrypting
//     the inbound frame to extract its SessionID, which is not wired until
//     T3.3. The manager exposes ValidateCookie now so T3.3 has a stable
//     surface to call.
//
// # Concurrency
//
// The manager's session table is guarded by a sync.RWMutex. The hot path
// (LookupSession / ValidateCookie on the recv side) takes the read lock and
// performs only a map index plus, for ValidateCookie, a constant-time HMAC
// compare on the session's cached cookie — no fresh HMAC computation per
// packet. Each Session's cookie is computed exactly once at construction
// time and is then immutable for the session's lifetime, so concurrent
// readers see the same bytes without any locking.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"sync/atomic"

	"ctun/internal/crypto"
)

// SessionIDSize is the fixed wire size of a SessionID, in bytes. The 4-byte
// width matches the protocol header field (design-doc §13.1) and keeps the
// type cheap to compare and copy as a value.
const SessionIDSize = 4

// CookieSize is the fixed wire size of the TFO cookie carried in the SYN's
// TCP option (Kind=34) payload. It is also the truncation length applied to
// HMAC-SHA256(authKey, sessionID) when deriving the cookie.
const CookieSize = 8

// SessionID is the 4-byte session identifier. A value-type [4]byte is used
// (rather than a slice or a uint32) because it is the cheapest representation
// to compare, copy, and use as a map key without any heap allocation or
// pointer chasing.
type SessionID [4]byte

// Counters holds the manager's drop-path counters. Future counters listed
// in Cross-Cutting Concerns ("Metrics") of docs/implementation-doc.md slot
// in alongside the existing fields with the same atomic.Uint64 storage.
//
// The struct is referenced by pointer (via Manager.Counters) so callers
// observe live values without any copy-and-staleness footgun. The fields are
// safe for concurrent use without external locking.
type Counters struct {
	// BadCookie is incremented every time ValidateCookie rejects an incoming
	// cookie because either (a) the SessionID is not in the manager's table
	// or (b) the HMAC compare against the registered session's cached cookie
	// fails. Maps to the design-doc / Cross-Cutting Concerns counter named
	// "dropped_bad_cookie".
	BadCookie atomic.Uint64

	// HandshakeBadHMAC is incremented every time RunServerHandshake rejects a
	// HELLO because the HMAC over the timestamped preamble does not validate
	// under the server's authKey. Maps to the design-doc / Cross-Cutting
	// Concerns counter named "dropped_handshake_bad_hmac". The single most
	// likely cause is a PSK mismatch between client and server.
	HandshakeBadHMAC atomic.Uint64

	// HandshakeStaleTimestamp is incremented every time RunServerHandshake
	// rejects a HELLO because its timestamp lies outside the server's
	// ±ClockSkewTolerance window. Distinct from HandshakeBadHMAC so an
	// operator can tell a clock-drift problem (this counter) apart from a
	// PSK-mismatch problem (HandshakeBadHMAC). Both increments are
	// silent — no outbound packets, no log lines, per design §8.4.
	HandshakeStaleTimestamp atomic.Uint64
}

// Manager owns the process's session table and the authKey used to derive
// session-bound TFO cookies. One Manager is constructed per ctun process
// (server or client) by the cmd/run wiring.
//
// T3.4 extends the constructor to also accept encKey — the ChaCha20-Poly1305
// key used by the data-path AEAD wrapper. Both keys come from
// crypto.DeriveKeys(psk); the manager stores them so the syntfo transport's
// secureConn can fetch encKey via EncKey() without re-deriving and so future
// session-scoped key-rotation work has a single ownership site.
//
// TODO(session-lifetime): design-doc §8.4 mentions session expiry as part of
// the security model; T3.2 keeps the table unbounded because no exchange is
// wired yet to populate it. Once T3.3 lands and real sessions accumulate,
// schedule an expiry / GC task per the design-doc's session-lifetime section.
// Until then the manager has no background goroutines (the goleak check in
// manager_test.go enforces this).
type Manager struct {
	encKey   [32]byte
	authKey  [32]byte
	mu       sync.RWMutex
	sessions map[SessionID]*Session
	// byCookie indexes registered sessions by their cached cookie. T3.4 uses
	// this for the gate's pre-decrypt cookie validation: with AEAD-wrapped
	// payloads the SessionID is no longer visible in plaintext, so the gate
	// can no longer fetch a session by SessionID. Looking up by the cookie
	// (which is HMAC-SHA256(authKey, sessionID)[:8] and therefore unique per
	// session with overwhelming probability) keeps the "fast pre-decrypt
	// reject" property the design-doc §8.4 calls for.
	byCookie map[[CookieSize]byte]*Session
	counters Counters
}

// NewManager constructs a Manager that derives session cookies from the
// supplied authKey via HMAC-SHA256(authKey, sessionID)[:CookieSize] and that
// hands encKey to its Sessions for the data-path AEAD wrapper (T3.4).
//
// encKey and authKey are typically the two 32-byte subkeys returned by
// crypto.DeriveKeys(psk); see design §8.1 for the derivation contract.
// crypto.DeriveKeys returns (encKey, authKey) in that order — the same order
// this constructor accepts them.
//
// The constructor does not start any goroutines. The Manager is safe for
// concurrent use immediately after construction.
func NewManager(encKey, authKey [32]byte) *Manager {
	return &Manager{
		encKey:   encKey,
		authKey:  authKey,
		sessions: make(map[SessionID]*Session),
		byCookie: make(map[[CookieSize]byte]*Session),
	}
}

// EncKey returns the 32-byte AEAD key the manager was constructed with. The
// syntfo secureConn (T3.4) calls this once at New time to obtain the key its
// Seal / Open path uses. Returning a copy (Go arrays are value types) keeps
// the manager's stored key inviolate even if a caller mutates the returned
// array.
func (m *Manager) EncKey() [32]byte {
	return m.encKey
}

// Counters returns the Manager's drop-path counters. The returned pointer is
// stable for the lifetime of the Manager; callers read the counters via the
// atomic Load methods.
func (m *Manager) Counters() *Counters {
	return &m.counters
}

// NewSession allocates a fresh SessionID, derives its cookie, registers the
// resulting Session in the manager's table, and returns it.
//
// Server-side API: this is the entry point T3.3 will call when a HELLO frame
// validates and the server is ready to mint a session for the client. Today
// it is also used by tests to seed the table for ValidateCookie / LookupSession
// exercises.
//
// SessionID generation reads SessionIDSize bytes from crypto/rand. A read
// failure from the OS RNG is treated as fatal — production code has no
// sensible recovery (a deployment without /dev/urandom or equivalent has
// bigger problems than a missing session), and falling back to weaker
// entropy would create a footgun the design-doc explicitly forbids.
// crypto/rand.Read does not return an error on any platform ctun supports
// in practice; we panic on the unreachable branch so a future regression
// (e.g. a sandboxed CI runner blocking /dev/urandom) fails loudly rather
// than silently degrading.
func (m *Manager) NewSession() *Session {
	var id SessionID
	if _, err := rand.Read(id[:]); err != nil {
		// Unreachable on all currently-supported platforms; see doc above.
		panic("session: crypto/rand.Read failed: " + err.Error())
	}
	s := newSession(id, m.authKey)
	m.mu.Lock()
	m.sessions[id] = s
	m.byCookie[s.cookie] = s
	m.mu.Unlock()
	return s
}

// LookupSession returns the Session registered under id, or nil if no such
// session exists. The returned pointer is stable for the lifetime of the
// session (sessions never get rewritten in-place once minted).
//
// Hot path: this is read-locked. The read lock is held only for the duration
// of the map index; the returned pointer is dereferenced by the caller
// without any further locking because the Session's fields are immutable
// after construction (cookie cached, ID fixed; the ReplayFilter is itself
// internally synchronized).
func (m *Manager) LookupSession(id SessionID) *Session {
	m.mu.RLock()
	s := m.sessions[id]
	m.mu.RUnlock()
	return s
}

// ValidateCookie looks up the session for id and, if found, compares the
// supplied cookie against the session's cached cookie in constant time. It
// returns the Session pointer and true on accept, or nil and false on
// reject. The BadCookie counter is incremented on reject for both the
// "unknown SessionID" and the "HMAC mismatch" cases.
//
// Constant-time compare is critical: a non-constant-time compare on the
// cookie would leak the prefix of the correct cookie to a network attacker
// who can measure response latency. hmac.Equal is the right primitive (it
// wraps subtle.ConstantTimeCompare).
//
// T3.2's recv-path gate does NOT call ValidateCookie yet — the SessionID is
// in the protocol header inside the AEAD ciphertext, and the AEAD layer is
// not wired onto the outbound path until T3.3. ValidateCookie is exposed
// today so T3.3 has a stable manager API to plug in. See the package-level
// doc for the full rationale.
func (m *Manager) ValidateCookie(id SessionID, cookie [CookieSize]byte) (*Session, bool) {
	s := m.LookupSession(id)
	if s == nil {
		m.counters.BadCookie.Add(1)
		return nil, false
	}
	want := s.cookie
	if !hmac.Equal(cookie[:], want[:]) {
		m.counters.BadCookie.Add(1)
		return nil, false
	}
	return s, true
}

// BindSession registers id as the client's bound session and returns the
// corresponding Session object. It is the client-side counterpart to
// NewSession: when the client receives a HELLO_ACK carrying the server-issued
// SessionID (T3.3), it calls BindSession to record the ID so subsequent
// post-handshake packets can stamp the right cookie via SessionCookieProvider.
//
// Idempotent: re-binding the same id returns the previously-registered
// Session pointer. A client that reconnects with a fresh session ID gets a
// new Session entry; this method does not garbage-collect older bindings
// (the client is expected to drop its reference and let the manager retain
// at most one bound entry per ID).
func (m *Manager) BindSession(id SessionID) *Session {
	m.mu.Lock()
	if s, ok := m.sessions[id]; ok {
		m.mu.Unlock()
		return s
	}
	s := newSession(id, m.authKey)
	m.sessions[id] = s
	m.byCookie[s.cookie] = s
	m.mu.Unlock()
	return s
}

// LookupByCookie returns the Session whose cached cookie equals the supplied
// cookie, or nil if no such session is registered. The cookie ↔ session
// mapping is unique with overwhelming probability (the cookie is a truncated
// HMAC and acts as a 64-bit identifier), so a single registered session per
// cookie is a safe invariant in practice.
//
// T3.4 uses this from the syntfo gate as a pre-decrypt fast reject: with
// AEAD-wrapped payloads the gate can no longer read the SessionID from the
// plaintext header, but it still sees the cookie in the TFO option. Looking
// the session up by cookie preserves the "drop attacker packets before AEAD
// open" property design-doc §8.4 calls for.
//
// Returning nil when no session matches is the gate's signal to drop and
// increment the bad-cookie counter; the manager's own BadCookie counter is
// NOT incremented from this method (gates are responsible for their own
// bookkeeping — ValidateCookie still owns the counter when called).
func (m *Manager) LookupByCookie(cookie [CookieSize]byte) *Session {
	m.mu.RLock()
	s := m.byCookie[cookie]
	m.mu.RUnlock()
	return s
}

// Session is one entry in the manager's session table. It carries the
// SessionID, the cached cookie (computed once at construction), the
// per-session anti-replay filter, and the per-session outbound sequence
// counter (T3.4). All fields are immutable after construction except for
// ReplayFilter's and seq's internal state, both of which are internally
// synchronized — Session is therefore safe for concurrent use without any
// external locking.
type Session struct {
	// ID is the 4-byte identifier the wire format (protocol.Message.SessionID)
	// carries. The field is exported because callers stamp it onto outgoing
	// frames and read it from incoming ones.
	ID SessionID

	// cookie is HMAC-SHA256(authKey, ID[:])[:CookieSize], computed once at
	// session construction. Cached because per-packet HMAC would be wasteful:
	// the cookie is constant for a session's lifetime by design (§8.4).
	cookie [CookieSize]byte

	// replay is the per-session anti-replay window. T3.2 exposes it via
	// ReplayFilter() so T3.4 can wire it into the post-decrypt path; T3.2
	// itself never calls Check.
	replay *crypto.ReplayFilter

	// seq is the per-session outbound sequence counter. Incremented by
	// NextSeq() on each outgoing AEAD-wrapped data frame and stamped into the
	// protocol.Message.Sequence field; the peer's anti-replay window (the
	// replay field on the peer's Session) consults this value after AEAD
	// Open succeeds. Starts at 0 so the first NextSeq() returns 1 — seq 0 is
	// reserved for the plaintext HELLO/HELLO_ACK frames that bypass the AEAD
	// path (those frames carry Sequence=0 because the receiver does not
	// replay-check the handshake; the HMAC over the timestamped preamble
	// already authenticates freshness).
	seq atomic.Uint64
}

// newSession is the internal Session constructor. It derives the cookie once
// (so concurrent Cookie() readers never race on the HMAC computation) and
// allocates a fresh ReplayFilter (so each session starts with a clean
// window).
func newSession(id SessionID, authKey [32]byte) *Session {
	mac := hmac.New(sha256.New, authKey[:])
	mac.Write(id[:])
	sum := mac.Sum(nil)
	var cookie [CookieSize]byte
	copy(cookie[:], sum[:CookieSize])
	return &Session{
		ID:     id,
		cookie: cookie,
		replay: crypto.NewReplayFilter(),
	}
}

// NextSeq returns the next outbound sequence number for this session,
// monotonically increasing from 1 (seq 0 is reserved for the plaintext
// handshake frames). Safe for concurrent use; concurrent callers each
// observe a distinct value and no number is ever skipped or repeated.
//
// The counter is per-session, not global: the AEAD path's anti-replay window
// is also per-session, so collisions across sessions are not a concern.
func (s *Session) NextSeq() uint64 {
	return s.seq.Add(1)
}

// Cookie returns HMAC-SHA256(authKey, sessionID)[:CookieSize]. The value is
// cached at session creation and never recomputed; concurrent Cookie() calls
// observe the same bytes without locking.
func (s *Session) Cookie() [CookieSize]byte {
	return s.cookie
}

// ReplayFilter returns the session's per-session anti-replay window. Each
// session owns its own filter (design §8.3); accepting a sequence number on
// one session has no bearing on whether the same sequence number is
// accepted on another. T3.4 wires the filter into the post-decrypt path;
// T3.2 only exposes the accessor.
func (s *Session) ReplayFilter() *crypto.ReplayFilter {
	return s.replay
}
