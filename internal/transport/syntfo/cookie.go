// CookieProvider, StaticCookieProvider and the default sentinel cookie used by
// the SYN-TFO transport's send path.
//
// The TFO option (TCP Option Kind=34) carries an 8-byte cookie. T1.2 only ships
// a constant stub provider — the real HMAC-SHA256(authKey, sessionID)[:8]
// provider lands in T3.2 once session management exists. The interface is kept
// minimal here so T3.2 can introduce a richer provider (or evolve the method
// signature) without rippling through the send path's call sites.
//
// The interface lives in this file (package syntfo) rather than a dedicated
// leaf package because both the send path (this package's send.go) and the
// future receive path (T1.3's recv.go in the same package) need to reach it
// without a build-time cycle. Anything that imports syntfo to obtain a cookie
// must not be importable from syntfo itself; the small leaf shape we have here
// is friendly to either direction.

package syntfo

import (
	"context"
	"sync"

	"ctun/internal/session"
)

// CookieSize is the on-wire size of the TFO cookie carried inside the TCP
// option payload. RFC 7413 specifies an 8-byte cookie for ctun's profile.
const CookieSize = 8

// CookieProvider returns the 8-byte TFO cookie that the SYN-TFO transport
// should stamp onto an outgoing SYN. T1.2 only consumes a single static value
// per provider; T3.2 will introduce session-bound providers that derive the
// cookie from HMAC-SHA256(authKey, sessionID).
//
// The context argument is reserved for future implementations that need to
// honour cancellation (e.g. a provider that blocks until the handshake has
// completed). The static provider ignores it.
type CookieProvider interface {
	// Cookie returns the 8-byte cookie payload to embed in the next SYN's
	// TFO option. Implementations must be safe for concurrent use because the
	// send path serialises packets from multiple goroutines.
	Cookie(ctx context.Context) [CookieSize]byte
}

// StaticCookieProvider is a CookieProvider that always returns the same
// 8-byte value. It exists to unblock T1.2's send-path tests without depending
// on the session machinery T3.2 introduces; the real provider will replace it
// at construction time once cookie derivation is wired up.
type StaticCookieProvider struct {
	value [CookieSize]byte
}

// NewStaticCookieProvider builds a StaticCookieProvider that returns b for
// every call to Cookie.
func NewStaticCookieProvider(b [CookieSize]byte) *StaticCookieProvider {
	return &StaticCookieProvider{value: b}
}

// Cookie returns the static cookie value the provider was constructed with.
// The ctx argument is ignored — the static provider never blocks.
func (p *StaticCookieProvider) Cookie(_ context.Context) [CookieSize]byte {
	return p.value
}

// defaultStaticCookieBytes is the sentinel cookie that DefaultStaticCookie
// returns. Chosen as a fixed, easily-spotted pattern that is unlikely to
// collide with values an HMAC-based provider (T3.2) would emit, so a packet
// capture in development can be distinguished from a session-bound
// deployment at a glance:
//
//	0xC7 0x55 0x00 0x01 0xDE 0xAD 0xBE 0xEF
//
// The leading 0xC7 is "ctun" mnemonic (C-7), 0x55 is alternating bits to make
// the byte stand out in hex dumps, the middle two zero bytes form an obvious
// "version 1" marker, and the trailing 0xDEADBEEF is a long-standing
// "sentinel value, not real data" idiom in systems code. None of these bytes
// are interpreted by the wire format — they are purely a developer-facing
// hint.
var defaultStaticCookieBytes = [CookieSize]byte{
	0xC7, 0x55, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF,
}

// DefaultStaticCookie returns the project-wide sentinel cookie value used by
// the SYN-TFO transport when no real (session-bound) provider has been wired
// in yet. T3.2 replaces the default at construction time; until then this is
// the value the send path will emit.
func DefaultStaticCookie() [CookieSize]byte {
	return defaultStaticCookieBytes
}

// SessionCookieProvider is the real CookieProvider that replaces the T1.2
// static stub for any deployment that has been handed a *session.Manager.
// It stamps the bound session's cached cookie onto every outgoing SYN.
//
// # Pre-handshake (HELLO) semantics
//
// Until a session is bound (server-issued via HELLO_ACK, client-recorded via
// session.Manager.BindSession), Cookie() returns the all-zero sentinel that
// design-doc §8.4 reserves for HELLO frames. The server's recv-path gate
// treats an all-zero cookie as "candidate handshake — try to decrypt as
// HELLO"; see the TODO(T3.3) in syntfo.go's gateOptions for the rule the
// recv side will enforce once the AEAD layer reaches the gate. Today the
// gate still passes any well-formed Kind=34 option through unchanged
// (Option A from the T3.2 brief — strictly in-scope and avoids faking a
// validation step that depends on a not-yet-wired AEAD layer).
//
// # Concurrency
//
// Bind / Bound are guarded by a small RWMutex. Cookie() takes only the read
// lock and falls through to the session's cached cookie value (which is
// itself immutable after construction), so the hot path is cheap. A
// concurrent Bind that promotes the provider from "unbound" to "bound" is
// linearizable with concurrent Cookie() calls: any Cookie() that runs after
// Bind returns will see the bound session.
//
// # Server vs client usage
//
// On the server side the per-session cookie is stamped onto outbound
// SYN-ACK / server-to-client frames; on the client side it is stamped onto
// the post-handshake client-to-server frames. Both sides construct the
// provider via NewSessionCookieProvider and rely on a downstream call to
// Bind once the session ID is known. Until that Bind happens the provider
// emits the zero cookie, which is the design-doc-mandated HELLO sentinel.
type SessionCookieProvider struct {
	mgr *session.Manager

	mu      sync.RWMutex
	session *session.Session
}

// NewSessionCookieProvider builds a SessionCookieProvider backed by mgr. The
// returned provider starts unbound — Cookie() returns the all-zero HELLO
// sentinel until Bind is called.
//
// mgr is retained but not consulted by Cookie() on the hot path: once a
// Session is bound, Cookie() returns the session's cached bytes directly.
// The manager reference is kept so future helpers (e.g. a Refresh() that
// re-binds against the manager's current session table) can be added
// without changing the constructor signature.
func NewSessionCookieProvider(mgr *session.Manager) *SessionCookieProvider {
	return &SessionCookieProvider{mgr: mgr}
}

// Bind records s as the provider's bound session. After Bind returns,
// Cookie() returns s.Cookie() on every call. Passing nil unbinds (Cookie()
// reverts to the zero sentinel) — this is convenient for tests but is not
// used by the production wiring.
//
// Idempotent: Bind(s) twice in a row is a no-op on the second call. Re-bind
// to a different session replaces the previous binding.
func (p *SessionCookieProvider) Bind(s *session.Session) {
	p.mu.Lock()
	p.session = s
	p.mu.Unlock()
}

// Bound returns the currently bound session, or nil if the provider is still
// in the pre-handshake state. Exported for tests and for future T3.3 wiring
// that needs to inspect the binding to populate the protocol.Message
// SessionID field.
func (p *SessionCookieProvider) Bound() *session.Session {
	p.mu.RLock()
	s := p.session
	p.mu.RUnlock()
	return s
}

// Cookie returns the bound session's cached cookie, or the all-zero HELLO
// sentinel when no session has been bound yet. The ctx argument is reserved
// for future implementations that may need to honour cancellation; this
// provider never blocks.
func (p *SessionCookieProvider) Cookie(_ context.Context) [CookieSize]byte {
	p.mu.RLock()
	s := p.session
	p.mu.RUnlock()
	if s == nil {
		return [CookieSize]byte{}
	}
	return s.Cookie()
}
