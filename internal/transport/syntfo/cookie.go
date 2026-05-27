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

import "context"

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
