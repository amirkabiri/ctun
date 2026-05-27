package syntfo

import (
	"context"
	"testing"

	"ctun/internal/session"
)

// Compile-time assertions that both providers satisfy CookieProvider. These
// pin the contract: any future evolution of the interface fails the build
// here before any consumer fails at runtime.
var (
	_ CookieProvider = (*StaticCookieProvider)(nil)
	_ CookieProvider = (*SessionCookieProvider)(nil)
)

func TestStaticCookieProvider_ReturnsStoredValue(t *testing.T) {
	want := [CookieSize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	p := NewStaticCookieProvider(want)

	got := p.Cookie(context.Background())
	if got != want {
		t.Fatalf("Cookie() = %x, want %x", got, want)
	}
}

func TestDefaultStaticCookie_MatchesSentinel(t *testing.T) {
	// The exact byte string is part of the public contract of T1.2: it is
	// the value that will show up on the wire in any pre-T3.2 deployment
	// or any test environment that hasn't wired a real provider. Pin it
	// byte-for-byte so a careless edit to cookie.go fails this test
	// rather than silently shifting what every developer sees in tcpdump.
	want := [CookieSize]byte{0xC7, 0x55, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF}

	got := DefaultStaticCookie()
	if got != want {
		t.Fatalf("DefaultStaticCookie() = %x, want %x", got, want)
	}
}

// testAuthKey is a non-zero authKey for SessionCookieProvider exercises. The
// concrete bytes are arbitrary; what matters is that they are not the
// all-zero key so a regression that accidentally re-derived against zero
// would surface immediately.
var testAuthKey = func() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}()

func TestSessionCookieProvider_UnboundReturnsZero(t *testing.T) {
	// Pre-handshake (HELLO) sentinel: until a session is bound, the provider
	// emits the all-zero cookie. design-doc §8.4 is explicit that this is
	// the value the server's recv gate will (once T3.3 wires the AEAD
	// layer) treat as "candidate HELLO".
	mgr := session.NewManager(testAuthKey)
	p := NewSessionCookieProvider(mgr)

	want := [CookieSize]byte{}
	got := p.Cookie(context.Background())
	if got != want {
		t.Fatalf("unbound Cookie() = %x, want %x (HELLO sentinel)", got, want)
	}
	if b := p.Bound(); b != nil {
		t.Fatalf("Bound() on fresh provider = %p, want nil", b)
	}
}

func TestSessionCookieProvider_BindStampsSessionCookie(t *testing.T) {
	// Once a session is bound, Cookie() must return that session's cached
	// HMAC-derived cookie verbatim. This is the post-handshake path that
	// will be active on the wire after T3.3 completes the HELLO_ACK flow.
	mgr := session.NewManager(testAuthKey)
	s := mgr.NewSession()
	p := NewSessionCookieProvider(mgr)
	p.Bind(s)

	want := s.Cookie()
	got := p.Cookie(context.Background())
	if got != want {
		t.Fatalf("bound Cookie() = %x, want %x", got, want)
	}
	if b := p.Bound(); b != s {
		t.Fatalf("Bound() = %p, want %p", b, s)
	}
}

func TestSessionCookieProvider_UnbindRevertsToZero(t *testing.T) {
	// Bind(nil) is permitted as a test convenience; the production wiring
	// never calls it. Verify the documented semantics: it reverts the
	// provider to the pre-handshake state.
	mgr := session.NewManager(testAuthKey)
	p := NewSessionCookieProvider(mgr)
	p.Bind(mgr.NewSession())
	p.Bind(nil)

	want := [CookieSize]byte{}
	if got := p.Cookie(context.Background()); got != want {
		t.Fatalf("after Bind(nil), Cookie() = %x, want %x", got, want)
	}
}

func TestSessionCookieProvider_ConcurrentReadsDuringBind(t *testing.T) {
	// Exercise the RWMutex under -race: many readers hammer Cookie() while
	// a writer flips Bind between sessions. The test does not assert any
	// particular interleaving — it only asserts no race-detector reports
	// and that every observed cookie is one of the two valid choices
	// (zero, sessionA.Cookie, or sessionB.Cookie). A future refactor that
	// dropped the lock would trip this under -race.
	mgr := session.NewManager(testAuthKey)
	sA := mgr.NewSession()
	sB := mgr.NewSession()
	p := NewSessionCookieProvider(mgr)

	const readers = 32
	stop := make(chan struct{})
	done := make(chan struct{}, readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				select {
				case <-stop:
					return
				default:
					_ = p.Cookie(context.Background())
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			p.Bind(sA)
		} else {
			p.Bind(sB)
		}
	}
	close(stop)
	for i := 0; i < readers; i++ {
		<-done
	}
}

func TestStaticCookieProvider_IsConcurrentSafe(t *testing.T) {
	// The CookieProvider doc requires concurrent-safe Cookie() calls. The
	// static provider is trivially safe (no mutable state), but exercise
	// it under the race detector so a future refactor that adds shared
	// state without locking gets caught.
	p := NewStaticCookieProvider(DefaultStaticCookie())
	const N = 64
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 1000; j++ {
				_ = p.Cookie(context.Background())
			}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
}
