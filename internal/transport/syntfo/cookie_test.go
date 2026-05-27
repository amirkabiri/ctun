package syntfo

import (
	"context"
	"testing"
)

// Compile-time assertion that *StaticCookieProvider satisfies CookieProvider.
// This pins the contract: if the interface evolves in T3.2, the build breaks
// here before any consumer breaks at runtime.
var _ CookieProvider = (*StaticCookieProvider)(nil)

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
