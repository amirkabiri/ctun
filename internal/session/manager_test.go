package session

import (
	"bytes"
	"sync"
	"testing"

	"go.uber.org/goleak"
)

// TestMain enforces the DoD's goroutine-leak check. The session manager
// explicitly starts no goroutines (T3.2 keeps the lifetime/GC for a follow-up
// task), so any goroutine reported by goleak at the end of the suite is a
// regression: either an accidental "go func() {}" we added here, or a leak
// in a dependency (crypto.NewReplayFilter, etc.) that didn't surface before.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// testAuthKey is the fixture authKey used by every test below. It is *not*
// the all-zero key (which would also work) because a non-trivial key makes
// the cookie bytes visually distinct in failure output and would surface a
// caller that accidentally derives cookies from a different (e.g. all-zero)
// key.
var testAuthKey = func() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}()

func newTestManager() *Manager {
	return NewManager(testAuthKey)
}

func TestManager_NewSession_GeneratesUniqueIDs(t *testing.T) {
	m := newTestManager()
	const N = 100
	seen := make(map[SessionID]struct{}, N)
	for i := 0; i < N; i++ {
		s := m.NewSession()
		if _, dup := seen[s.ID]; dup {
			t.Fatalf("duplicate SessionID after %d calls: %x", i, s.ID)
		}
		seen[s.ID] = struct{}{}
	}
}

func TestManager_NewSession_RandomBytes(t *testing.T) {
	// Distribution sanity-check, not a statistical RNG audit: we only assert
	// that the IDs look minimally diverse — no consecutive duplicates and no
	// all-zero in the first 1000 calls. A buggy entropy source that emitted
	// the same 4 bytes every time, or that emitted zeros, would trip this.
	m := newTestManager()
	const N = 1000
	zero := SessionID{}
	var prev SessionID
	for i := 0; i < N; i++ {
		s := m.NewSession()
		if s.ID == zero {
			t.Fatalf("got all-zero SessionID at iteration %d", i)
		}
		if i > 0 && s.ID == prev {
			t.Fatalf("got two consecutive identical SessionIDs at iteration %d: %x", i, s.ID)
		}
		prev = s.ID
	}
}

func TestManager_LookupSession_ReturnsRegistered(t *testing.T) {
	m := newTestManager()
	s := m.NewSession()
	got := m.LookupSession(s.ID)
	if got != s {
		t.Fatalf("LookupSession returned %p, want %p", got, s)
	}
}

func TestManager_LookupSession_NilForUnknown(t *testing.T) {
	m := newTestManager()
	// An ID we never registered. Use a fixed non-zero pattern so the test is
	// deterministic across runs.
	id := SessionID{0xAA, 0xBB, 0xCC, 0xDD}
	if got := m.LookupSession(id); got != nil {
		t.Fatalf("LookupSession(%x) = %p, want nil", id, got)
	}
}

func TestSession_Cookie_Deterministic(t *testing.T) {
	m := newTestManager()
	s := m.NewSession()
	first := s.Cookie()
	second := s.Cookie()
	if first != second {
		t.Fatalf("Cookie() returned different values across calls: %x vs %x", first, second)
	}
	// Also verify cookie is independent of how often we call: do many calls,
	// they must all match.
	for i := 0; i < 16; i++ {
		if c := s.Cookie(); c != first {
			t.Fatalf("Cookie() call %d diverged: %x vs %x", i, c, first)
		}
	}
}

func TestSession_Cookie_VariesWithKey(t *testing.T) {
	// Same SessionID, different authKey → different cookie.
	id := SessionID{0x01, 0x02, 0x03, 0x04}

	var keyA [32]byte
	for i := range keyA {
		keyA[i] = 0x11
	}
	var keyB [32]byte
	for i := range keyB {
		keyB[i] = 0x22
	}

	mA := NewManager(keyA)
	mB := NewManager(keyB)
	// We can't NewSession with a chosen ID, so call BindSession which lets us
	// pin the ID. BindSession derives the same cookie newSession would.
	sA := mA.BindSession(id)
	sB := mB.BindSession(id)
	if sA.Cookie() == sB.Cookie() {
		t.Fatalf("cookies must differ for different authKeys; both got %x", sA.Cookie())
	}
}

func TestSession_Cookie_VariesWithSession(t *testing.T) {
	// Same authKey, different SessionID → different cookie.
	m := newTestManager()
	sA := m.BindSession(SessionID{0x01, 0x02, 0x03, 0x04})
	sB := m.BindSession(SessionID{0x05, 0x06, 0x07, 0x08})
	if sA.Cookie() == sB.Cookie() {
		t.Fatalf("cookies must differ for different SessionIDs; both got %x", sA.Cookie())
	}
}

func TestSession_ReplayFilter_PerSession(t *testing.T) {
	m := newTestManager()
	sA := m.BindSession(SessionID{0xAA, 0xAA, 0xAA, 0xAA})
	sB := m.BindSession(SessionID{0xBB, 0xBB, 0xBB, 0xBB})

	// Pick a sequence number deliberately > 0 so the "first seq accepted"
	// semantics of the replay filter (Check(0) accepts on a fresh filter)
	// don't muddy the assertion.
	const seq uint64 = 42

	if !sA.ReplayFilter().Check(seq) {
		t.Fatalf("Session A first Check(%d) must accept", seq)
	}
	if sA.ReplayFilter().Check(seq) {
		t.Fatalf("Session A second Check(%d) must reject (duplicate)", seq)
	}
	// Same seq on the OTHER session must still be accepted; filters are
	// independent.
	if !sB.ReplayFilter().Check(seq) {
		t.Fatalf("Session B first Check(%d) must accept (per-session filter)", seq)
	}
}

func TestManager_ValidateCookie_AcceptsCorrect(t *testing.T) {
	m := newTestManager()
	s := m.NewSession()
	before := m.Counters().BadCookie.Load()

	got, ok := m.ValidateCookie(s.ID, s.Cookie())
	if !ok {
		t.Fatalf("ValidateCookie with correct cookie must accept")
	}
	if got != s {
		t.Fatalf("ValidateCookie returned %p, want %p", got, s)
	}
	after := m.Counters().BadCookie.Load()
	if after != before {
		t.Fatalf("BadCookie counter changed on accept: before=%d after=%d", before, after)
	}
}

func TestManager_ValidateCookie_RejectsWrong(t *testing.T) {
	m := newTestManager()
	s := m.NewSession()
	bad := s.Cookie()
	bad[0] ^= 0x01 // flip one bit

	// Sanity: ensure we actually changed it. Defensive — if Cookie() ever
	// returned an empty array this test would silently pass.
	good := s.Cookie()
	if bytes.Equal(bad[:], good[:]) {
		t.Fatalf("test setup bug: bad cookie equals real cookie")
	}

	before := m.Counters().BadCookie.Load()
	got, ok := m.ValidateCookie(s.ID, bad)
	if ok {
		t.Fatalf("ValidateCookie with flipped byte must reject")
	}
	if got != nil {
		t.Fatalf("ValidateCookie returned non-nil session on reject: %p", got)
	}
	if after := m.Counters().BadCookie.Load(); after != before+1 {
		t.Fatalf("BadCookie counter: before=%d after=%d, want +1", before, after)
	}
}

func TestManager_ValidateCookie_RejectsUnknownSession(t *testing.T) {
	m := newTestManager()
	// An ID never registered.
	id := SessionID{0xDE, 0xAD, 0xBE, 0xEF}
	// Cookie value doesn't matter — the lookup fails first.
	var cookie [CookieSize]byte

	before := m.Counters().BadCookie.Load()
	got, ok := m.ValidateCookie(id, cookie)
	if ok {
		t.Fatalf("ValidateCookie with unknown SessionID must reject")
	}
	if got != nil {
		t.Fatalf("ValidateCookie returned non-nil session on unknown-ID reject: %p", got)
	}
	if after := m.Counters().BadCookie.Load(); after != before+1 {
		t.Fatalf("BadCookie counter: before=%d after=%d, want +1", before, after)
	}
}

func TestManager_ConcurrentSessions(t *testing.T) {
	// 100 goroutines, each creating a fresh session and immediately looking
	// it up. Run under `-race`; assert all IDs unique and the manager's
	// table reflects every accept. Stresses the RWMutex and the rand source.
	m := newTestManager()
	const G = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make(map[SessionID]struct{}, G)

	wg.Add(G)
	for i := 0; i < G; i++ {
		go func() {
			defer wg.Done()
			s := m.NewSession()
			got := m.LookupSession(s.ID)
			if got != s {
				t.Errorf("Lookup mismatch: got %p want %p", got, s)
				return
			}
			mu.Lock()
			if _, dup := ids[s.ID]; dup {
				t.Errorf("duplicate SessionID across goroutines: %x", s.ID)
			}
			ids[s.ID] = struct{}{}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(ids) != G {
		t.Fatalf("expected %d unique SessionIDs, got %d", G, len(ids))
	}
}
