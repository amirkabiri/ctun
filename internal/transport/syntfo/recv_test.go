// Tests for the receive-side TFO option decoder (recv.go) and the gate
// closure the SYN-TFO Transport installs on the recv path. The package's
// other tests live next to their target file (cookie_test.go, send_test.go);
// recv_test.go follows the same convention.
//
// What this file does NOT test:
//   - Cookie *validation* (HMAC check). That is T3.2 — T1.3 only enforces
//     the option shape, and the decoder returns the cookie bytes verbatim
//     without inspecting their semantics.
//   - End-to-end integration with internal/socket.RecvHandle. The gate is
//     installed as a function-typed hook on RecvHandle; exercising the
//     full pcap-driven path requires root, so it lives in the T1.5
//     integration test rather than this unit test file.

package syntfo

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
)

// validCookie is the canonical cookie used by tests that don't care about
// the exact byte pattern. We deliberately use a non-trivial value (not all
// zeros or all 0xFF) so a faulty implementation that returns a zero array
// fails the equality check instead of accidentally matching.
var validCookie = [CookieSize]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// validTFOOption builds a single well-formed TCPOption for the TFO option
// carrying validCookie. Many of the tests need this in isolation, separate
// from BuildSYNOptions' full SYN-options block.
func validTFOOption() layers.TCPOption {
	data := make([]byte, CookieSize)
	copy(data, validCookie[:])
	return layers.TCPOption{
		OptionType:   TFOOptionKind,
		OptionLength: TFOOptionLength,
		OptionData:   data,
	}
}

func TestDecodeTFO_NoOptions(t *testing.T) {
	// Empty options slice: the trivial "this is not a ctun packet" case.
	// A real-world raw TCP SYN without any options is unusual but valid;
	// the decoder must reject it without exploding.
	got, ok := DecodeTFO(nil)
	if ok {
		t.Fatalf("DecodeTFO(nil) ok = true, want false")
	}
	if got != ([CookieSize]byte{}) {
		t.Fatalf("DecodeTFO(nil) cookie = %x, want zeros", got)
	}

	got, ok = DecodeTFO([]layers.TCPOption{})
	if ok {
		t.Fatalf("DecodeTFO(empty) ok = true, want false")
	}
	if got != ([CookieSize]byte{}) {
		t.Fatalf("DecodeTFO(empty) cookie = %x, want zeros", got)
	}
}

func TestDecodeTFO_OnlyMSS(t *testing.T) {
	// A single non-TFO option: the decoder must walk past it and return
	// "no TFO" without confusing MSS for TFO (the option type values are
	// far apart, but a copy-paste bug that compared OptionLength instead
	// of OptionType would slip through without this guard).
	opts := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
	}
	got, ok := DecodeTFO(opts)
	if ok {
		t.Fatalf("DecodeTFO(MSS-only) ok = true, want false")
	}
	if got != ([CookieSize]byte{}) {
		t.Fatalf("DecodeTFO(MSS-only) cookie = %x, want zeros", got)
	}
}

func TestDecodeTFO_WrongLength(t *testing.T) {
	// Two malformed shapes per the DoD: (a) Kind=34 with wrong
	// OptionLength, (b) Kind=34 with correct OptionLength but truncated
	// OptionData. Both must be rejected; the public function collapses
	// them to ok=false, but the underlying classifyTFO must mark them
	// malformed so the counter logic in gateOptions can distinguish
	// "missing" from "malformed" — exercised in the gate-level tests
	// further down this file.
	cases := []struct {
		name string
		opt  layers.TCPOption
	}{
		{
			name: "OptionLength=8 (too short)",
			opt: layers.TCPOption{
				OptionType:   TFOOptionKind,
				OptionLength: 8, // RFC permits 4/6/10/12/16/18; ctun fixes 10
				OptionData:   []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			},
		},
		{
			name: "OptionLength=12 (too long)",
			opt: layers.TCPOption{
				OptionType:   TFOOptionKind,
				OptionLength: 12,
				OptionData:   []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA},
			},
		},
		{
			name: "OptionLength=10 but OptionData truncated to 4 bytes",
			opt: layers.TCPOption{
				OptionType:   TFOOptionKind,
				OptionLength: TFOOptionLength,
				OptionData:   []byte{0x11, 0x22, 0x33, 0x44},
			},
		},
		{
			name: "OptionLength=10 but OptionData empty",
			opt: layers.TCPOption{
				OptionType:   TFOOptionKind,
				OptionLength: TFOOptionLength,
				OptionData:   nil,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := DecodeTFO([]layers.TCPOption{c.opt})
			if ok {
				t.Fatalf("DecodeTFO ok = true, want false for malformed shape")
			}
			if got != ([CookieSize]byte{}) {
				t.Fatalf("DecodeTFO cookie = %x, want zeros on rejection", got)
			}
		})
	}
}

func TestDecodeTFO_Valid(t *testing.T) {
	// Happy path: a single well-formed TFO option in the list. Asserts
	// both ok=true and that the cookie bytes round-trip exactly (the
	// decoder must not byte-swap, mask, or otherwise transform the
	// OptionData bytes).
	opts := []layers.TCPOption{validTFOOption()}
	got, ok := DecodeTFO(opts)
	if !ok {
		t.Fatalf("DecodeTFO(valid) ok = false, want true")
	}
	if got != validCookie {
		t.Fatalf("DecodeTFO cookie = %x, want %x", got, validCookie)
	}
}

func TestDecodeTFO_MultipleOptions_WithTFO(t *testing.T) {
	// The realistic case: the full ctun SYN option set as emitted by the
	// T1.2 BuildSYNOptions. The decoder must walk past MSS, SACK-perm,
	// Timestamps, NOPs, WindowScale and arrive at the TFO option at the
	// tail. This also closes the loop on T1.2 — the cookie that
	// BuildSYNOptions stamps must be exactly what DecodeTFO extracts.
	const tsVal uint32 = 0xABCD1234
	sendOpts := BuildSYNOptions(validCookie, tsVal)
	got, ok := DecodeTFO(sendOpts)
	if !ok {
		t.Fatalf("DecodeTFO(BuildSYNOptions output) ok = false, want true")
	}
	if got != validCookie {
		t.Fatalf("round-trip cookie = %x, want %x", got, validCookie)
	}
}

func TestDecodeTFO_TFOFirst(t *testing.T) {
	// Position-agnostic decode: T1.2 emits TFO last, but a real-world
	// middlebox or a future ctun version may reorder. Assert TFO at
	// position 0 still decodes — guards against an off-by-one or a
	// "skip first option" bug that wouldn't surface against the T1.2
	// output but would break interop later.
	opts := []layers.TCPOption{
		validTFOOption(),
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
	}
	got, ok := DecodeTFO(opts)
	if !ok {
		t.Fatalf("DecodeTFO(TFO-first) ok = false, want true")
	}
	if got != validCookie {
		t.Fatalf("cookie = %x, want %x", got, validCookie)
	}
}

// TestDecodeTFO_DuplicateTFO_FirstWins locks in the duplicate-TFO behaviour
// documented in recv.go: when the option list contains more than one
// Kind=34 entry, the decoder returns the first well-formed one and ignores
// any later entries.
//
// Rationale (also captured in the code comment): real Linux stacks reject
// duplicates outright, but pure first-wins lets a TFO-aware middlebox that
// re-emits the option on rewrite still parse cleanly. We deliberately pick
// the more-tolerant behaviour. If a future security review wants strict
// reject-on-duplicate, this test will fail loudly and force the change to
// be visible in the diff rather than slipping through unannounced.
func TestDecodeTFO_DuplicateTFO_FirstWins(t *testing.T) {
	firstCookie := [CookieSize]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	secondCookie := [CookieSize]byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}

	firstData := make([]byte, CookieSize)
	copy(firstData, firstCookie[:])
	secondData := make([]byte, CookieSize)
	copy(secondData, secondCookie[:])

	opts := []layers.TCPOption{
		{OptionType: TFOOptionKind, OptionLength: TFOOptionLength, OptionData: firstData},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: TFOOptionKind, OptionLength: TFOOptionLength, OptionData: secondData},
	}
	got, ok := DecodeTFO(opts)
	if !ok {
		t.Fatalf("DecodeTFO(duplicate-TFO) ok = false, want true")
	}
	if got != firstCookie {
		t.Fatalf("cookie = %x, want first %x (later duplicate must be ignored)", got, firstCookie)
	}
}

// BenchmarkDecodeTFO is the zero-allocation enforcer required by T1.3's
// DoD. Run with:
//
//	go test -bench=BenchmarkDecodeTFO -benchmem ./internal/transport/syntfo/
//
// and confirm "0 allocs/op" in the output. A non-zero allocs/op means the
// implementation has drifted toward a make(), a string conversion, or a
// closure that captures-by-reference; see recv.go's DecodeTFO contract.
func BenchmarkDecodeTFO(b *testing.B) {
	// Use BuildSYNOptions' real output as the input — that is what the
	// production hot path actually sees, and it exercises the "skip 7
	// options to find TFO at index 7" code path. Build it once outside
	// the timed loop so the timing only captures DecodeTFO itself.
	opts := BuildSYNOptions(validCookie, 0xDEADBEEF)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeTFO(opts)
	}
}

// --- Gate-level tests --------------------------------------------------------
//
// The Transport.gateOptions method is what RecvHandle.synGate calls per
// packet. These tests exercise it directly (no pcap handle) by constructing
// a Transport with just the fields gateOptions touches.

// newTransportForGateTest builds a Transport stub suitable for driving
// gateOptions in isolation. cfg, conn, and cookies are left nil because
// the gate path does not touch them; if a future refactor changes that,
// these tests will panic and the developer will know to update the stub.
func newTransportForGateTest() *Transport {
	return &Transport{counters: NewCounters()}
}

func TestTransport_GateOptions_ValidPasses(t *testing.T) {
	tr := newTransportForGateTest()
	opts := BuildSYNOptions(validCookie, 0)
	// T3.3 widened the gate signature with a payload argument. With no
	// session manager wired (t.mgr == nil — the test stub), the gate
	// preserves T1.3 semantics: accept on TFO shape alone, payload is
	// ignored. Pass nil to lock that fallback in.
	if !tr.gateOptions(opts, nil, nil) {
		t.Fatalf("gateOptions returned false for valid TFO; want true")
	}
	if got := tr.counters.DroppedNoTFO(); got != 0 {
		t.Errorf("DroppedNoTFO = %d, want 0", got)
	}
	if got := tr.counters.DroppedMalformedTFO(); got != 0 {
		t.Errorf("DroppedMalformedTFO = %d, want 0", got)
	}
}

func TestTransport_GateOptions_MissingTFO_IncrementsNoTFOCounter(t *testing.T) {
	tr := newTransportForGateTest()
	opts := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
	}
	for i := 0; i < 3; i++ {
		if tr.gateOptions(opts, nil, nil) {
			t.Fatalf("iter %d: gateOptions returned true for missing TFO; want false", i)
		}
	}
	if got := tr.counters.DroppedNoTFO(); got != 3 {
		t.Errorf("DroppedNoTFO = %d, want 3", got)
	}
	if got := tr.counters.DroppedMalformedTFO(); got != 0 {
		t.Errorf("DroppedMalformedTFO = %d, want 0 (no malformed packets)", got)
	}
}

func TestTransport_GateOptions_MalformedTFO_IncrementsMalformedCounter(t *testing.T) {
	tr := newTransportForGateTest()
	opts := []layers.TCPOption{
		{
			OptionType:   TFOOptionKind,
			OptionLength: 8, // malformed: ctun fixes 10
			OptionData:   []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		},
	}
	for i := 0; i < 2; i++ {
		if tr.gateOptions(opts, nil, nil) {
			t.Fatalf("iter %d: gateOptions returned true for malformed TFO; want false", i)
		}
	}
	if got := tr.counters.DroppedMalformedTFO(); got != 2 {
		t.Errorf("DroppedMalformedTFO = %d, want 2", got)
	}
	if got := tr.counters.DroppedNoTFO(); got != 0 {
		t.Errorf("DroppedNoTFO = %d, want 0 (no missing-TFO packets)", got)
	}
}

// TestCounters_StartAtZero pins the initial state: a freshly-allocated
// Counters must report zero on both fields. Trivially true today, but cheap
// insurance against a future refactor that adds a non-zero default.
func TestCounters_StartAtZero(t *testing.T) {
	c := NewCounters()
	if got := c.DroppedNoTFO(); got != 0 {
		t.Errorf("DroppedNoTFO = %d, want 0", got)
	}
	if got := c.DroppedMalformedTFO(); got != 0 {
		t.Errorf("DroppedMalformedTFO = %d, want 0", got)
	}
}
