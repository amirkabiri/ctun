package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// testKey returns a deterministic 32-byte key suitable for unit tests.
// The byte pattern is intentionally non-zero so that an implementation bug
// of "ignored key" would surface as an obvious mismatch rather than a quiet
// pass.
func testKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b ^ byte(i)
	}
	return k
}

// TestAEAD_RoundTrip exercises a range of plaintext lengths — zero, one byte,
// a single block (16), 1 KiB, and the largest UDP-ish payload (65535) — to
// catch off-by-one bugs at the boundaries of buffer pre-sizing and to confirm
// the framing constants hold across the full size range we expect on the wire.
func TestAEAD_RoundTrip(t *testing.T) {
	key := testKey(0x42)
	sizes := []int{0, 1, 16, 1024, 65535}
	for _, n := range sizes {
		n := n
		t.Run("", func(t *testing.T) {
			pt := make([]byte, n)
			if _, err := rand.Read(pt); err != nil {
				t.Fatalf("seed plaintext: %v", err)
			}
			sealed, err := Seal(key, pt)
			if err != nil {
				t.Fatalf("Seal(%d): %v", n, err)
			}
			if got, want := len(sealed), n+Overhead; got != want {
				t.Fatalf("sealed length: got %d, want %d", got, want)
			}
			got, err := Open(key, sealed)
			if err != nil {
				t.Fatalf("Open(%d): %v", n, err)
			}
			// For zero-length plaintext, Open is allowed to return either
			// a nil slice or an empty non-nil slice; bytes.Equal handles
			// both cases.
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch: got %x, want %x", got, pt)
			}
		})
	}
}

// TestAEAD_TamperedCiphertext flips a single byte in the middle of the
// ciphertext region. Poly1305 is a strong MAC, so any single-bit flip in the
// ciphertext must yield a tag mismatch.
func TestAEAD_TamperedCiphertext(t *testing.T) {
	key := testKey(0x11)
	pt := bytes.Repeat([]byte{0xAB}, 256)
	sealed, err := Seal(key, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a byte in the ciphertext region (after the nonce, before the tag).
	mid := NonceSize + len(pt)/2
	sealed[mid] ^= 0xFF
	got, err := Open(key, sealed)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Open of tampered ciphertext: err = %v (want ErrAuthFailed), plaintext = %x", err, got)
	}
	if got != nil {
		t.Fatalf("tampered Open returned non-nil plaintext: %x", got)
	}
}

// TestAEAD_TamperedTag flips a byte inside the trailing 16-byte Poly1305 tag.
// This is a direct attack on the MAC integrity field; Open must reject.
func TestAEAD_TamperedTag(t *testing.T) {
	key := testKey(0x22)
	pt := bytes.Repeat([]byte{0xCD}, 128)
	sealed, err := Seal(key, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip the last byte (definitely inside the tag, which is the last TagSize bytes).
	sealed[len(sealed)-1] ^= 0x01
	if _, err := Open(key, sealed); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Open of tampered tag: err = %v (want ErrAuthFailed)", err)
	}
}

// TestAEAD_TamperedNonce flips a byte in the 12-byte nonce prefix. The
// Poly1305 tag was computed over the original nonce, so changing the nonce
// must also fail the MAC check — covers the threat of an attacker rewriting
// the nonce to try to force a known ciphertext to decrypt to something else.
func TestAEAD_TamperedNonce(t *testing.T) {
	key := testKey(0x33)
	pt := []byte("nonce-tamper plaintext")
	sealed, err := Seal(key, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed[0] ^= 0x80
	if _, err := Open(key, sealed); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Open of tampered nonce: err = %v (want ErrAuthFailed)", err)
	}
}

// TestAEAD_WrongKey seals under key1 and tries to open under a different
// key2. Without the correct key the MAC cannot be reconstructed and Open
// must fail with ErrAuthFailed — never silently return garbage plaintext.
func TestAEAD_WrongKey(t *testing.T) {
	k1 := testKey(0x44)
	k2 := testKey(0x55)
	if k1 == k2 {
		t.Fatal("test bug: keys are equal")
	}
	pt := []byte("the secret crossing two domains")
	sealed, err := Seal(k1, pt)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(k2, sealed); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Open with wrong key: err = %v (want ErrAuthFailed)", err)
	}
}

// TestAEAD_ShortInput verifies that buffers strictly shorter than
// nonce+tag (Overhead) bytes are rejected with ErrCiphertextTooShort, NOT
// with ErrAuthFailed. The receive path in Phase 3 uses the distinction to
// avoid counting "obviously garbage" packets as MAC failures (which would
// drown out real attack signals).
func TestAEAD_ShortInput(t *testing.T) {
	key := testKey(0x66)
	for _, n := range []int{0, 1, NonceSize, NonceSize + TagSize - 1} {
		n := n
		t.Run("", func(t *testing.T) {
			_, err := Open(key, make([]byte, n))
			if !errors.Is(err, ErrCiphertextTooShort) {
				t.Fatalf("Open(len=%d): err = %v (want ErrCiphertextTooShort)", n, err)
			}
			if errors.Is(err, ErrAuthFailed) {
				t.Fatalf("Open(len=%d): wrongly reported ErrAuthFailed for short input", n)
			}
		})
	}
	// Boundary: a buffer of exactly Overhead bytes is *structurally* valid
	// (nonce + tag, zero-length ciphertext) but with all-zero contents the
	// MAC will not check out — so it must return ErrAuthFailed, not
	// ErrCiphertextTooShort. This pins the boundary.
	_, err := Open(key, make([]byte, Overhead))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Open(len=Overhead, all zeros): err = %v (want ErrAuthFailed)", err)
	}
}

// TestAEAD_NonceUnique asserts that 1000 sequential Seal calls with an
// identical key and plaintext produce 1000 distinct nonces (the first 12
// bytes of each output). A collision would indicate the RNG is broken or,
// worse, that the implementation was hard-coding a nonce — both of which
// catastrophically break the AEAD's security.
func TestAEAD_NonceUnique(t *testing.T) {
	key := testKey(0x77)
	pt := []byte("same plaintext every time")
	const N = 1000
	seen := make(map[[NonceSize]byte]struct{}, N)
	for i := 0; i < N; i++ {
		sealed, err := Seal(key, pt)
		if err != nil {
			t.Fatalf("Seal[%d]: %v", i, err)
		}
		var n [NonceSize]byte
		copy(n[:], sealed[:NonceSize])
		if _, dup := seen[n]; dup {
			t.Fatalf("nonce collision at iteration %d: %x", i, n)
		}
		seen[n] = struct{}{}
	}
	if got := len(seen); got != N {
		t.Fatalf("seen-set size %d, want %d (silent collision?)", got, N)
	}
}

// BenchmarkChaCha20Poly1305_Seal_1KB measures sealing a 1024-byte plaintext.
// Recorded here for future regression watching — a sudden 2x slowdown should
// trip review.
func BenchmarkChaCha20Poly1305_Seal_1KB(b *testing.B) {
	key := testKey(0x99)
	pt := make([]byte, 1024)
	if _, err := rand.Read(pt); err != nil {
		b.Fatalf("seed plaintext: %v", err)
	}
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Seal(key, pt); err != nil {
			b.Fatalf("Seal: %v", err)
		}
	}
}
