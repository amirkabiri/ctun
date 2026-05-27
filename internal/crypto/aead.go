package crypto

// This file implements ctun's outer AEAD per design-doc §8.2:
// a thin wrapper around golang.org/x/crypto/chacha20poly1305 that produces a
// self-contained ciphertext blob layed out as [nonce:12][ciphertext:N][tag:16].
//
// The wrapper deliberately does NOT expose the nonce parameter to callers.
// Every Seal call draws a fresh 12-byte nonce from crypto/rand, which is the
// only sound mode for a random-nonce AEAD on a long-lived key — by construction
// the caller cannot reuse a nonce. A 12-byte random nonce is appropriate here
// because our packet rate is far below the birthday bound (2^32 nonces under a
// single key) for the lifetime of any session; callers needing a higher safety
// margin should rotate keys, not switch to XChaCha.
//
// T2.2 introduces this primitive but does NOT wire it onto the send/recv path.
// Phase 3 (T3.x) integrates it with the wire format; for T2.2 the only
// surfacing in user-visible behaviour is a new top-level `cipher:` config field
// that gates which AEAD will be selected when Phase 3 turns the integration on.

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD framing constants. Exported so call sites that pre-size buffers (or
// integration tests that inspect on-the-wire bytes) can refer to them without
// re-deriving the magic numbers.
const (
	// NonceSize is the per-message random nonce length, in bytes. Matches
	// chacha20poly1305.NonceSize (12) and is the wire offset at which the
	// ciphertext begins. We pin it as a local constant so the layout doc
	// stays close to the code that emits it.
	NonceSize = chacha20poly1305.NonceSize

	// TagSize is the Poly1305 authentication tag length, in bytes (16).
	// The tag is appended by chacha20poly1305 to the ciphertext and is
	// the last TagSize bytes of a sealed blob.
	TagSize = chacha20poly1305.Overhead

	// Overhead is the total per-message expansion: nonce + tag.
	// A plaintext of length N seals to len(N)+Overhead bytes.
	Overhead = NonceSize + TagSize
)

// ErrAuthFailed is returned by Open when the AEAD tag does not validate.
// It is a typed error so callers can distinguish authentication failure
// (cryptographic mismatch — wrong key, tampered ciphertext or tag, replayed
// or otherwise corrupted blob) from structural errors such as a truncated
// input. The Phase 3 receive path branches on this to increment the
// `dropped_aead_open_fail` counter without logging on the hot path.
var ErrAuthFailed = errors.New("aead: authentication failed")

// ErrCiphertextTooShort is returned by Open when the sealed input is smaller
// than the minimum framing size (nonce + tag). It is distinct from
// ErrAuthFailed so callers can tell "obviously not one of ours" apart from
// "looks like ours but the MAC doesn't check out."
var ErrCiphertextTooShort = errors.New("aead: ciphertext shorter than nonce+tag")

// Seal encrypts plaintext under key, returning a fresh sealed blob laid out as
// [nonce:12][ciphertext:N][tag:16] (total len = len(plaintext) + Overhead).
//
// The 12-byte nonce is drawn from crypto/rand on every call. Callers do not
// (and cannot) supply nonces, so nonce reuse under the same key is impossible
// by construction. A failure of crypto/rand is treated as a fatal system
// condition and returned to the caller — there is no safe fallback at this
// layer; the caller should also treat it as terminal.
//
// plaintext may be nil or empty; the result is still a valid sealed blob of
// length Overhead containing only the nonce and the tag over zero bytes of
// ciphertext. (Phase 3 will not normally send empty payloads, but the AEAD
// itself must round-trip them faithfully.)
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		// chacha20poly1305.New only fails if the key length is wrong;
		// our [32]byte type makes that statically impossible, so this
		// branch is defensive against a future library API change.
		return nil, fmt.Errorf("aead: construct cipher: %w", err)
	}

	// Layout: prefix the random nonce, then let Seal append ciphertext||tag
	// directly into the same slice. Using out[:NonceSize] as the dst-prefix
	// argument to Seal hands the function a pre-filled "header" buffer so
	// it returns the complete on-wire blob in a single allocation.
	out := make([]byte, NonceSize, NonceSize+len(plaintext)+TagSize)
	if _, err := rand.Read(out[:NonceSize]); err != nil {
		return nil, fmt.Errorf("aead: read random nonce: %w", err)
	}
	// We pass no additional-authenticated-data here. T3.x can layer AAD on
	// top later (e.g. the plaintext header) by wrapping this primitive.
	sealed := aead.Seal(out, out[:NonceSize], plaintext, nil)
	return sealed, nil
}

// Open is the inverse of Seal. Given a sealed blob [nonce:12][ciphertext:N][tag:16],
// it returns the original plaintext or a typed error:
//
//   - ErrCiphertextTooShort if the input is shorter than Overhead bytes
//     (cannot possibly contain both a nonce and a tag).
//   - ErrAuthFailed if the AEAD tag does not validate — wrong key, tampered
//     ciphertext, tampered tag, tampered nonce, or otherwise corrupt input.
//   - A wrapped error from chacha20poly1305.New for the (currently impossible)
//     case of cipher construction failure.
//
// Returned plaintext is a freshly-allocated slice; the input buffer is not
// mutated.
func Open(key [32]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < Overhead {
		return nil, ErrCiphertextTooShort
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("aead: construct cipher: %w", err)
	}

	nonce := sealed[:NonceSize]
	ctAndTag := sealed[NonceSize:]
	plaintext, err := aead.Open(nil, nonce, ctAndTag, nil)
	if err != nil {
		// chacha20poly1305.Open returns a non-typed error
		// ("chacha20poly1305: message authentication failed") on tag
		// mismatch; we normalise that to our exported sentinel so
		// callers can branch with errors.Is.
		return nil, ErrAuthFailed
	}
	return plaintext, nil
}
