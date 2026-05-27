// Package crypto provides ctun's protocol-level cryptographic primitives.
//
// This file implements HKDF-SHA256 key derivation per design-doc §8.1:
// a single user-supplied PSK is expanded into two independent 32-byte keys,
// one for the AEAD (ChaCha20-Poly1305) and one for HMAC-based authenticators
// (handshake / TFO cookie). Splitting domains via a single HKDF reader avoids
// reusing the same key bytes across distinct cryptographic primitives.
package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hkdfSalt is the project-wide HKDF salt for ctun v1.
//
// MUST NOT change between versions without bumping the protocol version in
// the HKDF info string. Changing this invalidates every existing deployment's
// key material. The 16 ASCII bytes spell "ctun-v1-saltAAAA" so a future
// `grep` for either the salt or the info string surfaces all v1 derivation
// sites in one shot.
var hkdfSalt = [16]byte{
	'c', 't', 'u', 'n', '-', 'v', '1', '-',
	's', 'a', 'l', 't', 'A', 'A', 'A', 'A',
}

// hkdfInfo is the HKDF "info" parameter, exact 7 ASCII bytes "ctun-v1".
// A future v2 rollover changes only the suffix (e.g. "ctun-v2"); the
// distinct info string guarantees that v1 and v2 derive different keys
// from the same PSK so a mid-flight upgrade cannot accidentally reuse
// key material across protocol versions.
var hkdfInfo = []byte("ctun-v1")

// DeriveKeys expands a pre-shared key into two independent 32-byte subkeys
// using HKDF-SHA256 with the project salt and info string.
//
// The returned keys are intended for:
//   - encKey:  ChaCha20-Poly1305 packet encryption (see design §8.2).
//   - authKey: HMAC-SHA256 for handshake authentication and TFO cookies
//     (see design §8.3 and §9).
//
// Input handling:
//   - Any byte length is accepted, including empty. HKDF's extract step
//     internally HMAC-folds the IKM, so no length restriction is imposed.
//   - PSK security depends entirely on the caller; HKDF does not validate
//     entropy. For production use, callers should provide >= 32 bytes of
//     high-entropy material (e.g. the output of `ctun secret`). Passing an
//     empty or low-entropy PSK does not panic but trivially weakens the
//     channel.
//
// The function is deterministic: identical inputs always produce identical
// outputs. The two returned keys are independent: with a non-trivial PSK,
// encKey and authKey will differ (this is asserted in the tests).
func DeriveKeys(psk []byte) (encKey, authKey [32]byte) {
	r := hkdf.New(sha256.New, psk, hkdfSalt[:], hkdfInfo)
	// First 32 bytes of the HKDF stream -> encKey; next 32 -> authKey.
	// io.ReadFull cannot short-read from an hkdf.Reader for these sizes
	// (HKDF-SHA256 can emit up to 255*32 = 8160 bytes), so errors here are
	// unreachable in practice; we ignore them deliberately.
	_, _ = io.ReadFull(r, encKey[:])
	_, _ = io.ReadFull(r, authKey[:])
	return
}
