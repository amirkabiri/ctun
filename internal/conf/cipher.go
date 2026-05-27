package conf

// This file defines the outer-AEAD selector for ctun's wire format.
//
// Background — and how this differs from `transport.kcp.block`:
//
// paqet ships an existing cipher selector at `transport.kcp.block` (see
// kcp_block.go), which routes to kcp-go's per-segment BlockCrypt layer.
// That layer encrypts KCP datagrams *inside* the reliability protocol, with a
// PBKDF2-derived key, and is part of paqet's wire contract.
//
// ctun's design (see design-doc §8.2) introduces a separate, outer AEAD:
// ChaCha20-Poly1305 with an HKDF-derived 32-byte key, applied to whole frames
// before they hit the transport. This is structurally different from the KCP
// block layer — it sits one layer up, has its own random nonce per packet,
// and is keyed independently — so collapsing the two into a single config
// field would be a category error.
//
// To keep both selectors first-class without overloading either, T2.2 adds a
// NEW top-level `cipher:` field (sibling to `transport_impl:` introduced in
// T1.1). Values:
//
//   - ""              (default): no outer AEAD; legacy paqet behaviour where
//                                KCP's block layer is the only encryption.
//   - "none"                   : explicit synonym for "" — same behaviour.
//   - "chacha20poly1305"       : the AEAD introduced in this task. T2.2 only
//                                wires the *selection*; T3.x integrates it
//                                onto the send/recv path.
//
// Existing fixtures without a `cipher:` line continue to work unchanged.

// Cipher names a registered outer AEAD primitive. Phase 3 will use the
// selected value (returned by Conf.AEAD) to construct the AEAD instance for
// the send/recv hot path; defining the enum here lets Phase 3 avoid scattering
// switch-on-string code across the codebase.
type Cipher int

const (
	// CipherNone means no outer AEAD is applied. Matches `cipher: ""` or
	// `cipher: "none"` in YAML. This is the default and preserves legacy
	// paqet behaviour (KCP's block layer alone).
	CipherNone Cipher = iota

	// CipherChaCha20Poly1305 selects the AEAD wrapper defined in
	// internal/crypto/aead.go (ChaCha20-Poly1305, 12-byte random nonce per
	// packet, 16-byte Poly1305 tag). Matches `cipher: "chacha20poly1305"`.
	CipherChaCha20Poly1305
)

// String returns the canonical YAML spelling for a Cipher, suitable for log
// messages and validation errors. Round-trips with the YAML field for valid
// values.
func (c Cipher) String() string {
	switch c {
	case CipherNone:
		return "none"
	case CipherChaCha20Poly1305:
		return "chacha20poly1305"
	default:
		return "unknown"
	}
}

// validCipherValues is the canonical list of strings accepted in the YAML
// `cipher:` field. Kept in one place so the validator and any future help
// text stay in sync. Empty string is also accepted at validation time as a
// synonym for "none" (and is the field's zero-value default).
var validCipherValues = []string{"none", "chacha20poly1305"}

// AEAD returns the outer-AEAD primitive selected by the config and a boolean
// indicating whether an AEAD is actually configured. `none` (and the empty
// default) map to (CipherNone, false); explicit selections map to
// (Cipher<X>, true).
//
// Phase 3 calls this once at startup to construct the AEAD; today no caller
// in the tree consumes it. The method exists here so the call surface is
// stable before Phase 3 lands.
func (c *Conf) AEAD() (Cipher, bool) {
	switch c.Cipher {
	case "", "none":
		return CipherNone, false
	case "chacha20poly1305":
		return CipherChaCha20Poly1305, true
	default:
		// Unknown values are rejected by validate() before we get here,
		// so this branch is defensive. Treat as "no AEAD configured"
		// so callers don't accidentally fall through to enabling
		// encryption with a misparsed selector.
		return CipherNone, false
	}
}
