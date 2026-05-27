package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDeriveKeys_KAT pins the PSK -> (encKey, authKey) mapping to known-answer
// values. Any change to the salt, info string, HKDF construction, or the order
// of key extraction will surface as a loud diff here.
//
// Regeneration procedure (use only after a deliberate, intentional change to
// the derivation — bumping protocol version, rotating salt, etc.):
//
//  1. Add a temporary helper test that runs DeriveKeys on the KAT_PSK below
//     and t.Logf's the hex of encKey and authKey.
//  2. `go test -v -run <helper> ./internal/crypto/`
//  3. Paste the new hex strings into encKeyHex / authKeyHex below.
//  4. Delete the helper.
//
// The KAT PSK is exactly 32 bytes of stable ASCII so future devs can
// re-derive without ambiguity over encoding.
func TestDeriveKeys_KAT(t *testing.T) {
	const (
		katPSK     = "ctun-test-psk-known-answer-test!" // 32 bytes
		encKeyHex  = "0185a0633965b8a686d124979d0d57a927be9d1140a8ea02fd34e064b06f2014"
		authKeyHex = "e013b37ab34356b0cb72559726fbec8675e29caf8fae50361a608bafb485cd67"
	)
	if len(katPSK) != 32 {
		t.Fatalf("KAT PSK length drifted: got %d, want 32", len(katPSK))
	}

	wantEnc, err := hex.DecodeString(encKeyHex)
	if err != nil {
		t.Fatalf("decode encKeyHex: %v", err)
	}
	wantAuth, err := hex.DecodeString(authKeyHex)
	if err != nil {
		t.Fatalf("decode authKeyHex: %v", err)
	}

	gotEnc, gotAuth := DeriveKeys([]byte(katPSK))
	if !bytes.Equal(gotEnc[:], wantEnc) {
		t.Errorf("encKey mismatch:\n got  %s\n want %s", hex.EncodeToString(gotEnc[:]), encKeyHex)
	}
	if !bytes.Equal(gotAuth[:], wantAuth) {
		t.Errorf("authKey mismatch:\n got  %s\n want %s", hex.EncodeToString(gotAuth[:]), authKeyHex)
	}
}

// TestDeriveKeys_DistinctOutputs asserts that for several varied PSKs, the
// encryption and authentication keys are not accidentally identical. They
// would only collide if HKDF re-emitted the same 32 bytes for blocks 1 and 2,
// which is cryptographically impossible — this test guards against an
// implementation bug (e.g. reading the same slice twice).
func TestDeriveKeys_DistinctOutputs(t *testing.T) {
	psks := [][]byte{
		[]byte("a"),
		[]byte("ctun"),
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0x00}, 64),
		[]byte("a different production-shaped pre-shared key !!!"),
	}
	for i, psk := range psks {
		enc, auth := DeriveKeys(psk)
		if bytes.Equal(enc[:], auth[:]) {
			t.Errorf("psk[%d] (%q): encKey == authKey, expected distinct outputs", i, psk)
		}
	}
}

// TestDeriveKeys_Deterministic asserts that DeriveKeys is a pure function:
// repeated calls with the same PSK produce byte-identical keys.
func TestDeriveKeys_Deterministic(t *testing.T) {
	psk := []byte("deterministic-test-psk")
	enc1, auth1 := DeriveKeys(psk)
	enc2, auth2 := DeriveKeys(psk)
	if !bytes.Equal(enc1[:], enc2[:]) {
		t.Errorf("encKey non-deterministic:\n call1 %x\n call2 %x", enc1, enc2)
	}
	if !bytes.Equal(auth1[:], auth2[:]) {
		t.Errorf("authKey non-deterministic:\n call1 %x\n call2 %x", auth1, auth2)
	}
}

// TestDeriveKeys_EmptyPSK documents and pins the empty-input contract:
// DeriveKeys must not panic, must return two 32-byte keys, and the two
// returned keys must still differ from each other. HKDF-SHA256 accepts
// empty IKM; security in this case depends entirely on the caller and is
// out of scope here.
func TestDeriveKeys_EmptyPSK(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DeriveKeys panicked on empty PSK: %v", r)
		}
	}()
	enc, auth := DeriveKeys([]byte{})

	// Trivially-zero keys would mean the HKDF reader returned all zeros,
	// which would in turn mean the implementation never wrote to the
	// arrays. Catch that explicitly.
	var zero [32]byte
	if bytes.Equal(enc[:], zero[:]) {
		t.Error("empty-PSK encKey is all zeros — HKDF reader did not write")
	}
	if bytes.Equal(auth[:], zero[:]) {
		t.Error("empty-PSK authKey is all zeros — HKDF reader did not write")
	}
	if bytes.Equal(enc[:], auth[:]) {
		t.Error("empty-PSK encKey == authKey, expected distinct outputs")
	}
}

// TestDeriveKeys_DifferentPSKsDifferentKeys asserts that distinct PSKs map to
// distinct (encKey, authKey) pairs. This is a basic anti-collision check; a
// real collision in HKDF-SHA256 would be a cryptographic-break-level event,
// so this primarily guards against the implementation accidentally ignoring
// the PSK (e.g. always seeding HKDF from a constant).
func TestDeriveKeys_DifferentPSKsDifferentKeys(t *testing.T) {
	enc1, auth1 := DeriveKeys([]byte("psk-one"))
	enc2, auth2 := DeriveKeys([]byte("psk-two"))
	if bytes.Equal(enc1[:], enc2[:]) {
		t.Errorf("encKey identical for distinct PSKs: %x", enc1)
	}
	if bytes.Equal(auth1[:], auth2[:]) {
		t.Errorf("authKey identical for distinct PSKs: %x", auth1)
	}
}
