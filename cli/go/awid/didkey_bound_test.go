package awid

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

// DID text longer than its fixed decoded size can encode is refused on its
// length, before base58 decoding. Each refusal names the bound; a text at the
// bound reaches the decoder and fails, if at all, on what it decodes to.

func TestEncodedBoundsAreTheLongestBase58OfTheirByteCount(t *testing.T) {
	t.Parallel()
	// awid's Python did.py derives _DID_KEY_ENCODED_MAX (47) and
	// _STABLE_ID_ENCODED_MAX (28) the same way.
	if got := len(base58.Encode(bytes.Repeat([]byte{0xff}, 2+ed25519.PublicKeySize))); got != didKeyEncodedMax {
		t.Fatalf("did:key bound %d, longest base58 of 34 bytes %d", didKeyEncodedMax, got)
	}
	if didKeyEncodedMax != 47 {
		t.Fatalf("did:key bound %d, want 47 as in awid's Python did.py", didKeyEncodedMax)
	}
	if got := len(base58.Encode(bytes.Repeat([]byte{0xff}, stableIDBytes))); got != stableIDEncodedMax {
		t.Fatalf("did:aw bound %d, longest base58 of 20 bytes %d", stableIDEncodedMax, got)
	}
	if stableIDEncodedMax != 28 {
		t.Fatalf("did:aw bound %d, want 28 as in awid's Python did.py", stableIDEncodedMax)
	}
}

func TestExtractPublicKeyRefusesOverLongEncodingUndecoded(t *testing.T) {
	t.Parallel()
	real := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	if len(strings.TrimPrefix(real, didKeyPrefix)) != didKeyEncodedMax {
		t.Fatalf("a real did:key encodes to %d characters", didKeyEncodedMax)
	}
	if _, err := ExtractPublicKey(real); err != nil {
		t.Fatalf("real did:key at the bound refused: %v", err)
	}

	// At the bound the decoder runs: 47 '1' characters decode to 47 zero bytes.
	_, err := ExtractPublicKey(didKeyPrefix + strings.Repeat("1", didKeyEncodedMax))
	if err == nil || err.Error() != "invalid did:key: expected 34 bytes, got 47" {
		t.Fatalf("text at the bound: err=%v, want the decoded-size refusal", err)
	}

	for _, extra := range []int{1, 100, 20_000} {
		encoded := strings.Repeat("1", didKeyEncodedMax+extra)
		_, err := ExtractPublicKey(didKeyPrefix + encoded)
		want := "invalid did:key: encoding must be at most 47 characters, got " + strconv.Itoa(len(encoded))
		if err == nil || err.Error() != want {
			t.Fatalf("over-long by %d: err=%v, want %q", extra, err, want)
		}
	}
}

func TestDecodeStableIDRefusesOverLongSuffixUndecoded(t *testing.T) {
	t.Parallel()
	longest := base58.Encode(bytes.Repeat([]byte{0xff}, stableIDBytes))
	decoded, err := DecodeStableID(longest)
	if err != nil || !bytes.Equal(decoded, bytes.Repeat([]byte{0xff}, stableIDBytes)) {
		t.Fatalf("longest did:aw suffix: decoded=%x err=%v", decoded, err)
	}
	if !idCertificateIDValid("did:aw:"+longest, false) {
		t.Fatal("certificate id with the longest did:aw suffix refused")
	}

	// At the bound the decoder runs: 28 '1' characters decode to 28 zero bytes.
	_, err = DecodeStableID(strings.Repeat("1", stableIDEncodedMax))
	if err == nil || err.Error() != "invalid did:aw: expected 20 bytes, got 28" {
		t.Fatalf("suffix at the bound: err=%v, want the decoded-size refusal", err)
	}

	for _, extra := range []int{1, 100, 20_000} {
		suffix := strings.Repeat("1", stableIDEncodedMax+extra)
		_, err := DecodeStableID(suffix)
		want := "invalid did:aw: encoding must be at most 28 characters, got " + strconv.Itoa(len(suffix))
		if err == nil || err.Error() != want {
			t.Fatalf("over-long by %d: err=%v, want %q", extra, err, want)
		}
		if idCertificateIDValid("did:aw:"+suffix, false) {
			t.Fatalf("certificate id over-long by %d accepted", extra)
		}
	}
}
