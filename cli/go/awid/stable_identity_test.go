package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func TestVerifyDidKeyResolutionVerified(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	res := signedDidKeyResolution(t, priv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did,
		LogHead: &DidKeyEvidence{
			Seq:          1,
			Operation:    "create",
			NewDIDKey:    did,
			StateHash:    "5d00a7ffa63b444a8515c2cbd9fd6ca0ab12fd97ac49cc359316833cf5c71976",
			AuthorizedBy: did,
			Timestamp:    "2026-02-22T10:00:00Z",
		},
	})

	outcome, head, err := VerifyDidKeyResolution(res, nil, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != StableIdentityVerified {
		t.Fatalf("Outcome=%q", outcome)
	}
	if head == nil || head.Seq != 1 {
		t.Fatalf("head=%+v", head)
	}
}

func TestVerifyDidKeyResolutionDegradedWithoutLogHead(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	outcome, head, err := VerifyDidKeyResolution(&DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did,
	}, nil, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != StableIdentityDegraded {
		t.Fatalf("Outcome=%q", outcome)
	}
	if head != nil {
		t.Fatalf("head=%+v", head)
	}
}

func TestVerifyDidKeyResolutionHardErrorOnCurrentKeyMismatch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	res := signedDidKeyResolution(t, priv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: ComputeDIDKey(otherPub),
		LogHead: &DidKeyEvidence{
			Seq:          1,
			Operation:    "create",
			NewDIDKey:    did,
			StateHash:    "5d00a7ffa63b444a8515c2cbd9fd6ca0ab12fd97ac49cc359316833cf5c71976",
			AuthorizedBy: did,
			Timestamp:    "2026-02-22T10:00:00Z",
		},
	})

	outcome, _, err := VerifyDidKeyResolution(res, nil, time.Unix(0, 0))
	if err == nil {
		t.Fatal("expected hard-error mismatch")
	}
	if outcome != StableIdentityHardError {
		t.Fatalf("Outcome=%q", outcome)
	}
}

func TestVerifyDidKeyResolutionDegradedOnSeqGap(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	prev := "43b58a1ad5397eae908526b7c32db68e4a39bbe00b5dd74f969ae463814c440c"
	oldDid := did
	res := signedDidKeyResolution(t, priv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did,
		LogHead: &DidKeyEvidence{
			Seq:            3,
			Operation:      "rotate_key",
			PreviousDIDKey: &oldDid,
			NewDIDKey:      did,
			PrevEntryHash:  &prev,
			StateHash:      "8ee240bac1f366d008e77b006f8d9f0f7ea43a6bf69b46aa3e33f2525255a8ce",
			AuthorizedBy:   did,
			Timestamp:      "2026-02-22T10:05:00Z",
		},
	})

	outcome, _, err := VerifyDidKeyResolution(res, &VerifiedLogHead{
		Seq:           1,
		EntryHash:     "2da1337ba85e47b9655f7df960cff5cb6c1ba46f74493ce23f84abe5ca0b8659",
		StateHash:     "5d00a7ffa63b444a8515c2cbd9fd6ca0ab12fd97ac49cc359316833cf5c71976",
		CurrentDIDKey: did,
	}, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != StableIdentityDegraded {
		t.Fatalf("Outcome=%q", outcome)
	}
}

func TestVerifyDidKeyResolutionHardErrorOnRegression(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	res := signedDidKeyResolution(t, priv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did,
		LogHead: &DidKeyEvidence{
			Seq:          1,
			Operation:    "create",
			NewDIDKey:    did,
			StateHash:    "5d00a7ffa63b444a8515c2cbd9fd6ca0ab12fd97ac49cc359316833cf5c71976",
			AuthorizedBy: did,
			Timestamp:    "2026-02-22T10:00:00Z",
		},
	})

	outcome, _, err := VerifyDidKeyResolution(res, &VerifiedLogHead{
		Seq:           2,
		EntryHash:     "1cd9f3f8d49a23d3f04516c6d9d89c51ef9c4a242bf114a8477bcfca556932a7",
		StateHash:     "1705b185e47b30672ba7f40490b911c43936c0e465436e3ab7b44438392ba014",
		CurrentDIDKey: did,
	}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("expected regression error")
	}
	if outcome != StableIdentityHardError {
		t.Fatalf("Outcome=%q", outcome)
	}
}

func signedDidKeyResolution(t *testing.T, priv ed25519.PrivateKey, res *DidKeyResolution) *DidKeyResolution {
	t.Helper()
	payload := CanonicalDidLogPayload(res.DIDAW, res.LogHead)
	sum := sha256Hex([]byte(payload))
	res.LogHead.EntryHash = sum
	res.LogHead.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	return res
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
