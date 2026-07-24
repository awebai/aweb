package awid

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// TestForgedRotationSpoofsIdentity_Repro demonstrates the aajc.3 vulnerability:
// the DID-log verifier accepts a seq>1 rotation whose authorized_by /
// previous_did_key are keys the attacker fully controls, never binding them to
// the victim's genesis key. A registry-confirmed OK_VERIFIED for a victim's
// did:aw can therefore be produced entirely from attacker-held keys.
//
// After the fix this MUST NOT return OK_VERIFIED: an unanchored seq>1 head can
// only ever be OK_DEGRADED (forcing full-log verification from genesis).
func TestForgedRotationSpoofsIdentity_Repro(t *testing.T) {
	t.Parallel()

	// The victim's genuine genesis key -> the did:aw the attacker wants to steal.
	victimPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	victimStableID := ComputeStableID(victimPub)

	// Attacker keys, unrelated to the victim.
	attackerPrevPub, attackerPrevPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerNewPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	attackerPrevDID := ComputeDIDKey(attackerPrevPub)
	attackerNewDID := ComputeDIDKey(attackerNewPub)
	prevEntryHash := "0000000000000000000000000000000000000000000000000000000000000000"

	// A self-consistent seq-2 "rotation" signed by the attacker's own key,
	// claiming to rotate the victim's did:aw to an attacker-held key.
	forged := signedDidKeyResolution(t, attackerPrevPriv, &DidKeyResolution{
		DIDAW:         victimStableID,
		CurrentDIDKey: attackerNewDID,
		LogHead: &DidKeyEvidence{
			Seq:            2,
			Operation:      "rotate_key",
			PreviousDIDKey: &attackerPrevDID,
			NewDIDKey:      attackerNewDID,
			PrevEntryHash:  &prevEntryHash,
			StateHash:      stableIdentityStateHash(victimStableID, attackerNewDID),
			AuthorizedBy:   attackerPrevDID,
			Timestamp:      "2026-02-22T10:05:00Z",
		},
	})

	outcome, head, err := VerifyDidKeyResolution(forged, nil, time.Unix(0, 0))

	if outcome == StableIdentityVerified {
		t.Fatalf("VULNERABLE: forged rotation accepted as OK_VERIFIED (head=%+v, err=%v)", head, err)
	}
	if outcome != StableIdentityDegraded {
		t.Fatalf("unanchored seq>1 head must be OK_DEGRADED, got %q (err=%v)", outcome, err)
	}
}
