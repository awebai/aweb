package awid

import (
	"strings"
	"testing"
	"time"
)

// A DID-log seq must stay inside the JavaScript safe-integer range. Beyond 2^53
// JavaScript cannot distinguish adjacent integers at all, so the TypeScript
// verifier validates with Number.isSafeInteger (default-aamg) and Go must agree
// or the two runtimes disagree about the same log.
//
// This is a DECIDED divergence being closed by tightening the permissive side,
// per the contract rule from default-aajc.9a: the stricter side defines the
// contract unless the permissive behaviour is needed to read what the peer
// actually emits. Neither runtime emits a seq this large — no DID log has 2^53
// entries — so nothing legitimate is affected (default-aamh).
const realDIDKeyForSeqTest = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

func TestDidLogSeqOutsideSafeIntegerRangeIsRefused(t *testing.T) {
	verify := func(seq int) error {
		_, _, err := VerifyDidKeyResolution(&DidKeyResolution{
			DIDAW:         "did:aw:test",
			CurrentDIDKey: realDIDKeyForSeqTest,
			LogHead:       &DidKeyEvidence{Seq: seq, NewDIDKey: realDIDKeyForSeqTest},
		}, nil, time.Now())
		return err
	}

	outcome, _, err := VerifyDidKeyResolution(&DidKeyResolution{
		DIDAW:         "did:aw:test",
		CurrentDIDKey: realDIDKeyForSeqTest,
		LogHead:       &DidKeyEvidence{Seq: maxSafeInteger + 1, NewDIDKey: realDIDKeyForSeqTest},
	}, nil, time.Now())
	if err == nil {
		t.Fatal("a seq above the safe-integer range must be refused")
	}
	if !strings.Contains(err.Error(), "safe integer") {
		t.Errorf("error should name the safe-integer range, got: %v", err)
	}
	if outcome != StableIdentityHardError {
		t.Errorf("outcome=%q, want %q", outcome, StableIdentityHardError)
	}

	// The boundary value itself is inside the range: it must fail for other
	// reasons, never for being out of range.
	if err := verify(maxSafeInteger); err != nil && strings.Contains(err.Error(), "safe integer") {
		t.Errorf("2^53-1 is inside the safe range and must not be refused for it: %v", err)
	}
	// And an ordinary seq is unaffected.
	if err := verify(1); err != nil && strings.Contains(err.Error(), "safe integer") {
		t.Errorf("seq 1 must not be refused for range: %v", err)
	}
}
