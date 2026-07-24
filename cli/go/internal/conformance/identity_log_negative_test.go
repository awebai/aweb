package conformance_test

import (
	"encoding/json"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type identityLogNegativeVectors struct {
	Cases []struct {
		Name            string                `json:"name"`
		DIDAW           string                `json:"did_aw"`
		CurrentDIDKey   string                `json:"current_did_key"`
		LogHead         *awid.DidKeyEvidence  `json:"log_head"`
		Cached          *identityLogCachedVec `json:"cached"`
		ExpectedOutcome string                `json:"expected_outcome"`
	} `json:"cases"`
	LogCases []struct {
		Name                  string                `json:"name"`
		DIDAW                 string                `json:"did_aw"`
		Entries               []awid.DidKeyEvidence `json:"entries"`
		ExpectError           bool                  `json:"expect_error"`
		ExpectedCurrentDIDKey string                `json:"expected_current_did_key"`
	} `json:"log_cases"`
}

type identityLogCachedVec struct {
	Seq           int    `json:"seq"`
	EntryHash     string `json:"entry_hash"`
	StateHash     string `json:"state_hash"`
	CurrentDIDKey string `json:"current_did_key"`
}

// TestIdentityLogNegativeVectors runs the shared aajc.3 verifier vectors through
// the Go verifier. The identical vector file drives the TypeScript conformance
// test, keeping the two verifiers byte-for-byte aligned on authorization,
// state-hash, and anchoring semantics.
func TestIdentityLogNegativeVectors(t *testing.T) {
	data := readRootVector(t, "identity-log-negative-v1.json")
	var vectors identityLogNegativeVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 || len(vectors.LogCases) == 0 {
		t.Fatal("expected head and log cases")
	}

	now := time.Unix(0, 0).UTC()
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			res := &awid.DidKeyResolution{
				DIDAW:         c.DIDAW,
				CurrentDIDKey: c.CurrentDIDKey,
				LogHead:       c.LogHead,
			}
			var cached *awid.VerifiedLogHead
			if c.Cached != nil {
				cached = &awid.VerifiedLogHead{
					Seq:           c.Cached.Seq,
					EntryHash:     c.Cached.EntryHash,
					StateHash:     c.Cached.StateHash,
					CurrentDIDKey: c.Cached.CurrentDIDKey,
				}
			}
			outcome, _, err := awid.VerifyDidKeyResolution(res, cached, now)
			if string(outcome) != c.ExpectedOutcome {
				t.Fatalf("outcome=%q want %q (err=%v)", outcome, c.ExpectedOutcome, err)
			}
		})
	}

	for _, c := range vectors.LogCases {
		t.Run(c.Name, func(t *testing.T) {
			head, err := awid.VerifyDidLogEntries(c.DIDAW, c.Entries, now)
			if c.ExpectError {
				if err == nil {
					t.Fatalf("expected error, got head=%+v", head)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if head == nil || head.CurrentDIDKey != c.ExpectedCurrentDIDKey {
				t.Fatalf("head=%+v want current=%q", head, c.ExpectedCurrentDIDKey)
			}
		})
	}
}
