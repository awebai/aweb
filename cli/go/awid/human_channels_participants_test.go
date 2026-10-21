package awid

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestHumanChannelsParticipantSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-participants-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Derivations []struct {
			Name             string
			KeyHex           string `json:"key_hex"`
			Bridge, Platform string
			AccountScope     string `json:"account_scope"`
			AccountID        string `json:"account_id"`
			SubjectKind      string `json:"subject_kind"`
			Generation       string
			SessionID        string `json:"session_id"`
			Expected         HumanChannelsParticipant
		}
		Projections []struct {
			Name                string
			ExpectedSession     string                   `json:"expected_session"`
			ExpectedParticipant HumanChannelsParticipant `json:"expected_participant"`
			Group               HumanChannelsGroupContext
			SignerPrincipal     string `json:"signer_principal"`
			SignerVerified      bool   `json:"signer_verified"`
			Confidentiality     string
			Expected            map[string]any
			Error               string
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Derivations {
		t.Run(c.Name, func(t *testing.T) {
			key, err := hex.DecodeString(c.KeyHex)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := DeriveHumanChannelsGuestReference(key, HumanChannelsGuestDerivation{Bridge: c.Bridge, Platform: c.Platform, AccountScope: c.AccountScope, AccountID: c.AccountID, SubjectKind: c.SubjectKind, Generation: c.Generation, SessionID: c.SessionID})
			if err != nil || ref != c.Expected {
				t.Fatalf("derivation mismatch: %#v %v", ref, err)
			}
		})
	}
	for _, c := range fixture.Projections {
		t.Run(c.Name, func(t *testing.T) {
			result, err := ProjectHumanChannelsSessionAuthor(c.ExpectedSession, c.ExpectedParticipant, c.Group, c.SignerPrincipal, c.SignerVerified, c.Confidentiality)
			if c.Error != "" {
				var refusal *HumanChannelsContractError
				if !errors.As(err, &refusal) || refusal.Code != c.Error {
					t.Fatalf("wanted %s: %v", c.Error, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(result.Value, c.Expected) {
				t.Fatalf("projection mismatch: %#v %v", result.Value, err)
			}
		})
	}
}

func TestHumanChannelsNativeParticipantDTOCompatibility(t *testing.T) {
	for _, raw := range []string{`{"did":"did:aw:alice","alias":"Alice"}`, `{"did":"did:aw:alice","alias":"Alice","participant_ref":{"kind":"native","did":"did:aw:alice"}}`} {
		var p ChatParticipant
		if err := json.Unmarshal([]byte(raw), &p); err != nil || p.DID != "did:aw:alice" {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`{"alias":"same","participant_ref":{"kind":"bridged","bridge":"did:aw:bridge","subject":"guest-1"}}`, `{"did":"did:aw:alice","participant_ref":{"kind":"native","did":"did:aw:bob"}}`} {
		var p ChatParticipant
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Fatal("legacy DTO accepted a managed or mismatched participant")
		}
	}
}
