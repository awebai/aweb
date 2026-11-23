package main

import (
	"context"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestMembershipChainComparisonKeepsEncodingFailuresDistinctFromChangedChains(t *testing.T) {
	vectors := loadWhoVectors(t)
	selected := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{vectors.Certificates["alice"].Signed}}
	another := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{vectors.Certificates["alice"].Signed, vectors.Certificates["coordinator"].Signed}}
	for _, bundle := range []map[string]any{selected, another} {
		if _, err := awid.EncodeIDChainHeader(bundle); err != nil {
			t.Fatalf("published chain witness did not encode: %v", err)
		}
	}
	invalid := map[string]any{"v": 2}
	for _, scenario := range []struct {
		Name     string
		Expected map[string]any
		Actual   map[string]any
		Prefix   string
		Code     string
		Action   string
	}{
		{Name: "same signed chain", Expected: selected, Actual: selected},
		{Name: "selected encoding fails", Expected: invalid, Actual: selected, Prefix: "encode selected membership chain:", Code: "invalid_shape", Action: "restore the selected identity's original chain and retry the same invite"},
		{Name: "returned encoding fails", Expected: selected, Actual: invalid, Prefix: "encode accepted membership chain:", Code: "invalid_shape", Action: "ask the service operator to repair its chain response before retrying"},
		{Name: "successful encodings differ", Expected: selected, Actual: another, Prefix: "membership-only acceptance changed the original chain", Action: "ask the service operator to return the selected chain before retrying"},
	} {
		t.Run(scenario.Name, func(t *testing.T) {
			retained := &awid.IDChainResult{Outcome: "unknown", Reason: "retained-membership"}
			response := &awid.SpawnAcceptInviteResponse{IDTreeCreationResponse: awid.IDTreeCreationResponse{IDChain: awid.ReceivedIDChain(scenario.Actual)}}
			result, err := verifyHostedInviteAcceptedAttribution(context.Background(), hostedInviteAcceptedResponseRequest{
				Acceptance:       hostedInviteAcceptanceRequest{Creation: &hostedInviteCreation{MembershipChain: scenario.Expected}},
				Response:         response,
				Registry:         awid.NewAWIDRegistryClient(nil, nil),
				MembershipResult: retained,
			})
			if scenario.Prefix == "" {
				if err != nil || result != retained {
					t.Fatalf("unchanged verified chain lost retained result: %v", err)
				}
				return
			}
			if err == nil || result != nil || !strings.HasPrefix(err.Error(), scenario.Prefix) || awid.IDCertificateErrorCode(err) != scenario.Code || !strings.HasSuffix(err.Error(), scenario.Action) {
				t.Fatalf("encoding and mismatch outcomes lost their distinct cause/action: %v", err)
			}
		})
	}
}
