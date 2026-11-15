package main

import (
	"context"
	"testing"

	"github.com/awebai/aw/awid"
)

func whoTestEnrollment(domain string) func(context.Context, string, string) awid.IDTreeEnrollmentResult {
	return func(context.Context, string, string) awid.IDTreeEnrollmentResult {
		return awid.IDTreeEnrollmentResult{State: "enrolled", Domain: &domain}
	}
}

// The frozen chain/status are valid in example.com. Only the independent
// key-route enrollment changes, so a refusal cannot be a broken signature.
func TestWhoPresentedGlobalChainMustMatchEnrollmentDomain(t *testing.T) {
	v := loadWhoVectors(t)
	key := v.Keys["global_agent"]
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["global-agent"].Signed}}
	age := float64(0)
	evidence := &awid.IDChainEvidence{Status: v.Statuses["normal"], AgeSeconds: &age,
		NamespaceAuthority: map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": v.Keys["root"].DIDKey}}
	for _, tc := range []struct{ domain, outcome, reason string }{
		{"example.com", "nearest_human", "verified"},
		{"other.example.com", "unknown", "domain_mismatch"},
		{"", "unavailable", "evidence_unavailable"},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			calls := 0
			out, err := executeWhoReceived(t.Context(), awid.InboxMessage{FromDID: key.DIDKey, FromStableID: key.DIDAW, IDChain: chain, VerificationStatus: awid.Verified}, whoOptions{
				Status: whoFixedStatus{evidence}, TXTResolver: staticTXTResolver{},
				ReceivedEnrollment: func(_ context.Context, id, didKey string) awid.IDTreeEnrollmentResult {
					calls++
					if id != key.DIDAW || didKey != key.DIDKey {
						t.Fatal("enrollment was not bound to the authenticated subject")
					}
					if tc.domain == "" {
						return awid.IDTreeEnrollmentResult{State: "unknown"}
					}
					return awid.IDTreeEnrollmentResult{State: "enrolled", Domain: &tc.domain}
				},
			})
			if err != nil || calls != 1 || out.Outcome != tc.outcome || out.Reason != tc.reason {
				t.Fatalf("out %+v err=%v enrollment calls=%d", out, err, calls)
			}
			if tc.reason == "domain_mismatch" && (out.IdentityValid == nil || *out.IdentityValid || out.HumanID != nil || out.Kind != nil || len(out.Chain) != 0) {
				t.Fatalf("cross-domain presentation established authority: %+v", out)
			}
		})
	}
}
