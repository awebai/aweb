package main

import (
	"testing"

	"github.com/awebai/aw/awid"
)

func TestMemberParentDecision(t *testing.T) {
	const refusal = "this local creator cannot parent a registered global child; use aw id team add-member for the controller's unconditional admission path"
	for _, tc := range []struct {
		name    string
		facts   memberParentFacts
		parents bool
		refusal string
	}{
		{"local member has no parent", memberParentFacts{Scope: awid.IdentityScopeLocal, CreatorChained: true, CreatorStableID: "did:aw:creator"}, false, ""},
		{"chainless creator does not parent", memberParentFacts{Scope: awid.IdentityScopeGlobal}, false, ""},
		{"chained registered creator parents", memberParentFacts{Scope: awid.IdentityScopeGlobal, CreatorChained: true, CreatorStableID: "did:aw:creator"}, true, ""},
		{"chained local creator cannot parent", memberParentFacts{Scope: awid.IdentityScopeGlobal, CreatorChained: true}, false, refusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parents, err := decideMemberParent(tc.facts)
			if tc.refusal != "" {
				if err == nil || err.Error() != tc.refusal || exitCode(err) != 2 {
					t.Fatalf("error=%v, want usage error %q", err, tc.refusal)
				}
				return
			}
			if err != nil || parents != tc.parents {
				t.Fatalf("parents=%t err=%v, want %t", parents, err, tc.parents)
			}
		})
	}
}
