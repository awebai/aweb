package main

import (
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// A message to an alias the agent list confirms signs the identity the list
// names; a row that names none cannot be confirmed and refuses.
func TestAgentListRecipientIsTheRowsIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		agent   awid.AgentView
		want    awid.ConfirmedRecipient
		refuses bool
	}{
		{name: "global member", agent: awid.AgentView{Alias: "juan", DIDKey: "did:key:z6Mkjuan", DIDAW: "did:aw:juan"}, want: awid.ConfirmedRecipient{DID: "did:key:z6Mkjuan", StableID: "did:aw:juan"}},
		{name: "local member", agent: awid.AgentView{Alias: "juan", DIDKey: "did:key:z6Mkjuan"}, want: awid.ConfirmedRecipient{DID: "did:key:z6Mkjuan"}},
		{name: "no identity", agent: awid.AgentView{Alias: "juan"}, refuses: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agentListRecipient("juan", tc.agent)
			if tc.refuses {
				if err == nil || !strings.Contains(err.Error(), `cannot confirm recipient "juan"`) {
					t.Fatalf("recipient=%+v err=%v, want a refusal naming juan", got, err)
				}
				return
			}
			if err != nil || *got != tc.want {
				t.Fatalf("recipient=%+v err=%v, want %+v", got, err, tc.want)
			}
		})
	}
}
