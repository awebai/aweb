package awid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Malformed persisted checkpoints must not reopen trust or crash a reader.
func TestReceivedCheckpointMalformedFile(t *testing.T) {
	for _, value := range []string{"null", "[]", "{https://registry.test: {did:aw:sender: null}}"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_agents.yaml")
			data := "pins: {}\naddresses: {}\nreceived_identity_heads: " + value + "\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			ps, err := LoadPinStore(path)
			if err != nil {
				t.Fatal(err)
			}
			c := &Client{}
			c.SetPinStore(ps, path)
			if _, err := c.receivedCheckpoint("https://registry.test", "did:aw:sender"); err == nil {
				t.Fatal("malformed persisted checkpoint accepted")
			}
		})
	}
}

// Exercise the real pre-registry classification directly: a different selected
// team provides no proof about this delivery, even when its attestation is active.
func TestReceivedSenderOtherTeamIsUnproven(t *testing.T) {
	c := &Client{resolver: &ChainResolver{
		Team:                 &TeamRosterResolver{TeamID: "selected:example.test"},
		DeliveryTeamRegistry: NewRegistryResolver(nil, nil),
	}}
	for _, tc := range []struct {
		name, team, state, stable string
		want                      VerificationStatus
	}{
		{"other team", "delivery:example.test", "active", "did:aw:sender", VerificationStale},
		{"inactive", "selected:example.test", "inactive", "did:aw:sender", IdentityMismatch},
		{"different member", "selected:example.test", "active", "did:aw:other", IdentityMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := c.NormalizeReceivedSenderTrust(context.Background(), Verified, "", "sender", "did:key:sender", "did:aw:sender", &SenderMembership{TeamID: tc.team, State: tc.state, MemberDIDAW: tc.stable}, nil, nil, nil)
			if got != tc.want {
				t.Fatalf("status = %s, want %s", got, tc.want)
			}
		})
	}
}
