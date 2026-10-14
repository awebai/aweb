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

// Same decision matrix as "cross-team received local sender" in channel-core.
func TestReceivedLocalSenderMatrix(t *testing.T) {
	key := "did:key:z6Mkf5qoqVvkppr8VP9wGDqJNZoq1gMQy7KpGAaTZCpypWzH"
	for _, tc := range []struct {
		name string
		want VerificationStatus
	}{
		{"active", Verified}, {"missing", VerificationStale}, {"unknown", VerificationStale},
		{"empty-team", VerificationStale}, {"inactive", IdentityMismatch}, {"wrong-team", IdentityMismatch}, {"wrong-label", IdentityMismatch},
		{"global-projection", IdentityMismatch}, {"wrong-projected-key", IdentityMismatch},
		{"missing-projected-key", VerificationStale}, {"failed-signature", Failed},
		{"wrong-recipient", IdentityMismatch}, {"plaintext-label", Verified}, {"qualified-team-label", Verified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{resolver: &ChainResolver{Team: &TeamRosterResolver{TeamID: "support:acme.com"}}}
			c.SetPinStore(NewPinStore(), "")
			member := &SenderMembership{TeamID: "outbound:sender.test", State: "active"}
			binding := ReceivedSenderBinding{ProjectedDID: key, TeamID: "outbound:sender.test"}
			status, address := Verified, ""
			switch tc.name {
			case "missing":
				member = nil
			case "unknown":
				member.State = "unknown"
			case "empty-team":
				member.TeamID = ""
			case "inactive":
				member.State = "inactive"
			case "wrong-team":
				member.TeamID = "another:another.test"
			case "wrong-label":
				address = "wrong.test/alice"
			case "global-projection":
				member.MemberDIDAW = "did:aw:sender"
			case "wrong-projected-key":
				binding.ProjectedDID = "did:key:other"
			case "missing-projected-key":
				binding.ProjectedDID = ""
			case "failed-signature":
				status = Failed
			case "wrong-recipient":
				status = IdentityMismatch
			case "plaintext-label":
				address = "sender.test/alice"
				binding.TeamID = ""
			case "qualified-team-label":
				address = "outbound:sender.test/alice"
				binding.TeamID = ""
			}
			got, contact := c.NormalizeReceivedSenderTrust(context.Background(), status, address, "alice", key, "", member, nil, nil, nil, binding)
			if got != tc.want || contact != nil {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if len(c.pinStore.Pins) != 0 || len(c.pinStore.Addresses) != 0 {
				t.Fatal("local sender pinned")
			}
		})
	}
}
