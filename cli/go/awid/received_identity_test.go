package awid

import (
	"context"
	"encoding/json"
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
			if _, err := c.identityCheckpoint("https://registry.test", "did:aw:sender"); err == nil {
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
			got, _ := c.NormalizeReceivedSender(context.Background(), Verified, ReceivedSender{Alias: "sender", DID: "did:key:sender", StableID: "did:aw:sender", Membership: &SenderMembership{TeamID: tc.team, State: tc.state, MemberDIDAW: tc.stable}})
			if got != tc.want {
				t.Fatalf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

// Same decision matrix as "cross-team received local sender" in channel-core.
func TestReceivedLocalSenderMatrix(t *testing.T) {
	key := "did:key:z6Mkf5qoqVvkppr8VP9wGDqJNZoq1gMQy7KpGAaTZCpypWzH"
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "test-vectors", "trust", "sender-standing-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var standing struct {
		Cases []struct {
			ID     string             `json:"id"`
			State  string             `json:"state"`
			Status VerificationStatus `json:"verification_status"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &standing); err != nil {
		t.Fatal(err)
	}
	if len(standing.Cases) == 0 {
		t.Fatal("sender standing vectors contain no cases")
	}
	type testCase struct {
		name  string
		want  VerificationStatus
		state string
	}
	cases := []testCase{
		{name: "missing", want: VerificationStale}, {name: "unknown", want: VerificationStale},
		{name: "empty-team", want: VerificationStale}, {name: "wrong-team", want: IdentityMismatch},
		{name: "wrong-label", want: IdentityMismatch}, {name: "global-projection", want: IdentityMismatch},
		{name: "wrong-projected-key", want: IdentityMismatch}, {name: "missing-projected-key", want: VerificationStale},
		{name: "failed-signature", want: Failed}, {name: "wrong-recipient", want: IdentityMismatch},
		{name: "plaintext-label", want: Verified}, {name: "qualified-team-label", want: Verified},
	}
	for _, vector := range standing.Cases {
		cases = append(cases, testCase{name: vector.ID, want: vector.Status, state: vector.State})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{resolver: &ChainResolver{Team: &TeamRosterResolver{TeamID: "support:acme.com"}}}
			c.SetPinStore(NewPinStore(), "")
			member := &SenderMembership{TeamID: "outbound:sender.test", State: "active"}
			binding := ReceivedSenderBinding{ProjectedDID: key, TeamID: "outbound:sender.test"}
			status, address := Verified, ""
			if tc.state != "" {
				member.State = tc.state
			}
			switch tc.name {
			case "missing":
				member = nil
			case "unknown":
				member.State = "unknown"
			case "empty-team":
				member.TeamID = ""
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
			got, contact := c.NormalizeReceivedSender(context.Background(), status, ReceivedSender{Address: address, Alias: "alice", DID: key, Membership: member, Binding: &binding})
			if got != tc.want || contact != nil {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if len(c.pinStore.Pins) != 0 || len(c.pinStore.Addresses) != 0 {
				t.Fatal("local sender pinned")
			}
		})
	}
}
