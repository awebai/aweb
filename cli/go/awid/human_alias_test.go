package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHumanAliasScopedEncryptionDiscovery(t *testing.T) {
	for _, kind := range []string{"mail", "chat"} {
		for _, scenario := range []string{"valid", "missing", "invalid", "wrong-team"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				pub, priv, _ := ed25519.GenerateKey(nil)
				did, stable := ComputeDIDKey(pub), ComputeStableID(pub)
				assertion := testEncryptionAssertion(t, priv, did, stable)
				if scenario == "missing" {
					assertion = nil
				}
				if scenario == "invalid" {
					assertion.Signature = "invalid"
				}
				team := "backend:example.test"
				returnedTeam := team
				if scenario == "wrong-team" {
					returnedTeam = "other:example.test"
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/v1/agents":
						_ = json.NewEncoder(w).Encode(ListAgentsResponse{TeamID: team, Agents: []AgentView{}})
					case "/v1/messaging/participants/juan":
						_ = json.NewEncoder(w).Encode(map[string]any{"alias": "juan", "team_id": returnedTeam, "did_key": did, "did_aw": stable, "agent_type": "human", "status": "active", "encryption_key": assertion})
					default:
						t.Errorf("unexpected path %s", r.URL.Path)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				client, err := New(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				client.teamID = team
				var recipient E2EERecipientKey
				if kind == "mail" {
					recipient, err = client.e2eeMailRecipient(context.Background(), &SendMessageRequest{ToAlias: "juan"})
				} else {
					var recipients []E2EERecipientKey
					recipients, err = client.e2eeChatRecipients(context.Background(), []string{"juan"}, nil, nil)
					if err == nil {
						if len(recipients) != 1 {
							t.Fatalf("unexpected recipients %+v", recipients)
						}
						recipient = recipients[0]
					}
				}
				if scenario != "valid" {
					if err == nil {
						t.Fatalf("%s accepted", scenario)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if recipient.DID != did || recipient.StableID != stable || recipient.Address != "" || recipient.DeliveryOrigin != "" {
					t.Fatalf("unexpected recipient %+v", recipient)
				}
			})
		}
	}
}
