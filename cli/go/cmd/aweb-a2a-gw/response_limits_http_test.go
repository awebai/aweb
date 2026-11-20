package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awid"
)

type responseLimitProbe struct {
	Name   string
	Limit  int
	Prefix []byte
	Read   func(string) error
}

func encodeLimitPayload(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func responseLimitProbes(t *testing.T) []responseLimitProbe {
	t.Helper()
	card, err := a2a.RootDefaultCard(a2a.CardConfig{Host: "gateway.example", RouteID: "limit", Name: "Response limits", Description: "Response limit controls", Provider: a2a.Provider{Organization: "Aweb", URL: "https://aweb.ai"}, Skills: []a2a.Skill{{ID: "answer", Name: "Answer", Description: "Answer tasks", Tags: []string{"answer"}}}})
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(pub)
	config := managedRuntimeConfigPayload{GatewayID: "gateway", GatewayIdentity: awid.ComputeStableID(pub), GatewayIdentityStatus: "active", Capabilities: []providerCapability{recipientIdentityV1}, ConfigRevision: "limit-test", ExpiresAt: "2099-01-01T00:00:00Z", Routes: []managedRuntimeRoute{}}
	return []responseLimitProbe{
		{Name: "registry-health", Limit: 1 << 20, Prefix: []byte(`{"status":"healthy","version":"0.5.11"}`), Read: func(endpoint string) error {
			health := checkRegistryHealth(endpoint)
			if !health.Compatible {
				return errors.New(health.Error)
			}
			if !health.Reachable || health.Version != "0.5.11" {
				return fmt.Errorf("invalid health projection: %#v", health)
			}
			return nil
		}},
		{Name: "managed-config", Limit: 1 << 20, Prefix: encodeLimitPayload(t, config), Read: func(endpoint string) error {
			cfg := fileConfig{Host: "gateway.example", ManagedConfig: managedConfig{ConfigURL: endpoint + "/config", GatewayID: "gateway", BearerToken: "provider-token"}, ManagedRuntime: managedRuntimeMeta{ConfigRevision: "previous"}}
			if err := applyManagedRuntimeConfig(t.Context(), &cfg); err != nil {
				if cfg.ManagedRuntime.ConfigRevision != "previous" {
					return fmt.Errorf("failed config read mutated its snapshot")
				}
				return err
			}
			if cfg.ManagedRuntime.ConfigRevision != "limit-test" {
				return fmt.Errorf("config snapshot was not installed")
			}
			return nil
		}},
		{Name: "agent-card", Limit: 2 << 20, Prefix: encodeLimitPayload(t, card), Read: func(endpoint string) error {
			got, _, err := a2a.FetchCard(context.Background(), nil, endpoint+a2a.WellKnownAgentCardPath)
			if err != nil {
				return err
			}
			if got.Name != card.Name {
				return fmt.Errorf("card projection changed")
			}
			return a2a.ValidateCard(got, a2a.ValidationOptions{CardPath: a2a.WellKnownAgentCardPath})
		}},
		{Name: "rpc", Limit: 4 << 20, Prefix: []byte(`{"jsonrpc":"2.0","id":"limit-probe","result":{"id":"00000000-0000-4000-8000-000000000001","status":{"state":"TASK_STATE_COMPLETED"}}}`), Read: func(endpoint string) error {
			var task a2a.Task
			err := (&a2a.Client{RequestID: "limit-probe"}).Call(context.Background(), endpoint+"/rpc", a2a.MethodGetTask, map[string]string{"id": "00000000-0000-4000-8000-000000000001"}, a2a.Credential{TaskToken: "task-token"}, &task)
			if err != nil {
				return err
			}
			if task.ID != "00000000-0000-4000-8000-000000000001" || task.Status.State != a2a.TaskStateCompleted {
				return fmt.Errorf("task projection changed: %#v", task)
			}
			return nil
		}},
		{Name: "managed-bridge", Limit: 1 << 20, Prefix: encodeLimitPayload(t, awid.SendMessageResponse{MessageID: "mail", ConversationID: "conversation", RecipientDID: recipientDID, RecipientStableID: awid.ComputeStableID(pub), Status: "delivered"}), Read: func(endpoint string) error {
			cfg := fileConfig{ManagedConfig: managedConfig{BridgeURL: endpoint + "/bridge", GatewayID: "gateway", BearerToken: "provider-token"}, Routes: []routeConfig{{RouteID: "route", Address: "gateway.example/agent"}}}
			transport, err := managedBridgeTransportFromConfig(cfg)
			if err != nil {
				return err
			}
			receipt, err := transport.SendMessage(context.Background(), &awid.SendMessageRequest{ToAddress: "gateway.example/agent", Body: "question"})
			if err != nil {
				return err
			}
			if receipt.MessageID != "mail" || receipt.RecipientDID != recipientDID {
				return fmt.Errorf("receipt projection changed: %#v", receipt)
			}
			return nil
		}},
	}
}

func TestHTTPResponseLimitsRefuseOverflowBesideExactLimitJSON(t *testing.T) {
	for _, probe := range responseLimitProbes(t) {
		for _, boundary := range []struct {
			Name     string
			Suffix   string
			Overflow bool
		}{{Name: "exact-limit"}, {Name: "extra-value", Suffix: "{}", Overflow: true}, {Name: "extra-byte", Suffix: "x", Overflow: true}} {
			t.Run(probe.Name+"/"+boundary.Name, func(t *testing.T) {
				if len(probe.Prefix) > probe.Limit {
					t.Fatal("test payload already exceeds its boundary")
				}
				body := string(probe.Prefix) + strings.Repeat(" ", probe.Limit-len(probe.Prefix)) + boundary.Suffix
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					// An overflowing reader may close the peer before its write completes.
					if _, err := fmt.Fprint(w, body); err != nil && !boundary.Overflow {
						t.Error(err)
					}
				}))
				defer server.Close()
				err := probe.Read(server.URL)
				if boundary.Overflow {
					if err == nil || !strings.Contains(err.Error(), "Reduce the body") {
						t.Fatalf("overflow was accepted or lacks recovery: %v", err)
					}
				} else if err != nil {
					t.Fatalf("exact-limit valid JSON refused: %v", err)
				}
			})
		}
	}
}
