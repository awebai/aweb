package wake

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Controlled transport reproduction of the installer report's rows 28/29:
// session input can report submitted while a busy harness ignores the text.
// This runs the real bundled child with a local self-custodial team identity;
// OATS input/inspect and the self-hosted post office are external test boundaries.
// It does not establish what a live Codex/Pi process consumed in that incident.
func TestBundledBusyMailRecoversAtIdle(t *testing.T) {
	for _, initiallyBusy := range []bool{false, true} {
		name := "already-idle"
		if initiallyBusy {
			name = "busy-then-idle"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewStore(filepath.Join(root, "state"))
			if err != nil {
				t.Fatal(err)
			}
			busyPath := filepath.Join(root, "busy")
			if initiallyBusy {
				if err := os.WriteFile(busyPath, []byte("busy"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			consumedPath := filepath.Join(root, "consumed")
			inputPath := filepath.Join(root, "inputs")
			oats := filepath.Join(root, "oats")
			script := "#!/bin/sh\n" +
				"if [ \"$1 $2\" = \"session inspect\" ]; then state=idle; [ ! -f " + shellQuoteForTest(busyPath) + " ] || state=working; printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"%s\"}}' \"$state\"; exit 0; fi\n" +
				"if [ \"$1 $2\" = \"session input\" ]; then if [ -f " + shellQuoteForTest(busyPath) + " ]; then cat >> " + shellQuoteForTest(inputPath) + "; else tee -a " + shellQuoteForTest(inputPath) + " >> " + shellQuoteForTest(consumedPath) + "; fi; printf '{\"ok\":true,\"result\":{\"submitted\":true}}'; exit 0; fi\nexit 1\n"
			if err := os.WriteFile(oats, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			var acks atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveBusySender(w, r) {
					return
				}
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
					_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{signedBusyMessage(t, map[string]any{
						"message_id": "busy-brief", "from_alias": "bob", "subject": "builder brief", "body": "begin assigned work", "created_at": "2026-01-01T00:00:00Z",
					})}})
				case r.Method == http.MethodPost && r.URL.Path == "/v1/messages/busy-brief/ack":
					acks.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			identity := writeLocalWakeIdentity(t, root, server.URL)
			reg := Registration{Home: root, IdentityHome: identity, Delivery: DeliverySession}
			child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: oats, AWCommand: writeFakeAW(t, root, "")})
			defer child.Stop()
			waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
			event := awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "busy-brief"}
			child.Offer(reg.ReceiveBindings()[0], event)
			if initiallyBusy {
				waitForStatus(t, child, func(st ChannelCoreStatus) bool {
					return st.TraceStage == "lane_job_completed" || st.TraceStage == "lane_job_failed"
				})
				if err := os.Remove(busyPath); err != nil {
					t.Fatal(err)
				}
				// A reconnect snapshot reoffers the same unread ID after the turn ends.
				child.Offer(reg.ReceiveBindings()[0], event)
			}
			waitForFileContains(t, consumedPath, "begin assigned work")
			waitForCond(t, "idle input acknowledged", func() bool { return acks.Load() == 1 })
			data, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(data), "begin assigned work") != 1 {
				t.Fatalf("brief submitted more than once: %s", data)
			}
		})
	}
}

func writeLocalWakeIdentity(t *testing.T, root, serverURL string) string {
	t.Helper()
	home := filepath.Join(root, ".aw")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	// The HTTP boundary accepts this test certificate; config still checks its
	// team, alias and root-key binding, as in a local self-hosted identity home.
	files := map[string]any{
		"workspace.yaml": map[string]any{"aweb_url": serverURL, "memberships": []any{map[string]any{"team_id": "backend:acme.com"}}},
		"teams.yaml":     map[string]any{"active_team": "backend:acme.com", "memberships": []any{map[string]any{"team_id": "backend:acme.com", "alias": "alice", "cert_path": "cert.json"}}},
		"identity.yaml":  map[string]any{"did": did},
		"cert.json":      map[string]any{"version": 1, "team_id": "backend:acme.com", "member_did_key": did, "alias": "alice", "identity_scope": "local"},
	}
	for name, value := range files {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Confirm the fixture is a root home, never a grant-home substitute.
	if _, err := os.Stat(awconfig.GrantHomeStatePath(home)); !os.IsNotExist(err) {
		t.Fatalf("unexpected grant state: %v", err)
	}
	return home
}

var busySenderKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func serveBusySender(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/v1/agents" {
		return false
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "agents": []map[string]any{{
		"alias": "bob", "did_key": awid.ComputeDIDKey(busySenderKey.Public().(ed25519.PublicKey)), "identity_scope": "local",
	}}})
	return true
}

func signedBusyMessage(t *testing.T, message map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{"from": "bob", "from_did": awid.ComputeDIDKey(busySenderKey.Public().(ed25519.PublicKey))}
	for _, field := range []string{"message_id", "conversation_id", "subject", "body"} {
		if value, ok := message[field]; ok {
			payload[field] = value
		}
	}
	payload["timestamp"] = "2026-01-01T00:00:00Z"
	canonical, err := awid.CanonicalJSONValue(payload)
	if err != nil {
		t.Fatal(err)
	}
	message["from_did"] = payload["from_did"]
	message["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(busySenderKey, []byte(canonical)))
	message["signed_payload"] = canonical
	return message
}
