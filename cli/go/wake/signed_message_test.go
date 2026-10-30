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

	"github.com/awebai/aw/awid"
)

var wakeSenderKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

func serveWakeSender(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/v1/agents" {
		return false
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "agents": []map[string]any{{
		"alias": "bob", "did_key": awid.ComputeDIDKey(wakeSenderKey.Public().(ed25519.PublicKey)), "identity_scope": "local",
	}}})
	return true
}

func signedWakeMessage(t *testing.T, message map[string]any) map[string]any {
	t.Helper()
	payload := map[string]any{"from": "bob", "from_did": awid.ComputeDIDKey(wakeSenderKey.Public().(ed25519.PublicKey))}
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
	message["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(wakeSenderKey, []byte(canonical)))
	message["signed_payload"] = canonical
	return message
}

func TestBundledHoldsInvalidSenderUntilVerified(t *testing.T) {
	root := t.TempDir()
	store, _ := NewStore(filepath.Join(root, "state"))
	inputPath := filepath.Join(root, "input.txt")
	var valid atomic.Bool
	var acks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveWakeSender(w, r) {
			return
		}
		if r.Method == http.MethodPost {
			acks.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		message := signedWakeMessage(t, map[string]any{"message_id": "held-mail", "from_alias": "bob", "body": "verified later", "created_at": "2026-01-01T00:00:00Z"})
		if !valid.Load() {
			message["signature"] = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{message}})
	}))
	defer server.Close()
	identity := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	reg := Registration{Home: root, IdentityHome: identity, Delivery: DeliverySession}
	child := NewChannelCoreRunner(store).StartChild(context.Background(), reg, channelCoreChildConfig{OatsBin: writeFakeOATS(t, root, inputPath), AWCommand: writeFakeAW(t, root, "")})
	defer child.Stop()
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.Running })
	event := awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "held-mail"}
	child.Offer(reg.ReceiveBindings()[0], event)
	waitForStatus(t, child, func(st ChannelCoreStatus) bool {
		return st.TraceStage == "lane_job_failed" && strings.Contains(st.LastError, "sender is not verified")
	})
	if data, err := os.ReadFile(inputPath); !os.IsNotExist(err) {
		t.Fatalf("held sender produced input: %q, %v", data, err)
	}
	if acks.Load() != 0 {
		t.Fatal("held sender acknowledged")
	}
	deliveryPath := filepath.Join(identity, "channel-delivered-ids-backend_acme.com.json")
	data, _ := os.ReadFile(deliveryPath)
	if strings.Contains(string(data), "held-mail") {
		t.Fatal("held sender marked delivered")
	}
	valid.Store(true)
	child.Offer(reg.ReceiveBindings()[0], event)
	waitForFileContains(t, inputPath, "verified later")
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.TraceStage == "lane_job_completed" })
	if acks.Load() != 1 {
		t.Fatalf("verified sender ack count: %d", acks.Load())
	}
}
