package chat

import (
	"encoding/json"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestSignedPayloadSurvivesChatEventProjections(t *testing.T) {
	public, private, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	env := &awid.MessageEnvelope{From: "alice", FromDID: awid.ComputeDIDKey(public), To: "bob", Type: "chat", Body: "body", Timestamp: "2026-10-26T00:00:00Z", Via: "telegram"}
	signature, err := awid.SignMessage(private, env)
	if err != nil {
		t.Fatal(err)
	}
	raw := awid.CanonicalJSON(env)
	data, _ := json.Marshal(map[string]any{"from_agent": "alice", "from_did": env.FromDID, "body": env.Body, "timestamp": env.Timestamp, "signature": signature, "signed_payload": raw, "via": "msteams"})
	streamed := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(data)})
	if streamed.VerificationStatus != awid.Verified {
		t.Fatalf("streamed signature failed: %s", streamed.VerificationStatus)
	}
	messages := buildMessages([]awid.ChatMessage{{FromAgent: "alice", FromDID: env.FromDID, Body: env.Body, Signature: signature, SignedPayload: raw, VerificationStatus: awid.Verified}})
	for _, event := range []Event{streamed, messages[0]} {
		encoded, _ := json.Marshal(event)
		var projected map[string]any
		if err := json.Unmarshal(encoded, &projected); err != nil {
			t.Fatal(err)
		}
		if projected["signed_payload"] != raw {
			t.Fatal("chat event dropped original payload")
		}
		if projected["via"] != "telegram" {
			t.Fatalf("chat event trusted wrapper or lost via: %v", projected["via"])
		}
	}
}
