package chat

import (
	"encoding/json"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestReceivedProofSurvivesChatProjection(t *testing.T) {
	payload := `{"from_did":"did:key:sender","type":"chat"}`
	bundle := awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{}}
	wire, err := json.Marshal(map[string]any{"signed_payload": payload, "id_chain": bundle})
	if err != nil {
		t.Fatal(err)
	}
	events := map[string]Event{
		"history": buildMessages([]awid.ChatMessage{{SignedPayload: payload, IDChain: bundle}})[0],
		"stream":  parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(wire)}),
	}
	for name, event := range events {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			expected, _ := json.Marshal(payload)
			if string(got["signed_payload"]) != string(expected) {
				t.Fatalf("signed proof dropped: %s", raw)
			}
			expected, _ = json.Marshal(bundle)
			if string(got["id_chain"]) != string(expected) {
				t.Fatalf("chain carrier dropped: %s", raw)
			}
		})
	}
}
