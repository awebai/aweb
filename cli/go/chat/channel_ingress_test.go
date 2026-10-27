package chat

import (
	"encoding/json"
	"github.com/awebai/aw/awid"
	"reflect"
	"testing"
)

func TestChannelIngressEventProjections(t *testing.T) {
	context := map[string]any{"platform": "msteams", "presence_kind": "shared", "input_origin": "external_human", "confidentiality": "hosted_readable"}
	wire, _ := json.Marshal(map[string]any{"type": "message", "message_id": "m1", "body": "body", "ingress": context})
	streamed := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(wire)})
	var message awid.ChatMessage
	if err := json.Unmarshal(wire, &message); err != nil {
		t.Fatal(err)
	}
	for _, status := range []awid.VerificationStatus{awid.Verified, awid.Failed, awid.Unverified} {
		message.VerificationStatus = status
		for _, event := range []Event{streamed, buildMessages([]awid.ChatMessage{message})[0]} {
			encoded, _ := json.Marshal(event)
			var read map[string]any
			_ = json.Unmarshal(encoded, &read)
			if !reflect.DeepEqual(read["ingress"], context) {
				t.Fatalf("ingress lost at %s: %s", status, encoded)
			}
		}
	}
}
