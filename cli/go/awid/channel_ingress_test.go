package awid

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestChannelIngressMessageAndEventDecoding(t *testing.T) {
	context := map[string]any{"platform": "msteams", "presence_kind": "shared", "input_origin": "external_human", "confidentiality": "hosted_readable"}
	wire, _ := json.Marshal(map[string]any{"message_id": "m1", "ingress": context})
	for _, message := range []any{&InboxMessage{}, &ChatMessage{}} {
		if err := json.Unmarshal(wire, message); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(message)
		var read map[string]any
		_ = json.Unmarshal(encoded, &read)
		if !reflect.DeepEqual(read["ingress"], context) {
			t.Fatalf("typed message lost ingress: %s", encoded)
		}
	}
	event, ok, err := parseAgentEvent("actionable_mail", string(wire))
	if err != nil || !ok {
		t.Fatalf("mail event: %v", err)
	}
	encoded, _ := json.Marshal(event)
	var read map[string]any
	_ = json.Unmarshal(encoded, &read)
	if !reflect.DeepEqual(read["ingress"], context) {
		t.Fatalf("per-event decoder lost ingress: %s", encoded)
	}
	hint, _, err := parseAgentEvent("actionable_chat", `{"session_id":"s1","ingress":{"platform":"msteams"}}`)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(hint)
	// Do not infer a whole session's classification from a discovery event.
	var hintRead map[string]any
	_ = json.Unmarshal(encoded, &hintRead)
	if _, ok := hintRead["ingress"]; ok {
		t.Fatalf("discovery gained per-message authority: %s", encoded)
	}
}
