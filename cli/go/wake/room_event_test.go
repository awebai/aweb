package wake

import (
	"github.com/awebai/aw/awid"
	"testing"
)

func TestRoomEventUsesExistingChatReceiveCapabilityAndPreservesRoom(t *testing.T) {
	event := awid.AgentEvent{Type: awid.AgentEventActionableRoomPost, TeamID: "ops:example.test", RoomID: "room", MessageID: "post"}
	class, ok := eventDeliveryClass(event)
	if !ok || class != EventClassChat {
		t.Fatalf("class=%s ok=%v", class, ok)
	}
	converted := agentEventForChannelCore(event)
	if converted["type"] != "room_post" || converted["room_id"] != "room" || converted["team_id"] != "ops:example.test" {
		t.Fatalf("converted=%v", converted)
	}
	mailOnly := ReceiveIdentity{EventClasses: []string{EventClassMail}}
	if mailOnly.allowsEventClass(class) {
		t.Fatal("room notice escaped chat receive scope")
	}
	chat := ReceiveIdentity{EventClasses: []string{EventClassChat}}
	if !chat.allowsEventClass(class) {
		t.Fatal("chat-capable binding refused room notice")
	}
}
