package awid

import "testing"

func TestRoomEventCarriesRoomBindingWithoutMailOrChatState(t *testing.T) {
	raw := `{"type":"actionable_room_post","team_id":"ops:example.test","room_id":"room","message_id":"post","agent_id":"member","from_alias":"alice","subject":"Update"}`
	event, ok, err := parseAgentEvent("actionable_room_post", raw)
	if err != nil || !ok || event.Type != AgentEventActionableRoomPost || event.TeamID != "ops:example.test" || event.RoomID != "room" || event.MessageID != "post" || event.FromAlias != "alice" || event.Subject != "Update" || event.SenderWaiting || event.SessionID != "" {
		t.Fatalf("event=%+v ok=%v err=%v", event, ok, err)
	}
}
