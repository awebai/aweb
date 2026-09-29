package wake

import awid "github.com/awebai/aw/awid"

func eventDeliveryClass(ev awid.AgentEvent) (string, bool) {
	switch string(ev.Type) {
	case string(awid.AgentEventActionableMail), "mail_message":
		return EventClassMail, true
	case string(awid.AgentEventActionableChat), "chat_message":
		return EventClassChat, true
	case string(awid.AgentEventControlInterrupt), string(awid.AgentEventWorkAvailable), string(awid.AgentEventClaimUpdate), string(awid.AgentEventClaimRemoved), string(awid.AgentEventAppEvent):
		return "control", true
	default:
		return "", false
	}
}
