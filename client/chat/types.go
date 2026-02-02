// ABOUTME: Types for the chat protocol layer.
// ABOUTME: Defines events, results, and options used by protocol functions.

package chat

// Event represents an event received during chat (message or read receipt).
type Event struct {
	Type               string `json:"type"`
	Agent              string `json:"agent,omitempty"`
	SessionID          string `json:"session_id,omitempty"`
	MessageID          string `json:"message_id,omitempty"`
	FromAgent          string `json:"from_agent,omitempty"`
	Body               string `json:"body,omitempty"`
	By                 string `json:"by,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Timestamp          string `json:"timestamp,omitempty"`
	SenderLeaving      bool   `json:"sender_leaving,omitempty"`
	ReaderAlias        string `json:"reader_alias,omitempty"`
	HangOn             bool   `json:"hang_on,omitempty"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds,omitempty"`
}

// SendResult is the result of sending a message and optionally waiting for a reply.
type SendResult struct {
	SessionID          string  `json:"session_id"`
	Status             string  `json:"status"` // sent, replied, sender_left, pending, targets_left
	TargetAgent        string  `json:"target_agent,omitempty"`
	Reply              string  `json:"reply,omitempty"`
	Events             []Event `json:"events"`
	Error              string  `json:"error,omitempty"`
	TargetNotConnected bool    `json:"target_not_connected,omitempty"`
	SenderWaiting      bool    `json:"sender_waiting,omitempty"`
	WaitedSeconds      int     `json:"waited_seconds,omitempty"`
}

// OpenResult is the result of opening unread messages for a conversation.
type OpenResult struct {
	SessionID           string  `json:"session_id"`
	TargetAgent         string  `json:"target_agent"`
	Messages            []Event `json:"messages"`
	MarkedRead          int     `json:"marked_read"`
	SenderWaiting       bool    `json:"sender_waiting"`
	UnreadWasEmpty      bool    `json:"unread_was_empty,omitempty"`
	WaitExtendedSeconds int     `json:"wait_extended_seconds,omitempty"`
}

// HistoryResult is the result of fetching chat history.
type HistoryResult struct {
	SessionID string  `json:"session_id"`
	Messages  []Event `json:"messages"`
}

// PendingResult is the result of checking pending conversations.
type PendingResult struct {
	Pending         []PendingConversation `json:"pending"`
	MessagesWaiting int                   `json:"messages_waiting"`
}

// PendingConversation represents a conversation with unread messages.
type PendingConversation struct {
	SessionID            string   `json:"session_id"`
	Participants         []string `json:"participants"`
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	UnreadCount          int      `json:"unread_count"`
	LastActivity         string   `json:"last_activity"`
	SenderWaiting        bool     `json:"sender_waiting"`
	TimeRemainingSeconds *int     `json:"time_remaining_seconds"`
}

// HangOnResult is the result of a hang-on acknowledgment.
type HangOnResult struct {
	SessionID          string `json:"session_id"`
	TargetAgent        string `json:"target_agent"`
	Message            string `json:"message"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

// SendOptions configures message sending behavior.
type SendOptions struct {
	Wait              int  // Seconds to wait for reply (0 = no wait)
	Leaving           bool // Sender is leaving the conversation
	StartConversation bool // Ignore targets_left, use 5min default wait
}

// StatusCallback receives protocol status updates.
// kind is one of: "read_receipt", "hang_on", "wait_extended".
type StatusCallback func(kind string, message string)
