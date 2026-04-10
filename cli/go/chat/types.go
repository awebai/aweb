// ABOUTME: Types for the chat protocol layer.
// ABOUTME: Defines events, results, and options used by protocol functions.

package chat

import awid "github.com/awebai/aw/awid"

// Event represents an event received during chat (message or read receipt).
type Event struct {
	Type               string `json:"type"`
	Agent              string `json:"agent,omitempty"`
	SessionID          string `json:"session_id,omitempty"`
	MessageID          string `json:"message_id,omitempty"`
	FromAgent          string `json:"from_agent,omitempty"`
	FromAddress        string `json:"from_address,omitempty"`
	ToAddress          string `json:"to_address,omitempty"`
	Body               string `json:"body,omitempty"`
	By                 string `json:"by,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Timestamp          string `json:"timestamp,omitempty"`
	SenderLeaving      bool   `json:"sender_leaving,omitempty"`
	SenderWaiting      bool   `json:"sender_waiting,omitempty"`
	ReaderAlias        string `json:"reader_alias,omitempty"`
	ExtendWait         bool   `json:"hang_on,omitempty"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds,omitempty"`
	ReplyToMessageID   string `json:"reply_to_message_id,omitempty"`

	// Identity fields for message verification.
	FromDID            string `json:"from_did,omitempty"`
	ToDID              string `json:"to_did,omitempty"`
	FromStableID       string `json:"from_stable_id,omitempty"`
	ToStableID         string `json:"to_stable_id,omitempty"`
	Signature              string                    `json:"signature,omitempty"`
	SigningKeyID           string                    `json:"signing_key_id,omitempty"`
	RotationAnnouncement   *awid.RotationAnnouncement `json:"rotation_announcement,omitempty"`
	ReplacementAnnouncement *awid.ReplacementAnnouncement `json:"replacement_announcement,omitempty"`
	VerificationStatus     awid.VerificationStatus    `json:"verification_status,omitempty"`
	IsContact              *bool                      `json:"is_contact,omitempty"`
}

// SendResult is the result of sending a message and optionally waiting for a reply.
type SendResult struct {
	SessionID          string  `json:"session_id"`
	Status             string  `json:"status"` // sent, replied, sender_left, pending, targets_left, timeout
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
	SessionID      string  `json:"session_id"`
	TargetAgent    string  `json:"target_agent"`
	Messages       []Event `json:"messages"`
	MarkedRead     int     `json:"marked_read"`
	SenderWaiting  bool    `json:"sender_waiting"`
	UnreadWasEmpty bool    `json:"unread_was_empty,omitempty"`
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
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	LastFromAddress      string   `json:"last_from_address,omitempty"`
	UnreadCount          int      `json:"unread_count"`
	LastActivity         string   `json:"last_activity"`
	SenderWaiting        bool     `json:"sender_waiting"`
	TimeRemainingSeconds *int     `json:"time_remaining_seconds"`
}

// ExtendWaitResult is the result of an extend-wait acknowledgment.
type ExtendWaitResult struct {
	SessionID          string `json:"session_id"`
	TargetAgent        string `json:"target_agent"`
	Message            string `json:"message"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

// SendOptions configures message sending behavior.
type SendOptions struct {
	Wait              int  // Seconds to wait for reply (0 = no wait)
	WaitExplicit      bool // true if caller explicitly set Wait
	Leaving           bool // Sender is leaving the conversation
	StartConversation bool // Ignore targets_left, use 5min default wait
}

// StatusCallback receives protocol status updates.
// kind is one of: "read_receipt", "extend_wait", "wait_extended".
type StatusCallback func(kind string, message string)
