// ABOUTME: Types for the chat protocol layer.
// ABOUTME: Defines events, results, and options used by protocol functions.

package chat

import awid "github.com/awebai/aw/awid"

// Event represents an event received during chat (message or read receipt).
type Event struct {
	IDChain              awid.ReceivedIDChain        `json:"id_chain,omitempty"`
	SignedPayload        string                      `json:"signed_payload,omitempty"`
	Attachments          []awid.AttachmentDescriptor `json:"attachments,omitempty"`
	AttachmentsAvailable bool                        `json:"attachments_available"`
	SenderMembership     *awid.SenderMembership      `json:"sender_membership,omitempty"`
	Type                 string                      `json:"type"`
	Seq                  int64                       `json:"seq,omitempty"`
	Agent                string                      `json:"agent,omitempty"`
	SessionID            string                      `json:"session_id,omitempty"`
	MessageID            string                      `json:"message_id,omitempty"`
	FromAgent            string                      `json:"from_agent,omitempty"`
	FromAddress          string                      `json:"from_address,omitempty"`
	ToAddress            string                      `json:"to_address,omitempty"`
	Body                 string                      `json:"body,omitempty"`
	ContentMode          string                      `json:"content_mode,omitempty"`
	MessageVersion       int                         `json:"message_version,omitempty"`
	By                   string                      `json:"by,omitempty"`
	Reason               string                      `json:"reason,omitempty"`
	Timestamp            string                      `json:"timestamp,omitempty"`
	SenderLeaving        bool                        `json:"sender_leaving,omitempty"`
	SenderWaiting        bool                        `json:"sender_waiting,omitempty"`
	ReaderAlias          string                      `json:"reader_alias,omitempty"`
	ExtendWait           bool                        `json:"hang_on,omitempty"`
	ExtendsWaitSeconds   int                         `json:"extends_wait_seconds,omitempty"`
	ReplyToMessageID     string                      `json:"reply_to_message_id,omitempty"`

	// Identity fields for message verification.
	FromDID                 string                        `json:"from_did,omitempty"`
	ToDID                   string                        `json:"to_did,omitempty"`
	FromStableID            string                        `json:"from_stable_id,omitempty"`
	ToStableID              string                        `json:"to_stable_id,omitempty"`
	Signature               string                        `json:"signature,omitempty"`
	SigningKeyID            string                        `json:"signing_key_id,omitempty"`
	Encrypted               *awid.E2EEMessageEnvelope     `json:"encrypted_envelope,omitempty"`
	RotationAnnouncement    *awid.RotationAnnouncement    `json:"rotation_announcement,omitempty"`
	ReplacementAnnouncement *awid.ReplacementAnnouncement `json:"replacement_announcement,omitempty"`
	VerificationStatus      awid.VerificationStatus       `json:"verification_status,omitempty"`
	IsContact               *bool                         `json:"is_contact,omitempty"`
}

// How a chat send ended: the values of SendResult.Status.
const (
	// SendSent: delivered, with no wait for a reply.
	SendSent = "sent"
	// SendReplied: the target replied.
	SendReplied = "replied"
	// SendSenderLeft: the target replied and left the conversation.
	SendSenderLeft = "sender_left"
	// SendPending: an unread message is waiting in the conversation.
	SendPending = "pending"
	// SendTargetsLeft: the target had already left, so nothing waited.
	SendTargetsLeft = "targets_left"
	// SendTimeout: the wait ended with no reply.
	SendTimeout = "timeout"
)

// Kinds of chat stream event named by this package: values of Event.Type.
const (
	EventMessage                 = "message"
	EventReadReceipt             = "read_receipt"
	EventVerificationUnavailable = "verification_unavailable"
)

// SendResult is the result of sending a message and optionally waiting for a reply.
type SendResult struct {
	SessionID          string  `json:"session_id"`
	MessageID          string  `json:"message_id,omitempty"`
	Status             string  `json:"status"`
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
	SessionID   string  `json:"session_id"`
	TargetAgent string  `json:"target_agent"`
	Messages    []Event `json:"messages"`
	MarkedRead  int     `json:"marked_read"`
	// MarkReadError carries why the acknowledgement failed, for the messages
	// this result presented. Open still succeeds when it is set: the messages
	// were delivered, they were just not acknowledged, so they will be
	// presented again.
	MarkReadError string `json:"mark_read_error,omitempty"`
	// ReceiptError reports a failed local write without losing opened messages
	// or conflating the cache with the server acknowledgement.
	ReceiptError   string `json:"receipt_error,omitempty"`
	SenderWaiting  bool   `json:"sender_waiting"`
	UnreadWasEmpty bool   `json:"unread_was_empty,omitempty"`
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
	ParticipantDIDs      []string `json:"participant_dids,omitempty"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	LastFromStableID     string   `json:"last_from_stable_id,omitempty"`
	LastFromDID          string   `json:"last_from_did,omitempty"`
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

// E2EEChoice is how a chat send chooses end-to-end encryption; it is
// awid's, so chat and mail share one continuation rule.
type E2EEChoice = awid.E2EEChoice

const (
	E2EEInherit   = awid.E2EEInherit
	E2EERequired  = awid.E2EERequired
	E2EEPlaintext = awid.E2EEPlaintext
)

// SendOptions configures message sending behavior.
type SendOptions struct {
	Wait              int        // Seconds to wait for reply (0 = no wait)
	WaitExplicit      bool       // true if caller explicitly set Wait
	Leaving           bool       // Sender is leaving the conversation
	StartConversation bool       // Ignore targets_left, use 5min default wait
	E2EE              E2EEChoice // How the message chooses end-to-end encryption
	// EncryptE2EE is the released (aw-v1.36.58) way to require encryption;
	// true is E2EE: E2EERequired, whatever E2EE says.
	EncryptE2EE bool
	// RecipientDID is the DID the caller confirmed for its one target. An
	// existing session is then selected by this strong identity only.
	RecipientDID string
	// ConfirmedRecipient is what the caller's team roster names for its one
	// alias target; a new session signs it as the recipient binding.
	ConfirmedRecipient *awid.ConfirmedRecipient
}

// Encryption is the end-to-end encryption choice the options make.
func (o SendOptions) Encryption() E2EEChoice {
	return encryptionChoice(o.EncryptE2EE, o.E2EE)
}

func encryptionChoice(encryptE2EE bool, choice E2EEChoice) E2EEChoice {
	if encryptE2EE {
		return E2EERequired
	}
	return choice
}

// StatusCallback receives protocol status updates.
// kind is one of: "read_receipt", "extend_wait", "wait_extended".
type StatusCallback func(kind string, message string)
