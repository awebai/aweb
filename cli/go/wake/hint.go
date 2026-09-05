package wake

import (
	"strings"
	"time"

	awid "github.com/awebai/aw/awid"
)

// Kind is the class of coordination item a hint announces.
type Kind string

const (
	KindMail         Kind = "mail"
	KindChat         Kind = "chat"
	KindControl      Kind = "control"
	KindWork         Kind = "work"
	KindClaim        Kind = "claim"
	KindClaimRemoved Kind = "claim_removed"
	KindApp          Kind = "app"
	KindReconnect    Kind = "reconnect"
)

// Intent is the delivery intent channel-core assigns per event kind
// (docs/receiving-events.md, docs/terminal-wake-broker.md §2).
type Intent string

const (
	IntentWake    Intent = "wake"
	IntentSteer   Intent = "steer"
	IntentAmbient Intent = "ambient"
)

// Hint is what the broker knows about one waiting item: metadata and counts,
// never content.
//
// The absence of Subject, Body, Text and Payload fields is the design, not an
// omission. The broker never fetches, decrypts or types a sender's content
// (§1, §6), so the composer is structurally unable to leak one: there is
// nowhere for it to arrive. Adding such a field would silently defeat the
// composition test, which can only assert about the values it is given.
type Hint struct {
	Kind           Kind      `json:"kind"`
	Intent         Intent    `json:"intent"`
	MessageID      string    `json:"message_id,omitempty"`
	ConversationID string    `json:"conversation_id,omitempty"`
	SignalID       string    `json:"signal_id,omitempty"`
	EventID        string    `json:"event_id,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
	TaskID         string    `json:"task_id,omitempty"`
	AppID          string    `json:"app_id,omitempty"`
	AppEventType   string    `json:"app_event_type,omitempty"`
	From           string    `json:"from,omitempty"`
	SenderWaiting  bool      `json:"sender_waiting,omitempty"`
	At             time.Time `json:"at"`

	// Transient marks a hint that is never persisted. A control signal is an
	// at-most-once wake signal (docs/receiving-events.md); one consumed during
	// an SSE gap is lost, which the note states plainly rather than designing
	// around (§4). Persisting it would turn a lost transient into a durable
	// replay it never promised.
	Transient bool `json:"-"`
}

// DedupeKey identifies a hint inside the pending set.
//
// The key is the kind plus whichever id the event carried — message, signal,
// event, session, conversation, task — matching §4's coalescing key. It exists
// so a burst does not queue the same item twice *while it is pending*. It is
// never a presented mark: the pending set is emptied on a submission attempt
// that reached the terminal, so the same id may legitimately arrive again
// later and produce another rate-limited reminder (§4, §6).
func (h Hint) DedupeKey() string {
	id := firstNonEmpty(h.MessageID, h.SignalID, h.EventID, h.SessionID, h.ConversationID, h.TaskID)
	if id == "" {
		// Nothing identifying: keep it, keyed on arrival, rather than
		// collapsing unrelated items onto one key.
		return string(h.Kind) + "|@" + h.At.UTC().Format(time.RFC3339Nano)
	}
	return string(h.Kind) + "|" + id
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// HintFromEvent converts a stream event into a hint.
//
// It accepts both spellings of mail and chat: the wire names actionable_mail
// and actionable_chat, and channel-core's normalised mail_message and
// chat_message (§2). Events that carry no waiting item — connected, error, and
// the control pause/resume signals, which change durable broker state rather
// than announcing work — return false.
func HintFromEvent(ev awid.AgentEvent, now time.Time) (Hint, bool) {
	base := Hint{At: now}
	switch string(ev.Type) {
	case string(awid.AgentEventActionableMail), "mail_message":
		base.Kind = KindMail
		base.Intent = IntentWake
		base.MessageID = ev.MessageID
		base.ConversationID = ev.ConversationID
		base.From = ev.FromAlias
		return base, true

	case string(awid.AgentEventActionableChat), "chat_message":
		base.Kind = KindChat
		base.Intent = IntentWake
		if ev.SenderWaiting {
			base.Intent = IntentSteer
		}
		base.MessageID = ev.MessageID
		base.ConversationID = ev.ConversationID
		base.SessionID = ev.SessionID
		base.From = ev.FromAlias
		base.SenderWaiting = ev.SenderWaiting
		return base, true

	case string(awid.AgentEventControlInterrupt):
		base.Kind = KindControl
		base.Intent = IntentSteer
		base.SignalID = ev.SignalID
		base.From = ev.FromAlias
		base.Transient = true
		return base, true

	case string(awid.AgentEventWorkAvailable):
		base.Kind = KindWork
		base.Intent = IntentAmbient
		base.TaskID = ev.TaskID
		return base, true

	case string(awid.AgentEventClaimUpdate):
		base.Kind = KindClaim
		base.Intent = IntentAmbient
		base.TaskID = ev.TaskID
		return base, true

	case string(awid.AgentEventClaimRemoved):
		base.Kind = KindClaimRemoved
		base.Intent = IntentAmbient
		base.TaskID = ev.TaskID
		return base, true

	case string(awid.AgentEventAppEvent):
		base.Kind = KindApp
		base.Intent = normalizeIntent(ev.DeliveryIntent)
		base.EventID = ev.EventID
		base.AppID = ev.AppID
		base.AppEventType = ev.AppEventType
		return base, true

	case string(awid.AgentEventChannelReconnected):
		// One catch-up hint after an outage, not one per missed message (§6).
		base.Kind = KindReconnect
		base.Intent = IntentWake
		return base, true

	default:
		// connected, error, control_pause, control_resume, and anything a
		// future server adds: no waiting item to announce.
		return Hint{}, false
	}
}

func normalizeIntent(raw string) Intent {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "wake":
		return IntentWake
	case "steer":
		return IntentSteer
	default:
		return IntentAmbient
	}
}

// batchRank orders a batch interrupt, communication, coordination (§4). The
// bands are the ones cli/go/run/eventbus.go already classifies events into, so
// a reader comparing the two sees the same three groups.
func batchRank(h Hint) int {
	switch h.Kind {
	case KindControl:
		return 0
	case KindMail, KindChat, KindReconnect:
		return 1
	case KindApp:
		if h.Intent == IntentWake || h.Intent == IntentSteer {
			return 1
		}
		return 2
	default:
		return 2
	}
}
