package awid

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// PlaintextIntoEncryptedNotice is what aw says when --plaintext sends into a
// conversation that carries end-to-end encrypted messages.
const PlaintextIntoEncryptedNotice = "sending server-readable plaintext into an end-to-end encrypted conversation (--plaintext)"

// ConversationEncryption is what a conversation's stored rows show about its
// end-to-end encryption.
type ConversationEncryption string

const (
	// ConversationEncrypted: a stored row is end-to-end encrypted.
	ConversationEncrypted ConversationEncryption = "encrypted"
	// ConversationPlaintext: every stored row was read and none is encrypted.
	ConversationPlaintext ConversationEncryption = "plaintext"
	// ConversationEncryptionUnknown: the rows that would show it cannot be
	// read, or the widest page the server returns is full without an
	// encrypted row, so an older one may be.
	ConversationEncryptionUnknown ConversationEncryption = "unknown"
)

// ConversationEncryptionReading is a conversation's encryption and, when it
// is unknown, why.
type ConversationEncryptionReading struct {
	State  ConversationEncryption
	Reason string
}

// The widest page of a conversation's latest rows that every released server
// returns: chat history has accepted limit up to 2000 since server-v1.0.0,
// and the mail conversation route up to 500 since it shipped.
const (
	chatEncryptionPage = 2000
	mailEncryptionPage = 500
)

// storedEncryptionRow is the part of a stored chat or mail row that shows
// whether it is end-to-end encrypted.
type storedEncryptionRow struct {
	ContentMode    string               `json:"content_mode"`
	MessageVersion int                  `json:"message_version"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope"`
}

type storedEncryptionPage struct {
	Messages []storedEncryptionRow `json:"messages"`
	HasMore  bool                  `json:"has_more"`
}

// StoredRowEncrypted reports whether a stored chat or mail row is end-to-end
// encrypted, from the row as the server returns it.
func StoredRowEncrypted(contentMode string, messageVersion int, envelope *E2EEMessageEnvelope) bool {
	return contentMode == ContentModeEncryptedV2 || messageVersion == E2EEMessageVersion || envelope != nil
}

// ChatSessionEncryption reads a chat session's latest stored rows to learn
// whether it is end-to-end encrypted, decrypting nothing, so it needs no
// key. A continuation inherits the answer.
func (c *Client) ChatSessionEncryption(ctx context.Context, sessionID string) (ConversationEncryptionReading, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(strings.TrimSpace(sessionID)) + "/messages?limit=" + itoa(chatEncryptionPage)
	return c.readConversationEncryption(ctx, path, chatEncryptionPage, false)
}

// MailConversationEncryption reads a mail conversation's latest stored rows
// to learn whether it is end-to-end encrypted. A server that answers the
// route itself as not found predates the conversation route
// (server-v1.19.0) and so end-to-end encryption (server-v1.26.0): its
// conversations are plaintext.
func (c *Client) MailConversationEncryption(ctx context.Context, conversationID string) (ConversationEncryptionReading, error) {
	path := "/v1/messages/conversations/" + urlPathEscape(strings.TrimSpace(conversationID)) + "?limit=" + itoa(mailEncryptionPage)
	return c.readConversationEncryption(ctx, path, mailEncryptionPage, true)
}

func (c *Client) readConversationEncryption(ctx context.Context, path string, page int, routeMissingIsPlaintext bool) (ConversationEncryptionReading, error) {
	var out storedEncryptionPage
	if err := c.Get(ctx, path, &out); err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			return ConversationEncryptionReading{}, err
		}
		switch {
		case routeMissingIsPlaintext && apiErr.StatusCode == http.StatusNotFound && strings.TrimSpace(apiErr.Body) == `{"detail":"Not Found"}`:
			return ConversationEncryptionReading{State: ConversationPlaintext}, nil
		case apiErr.StatusCode == http.StatusForbidden:
			return ConversationEncryptionReading{State: ConversationEncryptionUnknown, Reason: "the server does not let this identity read the conversation (HTTP 403)"}, nil
		case apiErr.StatusCode == http.StatusNotFound:
			return ConversationEncryptionReading{State: ConversationEncryptionUnknown, Reason: "the server does not show this identity the conversation (HTTP 404)"}, nil
		}
		return ConversationEncryptionReading{}, err
	}
	for _, row := range out.Messages {
		if StoredRowEncrypted(row.ContentMode, row.MessageVersion, row.Encrypted) {
			return ConversationEncryptionReading{State: ConversationEncrypted}, nil
		}
	}
	if out.HasMore || len(out.Messages) >= page {
		return ConversationEncryptionReading{State: ConversationEncryptionUnknown, Reason: "its latest " + itoa(len(out.Messages)) + " messages are plaintext and older ones cannot be read"}, nil
	}
	return ConversationEncryptionReading{State: ConversationPlaintext}, nil
}

// UnknownConversationEncryptionError refuses a default continuation whose
// conversation's encryption cannot be established: inheriting it might send
// server-readable text into an encrypted conversation.
type UnknownConversationEncryptionError struct{ Reason string }

func (e *UnknownConversationEncryptionError) Error() string {
	return "cannot tell whether this conversation is end-to-end encrypted: " + e.Reason + "; pass --e2ee to encrypt or --plaintext to send server-readable text"
}
