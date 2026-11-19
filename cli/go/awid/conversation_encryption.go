package awid

import (
	"context"
	"net/http"
	"strings"
)

// PlaintextIntoEncryptedNotice is what aw says when --plaintext sends into a
// conversation that carries end-to-end encrypted messages.
const PlaintextIntoEncryptedNotice = "sending server-readable plaintext into an end-to-end encrypted conversation (--plaintext)"

// conversationEncryptionPage is how many of a conversation's latest messages
// are read to learn whether it is end-to-end encrypted.
const conversationEncryptionPage = 50

func storedRowEncrypted(contentMode string, messageVersion int, envelope *E2EEMessageEnvelope) bool {
	return contentMode == ContentModeEncryptedV2 || messageVersion == E2EEMessageVersion || envelope != nil
}

// conversationHidden reports a read the server refuses because it will not
// show this reader the conversation: there is no encryption to inherit, and
// the send itself then answers with the server's refusal. The mail send path
// already reads these two answers that way (targetForMailConversation).
func conversationHidden(err error) bool {
	return httpStatusIs(err, http.StatusNotFound) || httpStatusIs(err, http.StatusForbidden)
}

// ChatSessionEncrypted reports whether a chat session's latest messages
// include an end-to-end encrypted one. It reads the rows as stored and
// decrypts nothing, so it needs no key; a continuation inherits the answer.
func (c *Client) ChatSessionEncrypted(ctx context.Context, sessionID string) (bool, error) {
	var out ChatHistoryResponse
	path := "/v1/chat/sessions/" + urlPathEscape(strings.TrimSpace(sessionID)) + "/messages?limit=" + itoa(conversationEncryptionPage)
	if err := c.Get(ctx, path, &out); err != nil {
		if conversationHidden(err) {
			return false, nil
		}
		return false, err
	}
	for _, m := range out.Messages {
		if storedRowEncrypted(m.ContentMode, m.MessageVersion, m.Encrypted) {
			return true, nil
		}
	}
	return false, nil
}

// MailConversationEncrypted reports whether a mail conversation's latest
// messages include an end-to-end encrypted one, from the rows as stored.
func (c *Client) MailConversationEncrypted(ctx context.Context, conversationID string) (bool, error) {
	var out InboxResponse
	path := "/v1/messages/conversations/" + urlPathEscape(strings.TrimSpace(conversationID)) + "?limit=" + itoa(conversationEncryptionPage)
	if err := c.Get(ctx, path, &out); err != nil {
		if conversationHidden(err) {
			return false, nil
		}
		return false, err
	}
	for _, m := range out.Messages {
		if storedRowEncrypted(m.ContentMode, m.MessageVersion, m.Encrypted) {
			return true, nil
		}
	}
	return false, nil
}
