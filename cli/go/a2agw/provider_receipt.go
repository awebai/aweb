package a2agw

import (
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
)

type providerReceiptFault string

const (
	missingRecipientIdentity providerReceiptFault = "missing_recipient_identity"
	missingConversation      providerReceiptFault = "missing_conversation_id"
)

type providerReceiptError struct {
	Provider string
	Fault    providerReceiptFault
}

func (e *providerReceiptError) Error() string {
	detail := "recipient identity"
	if e.Fault == missingConversation {
		detail = "conversation_id"
	}
	return fmt.Sprintf("A2A provider %s returned a send receipt without %s. Repair the provider's recipient_identity_v1 response before retrying the task.", e.Provider, detail)
}

// validateSendReceipt treats a broken declared capability as a provider fault,
// never as a wrong-sender reply (docs/a2a.md:967-974). Native signed recipient
// fields remain authoritative even when an older server omits the additions.
func (b *MailBridge) validateSendReceipt(req *awid.SendMessageRequest, response *awid.SendMessageResponse) (recipientIdentity, *providerReceiptError) {
	fault := func(kind providerReceiptFault) (recipientIdentity, *providerReceiptError) {
		return recipientIdentity{}, &providerReceiptError{Provider: b.providerDisplayName(), Fault: kind}
	}
	if response == nil || strings.TrimSpace(response.ConversationID) == "" {
		return fault(missingConversation)
	}
	recipient := recipientFromSend(req, response)
	if provider, ok := b.client.(recipientIdentityProvider); ok && provider.ProvidesRecipientIdentity() && recipient.DID == "" && recipient.StableID == "" {
		return fault(missingRecipientIdentity)
	}
	return recipient, nil
}
