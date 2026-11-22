package awid

import (
	"context"
	"fmt"
	"strings"
)

// receivedKind is the signed envelope type of a received message. It decides
// which displayed fields the signature covers.
type receivedKind string

const (
	receivedMail receivedKind = "mail"
	receivedChat receivedKind = "chat"
)

// receivedMessage is one received mail or chat message as the reader sees it.
// verifyReceived checks it by one rule for both kinds; the first group of
// fields is read, the second is set from what verification authenticated.
type receivedMessage struct {
	kind receivedKind
	// fromAlias is the sender's name in the unsigned envelope when the
	// message carries no address; trustAlias names the sender for trust
	// normalisation in that case.
	fromAlias  string
	trustAlias string
	toAlias    string
	priority   MessagePriority
	timestamp  string
	// authenticatedSenderRead is a read through the server-authorized sender
	// view: the reader may be the message's author.
	authenticatedSenderRead bool
	messageID               string
	conversationID          string
	// requestedConversationID is the conversation the reader asked for, when
	// it read one: a message is shown there only if it belongs to it.
	requestedConversationID string
	contentMode             string
	messageVersion          int
	encrypted               *E2EEMessageEnvelope
	// Only the authenticated managed mail reader can supply this projection.
	providerDecryptable     *bool
	signature               string
	signingKeyID            string
	signedPayload           string
	senderMembership        *SenderMembership
	rotationAnnouncement    *RotationAnnouncement
	replacementAnnouncement *ReplacementAnnouncement

	subject              string
	body                 string
	fromDID              string
	toDID                string
	fromStableID         string
	toStableID           string
	fromAddress          string
	toAddress            string
	attachments          []AttachmentDescriptor
	attachmentsAvailable bool
	status               VerificationStatus
	isContact            *bool
}

func (r *receivedMessage) isEncrypted() bool {
	return r.contentMode == ContentModeEncryptedV2 || r.messageVersion == E2EEMessageVersion || r.encrypted != nil
}

// verifyReceived sets a received message's verification status and its
// authenticated sender and recipient fields. In order: a message read from a
// conversation must belong to it; the displayed fields
// must be the signed ones before signed metadata is projected over them.
// For encrypted mail and chat, the envelope and its identifiers must verify
// before using locally decrypted content or a managed bridge's opened mail.
// The message is bound to its signed recipient, and only then is the sender's trust looked
// up, so a message signed for someone else never reaches the roster or the
// pin store. An error means the message could not be read at all.
func (c *Client) verifyReceived(ctx context.Context, r *receivedMessage) error {
	r.attachments = nil
	r.attachmentsAvailable = true
	binding := ReceivedSenderBinding{ProjectedDID: r.fromDID}
	if r.requestedConversationID != "" {
		// A message read from a conversation is checked against that
		// conversation, not only the one its row names: a row from another
		// conversation is a replay, however it is signed. A server that
		// names no conversation in the row leaves the requested one.
		if r.conversationID == "" {
			r.conversationID = r.requestedConversationID
		} else if r.conversationID != r.requestedConversationID {
			r.status = Failed
			return nil
		}
	}
	if !r.isEncrypted() && r.signedPayload != "" && !c.receivedDisplayMatches(r) {
		// Preserve the observed response so a mismatch cannot be hidden by
		// metadata overlay or subsequently promoted by trust normalization.
		r.status = Failed
		return nil
	}
	if r.isEncrypted() {
		teamID, ok, err := c.decryptReceived(ctx, r)
		if err != nil || !ok {
			return err
		}
		binding.TeamID = teamID
	}
	if r.contentMode != ContentModeEncryptedV2 {
		r.applySignedMetadata()
		r.status = r.signatureStatus()
	}
	// The v2 envelope signature was verified before decrypting.
	c.bindAndNormaliseReceived(ctx, r, binding)
	return nil
}

func (c *Client) receivedDisplayMatches(r *receivedMessage) bool {
	if r.kind == receivedMail {
		return c.signedMailDisplayMatches(r.signedPayload, map[string]string{
			"type": string(receivedMail), "body": r.body, "subject": r.subject,
			"message_id": r.messageID, "conversation_id": r.conversationID,
			"from_did": r.fromDID, "to_did": r.toDID,
		}, r.authenticatedSenderRead)
	}
	return signedChatDisplayMatches(r.signedPayload, chatDisplay{
		Body:           r.body,
		MessageID:      r.messageID,
		ConversationID: r.conversationID,
		FromDID:        r.fromDID,
		ToDID:          r.toDID,
	})
}

// decryptReceived obtains readable encrypted content and authenticated
// identifiers. A failed evidence check leaves the message unverified.
func (c *Client) decryptReceived(ctx context.Context, r *receivedMessage) (string, bool, error) {
	if r.providerDecryptable != nil {
		teamID, verified := c.verifyProviderOpenedMail(r)
		return teamID, verified, nil
	}
	if r.encrypted == nil {
		return "", false, fmt.Errorf("encrypted %s message is missing its encrypted envelope", r.kind)
	}
	plain, err := c.DecryptE2EEEnvelopeWithContext(ctx, r.encrypted)
	if err != nil {
		return "", false, err
	}
	if r.messageID != plain.MessageID || r.conversationID != plain.ConversationID {
		r.status = Failed
		return "", false, nil
	}
	if r.kind == receivedMail {
		r.subject = plain.Subject
	}
	r.body = plain.Body
	r.attachments, r.attachmentsAvailable = DecodeAttachmentContent(plain.Attachments)
	r.applyEncryptedIdentityMetadata(plain.From, plain.Recipients)
	r.status = Verified
	return plain.From.TeamID, true, nil
}

// The provider attests that it opened the displayed body under the hosted
// recipient key. The envelope independently authenticates the original sender
// and binds that encrypted message to the gateway and requested conversation.
func (c *Client) verifyProviderOpenedMail(r *receivedMessage) (string, bool) {
	r.status = Failed
	r.attachmentsAvailable = false
	envelope := r.encrypted
	if !*r.providerDecryptable || r.contentMode != ContentModeEncryptedV2 ||
		verifyE2EEMessageEnvelope(envelope) != nil || envelope.Kind != string(receivedMail) ||
		envelope.MessageID == "" || envelope.MessageID != r.messageID ||
		envelope.ConversationID != r.requestedConversationID || len(envelope.Recipients) != 1 {
		return "", false
	}
	recipient := envelope.Recipients[0]
	if c.stableID == "" || recipient.StableID != c.stableID || strings.TrimSpace(recipient.DID) == "" {
		return "", false
	}
	r.applyEncryptedIdentityMetadata(envelope.From, []E2EEIdentityRef{{
		DID: recipient.DID, StableID: recipient.StableID, Address: recipient.Address,
	}})
	r.status = Verified
	return envelope.From.TeamID, true
}

func (r *receivedMessage) applyEncryptedIdentityMetadata(from E2EEIdentityRef, recipients []E2EEIdentityRef) {
	if did := strings.TrimSpace(from.DID); did != "" {
		r.fromDID = did
	}
	r.fromStableID = strings.TrimSpace(from.StableID)
	// An authenticated empty address is meaningful; never retain a projected
	// alias/address here. Server-attested membership remains separate.
	r.fromAddress = strings.TrimSpace(from.Address)
	// A single authenticated recipient is the message's recipient binding.
	if len(recipients) == 1 {
		recipient := recipients[0]
		r.toDID = strings.TrimSpace(recipient.DID)
		r.toStableID = strings.TrimSpace(recipient.StableID)
		if address := strings.TrimSpace(recipient.Address); address != "" {
			r.toAddress = address
		}
	}
}

func (r *receivedMessage) applySignedMetadata() {
	meta, ok := parseSignedEnvelopeMetadata(r.signedPayload)
	if !ok {
		return
	}
	if meta.FromDID != "" {
		r.fromDID = meta.FromDID
	}
	if meta.ToDID != "" {
		r.toDID = meta.ToDID
	}
	if r.fromStableID == "" {
		r.fromStableID = meta.FromStableID
	}
	if r.toStableID == "" {
		r.toStableID = meta.ToStableID
	}
	// A signed member name is not a public address. Preserve an explicit
	// server projection; only suppress alias-to-address fallback.
	stableAlias := strings.HasPrefix(meta.FromStableID, "did:aw:") && !strings.Contains(meta.From, "/")
	if r.fromAddress == "" && meta.From != "" && !stableAlias {
		r.fromAddress = meta.From
	}
	if r.toAddress == "" && meta.To != "" {
		r.toAddress = meta.To
	}
	if stableAlias {
		r.fromStableID = meta.FromStableID
	}
}

func (r *receivedMessage) signatureStatus() VerificationStatus {
	if r.signedPayload != "" {
		status := signatureVerdict(VerifySignedPayload(r.signedPayload, r.signature, r.fromDID, r.signingKeyID))
		if status == Verified {
			status = SignedPayloadConversationStatus(r.signedPayload, r.conversationID)
		}
		return status
	}
	from := r.fromAlias
	if r.fromAddress != "" {
		from = r.fromAddress
	}
	to := r.toAlias
	if r.toAddress != "" {
		to = r.toAddress
	}
	env := &MessageEnvelope{
		From:           from,
		FromDID:        r.fromDID,
		To:             to,
		ToDID:          r.toDID,
		Type:           string(r.kind),
		Priority:       signedMailPriority(r.priority),
		Subject:        r.subject,
		Body:           r.body,
		Timestamp:      r.timestamp,
		FromStableID:   r.fromStableID,
		ToStableID:     r.toStableID,
		MessageID:      r.messageID,
		ConversationID: r.conversationID,
		Signature:      r.signature,
		SigningKeyID:   r.signingKeyID,
	}
	status := signatureVerdict(VerifyMessage(env))
	if status == Failed && r.conversationID != "" {
		env.ConversationID = ""
		if signatureVerdict(VerifyMessage(env)) == Verified {
			status = VerifiedLegacy
		}
	}
	return status
}

func (c *Client) bindAndNormaliseReceived(ctx context.Context, r *receivedMessage, binding ReceivedSenderBinding) {
	// Recipient binding is a receiver-side check. Sender-visible reads may establish
	// authorship from the server-authorized stored routing DID before signed metadata
	// restores a historical signing key after rotation or resident custody signing.
	senderRead := r.authenticatedSenderRead &&
		(r.status == Verified || r.status == VerifiedLegacy) &&
		c.messageSignedByClientIdentity(r.fromDID, r.fromStableID)
	if !senderRead && !c.messageAuthoredByClientDID(r.fromDID) {
		r.status = c.checkRecipientBinding(r.status, r.toDID, r.toStableID)
	}
	// Own-sent reads establish authorship, not a received sender's team trust.
	// Require the server-authorized sender view AND our stable ID AND a
	// signature by our current resident key; a claimed stable ID is not enough.
	ownAddressless := senderRead && strings.TrimSpace(r.fromAddress) == "" && c.stableID != "" &&
		r.fromStableID == c.stableID && c.ParticipantDID() != "" && r.fromDID == c.ParticipantDID()
	if !ownAddressless {
		r.status, r.isContact = c.NormalizeReceivedSender(ctx, r.status, ReceivedSender{
			Address: r.fromAddress, Alias: r.trustAlias, DID: r.fromDID, StableID: r.fromStableID,
			Membership: r.senderMembership, Rotation: r.rotationAnnouncement, Replacement: r.replacementAnnouncement,
			IsContact: r.isContact, Binding: &binding,
		})
	}
}

// signatureVerdict is the status a signature check concludes. Its error is
// the reason a signature does not verify, so any error is Failed, whatever
// status came with it.
func signatureVerdict(status VerificationStatus, err error) VerificationStatus {
	if err != nil {
		return Failed
	}
	return status
}
