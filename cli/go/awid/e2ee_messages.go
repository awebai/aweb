package awid

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	E2EEMessageVersion = 2
	E2EEEnvelopeType   = "aweb.e2ee.message"
	E2EESuite          = "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519"
	E2EEWrapVersion    = "aweb-e2ee-wrap-v1"

	e2eeKeyWrapAlgorithm = "hpke-base-x25519-hkdf-sha256-aes256gcm"
	e2eeWrapInfoPrefix   = "aweb-e2ee-v2 key-wrap\n"
)

type E2EEIdentityRef struct {
	Address         string `json:"address,omitempty"`
	DID             string `json:"did,omitempty"`
	StableID        string `json:"stable_id,omitempty"`
	TeamID          string `json:"team_id,omitempty"`
	EncryptionKeyID string `json:"encryption_key_id,omitempty"`
}

type E2EERecipientRef struct {
	Address         string `json:"address,omitempty"`
	DID             string `json:"did,omitempty"`
	StableID        string `json:"stable_id,omitempty"`
	TeamID          string `json:"team_id,omitempty"`
	EncryptionKeyID string `json:"encryption_key_id,omitempty"`
	WrapID          string `json:"wrap_id,omitempty"`
}

type E2EERouting struct {
	To                        string `json:"to,omitempty"`
	ToDID                     string `json:"to_did,omitempty"`
	ToStableID                string `json:"to_stable_id,omitempty"`
	DeliveryOrigin            string `json:"delivery_origin,omitempty"`
	SenderObservedInboundMode string `json:"sender_observed_inbound_mode,omitempty"`
}

type E2EEPolicy struct {
	RequiresE2EE           bool `json:"requires_e2ee"`
	LegacyPlaintextAllowed bool `json:"legacy_plaintext_allowed"`
}

type E2EECryptoHeader struct {
	Suite           string `json:"suite"`
	ContentNonce    string `json:"content_nonce"`
	CiphertextHash  string `json:"ciphertext_hash,omitempty"`
	CiphertextSize  int    `json:"ciphertext_size"`
	InnerHeaderHash string `json:"inner_header_hash"`
	KeyWrapsHash    string `json:"key_wraps_hash"`
}

type E2EEKeyWrap struct {
	WrapID                   string `json:"wrap_id"`
	RecipientStableID        string `json:"recipient_stable_id,omitempty"`
	RecipientDID             string `json:"recipient_did,omitempty"`
	RecipientAddress         string `json:"recipient_address,omitempty"`
	RecipientEncryptionKeyID string `json:"recipient_encryption_key_id"`
	SenderEncryptionKeyID    string `json:"sender_encryption_key_id"`
	SenderDID                string `json:"sender_did"`
	SenderStableID           string `json:"sender_stable_id,omitempty"`
	WrapPurpose              string `json:"wrap_purpose"`
	Algorithm                string `json:"algorithm"`
	EncapsulatedKey          string `json:"encapsulated_key"`
	WrappedCEK               string `json:"wrapped_cek"`
}

type E2EEMessageEnvelope struct {
	MessageVersion      int                     `json:"message_version"`
	EnvelopeType        string                  `json:"envelope_type"`
	Kind                string                  `json:"kind"`
	MessageID           string                  `json:"message_id"`
	ConversationID      string                  `json:"conversation_id"`
	ReplyToMessageID    string                  `json:"reply_to_message_id,omitempty"`
	CreatedAt           string                  `json:"created_at"`
	ExpiresAt           string                  `json:"expires_at"`
	From                E2EEIdentityRef         `json:"from"`
	SenderEncryptionKey *EncryptionKeyAssertion `json:"sender_encryption_key,omitempty"`
	Recipients          []E2EERecipientRef      `json:"recipients"`
	Routing             E2EERouting             `json:"routing"`
	Policy              E2EEPolicy              `json:"policy"`
	Crypto              E2EECryptoHeader        `json:"crypto"`
	KeyWraps            []E2EEKeyWrap           `json:"key_wraps"`
	Ciphertext          string                  `json:"ciphertext"`
	Signature           string                  `json:"signature,omitempty"`
	SigningKeyID        string                  `json:"signing_key_id"`
}

type E2EEInnerPayload struct {
	InnerVersion     int               `json:"inner_version"`
	Kind             string            `json:"kind"`
	MessageID        string            `json:"message_id"`
	ConversationID   string            `json:"conversation_id"`
	ReplyToMessageID string            `json:"reply_to_message_id,omitempty"`
	CreatedAt        string            `json:"created_at"`
	From             E2EEIdentityRef   `json:"from"`
	Recipients       []E2EEIdentityRef `json:"recipients"`
	Subject          string            `json:"subject,omitempty"`
	Body             string            `json:"body"`
}

type E2EERecipientKey struct {
	Address        string
	DID            string
	StableID       string
	TeamID         string
	DeliveryOrigin string
	InboundMode    string
	EncryptionKey  *EncryptionKeyAssertion
}

type E2EESenderKey struct {
	Address       string
	DID           string
	StableID      string
	TeamID        string
	EncryptionKey *EncryptionKeyAssertion
	SigningKey    ed25519.PrivateKey
}

type E2EEEncryptMessageParams struct {
	Kind                string
	Sender              E2EESenderKey
	Recipients          []E2EERecipientKey
	Subject             string
	Body                string
	MessageID           string
	ConversationID      string
	ReplyToMessageID    string
	CreatedAt           time.Time
	DeliveryOrigin      string
	ObservedInboundMode string
}

type E2EEEncryptMailParams = E2EEEncryptMessageParams

type E2EEDecryptIdentity struct {
	Address         string
	DID             string
	StableID        string
	EncryptionKeyID string
	PrivateKey      *ecdh.PrivateKey
}

func (c *Client) DecryptE2EEEnvelope(envelope *E2EEMessageEnvelope) (*E2EEInnerPayload, error) {
	if c == nil {
		return nil, fmt.Errorf("missing client")
	}
	if c.e2eePrivateKey == nil {
		return nil, fmt.Errorf("encrypted message requires local encryption private key; restore .aw/encryption-keys or run `aw id encryption-key setup` for future messages")
	}
	stableID := c.stableID
	encryptionKeyID := ""
	if c.e2eeEncryptionKey != nil {
		encryptionKeyID = strings.TrimSpace(c.e2eeEncryptionKey.EncryptionKeyID)
		if c.e2eeEncryptionKey.IdentityStableID != nil && strings.TrimSpace(*c.e2eeEncryptionKey.IdentityStableID) != "" {
			stableID = strings.TrimSpace(*c.e2eeEncryptionKey.IdentityStableID)
		}
	}
	return DecryptE2EEMessage(envelope, E2EEDecryptIdentity{
		Address:         c.address,
		DID:             c.did,
		StableID:        stableID,
		EncryptionKeyID: encryptionKeyID,
		PrivateKey:      c.e2eePrivateKey,
	})
}

func EncryptE2EEMail(params E2EEEncryptMailParams) (*E2EEMessageEnvelope, error) {
	params.Kind = "mail"
	if len(params.Recipients) != 1 {
		return nil, fmt.Errorf("E2E mail requires exactly one delivery recipient")
	}
	return EncryptE2EEMessage(params)
}

func EncryptE2EEChat(params E2EEEncryptMessageParams) (*E2EEMessageEnvelope, error) {
	params.Kind = "chat"
	params.Subject = ""
	if len(params.Recipients) == 0 {
		return nil, fmt.Errorf("E2E chat requires at least one delivery recipient")
	}
	return EncryptE2EEMessage(params)
}

func EncryptE2EEMessage(params E2EEEncryptMessageParams) (*E2EEMessageEnvelope, error) {
	kind := strings.TrimSpace(params.Kind)
	if kind == "" {
		kind = "mail"
	}
	if kind != "mail" && kind != "chat" {
		return nil, fmt.Errorf("unsupported E2E message kind %q", kind)
	}
	if strings.TrimSpace(params.MessageID) == "" {
		return nil, fmt.Errorf("message_id is required")
	}
	if strings.TrimSpace(params.ConversationID) == "" {
		return nil, fmt.Errorf("conversation_id is required")
	}
	if params.Sender.SigningKey == nil {
		return nil, fmt.Errorf("sender signing key is required")
	}
	if params.Sender.EncryptionKey == nil {
		return nil, fmt.Errorf("sender encryption key is required")
	}
	if len(params.Recipients) == 0 {
		return nil, fmt.Errorf("at least one delivery recipient is required")
	}
	createdAt := params.CreatedAt.UTC().Truncate(time.Second)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Second)
	}
	expiresAt := createdAt.Add(5 * time.Minute)
	from := E2EEIdentityRef{
		Address:         strings.TrimSpace(params.Sender.Address),
		DID:             strings.TrimSpace(params.Sender.DID),
		StableID:        strings.TrimSpace(params.Sender.StableID),
		TeamID:          strings.TrimSpace(params.Sender.TeamID),
		EncryptionKeyID: strings.TrimSpace(params.Sender.EncryptionKey.EncryptionKeyID),
	}
	if from.DID == "" || from.EncryptionKeyID == "" {
		return nil, fmt.Errorf("sender did and encryption key id are required")
	}
	if got := ComputeDIDKey(params.Sender.SigningKey.Public().(ed25519.PublicKey)); got != from.DID {
		return nil, fmt.Errorf("sender signing key does not match sender did")
	}
	if err := VerifyEncryptionKeyAssertion(params.Sender.EncryptionKey, from.DID, from.StableID, createdAt); err != nil {
		return nil, fmt.Errorf("sender encryption key assertion: %w", err)
	}

	recipients := make([]E2EERecipientRef, 0, len(params.Recipients))
	innerRecipients := make([]E2EEIdentityRef, 0, len(params.Recipients))
	for i, recipient := range params.Recipients {
		if recipient.EncryptionKey == nil {
			return nil, fmt.Errorf("recipient %d encryption key is required", i)
		}
		recipientRef := E2EERecipientRef{
			Address:         strings.TrimSpace(recipient.Address),
			DID:             strings.TrimSpace(recipient.DID),
			StableID:        strings.TrimSpace(recipient.StableID),
			TeamID:          strings.TrimSpace(recipient.TeamID),
			EncryptionKeyID: strings.TrimSpace(recipient.EncryptionKey.EncryptionKeyID),
		}
		if recipientRef.DID == "" || recipientRef.EncryptionKeyID == "" {
			return nil, fmt.Errorf("recipient %d did and encryption key are required", i)
		}
		if err := VerifyEncryptionKeyAssertion(recipient.EncryptionKey, recipientRef.DID, recipientRef.StableID, createdAt); err != nil {
			return nil, fmt.Errorf("recipient encryption key assertion %d: %w", i, err)
		}
		recipients = append(recipients, recipientRef)
		innerRecipients = append(innerRecipients, E2EEIdentityRef{
			Address:  recipientRef.Address,
			DID:      recipientRef.DID,
			StableID: recipientRef.StableID,
			TeamID:   recipientRef.TeamID,
		})
	}
	inner := E2EEInnerPayload{
		InnerVersion:     E2EEMessageVersion,
		Kind:             kind,
		MessageID:        strings.TrimSpace(params.MessageID),
		ConversationID:   strings.TrimSpace(params.ConversationID),
		ReplyToMessageID: strings.TrimSpace(params.ReplyToMessageID),
		CreatedAt:        createdAt.Format(time.RFC3339),
		From:             from,
		Recipients:       innerRecipients,
		Subject:          params.Subject,
		Body:             params.Body,
	}
	innerHeaderHash, err := e2eeInnerHeaderHash(inner)
	if err != nil {
		return nil, err
	}

	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("generate content key: %w", err)
	}
	contentNonce := make([]byte, 12)
	if _, err := rand.Read(contentNonce); err != nil {
		return nil, fmt.Errorf("generate content nonce: %w", err)
	}
	if bytes.Equal(contentNonce, make([]byte, len(contentNonce))) {
		return nil, fmt.Errorf("generated all-zero content nonce")
	}

	keyWraps := make([]E2EEKeyWrap, 0, len(params.Recipients)+1)
	for i, recipient := range params.Recipients {
		deliveryWrap, err := buildE2EEKeyWrap(cek, params.MessageID, params.ConversationID, from, recipients[i], "delivery", recipient.EncryptionKey)
		if err != nil {
			return nil, err
		}
		keyWraps = append(keyWraps, *deliveryWrap)
		recipients[i].WrapID = deliveryWrap.WrapID
	}
	senderAsRecipient := E2EERecipientRef{
		Address:         from.Address,
		DID:             from.DID,
		StableID:        from.StableID,
		TeamID:          from.TeamID,
		EncryptionKeyID: from.EncryptionKeyID,
	}
	selfWrap, err := buildE2EEKeyWrap(cek, params.MessageID, params.ConversationID, from, senderAsRecipient, "sender_copy", params.Sender.EncryptionKey)
	if err != nil {
		return nil, err
	}
	keyWraps = append(keyWraps, *selfWrap)

	keyWrapsHash, err := e2eeHashCanonical("key_wraps", e2eeKeyWrapsJSONValue(keyWraps))
	if err != nil {
		return nil, err
	}
	innerBytes, err := e2eeInnerPayloadCanonical(inner)
	if err != nil {
		return nil, err
	}
	ciphertextSize := len(innerBytes) + 16
	envelope := &E2EEMessageEnvelope{
		MessageVersion:   E2EEMessageVersion,
		EnvelopeType:     E2EEEnvelopeType,
		Kind:             kind,
		MessageID:        strings.TrimSpace(params.MessageID),
		ConversationID:   strings.TrimSpace(params.ConversationID),
		ReplyToMessageID: strings.TrimSpace(params.ReplyToMessageID),
		CreatedAt:        createdAt.Format(time.RFC3339),
		ExpiresAt:        expiresAt.Format(time.RFC3339),
		From:             from,
		Recipients:       recipients,
		Routing: E2EERouting{
			To:                        e2eeRoutingTo(recipients),
			ToDID:                     e2eeSingleRecipientField(recipients, "did"),
			ToStableID:                e2eeSingleRecipientField(recipients, "stable_id"),
			DeliveryOrigin:            strings.TrimSpace(params.DeliveryOrigin),
			SenderObservedInboundMode: strings.TrimSpace(params.ObservedInboundMode),
		},
		Policy: E2EEPolicy{RequiresE2EE: true, LegacyPlaintextAllowed: false},
		Crypto: E2EECryptoHeader{
			Suite:           E2EESuite,
			ContentNonce:    base64.RawStdEncoding.EncodeToString(contentNonce),
			CiphertextSize:  ciphertextSize,
			InnerHeaderHash: innerHeaderHash,
			KeyWrapsHash:    keyWrapsHash,
		},
		KeyWraps:     keyWraps,
		SigningKeyID: from.DID,
	}
	if from.Address == "" {
		envelope.SenderEncryptionKey = params.Sender.EncryptionKey
	}
	aad, err := e2eeContentAAD(envelope)
	if err != nil {
		return nil, err
	}
	ciphertext, err := aesGCMSeal(cek, contentNonce, innerBytes, aad)
	if err != nil {
		return nil, err
	}
	envelope.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	envelope.Crypto.CiphertextHash = e2eeHashBytes(ciphertext)
	signedPayload, err := e2eeEnvelopeCanonical(envelope, false, true, true)
	if err != nil {
		return nil, err
	}
	envelope.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(params.Sender.SigningKey, []byte(signedPayload)))
	return envelope, nil
}

func e2eeRoutingTo(recipients []E2EERecipientRef) string {
	values := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		value := firstNonEmptyString(recipient.Address, recipient.StableID, recipient.DID)
		if value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ",")
}

func e2eeSingleRecipientField(recipients []E2EERecipientRef, field string) string {
	if len(recipients) != 1 {
		return ""
	}
	switch field {
	case "did":
		return strings.TrimSpace(recipients[0].DID)
	case "stable_id":
		return strings.TrimSpace(recipients[0].StableID)
	default:
		return ""
	}
}

func DecryptE2EEMessage(envelope *E2EEMessageEnvelope, identity E2EEDecryptIdentity) (*E2EEInnerPayload, error) {
	if envelope == nil {
		return nil, fmt.Errorf("missing e2ee envelope")
	}
	if envelope.MessageVersion != E2EEMessageVersion || envelope.EnvelopeType != E2EEEnvelopeType {
		return nil, fmt.Errorf("unsupported e2ee envelope version")
	}
	if err := VerifyE2EEMessageEnvelopeSignature(envelope); err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Ciphertext))
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if got := e2eeHashBytes(ciphertext); got != strings.TrimSpace(envelope.Crypto.CiphertextHash) {
		return nil, fmt.Errorf("ciphertext hash mismatch")
	}
	if len(ciphertext) != envelope.Crypto.CiphertextSize {
		return nil, fmt.Errorf("ciphertext size mismatch")
	}
	if got, err := e2eeHashCanonical("key_wraps", e2eeKeyWrapsJSONValue(envelope.KeyWraps)); err != nil {
		return nil, err
	} else if got != strings.TrimSpace(envelope.Crypto.KeyWrapsHash) {
		return nil, fmt.Errorf("key_wraps hash mismatch")
	}
	if identity.PrivateKey == nil {
		return nil, fmt.Errorf("missing local encryption private key")
	}
	wrap, err := selectE2EEKeyWrap(envelope, identity)
	if err != nil {
		return nil, err
	}
	cek, err := openE2EEKeyWrap(wrap, envelope.MessageID, envelope.ConversationID, envelope.From, identity)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Crypto.ContentNonce))
	if err != nil {
		return nil, fmt.Errorf("decode content nonce: %w", err)
	}
	aad, err := e2eeContentAAD(envelope)
	if err != nil {
		return nil, err
	}
	plain, err := aesGCMOpen(cek, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt content: %w", err)
	}
	var inner E2EEInnerPayload
	if err := unmarshalCanonicalJSON(plain, &inner); err != nil {
		return nil, fmt.Errorf("decode inner payload: %w", err)
	}
	if got, err := e2eeInnerHeaderHash(inner); err != nil {
		return nil, err
	} else if got != strings.TrimSpace(envelope.Crypto.InnerHeaderHash) {
		return nil, fmt.Errorf("inner header hash mismatch")
	}
	if err := verifyE2EEInnerHeader(envelope, &inner); err != nil {
		return nil, err
	}
	return &inner, nil
}

func VerifyE2EEMessageEnvelopeSignature(envelope *E2EEMessageEnvelope) error {
	if envelope == nil {
		return fmt.Errorf("missing e2ee envelope")
	}
	if strings.TrimSpace(envelope.SigningKeyID) == "" {
		return fmt.Errorf("missing e2ee envelope signature key")
	}
	if strings.TrimSpace(envelope.SigningKeyID) != strings.TrimSpace(envelope.From.DID) {
		return fmt.Errorf("e2ee envelope signing key does not match sender did")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil {
		return fmt.Errorf("decode e2ee envelope signature: %w", err)
	}
	payload, err := e2eeEnvelopeCanonical(envelope, false, true, true)
	if err != nil {
		return err
	}
	pub, err := ExtractPublicKey(envelope.From.DID)
	if err != nil {
		return fmt.Errorf("extract e2ee sender did:key: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("invalid e2ee envelope signature")
	}
	return nil
}

func E2EERecipientFromEnvelopeSender(envelope *E2EEMessageEnvelope, now time.Time) (E2EERecipientKey, error) {
	if envelope == nil {
		return E2EERecipientKey{}, fmt.Errorf("missing e2ee envelope")
	}
	assertion := envelope.SenderEncryptionKey
	if assertion == nil {
		return E2EERecipientKey{}, fmt.Errorf("encrypted conversation does not include the sender E2E key assertion; ask the sender to upgrade aw/Pi/channel, or explicitly send a server-readable upgrade note with --plaintext")
	}
	from := envelope.From
	if strings.TrimSpace(from.DID) == "" {
		return E2EERecipientKey{}, fmt.Errorf("encrypted envelope sender did is missing")
	}
	if strings.TrimSpace(assertion.EncryptionKeyID) != strings.TrimSpace(from.EncryptionKeyID) {
		return E2EERecipientKey{}, fmt.Errorf("sender encryption key assertion id does not match envelope sender key id")
	}
	if err := VerifyEncryptionKeyAssertion(assertion, strings.TrimSpace(from.DID), strings.TrimSpace(from.StableID), now); err != nil {
		return E2EERecipientKey{}, err
	}
	return E2EERecipientKey{
		Address:       strings.TrimSpace(from.Address),
		DID:           strings.TrimSpace(from.DID),
		StableID:      strings.TrimSpace(from.StableID),
		TeamID:        strings.TrimSpace(from.TeamID),
		EncryptionKey: assertion,
	}, nil
}

func buildE2EEKeyWrap(cek []byte, messageID, conversationID string, sender E2EEIdentityRef, recipient E2EERecipientRef, purpose string, assertion *EncryptionKeyAssertion) (*E2EEKeyWrap, error) {
	if len(cek) != 32 {
		return nil, fmt.Errorf("content key must be 32 bytes")
	}
	if assertion == nil {
		return nil, fmt.Errorf("recipient encryption key assertion is required")
	}
	if strings.TrimSpace(assertion.EncryptionKeyID) != strings.TrimSpace(recipient.EncryptionKeyID) {
		return nil, fmt.Errorf("recipient encryption key id mismatch")
	}
	binding := e2eeKeyWrapBindingMap(messageID, conversationID, sender, recipient, purpose)
	bindingBytes, err := canonicalJSONBytes(binding)
	if err != nil {
		return nil, err
	}
	wrapID := e2eeHashBytes(bindingBytes)
	rawRecipientPub, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(assertion.EncryptionPublicKey))
	if err != nil {
		return nil, fmt.Errorf("decode recipient encryption public key: %w", err)
	}
	enc, wrapped, err := hpkeBaseSealX25519AES256GCM(rawRecipientPub, append([]byte(e2eeWrapInfoPrefix), bindingBytes...), nil, cek)
	if err != nil {
		return nil, err
	}
	return &E2EEKeyWrap{
		WrapID:                   wrapID,
		RecipientStableID:        strings.TrimSpace(recipient.StableID),
		RecipientDID:             strings.TrimSpace(recipient.DID),
		RecipientAddress:         strings.TrimSpace(recipient.Address),
		RecipientEncryptionKeyID: strings.TrimSpace(recipient.EncryptionKeyID),
		SenderEncryptionKeyID:    strings.TrimSpace(sender.EncryptionKeyID),
		SenderDID:                strings.TrimSpace(sender.DID),
		SenderStableID:           strings.TrimSpace(sender.StableID),
		WrapPurpose:              strings.TrimSpace(purpose),
		Algorithm:                e2eeKeyWrapAlgorithm,
		EncapsulatedKey:          base64.RawStdEncoding.EncodeToString(enc),
		WrappedCEK:               base64.RawStdEncoding.EncodeToString(wrapped),
	}, nil
}

func selectE2EEKeyWrap(envelope *E2EEMessageEnvelope, identity E2EEDecryptIdentity) (*E2EEKeyWrap, error) {
	keyID := strings.TrimSpace(identity.EncryptionKeyID)
	if keyID == "" && identity.PrivateKey != nil {
		var err error
		keyID, err = ComputeEncryptionKeyID(identity.PrivateKey.PublicKey().Bytes())
		if err != nil {
			return nil, err
		}
	}
	for i := range envelope.KeyWraps {
		wrap := &envelope.KeyWraps[i]
		if strings.TrimSpace(wrap.RecipientEncryptionKeyID) != keyID {
			continue
		}
		if !identityFieldMatches(wrap.RecipientDID, identity.DID) {
			continue
		}
		if !identityFieldMatches(wrap.RecipientStableID, identity.StableID) {
			continue
		}
		if !identityFieldMatches(wrap.RecipientAddress, identity.Address) {
			continue
		}
		return wrap, nil
	}
	return nil, fmt.Errorf("not a recipient")
}

func identityFieldMatches(wrapValue, localValue string) bool {
	wrapValue = strings.TrimSpace(wrapValue)
	localValue = strings.TrimSpace(localValue)
	return wrapValue == "" || (localValue != "" && wrapValue == localValue)
}

func openE2EEKeyWrap(wrap *E2EEKeyWrap, messageID, conversationID string, sender E2EEIdentityRef, identity E2EEDecryptIdentity) ([]byte, error) {
	if wrap == nil {
		return nil, fmt.Errorf("missing key wrap")
	}
	if wrap.Algorithm != e2eeKeyWrapAlgorithm {
		return nil, fmt.Errorf("unsupported key wrap algorithm")
	}
	recipient := E2EERecipientRef{
		Address:         strings.TrimSpace(wrap.RecipientAddress),
		DID:             strings.TrimSpace(wrap.RecipientDID),
		StableID:        strings.TrimSpace(wrap.RecipientStableID),
		EncryptionKeyID: strings.TrimSpace(wrap.RecipientEncryptionKeyID),
	}
	binding := e2eeKeyWrapBindingMap(messageID, conversationID, sender, recipient, strings.TrimSpace(wrap.WrapPurpose))
	bindingBytes, err := canonicalJSONBytes(binding)
	if err != nil {
		return nil, err
	}
	if got := e2eeHashBytes(bindingBytes); got != strings.TrimSpace(wrap.WrapID) {
		return nil, fmt.Errorf("key wrap binding mismatch")
	}
	enc, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(wrap.EncapsulatedKey))
	if err != nil {
		return nil, fmt.Errorf("decode encapsulated key: %w", err)
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(wrap.WrappedCEK))
	if err != nil {
		return nil, fmt.Errorf("decode wrapped content key: %w", err)
	}
	cek, err := hpkeBaseOpenX25519AES256GCM(identity.PrivateKey, enc, append([]byte(e2eeWrapInfoPrefix), bindingBytes...), nil, wrapped)
	if err != nil {
		return nil, fmt.Errorf("open key wrap: %w", err)
	}
	if len(cek) != 32 {
		return nil, fmt.Errorf("invalid content key size")
	}
	return cek, nil
}

func e2eeKeyWrapBindingMap(messageID, conversationID string, sender E2EEIdentityRef, recipient E2EERecipientRef, purpose string) map[string]any {
	out := map[string]any{
		"version":                     E2EEWrapVersion,
		"message_id":                  strings.TrimSpace(messageID),
		"conversation_id":             strings.TrimSpace(conversationID),
		"recipient_did":               strings.TrimSpace(recipient.DID),
		"recipient_encryption_key_id": strings.TrimSpace(recipient.EncryptionKeyID),
		"sender_did":                  strings.TrimSpace(sender.DID),
		"sender_encryption_key_id":    strings.TrimSpace(sender.EncryptionKeyID),
		"wrap_purpose":                strings.TrimSpace(purpose),
		"suite":                       E2EESuite,
	}
	addNonEmpty(out, "recipient_stable_id", recipient.StableID)
	addNonEmpty(out, "recipient_address", recipient.Address)
	addNonEmpty(out, "sender_stable_id", sender.StableID)
	return out
}

func e2eeInnerHeaderHash(inner E2EEInnerPayload) (string, error) {
	header := e2eeInnerPayloadMap(inner, false)
	return e2eeHashCanonical("inner_header", header)
}

func e2eeInnerPayloadCanonical(inner E2EEInnerPayload) ([]byte, error) {
	return canonicalJSONBytes(e2eeInnerPayloadMap(inner, true))
}

func e2eeInnerPayloadMap(inner E2EEInnerPayload, includeContent bool) map[string]any {
	out := map[string]any{
		"inner_version":   inner.InnerVersion,
		"kind":            strings.TrimSpace(inner.Kind),
		"message_id":      strings.TrimSpace(inner.MessageID),
		"conversation_id": strings.TrimSpace(inner.ConversationID),
		"created_at":      strings.TrimSpace(inner.CreatedAt),
		"from":            e2eeIdentityRefMap(inner.From, false),
		"recipients":      e2eeIdentityRefsJSONValue(inner.Recipients),
	}
	addNonEmpty(out, "reply_to_message_id", inner.ReplyToMessageID)
	if includeContent {
		if inner.Kind == "mail" {
			out["subject"] = inner.Subject
		}
		out["body"] = inner.Body
	}
	return out
}

func verifyE2EEInnerHeader(envelope *E2EEMessageEnvelope, inner *E2EEInnerPayload) error {
	if inner == nil || envelope == nil {
		return fmt.Errorf("missing inner header")
	}
	if inner.InnerVersion != E2EEMessageVersion ||
		inner.Kind != envelope.Kind ||
		inner.MessageID != envelope.MessageID ||
		inner.ConversationID != envelope.ConversationID ||
		strings.TrimSpace(inner.ReplyToMessageID) != strings.TrimSpace(envelope.ReplyToMessageID) ||
		inner.CreatedAt != envelope.CreatedAt {
		return fmt.Errorf("inner header does not match outer envelope")
	}
	if !e2eeIdentityRefsEqual(inner.From, envelope.From) {
		return fmt.Errorf("inner sender does not match outer envelope")
	}
	if len(inner.Recipients) != len(envelope.Recipients) {
		return fmt.Errorf("inner recipients do not match outer envelope")
	}
	for i := range inner.Recipients {
		if !e2eeIdentityRefsEqual(inner.Recipients[i], E2EEIdentityRef{
			Address:  envelope.Recipients[i].Address,
			DID:      envelope.Recipients[i].DID,
			StableID: envelope.Recipients[i].StableID,
			TeamID:   envelope.Recipients[i].TeamID,
		}) {
			return fmt.Errorf("inner recipients do not match outer envelope")
		}
	}
	return nil
}

func e2eeIdentityRefsEqual(left, right E2EEIdentityRef) bool {
	return strings.TrimSpace(left.Address) == strings.TrimSpace(right.Address) &&
		strings.TrimSpace(left.DID) == strings.TrimSpace(right.DID) &&
		strings.TrimSpace(left.StableID) == strings.TrimSpace(right.StableID) &&
		strings.TrimSpace(left.TeamID) == strings.TrimSpace(right.TeamID)
}

func e2eeContentAAD(envelope *E2EEMessageEnvelope) ([]byte, error) {
	return e2eeEnvelopeCanonical(envelope, false, false, false)
}

func e2eeEnvelopeCanonical(envelope *E2EEMessageEnvelope, includeSignature, includeCiphertext, includeCiphertextHash bool) ([]byte, error) {
	return canonicalJSONBytes(e2eeEnvelopeMap(envelope, includeSignature, includeCiphertext, includeCiphertextHash))
}

func e2eeEnvelopeMap(envelope *E2EEMessageEnvelope, includeSignature, includeCiphertext, includeCiphertextHash bool) map[string]any {
	out := map[string]any{
		"message_version": envelope.MessageVersion,
		"envelope_type":   envelope.EnvelopeType,
		"kind":            envelope.Kind,
		"message_id":      envelope.MessageID,
		"conversation_id": envelope.ConversationID,
		"created_at":      envelope.CreatedAt,
		"expires_at":      envelope.ExpiresAt,
		"from":            e2eeIdentityRefMap(envelope.From, true),
		"routing":         e2eeRoutingMap(envelope.Routing),
		"policy": map[string]any{
			"requires_e2ee":            envelope.Policy.RequiresE2EE,
			"legacy_plaintext_allowed": envelope.Policy.LegacyPlaintextAllowed,
		},
		"crypto":         e2eeCryptoMap(envelope.Crypto, includeCiphertextHash),
		"key_wraps":      e2eeKeyWrapsJSONValue(envelope.KeyWraps),
		"signing_key_id": envelope.SigningKeyID,
	}
	if envelope.SenderEncryptionKey != nil {
		out["sender_encryption_key"] = e2eeEncryptionKeyAssertionJSONValue(envelope.SenderEncryptionKey)
	}
	out["recipients"] = e2eeRecipientRefsJSONValue(envelope.Recipients)
	addNonEmpty(out, "reply_to_message_id", envelope.ReplyToMessageID)
	if includeCiphertext {
		out["ciphertext"] = envelope.Ciphertext
	}
	if includeSignature {
		addNonEmpty(out, "signature", envelope.Signature)
	}
	return out
}

func e2eeEncryptionKeyAssertionJSONValue(assertion *EncryptionKeyAssertion) map[string]any {
	out := map[string]any{
		"operation":             strings.TrimSpace(assertion.Operation),
		"version":               strings.TrimSpace(assertion.Version),
		"identity_did":          strings.TrimSpace(assertion.IdentityDID),
		"encryption_key_id":     strings.TrimSpace(assertion.EncryptionKeyID),
		"encryption_public_key": strings.TrimSpace(assertion.EncryptionPublicKey),
		"algorithm":             strings.TrimSpace(assertion.Algorithm),
		"created_at":            strings.TrimSpace(assertion.CreatedAt),
		"not_before":            strings.TrimSpace(assertion.NotBefore),
		"expires_at":            strings.TrimSpace(assertion.ExpiresAt),
		"signature":             strings.TrimSpace(assertion.Signature),
	}
	if assertion.IdentityStableID != nil {
		addNonEmpty(out, "identity_stable_id", *assertion.IdentityStableID)
	}
	addNonEmpty(out, "custody", assertion.Custody)
	if assertion.PreviousEncryptionKeyID != nil {
		addNonEmpty(out, "previous_encryption_key_id", *assertion.PreviousEncryptionKeyID)
	}
	return out
}

func e2eeIdentityRefMap(ref E2EEIdentityRef, includeKeyID bool) map[string]any {
	out := map[string]any{}
	addNonEmpty(out, "address", ref.Address)
	addNonEmpty(out, "did", ref.DID)
	addNonEmpty(out, "stable_id", ref.StableID)
	addNonEmpty(out, "team_id", ref.TeamID)
	if includeKeyID {
		addNonEmpty(out, "encryption_key_id", ref.EncryptionKeyID)
	}
	return out
}

func e2eeIdentityRefsJSONValue(refs []E2EEIdentityRef) []any {
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, e2eeIdentityRefMap(ref, false))
	}
	return out
}

func e2eeRecipientRefsJSONValue(refs []E2EERecipientRef) []any {
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		item := map[string]any{}
		addNonEmpty(item, "address", ref.Address)
		addNonEmpty(item, "did", ref.DID)
		addNonEmpty(item, "stable_id", ref.StableID)
		addNonEmpty(item, "team_id", ref.TeamID)
		addNonEmpty(item, "encryption_key_id", ref.EncryptionKeyID)
		addNonEmpty(item, "wrap_id", ref.WrapID)
		out = append(out, item)
	}
	return out
}

func e2eeRoutingMap(r E2EERouting) map[string]any {
	out := map[string]any{}
	addNonEmpty(out, "to", r.To)
	addNonEmpty(out, "to_did", r.ToDID)
	addNonEmpty(out, "to_stable_id", r.ToStableID)
	addNonEmpty(out, "delivery_origin", r.DeliveryOrigin)
	addNonEmpty(out, "sender_observed_inbound_mode", r.SenderObservedInboundMode)
	return out
}

func e2eeCryptoMap(c E2EECryptoHeader, includeCiphertextHash bool) map[string]any {
	out := map[string]any{
		"suite":             c.Suite,
		"content_nonce":     c.ContentNonce,
		"ciphertext_size":   c.CiphertextSize,
		"inner_header_hash": c.InnerHeaderHash,
		"key_wraps_hash":    c.KeyWrapsHash,
	}
	if includeCiphertextHash {
		addNonEmpty(out, "ciphertext_hash", c.CiphertextHash)
	}
	return out
}

func e2eeKeyWrapsJSONValue(wraps []E2EEKeyWrap) []any {
	out := make([]any, 0, len(wraps))
	for _, wrap := range wraps {
		item := map[string]any{
			"wrap_id":                     wrap.WrapID,
			"recipient_encryption_key_id": wrap.RecipientEncryptionKeyID,
			"sender_encryption_key_id":    wrap.SenderEncryptionKeyID,
			"sender_did":                  wrap.SenderDID,
			"wrap_purpose":                wrap.WrapPurpose,
			"algorithm":                   wrap.Algorithm,
			"encapsulated_key":            wrap.EncapsulatedKey,
			"wrapped_cek":                 wrap.WrappedCEK,
		}
		addNonEmpty(item, "recipient_stable_id", wrap.RecipientStableID)
		addNonEmpty(item, "recipient_did", wrap.RecipientDID)
		addNonEmpty(item, "recipient_address", wrap.RecipientAddress)
		addNonEmpty(item, "sender_stable_id", wrap.SenderStableID)
		out = append(out, item)
	}
	return out
}

func addNonEmpty(m map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		m[key] = strings.TrimSpace(value)
	}
}

func canonicalJSONBytes(v any) ([]byte, error) {
	s, err := CanonicalJSONValue(v)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func unmarshalCanonicalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func e2eeHashCanonical(label string, v any) (string, error) {
	b, err := canonicalJSONBytes(v)
	if err != nil {
		return "", fmt.Errorf("canonicalize %s: %w", label, err)
	}
	return e2eeHashBytes(b), nil
}

func e2eeHashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func aesGCMSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func aesGCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("nonce must be %d bytes", gcm.NonceSize())
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

var (
	hpkeKEMID   = []byte{0x00, 0x20}
	hpkeKDFID   = []byte{0x00, 0x01}
	hpkeAEADID  = []byte{0x00, 0x02}
	hpkeSuiteID = append(append(append([]byte("HPKE"), hpkeKEMID...), hpkeKDFID...), hpkeAEADID...)
	kemSuiteID  = append([]byte("KEM"), hpkeKEMID...)
)

func hpkeBaseSealX25519AES256GCM(recipientRawPublicKey, info, aad, plaintext []byte) ([]byte, []byte, error) {
	recipientPub, err := ecdh.X25519().NewPublicKey(recipientRawPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("parse recipient x25519 public key: %w", err)
	}
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate hpke ephemeral key: %w", err)
	}
	sharedSecret, err := hpkeDHKEMExtractAndExpand(ephPriv, recipientPub, ephPriv.PublicKey().Bytes(), recipientRawPublicKey)
	if err != nil {
		return nil, nil, err
	}
	key, baseNonce, err := hpkeKeySchedule(sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := aesGCMSeal(key, baseNonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return ephPriv.PublicKey().Bytes(), ciphertext, nil
}

func hpkeBaseOpenX25519AES256GCM(recipientPriv *ecdh.PrivateKey, enc, info, aad, ciphertext []byte) ([]byte, error) {
	if recipientPriv == nil {
		return nil, fmt.Errorf("recipient private key is required")
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("parse encapsulated key: %w", err)
	}
	sharedSecret, err := hpkeDHKEMExtractAndExpand(recipientPriv, ephemeralPub, enc, recipientPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	key, baseNonce, err := hpkeKeySchedule(sharedSecret, info)
	if err != nil {
		return nil, err
	}
	return aesGCMOpen(key, baseNonce, ciphertext, aad)
}

func hpkeDHKEMExtractAndExpand(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, enc, pkRm []byte) ([]byte, error) {
	dh, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("hpke dh: %w", err)
	}
	eaePRK, err := hpkeLabeledExtract(kemSuiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	kemContext := append(append([]byte{}, enc...), pkRm...)
	return hpkeLabeledExpand(kemSuiteID, eaePRK, "shared_secret", kemContext, 32)
}

func hpkeKeySchedule(sharedSecret, info []byte) ([]byte, []byte, error) {
	pskIDHash, err := hpkeLabeledExtract(hpkeSuiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := hpkeLabeledExtract(hpkeSuiteID, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	keyScheduleContext := append([]byte{0x00}, append(pskIDHash, infoHash...)...)
	secret, err := hpkeLabeledExtract(hpkeSuiteID, sharedSecret, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	key, err := hpkeLabeledExpand(hpkeSuiteID, secret, "key", keyScheduleContext, 32)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := hpkeLabeledExpand(hpkeSuiteID, secret, "base_nonce", keyScheduleContext, 12)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

func hpkeLabeledExtract(suiteID []byte, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := append(append(append([]byte("HPKE-v1"), suiteID...), []byte(label)...), ikm...)
	return hkdf.Extract(sha256.New, labeledIKM, salt)
}

func hpkeLabeledExpand(suiteID []byte, prk []byte, label string, info []byte, length int) ([]byte, error) {
	labeledInfo := make([]byte, 2, 2+len("HPKE-v1")+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
}
