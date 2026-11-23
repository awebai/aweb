package awid

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (c *Client) namespaceSlug() string {
	parts := strings.SplitN(c.address, "/", 2)
	if len(parts) == 2 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func (c *Client) toAddressForAliases(aliases []string) string {
	return deterministicTargetList(aliases)
}

func deterministicTargetList(values []string) string {
	if len(values) == 0 {
		return ""
	}
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	sort.Strings(clean)
	var b strings.Builder
	for i, value := range clean {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(value)
	}
	return b.String()
}

func removeOneSelfIdentifier(values []string, selfIDs ...string) []string {
	if len(values) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(values))
	removedSelf := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !removedSelf {
			for _, selfID := range selfIDs {
				selfID = strings.TrimSpace(selfID)
				if selfID != "" && strings.EqualFold(value, selfID) {
					removedSelf = true
					value = ""
					break
				}
			}
		}
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (c *Client) toAddressForSession(ctx context.Context, sessionID string, preferAddress bool) (string, error) {
	if sessionID == "" {
		return "", nil
	}
	resp, err := c.ChatListSessions(ctx)
	if err != nil {
		return "", err
	}
	for _, s := range resp.Sessions {
		if s.SessionID != sessionID {
			continue
		}
		otherDIDs, otherAddresses := OtherConversationParticipants(
			s.ParticipantDIDs,
			s.ParticipantAddresses,
			c.stableID,
			c.did,
			c.address,
		)
		if preferAddress {
			if len(otherDIDs) == 1 && isLocalDIDKey(otherDIDs[0]) {
				return otherDIDs[0], nil
			}
			if toAddr := c.toAddressForAliases(otherAddresses); toAddr != "" {
				return toAddr, nil
			}
			if selfAlias := c.addressAlias(); selfAlias != "" {
				if toAlias := c.toAddressForAliases(removeOneSelfIdentifier(s.Participants, selfAlias)); toAlias != "" {
					return toAlias, nil
				}
			}
		}
		if len(otherDIDs) == 1 {
			return otherDIDs[0], nil
		}
		if toAddr := c.toAddressForAliases(otherAddresses); toAddr != "" {
			return toAddr, nil
		}
		selfAlias := c.addressAlias()
		if selfAlias == "" {
			return "", nil
		}
		others := make([]string, 0, len(s.Participants))
		removedSelf := false
		for _, a := range s.Participants {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if a == selfAlias && !removedSelf {
				removedSelf = true
				continue
			}
			others = append(others, a)
		}
		sort.Strings(others)
		return c.toAddressForAliases(others), nil
	}
	return "", nil
}

// OtherConversationParticipants removes the caller's single participant row
// from paired DID/address participant lists and returns the remaining values.
func OtherConversationParticipants(participantDIDs, participantAddresses []string, selfStableID, selfDID, selfAddress string) ([]string, []string) {
	selfDIDs := []string{selfStableID, selfDID}
	selfAddress = strings.TrimSpace(selfAddress)
	maxLen := len(participantDIDs)
	if len(participantAddresses) > maxLen {
		maxLen = len(participantAddresses)
	}
	otherDIDs := make([]string, 0, len(participantDIDs))
	otherAddresses := make([]string, 0, len(participantAddresses))
	removedSelf := false
	for i := 0; i < maxLen; i++ {
		did := ""
		if i < len(participantDIDs) {
			did = strings.TrimSpace(participantDIDs[i])
		}
		address := ""
		if i < len(participantAddresses) {
			address = strings.TrimSpace(participantAddresses[i])
		}
		isSelf := false
		if !removedSelf && selfAddress != "" && address != "" && strings.EqualFold(address, selfAddress) {
			isSelf = true
		}
		if !removedSelf && !isSelf {
			for _, selfDID := range selfDIDs {
				selfDID = strings.TrimSpace(selfDID)
				if selfDID != "" && did != "" && strings.EqualFold(did, selfDID) {
					isSelf = true
					break
				}
			}
		}
		if isSelf {
			removedSelf = true
			continue
		}
		if did != "" {
			otherDIDs = append(otherDIDs, did)
		}
		if address != "" {
			otherAddresses = append(otherAddresses, address)
		}
	}
	return otherDIDs, otherAddresses
}

type ChatCreateSessionRequest struct {
	SessionID      string               `json:"session_id,omitempty"`
	ToAliases      []string             `json:"to_aliases,omitempty"`
	ToDIDs         []string             `json:"to_dids,omitempty"`
	ToAddresses    []string             `json:"to_addresses,omitempty"`
	Message        string               `json:"message"`
	ContentMode    string               `json:"content_mode,omitempty"`
	MessageVersion int                  `json:"message_version,omitempty"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	Leaving        bool                 `json:"leaving,omitempty"`
	WaitSeconds    *int                 `json:"wait_seconds,omitempty"`
	ReplyTo        string               `json:"reply_to,omitempty"`
	FromDID        string               `json:"from_did,omitempty"`
	Signature      string               `json:"signature,omitempty"`
	Timestamp      string               `json:"timestamp,omitempty"`
	MessageID      string               `json:"message_id,omitempty"`
	SignedPayload  string               `json:"signed_payload,omitempty"`
	EncryptE2EE    bool                 `json:"-"`
	// ConfirmedRecipient is what the sender's team roster names for the one
	// alias in ToAliases; it is signed, never sent as a selector.
	ConfirmedRecipient *ConfirmedRecipient `json:"-"`
}

type ChatCreateSessionResponse struct {
	SessionID        string            `json:"session_id"`
	MessageID        string            `json:"message_id"`
	Participants     []ChatParticipant `json:"participants"`
	SSEURL           string            `json:"sse_url"`
	TargetsConnected []string          `json:"targets_connected"`
	TargetsLeft      []string          `json:"targets_left"`
}

type ChatParticipant struct {
	AgentID string `json:"agent_id"`
	Alias   string `json:"alias"`
	DID     string `json:"did,omitempty"`
	Address string `json:"address,omitempty"`
}

func (c *Client) ChatCreateSession(ctx context.Context, req *ChatCreateSessionRequest) (*ChatCreateSessionResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req
	if c.canAttachPlainMessageSignature() && strings.TrimSpace(payload.SessionID) == "" {
		sessionID, err := GenerateUUID4()
		if err != nil {
			return nil, err
		}
		payload.SessionID = sessionID
	}
	if payload.EncryptE2EE {
		if err := c.prepareE2EEChatCreate(ctx, &payload); err != nil {
			return nil, err
		}
		var out ChatCreateSessionResponse
		if err := c.Post(ctx, "/v1/chat/sessions", &payload, &out); err != nil {
			return nil, serverCustodialRefusal(err, payload.Encrypted)
		}
		return &out, nil
	}

	to := strings.Join(payload.ToAliases, ",")
	directIdentityTargets := len(payload.ToDIDs) > 0 || len(payload.ToAddresses) > 0
	if len(payload.ToDIDs) > 0 {
		targets := append([]string(nil), payload.ToDIDs...)
		sort.Strings(targets)
		to = strings.Join(targets, ",")
	} else if len(payload.ToAddresses) > 0 {
		targets := append([]string(nil), payload.ToAddresses...)
		sort.Strings(targets)
		to = strings.Join(targets, ",")
	}
	from := c.address
	if c.canAttachPlainMessageSignature() {
		if len(payload.ToAddresses) > 0 {
			targets := append([]string(nil), payload.ToAddresses...)
			sort.Strings(targets)
			to = strings.Join(targets, ",")
		} else if toAddr := c.toAddressForAliases(payload.ToAliases); toAddr != "" {
			to = toAddr
		}
		from = c.signedPayloadFrom(false, !directIdentityTargets)
	}
	env := &MessageEnvelope{
		From:                    from,
		To:                      to,
		Type:                    "chat",
		Body:                    payload.Message,
		ConversationID:          strings.TrimSpace(payload.SessionID),
		WaitSeconds:             payload.WaitSeconds,
		ReplyTo:                 payload.ReplyTo,
		SenderLeaving:           payload.Leaving,
		RequireRecipientBinding: len(payload.ToAddresses) == 1 && c.requireRecipientBinding,
	}
	if len(payload.ToDIDs) == 1 {
		env.ToDID = strings.TrimSpace(payload.ToDIDs[0])
	}
	if payload.ConfirmedRecipient != nil && len(payload.ToAliases) == 1 && !directIdentityTargets {
		env.ToDID = strings.TrimSpace(payload.ConfirmedRecipient.DID)
		env.ToStableID = strings.TrimSpace(payload.ConfirmedRecipient.StableID)
	}
	sf, err := c.signEnvelope(ctx, env)
	if err != nil {
		return nil, err
	}
	if c.canAttachPlainMessageSignature() {
		payload.FromDID = sf.FromDID
		payload.Signature = sf.Signature
		payload.Timestamp = sf.Timestamp
		payload.MessageID = sf.MessageID
		payload.SignedPayload = sf.SignedPayload
	}

	var out ChatCreateSessionResponse
	if err := c.Post(ctx, "/v1/chat/sessions", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) prepareE2EEChatCreate(ctx context.Context, payload *ChatCreateSessionRequest) error {
	if c == nil || payload == nil {
		return errors.New("aweb: request is required")
	}
	if _, refusal := c.e2eeSenderGap(); refusal != nil {
		return refusal
	}
	custody := c.e2eeCustody()
	recipients, err := c.e2eeChatRecipients(ctx, payload.ToAliases, payload.ToDIDs, payload.ToAddresses)
	if err != nil {
		return err
	}
	if err := refuseCustodialRecipients(recipients, time.Now().UTC()); err != nil {
		return err
	}
	messageID, err := GenerateUUID4()
	if err != nil {
		return err
	}
	if strings.TrimSpace(payload.MessageID) != "" {
		messageID = strings.TrimSpace(payload.MessageID)
	}
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		sessionID, err = GenerateUUID4()
		if err != nil {
			return err
		}
		payload.SessionID = sessionID
	}
	now := time.Now().UTC().Truncate(time.Second)
	if custody != nil {
		envelope, err := c.createCustodyE2EEEnvelope(ctx, custody, custodyEnvelopeMessage{Kind: custodyChatMessage, Body: payload.Message, MessageID: messageID, ConversationID: sessionID, ReplyTo: payload.ReplyTo, Recipients: recipients})
		if err != nil {
			return err
		}
		payload.MessageID = envelope.MessageID
		payload.Timestamp = envelope.CreatedAt
		payload.FromDID = envelope.From.DID
		payload.ContentMode = ContentModeEncryptedV2
		payload.MessageVersion = E2EEMessageVersion
		payload.Encrypted = envelope
		payload.Message = ""
		payload.Signature = ""
		payload.SignedPayload = ""
		return nil
	}
	envelope, err := EncryptE2EEChat(E2EEEncryptMessageParams{
		Sender: E2EESenderKey{
			Address:       c.e2eeAddress(),
			DID:           c.did,
			StableID:      c.stableID,
			TeamID:        c.teamID,
			EncryptionKey: c.e2eeEncryptionKey,
			SigningKey:    c.signingKey,
		},
		Recipients:       recipients,
		Body:             payload.Message,
		MessageID:        messageID,
		ConversationID:   sessionID,
		ReplyToMessageID: payload.ReplyTo,
		CreatedAt:        now,
	})
	if err != nil {
		return err
	}
	payload.MessageID = envelope.MessageID
	payload.Timestamp = envelope.CreatedAt
	payload.FromDID = c.did
	payload.ContentMode = ContentModeEncryptedV2
	payload.MessageVersion = E2EEMessageVersion
	payload.Encrypted = envelope
	payload.Message = ""
	payload.Signature = ""
	payload.SignedPayload = ""
	return nil
}

func (c *Client) prepareE2EEChatSend(ctx context.Context, sessionID string, payload *ChatSendMessageRequest) error {
	if c == nil || payload == nil {
		return errors.New("aweb: request is required")
	}
	if _, refusal := c.e2eeSenderGap(); refusal != nil {
		return refusal
	}
	custody := c.e2eeCustody()
	recipients, err := c.e2eeChatRecipientsForSession(ctx, sessionID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if payload.E2EEInherited && len(recipients) == 1 && recipientKeyIsHosted(recipients[0], now) {
		payload.EncryptE2EE = false
		return nil
	}
	if err := refuseCustodialRecipients(recipients, now); err != nil {
		return err
	}
	messageID, err := GenerateUUID4()
	if err != nil {
		return err
	}
	if strings.TrimSpace(payload.MessageID) != "" {
		messageID = strings.TrimSpace(payload.MessageID)
	}
	now = now.Truncate(time.Second)
	if custody != nil {
		envelope, err := c.createCustodyE2EEEnvelope(ctx, custody, custodyEnvelopeMessage{Kind: custodyChatMessage, Body: payload.Body, MessageID: messageID, ConversationID: strings.TrimSpace(sessionID), ReplyTo: payload.ReplyTo, Recipients: recipients})
		if err != nil {
			return err
		}
		payload.MessageID = envelope.MessageID
		payload.Timestamp = envelope.CreatedAt
		payload.FromDID = envelope.From.DID
		payload.ContentMode = ContentModeEncryptedV2
		payload.MessageVersion = E2EEMessageVersion
		payload.Encrypted = envelope
		payload.Body = ""
		payload.Signature = ""
		payload.SignedPayload = ""
		return nil
	}
	envelope, err := EncryptE2EEChat(E2EEEncryptMessageParams{
		Sender: E2EESenderKey{
			Address:       c.e2eeAddress(),
			DID:           c.did,
			StableID:      c.stableID,
			TeamID:        c.teamID,
			EncryptionKey: c.e2eeEncryptionKey,
			SigningKey:    c.signingKey,
		},
		Recipients:       recipients,
		Body:             payload.Body,
		MessageID:        messageID,
		ConversationID:   strings.TrimSpace(sessionID),
		ReplyToMessageID: payload.ReplyTo,
		CreatedAt:        now,
	})
	if err != nil {
		return err
	}
	payload.MessageID = envelope.MessageID
	payload.Timestamp = envelope.CreatedAt
	payload.FromDID = c.did
	payload.ContentMode = ContentModeEncryptedV2
	payload.MessageVersion = E2EEMessageVersion
	payload.Encrypted = envelope
	payload.Body = ""
	payload.Signature = ""
	payload.SignedPayload = ""
	return nil
}

func (c *Client) e2eeChatRecipientsForSession(ctx context.Context, sessionID string) ([]E2EERecipientKey, error) {
	if recipient, ok, err := c.addressedSessionParticipant(ctx, sessionID); err != nil {
		return nil, err
	} else if ok {
		return []E2EERecipientKey{recipient}, nil
	}
	to, err := c.toAddressForSession(ctx, sessionID, true)
	if err != nil {
		return nil, err
	}
	aliases, dids, addresses := classifyE2EEChatTargets(to)
	if len(addresses) > 0 || len(aliases) > 0 || hasGlobalDIDTarget(dids) {
		return c.e2eeChatRecipients(ctx, aliases, dids, addresses)
	}
	if len(dids) > 0 {
		if recipients, ok, err := c.learnedE2EEChatRecipients(ctx, sessionID); err != nil {
			return nil, err
		} else if ok {
			return recipients, nil
		}
	}
	return c.e2eeChatRecipients(ctx, aliases, dids, addresses)
}

// addressedSessionParticipant resolves the other participant of a one-to-one
// session through its address or team alias, when the session lists one. It is
// that participant only if resolution matches the session's did:key; a name
// now held by another identity cannot replace the participant.
func (c *Client) addressedSessionParticipant(ctx context.Context, sessionID string) (E2EERecipientKey, bool, error) {
	resp, err := c.ChatListSessions(ctx)
	if err != nil {
		return E2EERecipientKey{}, false, err
	}
	for _, session := range resp.Sessions {
		if session.SessionID != sessionID {
			continue
		}
		otherDIDs, otherAddresses := OtherConversationParticipants(session.ParticipantDIDs, session.ParticipantAddresses, c.stableID, c.did, c.address)
		if len(otherDIDs) != 1 || len(otherAddresses) != 1 || !isLocalDIDKey(otherDIDs[0]) {
			return E2EERecipientKey{}, false, nil
		}
		aliases, _, addresses := classifyE2EEChatTargets(otherAddresses[0])
		if len(aliases) == 1 {
			// Use the same verified roster lookup as alias mail. Missing alias
			// metadata is not a new authority requirement for an existing peer.
			agent, err := c.e2eeRecipientAgent(ctx, "", aliases[0])
			if err != nil {
				if status, ok := HTTPStatusCode(err); !ok || status != http.StatusNotFound {
					return E2EERecipientKey{}, false, err
				}
			} else {
				if strings.TrimSpace(agent.DIDKey) != strings.TrimSpace(otherDIDs[0]) {
					return E2EERecipientKey{}, false, errNoPublishedEncryptionKey
				}
				// An invalid publication must not become an absent publication;
				// nor may a global identity use local history instead of AWID.
				if agent.EncryptionKey != nil || agent.encryptionKeyRejected || strings.TrimSpace(agent.DIDAW) != "" {
					recipient, err := c.e2eeRecipientFromAgent(ctx, agent)
					if err != nil {
						return E2EERecipientKey{}, false, err
					}
					if strings.TrimSpace(recipient.DID) != strings.TrimSpace(otherDIDs[0]) {
						return E2EERecipientKey{}, false, errNoPublishedEncryptionKey
					}
					return recipient, true, nil
				}
			}
			// A local peer without a current roster publication may supply its
			// key in a verified envelope from this conversation and exact DID.
			recipients, _, err := c.learnedE2EEChatRecipients(ctx, sessionID)
			if err != nil {
				return E2EERecipientKey{}, false, err
			}
			for _, recipient := range recipients {
				if strings.TrimSpace(recipient.DID) == strings.TrimSpace(otherDIDs[0]) {
					return recipient, true, nil
				}
			}
			return E2EERecipientKey{}, false, errNoPublishedEncryptionKey
		}
		if len(addresses) != 1 {
			return E2EERecipientKey{}, false, nil
		}
		identity, err := c.ResolveIdentity(ctx, otherAddresses[0])
		if err != nil || identity == nil || identity.EncryptionKey == nil || strings.TrimSpace(identity.DID) != strings.TrimSpace(otherDIDs[0]) {
			return E2EERecipientKey{}, false, nil
		}
		return E2EERecipientKey{
			Address:        strings.TrimSpace(identity.Address),
			DID:            strings.TrimSpace(identity.DID),
			StableID:       strings.TrimSpace(identity.StableID),
			EncryptionKey:  identity.EncryptionKey,
			DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		}, true, nil
	}
	return E2EERecipientKey{}, false, nil
}

func hasGlobalDIDTarget(dids []string) bool {
	for _, did := range dids {
		if strings.HasPrefix(strings.TrimSpace(did), "did:aw:") {
			return true
		}
	}
	return false
}

func isLocalDIDKey(did string) bool {
	return strings.HasPrefix(strings.TrimSpace(did), "did:key:")
}

func (c *Client) learnedE2EEChatRecipients(ctx context.Context, sessionID string) ([]E2EERecipientKey, bool, error) {
	history, err := c.ChatHistory(ctx, ChatHistoryParams{SessionID: sessionID, Limit: 50})
	if err != nil {
		return nil, false, err
	}
	recipients := make([]E2EERecipientKey, 0, 1)
	seen := map[string]bool{}
	for _, msg := range history.Messages {
		// A valid envelope from another conversation, or a projection that
		// failed verification, cannot authorize this conversation's reply key.
		if msg.VerificationStatus != Verified || msg.ConversationID != sessionID || msg.Encrypted == nil || msg.Encrypted.ConversationID != sessionID {
			continue
		}
		recipient, ok, err := c.learnedE2EERecipientFromEnvelope(msg.Encrypted)
		if err != nil {
			return nil, true, err
		}
		if !ok {
			continue
		}
		key := strings.TrimSpace(recipient.DID)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		recipients = append(recipients, recipient)
	}
	if len(recipients) == 0 {
		return nil, false, nil
	}
	return recipients, true, nil
}

func (c *Client) learnedE2EEChatRecipientForDID(ctx context.Context, did string) (E2EERecipientKey, bool, error) {
	did = strings.TrimSpace(did)
	if !isLocalDIDKey(did) {
		return E2EERecipientKey{}, false, nil
	}
	resp, err := c.ChatListSessions(ctx)
	if err != nil {
		return E2EERecipientKey{}, false, err
	}
	for _, session := range resp.Sessions {
		if !stringSliceContainsFold(session.ParticipantDIDs, did) {
			continue
		}
		recipients, ok, err := c.learnedE2EEChatRecipients(ctx, session.SessionID)
		if err != nil {
			return E2EERecipientKey{}, true, err
		}
		if !ok {
			continue
		}
		for _, recipient := range recipients {
			if strings.EqualFold(strings.TrimSpace(recipient.DID), did) {
				return recipient, true, nil
			}
		}
	}
	return E2EERecipientKey{}, false, nil
}

func stringSliceContainsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func classifyE2EEChatTargets(targetList string) (aliases []string, dids []string, addresses []string) {
	for _, raw := range strings.Split(targetList, ",") {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		switch {
		case strings.HasPrefix(target, "did:"):
			dids = append(dids, target)
		case strings.Contains(target, "/"):
			addresses = append(addresses, target)
		default:
			aliases = append(aliases, target)
		}
	}
	return aliases, dids, addresses
}

func (c *Client) e2eeChatRecipients(ctx context.Context, aliases []string, dids []string, addresses []string) ([]E2EERecipientKey, error) {
	recipients := make([]E2EERecipientKey, 0, len(aliases)+len(dids)+len(addresses))
	if len(aliases) > 0 {
		resp, err := c.ListAgents(ctx)
		if err != nil {
			return nil, err
		}
		agentsByAlias := map[string]AgentView{}
		for _, agent := range resp.Agents {
			agentsByAlias[strings.TrimSpace(agent.Alias)] = agent
		}
		for _, alias := range aliases {
			agent, ok := agentsByAlias[strings.TrimSpace(alias)]
			if !ok {
				agent, err = c.e2eeRecipientAgent(ctx, "", alias)
				if err != nil {
					return nil, err
				}
			}
			recipient, err := c.e2eeRecipientFromAgent(ctx, agent)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, recipient)
		}
	}
	for _, target := range addresses {
		identity, err := c.ResolveIdentity(ctx, target)
		if err != nil {
			return nil, err
		}
		if identity.EncryptionKey == nil {
			return nil, errNoPublishedEncryptionKey
		}
		recipients = append(recipients, E2EERecipientKey{
			Address:        strings.TrimSpace(identity.Address),
			DID:            strings.TrimSpace(identity.DID),
			StableID:       strings.TrimSpace(identity.StableID),
			EncryptionKey:  identity.EncryptionKey,
			DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		})
	}
	for _, target := range dids {
		identity, err := c.ResolveIdentity(ctx, target)
		if err != nil {
			return nil, err
		}
		if identity.EncryptionKey == nil {
			if recipient, ok, err := c.learnedE2EEChatRecipientForDID(ctx, target); err != nil {
				return nil, err
			} else if ok {
				recipients = append(recipients, recipient)
				continue
			}
			return nil, errNoPublishedEncryptionKey
		}
		recipients = append(recipients, E2EERecipientKey{
			Address:        strings.TrimSpace(identity.Address),
			DID:            strings.TrimSpace(identity.DID),
			StableID:       strings.TrimSpace(identity.StableID),
			EncryptionKey:  identity.EncryptionKey,
			DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		})
	}
	if len(recipients) == 0 {
		return nil, errors.New("E2E chat requires at least one recipient")
	}
	return recipients, nil
}

type ChatPendingResponse struct {
	Pending         []ChatPendingItem `json:"pending"`
	MessagesWaiting int               `json:"messages_waiting"`
}

type ChatPendingItem struct {
	SessionID              string               `json:"session_id"`
	TeamID                 string               `json:"team_id,omitempty"`
	Participants           []string             `json:"participants"`
	ParticipantDIDs        []string             `json:"participant_dids,omitempty"`
	ParticipantAddresses   []string             `json:"participant_addresses,omitempty"`
	LastMessage            string               `json:"last_message"`
	LastMessageContentMode string               `json:"last_message_content_mode,omitempty"`
	LastMessageVersion     int                  `json:"last_message_version,omitempty"`
	LastEncrypted          *E2EEMessageEnvelope `json:"last_encrypted_envelope,omitempty"`
	LastFrom               string               `json:"last_from"`
	LastFromStableID       string               `json:"last_from_stable_id,omitempty"`
	LastFromDID            string               `json:"last_from_did,omitempty"`
	LastFromAddress        string               `json:"last_from_address,omitempty"`
	UnreadCount            int                  `json:"unread_count"`
	LastActivity           string               `json:"last_activity"`
	SenderWaiting          bool                 `json:"sender_waiting"`
	TimeRemainingSeconds   *int                 `json:"time_remaining_seconds"`
}

func (c *Client) ChatPending(ctx context.Context) (*ChatPendingResponse, error) {
	var out ChatPendingResponse
	if err := c.Get(ctx, "/v1/chat/pending", &out); err != nil {
		return nil, err
	}
	for i := range out.Pending {
		item := &out.Pending[i]
		if item.LastMessageContentMode == ContentModeEncryptedV2 || item.LastMessageVersion == E2EEMessageVersion || item.LastEncrypted != nil {
			if item.LastEncrypted == nil {
				return nil, errors.New("encrypted chat pending response is missing encrypted envelope")
			}
			plain, err := c.DecryptE2EEEnvelopeWithContext(ctx, item.LastEncrypted)
			if err != nil {
				return nil, err
			}
			item.LastMessage = plain.Body
		}
	}
	return &out, nil
}

type ChatHistoryResponse struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	IDChain                 ReceivedIDChain          `json:"id_chain,omitempty"`
	Attachments             []AttachmentDescriptor   `json:"attachments,omitempty"`
	AttachmentsAvailable    bool                     `json:"attachments_available"`
	SenderMembership        *SenderMembership        `json:"sender_membership,omitempty"`
	MessageID               string                   `json:"message_id"`
	ConversationID          string                   `json:"conversation_id,omitempty"`
	FromAgent               string                   `json:"from_agent"`
	FromAddress             string                   `json:"from_address,omitempty"`
	ToAddress               string                   `json:"to_address,omitempty"`
	Body                    string                   `json:"body"`
	ContentMode             string                   `json:"content_mode,omitempty"`
	MessageVersion          int                      `json:"message_version,omitempty"`
	Encrypted               *E2EEMessageEnvelope     `json:"encrypted_envelope,omitempty"`
	Timestamp               string                   `json:"timestamp"`
	SenderLeaving           bool                     `json:"sender_leaving"`
	ReplyToMessageID        string                   `json:"reply_to_message_id,omitempty"`
	FromDID                 string                   `json:"from_did,omitempty"`
	ToDID                   string                   `json:"to_did,omitempty"`
	FromStableID            string                   `json:"from_stable_id,omitempty"`
	ToStableID              string                   `json:"to_stable_id,omitempty"`
	Signature               string                   `json:"signature,omitempty"`
	SigningKeyID            string                   `json:"signing_key_id,omitempty"`
	SignedPayload           string                   `json:"signed_payload,omitempty"`
	RotationAnnouncement    *RotationAnnouncement    `json:"rotation_announcement,omitempty"`
	ReplacementAnnouncement *ReplacementAnnouncement `json:"replacement_announcement,omitempty"`
	VerificationStatus      VerificationStatus       `json:"verification_status,omitempty"`
	IsContact               *bool                    `json:"is_contact,omitempty"`
}

type ChatHistoryParams struct {
	SessionID  string
	MessageID  string
	UnreadOnly bool
	Limit      int
}

func (c *Client) ChatHistory(ctx context.Context, p ChatHistoryParams) (*ChatHistoryResponse, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(p.SessionID) + "/messages"
	sep := "?"
	if p.UnreadOnly {
		path += sep + "unread_only=true"
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
		sep = "&"
	}
	if strings.TrimSpace(p.MessageID) != "" {
		path += sep + "message_id=" + urlQueryEscape(strings.TrimSpace(p.MessageID))
	}
	var out ChatHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		if err := c.VerifyReceivedChatMessage(ctx, m, p.SessionID, m.FromAgent); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// VerifyReceivedChatMessage sets a plaintext or encrypted chat message's
// verification status and authenticated sender fields, the same way for every
// reader (chat history and the live stream) and by the rule mail uses
// (verifyReceived). conversationID is the conversation the reader read the
// message from; a message from any other conversation is Failed. trustAlias
// names the sender for trust normalisation when the message carries no
// address. An error means the message could not be read at all.
func (c *Client) VerifyReceivedChatMessage(ctx context.Context, m *ChatMessage, conversationID, trustAlias string) error {
	r := receivedChatMessage(m, trustAlias)
	r.requestedConversationID = strings.TrimSpace(conversationID)
	if err := c.verifyReceived(ctx, &r); err != nil {
		return err
	}
	r.applyToChat(m)
	return nil
}

func receivedChatMessage(m *ChatMessage, trustAlias string) receivedMessage {
	return receivedMessage{
		kind:                    receivedChat,
		fromAlias:               m.FromAgent,
		trustAlias:              trustAlias,
		timestamp:               m.Timestamp,
		messageID:               m.MessageID,
		conversationID:          m.ConversationID,
		contentMode:             m.ContentMode,
		messageVersion:          m.MessageVersion,
		encrypted:               m.Encrypted,
		signature:               m.Signature,
		signingKeyID:            m.SigningKeyID,
		signedPayload:           m.SignedPayload,
		senderMembership:        m.SenderMembership,
		rotationAnnouncement:    m.RotationAnnouncement,
		replacementAnnouncement: m.ReplacementAnnouncement,
		body:                    m.Body,
		fromDID:                 m.FromDID,
		toDID:                   m.ToDID,
		fromStableID:            m.FromStableID,
		toStableID:              m.ToStableID,
		fromAddress:             m.FromAddress,
		toAddress:               m.ToAddress,
		attachments:             m.Attachments,
		attachmentsAvailable:    m.AttachmentsAvailable,
		status:                  m.VerificationStatus,
		isContact:               m.IsContact,
	}
}

func (r *receivedMessage) applyToChat(m *ChatMessage) {
	m.Body = r.body
	m.FromDID = r.fromDID
	m.ToDID = r.toDID
	m.FromStableID = r.fromStableID
	m.ToStableID = r.toStableID
	m.FromAddress = r.fromAddress
	m.ToAddress = r.toAddress
	m.Attachments = r.attachments
	m.AttachmentsAvailable = r.attachmentsAvailable
	m.VerificationStatus = r.status
	m.IsContact = r.isContact
}

type ChatMarkReadRequest struct {
	MessageIDs []string `json:"message_ids"`
}

type chatMarkReadWatermarkRequest struct {
	UpToMessageID string `json:"up_to_message_id"`
}

type ChatMarkReadResponse struct {
	Success        bool `json:"success"`
	MessagesMarked int  `json:"messages_marked"`
}

func (c *Client) ChatMarkRead(ctx context.Context, sessionID string, req *ChatMarkReadRequest) (*ChatMarkReadResponse, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(sessionID) + "/read"
	var out ChatMarkReadResponse
	originalErr := c.Post(ctx, path, req, &out)
	if originalErr == nil {
		return &out, nil
	}

	// The exact request is always sent first so the server remains the
	// authoritative validator. Only an older server's answer to the ids-list
	// shape is retried with a watermark; every other refusal is returned as
	// itself, since a watermark would mark unpresented messages read.
	if !olderServerRequiresWatermark(originalErr) || !wellFormedChatMessageIDs(req) {
		return nil, originalErr
	}

	fallback := &chatMarkReadWatermarkRequest{UpToMessageID: req.MessageIDs[len(req.MessageIDs)-1]}
	var fallbackOut ChatMarkReadResponse
	if err := c.Post(ctx, path, fallback, &fallbackOut); err != nil {
		return nil, originalErr
	}
	return &fallbackOut, nil
}

// olderServerRequiresWatermark reports the answer a server released before
// v1.26.28 gives an ids-list read: FastAPI's 422 validation refusal naming
// the missing up_to_message_id, since its MarkReadRequest required that field
// and forbade others (server/src/aweb/routes/chat.py, server-v1.8.1 through
// server-v1.26.24).
func olderServerRequiresWatermark(err error) bool {
	if status, ok := HTTPStatusCode(err); !ok || status != http.StatusUnprocessableEntity {
		return false
	}
	body, ok := HTTPErrorBody(err)
	if !ok {
		return false
	}
	var refusal struct {
		Detail []struct {
			Type string `json:"type"`
			Loc  []any  `json:"loc"`
		} `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &refusal) != nil {
		return false
	}
	for _, detail := range refusal.Detail {
		if detail.Type == "missing" && len(detail.Loc) == 2 && detail.Loc[0] == "body" && detail.Loc[1] == "up_to_message_id" {
			return true
		}
	}
	return false
}

func wellFormedChatMessageIDs(req *ChatMarkReadRequest) bool {
	if req == nil || len(req.MessageIDs) == 0 {
		return false
	}
	for _, messageID := range req.MessageIDs {
		if !isCanonicalUUID(messageID) {
			return false
		}
	}
	return true
}

func isCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	_, err := hex.DecodeString(compact)
	return err == nil
}

// ChatStream opens an SSE stream for a session.
//
// deadline is required by the aweb API and must be a future time.
// after controls replay: if non-nil, the server replays only messages created after
// that timestamp; if nil, no replay (server polls from now).
// Uses a dedicated HTTP client without response timeout since SSE connections are long-lived.
func (c *Client) ChatStream(ctx context.Context, sessionID string, deadline time.Time, after *time.Time) (*SSEStream, error) {
	path := chatStreamPath(sessionID, deadline)
	if after != nil && !after.IsZero() {
		// Truncate to second precision so the server replay query
		// (WHERE created_at > $after) always includes our sent message.
		// The signed timestamp uses RFC3339 (second precision), but sentAt
		// has nanosecond precision — without truncation the sent message
		// falls before the after boundary and is excluded from the replay.
		// Subtract one second to handle the > (not >=) query and the case
		// where sentAt and the signed timestamp land in the same second.
		path += "&after=" + urlQueryEscape(after.Truncate(time.Second).Add(-time.Second).UTC().Format(time.RFC3339))
	}
	return c.openChatStream(ctx, path)
}

// ChatStreamAfterSeq opens an SSE stream for a session that delivers every
// message and read receipt numbered after afterSeq. A client resumes a stream
// the server ended this way without losing or repeating an event.
func (c *Client) ChatStreamAfterSeq(ctx context.Context, sessionID string, deadline time.Time, afterSeq int64) (*SSEStream, error) {
	return c.openChatStream(ctx, chatStreamPath(sessionID, deadline)+"&after_seq="+strconv.FormatInt(afterSeq, 10))
}

func chatStreamPath(sessionID string, deadline time.Time) string {
	return "/v1/chat/sessions/" + urlPathEscape(sessionID) + "/stream?deadline=" + urlQueryEscape(deadline.UTC().Format(time.RFC3339Nano))
}

func (c *Client) openChatStream(ctx context.Context, path string) (*SSEStream, error) {
	resp, err := c.openStream(ctx, path)
	if err != nil {
		return nil, err
	}
	return NewSSEStream(resp.Body), nil
}

// openStream opens the SSE stream at path with the client's auth. A stream
// refused for a team certificate under a superseded key is opened once more
// with the certificate now recorded for the member.
func (c *Client) openStream(ctx context.Context, path string) (*http.Response, error) {
	for refreshed := false; ; refreshed = true {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")
		setUserAgent(req, c.userAgent)
		if err := c.signRequest(req, nil); err != nil {
			return nil, err
		}

		resp, err := DoNoRedirect(c.sseClient, req)
		if err != nil {
			return nil, err
		}
		if v := resp.Header.Get("X-Latest-Client-Version"); v != "" {
			c.latestClientVersion.Store(v)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		if !refreshed {
			retry, err := c.refreshSupersededTeamCertificate(ctx, resp)
			if err != nil {
				_ = resp.Body.Close()
				return nil, err
			}
			if retry {
				_ = resp.Body.Close()
				continue
			}
		}
		body := ReadErrorExcerpt(resp.Body)
		_ = resp.Body.Close()
		return nil, newAPIError(resp, body)
	}
}

// ChatSendMessage sends a message in an existing chat session.
type ChatSendMessageRequest struct {
	Body           string               `json:"body"`
	ContentMode    string               `json:"content_mode,omitempty"`
	MessageVersion int                  `json:"message_version,omitempty"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	Leaving        bool                 `json:"leaving,omitempty"`
	ExtendWait     bool                 `json:"hang_on,omitempty"`
	ReplyTo        string               `json:"reply_to,omitempty"`
	FromDID        string               `json:"from_did,omitempty"`
	Signature      string               `json:"signature,omitempty"`
	Timestamp      string               `json:"timestamp,omitempty"`
	MessageID      string               `json:"message_id,omitempty"`
	SignedPayload  string               `json:"signed_payload,omitempty"`
	EncryptE2EE    bool                 `json:"-"`
	// E2EEInherited permits a server-readable continuation to a verified
	// hosted peer when encryption came from the existing conversation.
	E2EEInherited bool `json:"-"`
}

type ChatSendMessageResponse struct {
	MessageID          string `json:"message_id"`
	Delivered          bool   `json:"delivered"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

func (c *Client) ChatSendMessage(ctx context.Context, sessionID string, req *ChatSendMessageRequest) (*ChatSendMessageResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req
	if payload.EncryptE2EE {
		if err := c.prepareE2EEChatSend(ctx, sessionID, &payload); err != nil {
			return nil, err
		}
	}
	if payload.EncryptE2EE {
		var out ChatSendMessageResponse
		if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", &payload, &out); err != nil {
			return nil, serverCustodialRefusal(err, payload.Encrypted)
		}
		return &out, nil
	}

	// In-session messages: include deterministic To for signature verification.
	// (aweb returns to_address for reconstruction; we sign the same value.)
	to := ""
	from := c.address
	targetIsAddress := false
	if c.canAttachPlainMessageSignature() {
		if toAddr, err := c.toAddressForSession(ctx, sessionID, false); err == nil {
			to = toAddr
		}
		targetIsAddress = isRoutableAddressTarget(to) && !strings.Contains(to, ",")
		targetIsIdentity := strings.HasPrefix(strings.TrimSpace(to), "did:")
		// In-session continuations may be relayed through federation using the
		// stored participant route. Sign the full address so the remote envelope
		// sender_address can be verified even when the recipient target is a
		// stable did:aw rather than an address.
		from = c.signedPayloadFrom(false, !(targetIsAddress || targetIsIdentity))
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From:                          from,
		To:                            to,
		Type:                          "chat",
		Body:                          payload.Body,
		ConversationID:                strings.TrimSpace(sessionID),
		ReplyTo:                       payload.ReplyTo,
		SenderLeaving:                 payload.Leaving,
		HangOn:                        payload.ExtendWait,
		RequireRecipientBinding:       targetIsAddress && c.requireRecipientBinding,
		AllowStoredRouteGlobalBinding: true,
	})
	if err != nil {
		return nil, err
	}
	if c.canAttachPlainMessageSignature() {
		payload.FromDID = sf.FromDID
		payload.Signature = sf.Signature
		payload.Timestamp = sf.Timestamp
		payload.MessageID = sf.MessageID
		payload.SignedPayload = sf.SignedPayload
	}

	var out ChatSendMessageResponse
	if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatListSessions lists chat sessions the authenticated agent participates in.
type ChatSessionItem struct {
	SessionID            string   `json:"session_id"`
	TeamID               string   `json:"team_id,omitempty"`
	Participants         []string `json:"participants"`
	ParticipantDIDs      []string `json:"participant_dids,omitempty"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	CreatedAt            string   `json:"created_at"`
	LastActivity         string   `json:"last_activity,omitempty"`
	SenderWaiting        bool     `json:"sender_waiting,omitempty"`
}

type ChatListSessionsResponse struct {
	Sessions []ChatSessionItem `json:"sessions"`
}

func (c *Client) ChatListSessions(ctx context.Context) (*ChatListSessionsResponse, error) {
	var out ChatListSessionsResponse
	if err := c.Get(ctx, "/v1/chat/sessions", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
