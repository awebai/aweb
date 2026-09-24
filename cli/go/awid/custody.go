package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// PlainMessageSignRequest is the structured local-custody request for signing
// an ordinary mail/chat message envelope. The resident service, not the
// worker, decides the final sender identity fields and signs only an internally
// constructed MessageEnvelope canonical payload.
type PlainMessageSignRequest struct {
	Version       int             `json:"v"`
	Operation     string          `json:"op"`
	GrantID       string          `json:"grant_id"`
	SessionDIDKey string          `json:"session_did_key"`
	TeamID        string          `json:"team_id"`
	SubjectDIDAW  string          `json:"subject_did_aw,omitempty"`
	SubjectDIDKey string          `json:"subject_did_key"`
	Audience      string          `json:"aud"`
	Nonce         string          `json:"nonce"`
	Timestamp     string          `json:"timestamp"`
	RequestDigest string          `json:"request_digest"`
	Signature     string          `json:"signature"`
	Envelope      MessageEnvelope `json:"envelope"`
}

type PlainMessageSignResponse struct {
	FromDID       string `json:"from_did"`
	SigningKeyID  string `json:"signing_key_id"`
	FromStableID  string `json:"from_stable_id,omitempty"`
	ToDID         string `json:"to_did,omitempty"`
	ToStableID    string `json:"to_stable_id,omitempty"`
	MessageID     string `json:"message_id"`
	Timestamp     string `json:"timestamp"`
	Signature     string `json:"signature"`
	SignedPayload string `json:"signed_payload"`
}

type PlainMessageSigner interface {
	SignPlainMessage(ctx context.Context, req *PlainMessageSignRequest) (*PlainMessageSignResponse, error)
}

type custodySubject struct {
	TeamID  string
	DIDAW   string
	DIDKey  string
	Address string
	Alias   string
}

func (c *Client) SetGrantSubject(teamID, didAW, didKey, address, alias string) {
	if c == nil {
		return
	}
	c.teamID = strings.TrimSpace(teamID)
	c.stableID = strings.TrimSpace(didAW)
	c.address = strings.TrimSpace(address)
	if strings.TrimSpace(didKey) != "" {
		// The grant request-auth did remains the session DID in c.did.  Store the
		// subject did:key only for custody proof construction.
		c.custodySubject.DIDKey = strings.TrimSpace(didKey)
	}
	c.custodySubject.TeamID = strings.TrimSpace(teamID)
	c.custodySubject.DIDAW = strings.TrimSpace(didAW)
	c.custodySubject.Address = strings.TrimSpace(address)
	c.custodySubject.Alias = strings.TrimSpace(alias)
}

func (c *Client) SetPlainMessageSigner(signer PlainMessageSigner) {
	if c != nil {
		c.plainMessageSigner = signer
	}
}

// UnixCustodyClient calls a local resident custody service over a Unix socket.
type UnixCustodyClient struct{ SocketPath string }

func (c *UnixCustodyClient) ServiceAudience(ctx context.Context) (string, error) {
	var status struct {
		ServiceID string `json:"service_id"`
	}
	if err := c.do(ctx, http.MethodGet, "/status", nil, &status); err != nil {
		return "", err
	}
	if strings.TrimSpace(status.ServiceID) == "" {
		return "", fmt.Errorf("custody_unavailable")
	}
	return "local-resident-custody:" + strings.TrimSpace(status.ServiceID), nil
}

func (c *UnixCustodyClient) SignPlainMessage(ctx context.Context, req *PlainMessageSignRequest) (*PlainMessageSignResponse, error) {
	var out PlainMessageSignResponse
	if err := c.do(ctx, http.MethodPost, "/sign_plain_message", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *UnixCustodyClient) do(ctx context.Context, method, path string, in any, out any) error {
	if c == nil || strings.TrimSpace(c.SocketPath) == "" {
		return fmt.Errorf("custody_unavailable")
	}
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", strings.TrimSpace(c.SocketPath))
	}}}
	hreq, err := http.NewRequestWithContext(ctx, method, "http://local"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hreq)
	if err != nil {
		return fmt.Errorf("custody_unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var er struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&er)
		if er.Error != "" {
			return errors.New(er.Error)
		}
		if er.Detail != "" {
			return errors.New(er.Detail)
		}
		return fmt.Errorf("custody_error_%d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

func custodyRequestDigest(req *PlainMessageSignRequest) (string, error) {
	if req == nil {
		return "", fmt.Errorf("request is required")
	}
	payload := map[string]any{
		"v":               req.Version,
		"op":              req.Operation,
		"grant_id":        req.GrantID,
		"session_did_key": req.SessionDIDKey,
		"team_id":         req.TeamID,
		"subject_did_aw":  req.SubjectDIDAW,
		"subject_did_key": req.SubjectDIDKey,
		"aud":             req.Audience,
		"envelope":        req.Envelope,
	}
	canonical, err := CanonicalJSONValue(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func custodyProofCanonical(req *PlainMessageSignRequest) (string, error) {
	payload := map[string]any{
		"v":               req.Version,
		"op":              req.Operation,
		"grant_id":        req.GrantID,
		"session_did_key": req.SessionDIDKey,
		"team_id":         req.TeamID,
		"subject_did_aw":  req.SubjectDIDAW,
		"subject_did_key": req.SubjectDIDKey,
		"aud":             req.Audience,
		"nonce":           req.Nonce,
		"timestamp":       req.Timestamp,
		"request_digest":  req.RequestDigest,
	}
	return CanonicalJSONValue(payload)
}

func SignCustodyProof(key ed25519.PrivateKey, req *PlainMessageSignRequest) error {
	if key == nil {
		return fmt.Errorf("signing key is required")
	}
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = "sign_plain_message"
	}
	if strings.TrimSpace(req.SessionDIDKey) == "" {
		req.SessionDIDKey = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	if strings.TrimSpace(req.Timestamp) == "" {
		req.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(req.Nonce) == "" {
		n, err := GenerateUUID4()
		if err != nil {
			return err
		}
		req.Nonce = n
	}
	digest, err := custodyRequestDigest(req)
	if err != nil {
		return err
	}
	req.RequestDigest = digest
	canonical, err := custodyProofCanonical(req)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(key, []byte(canonical))
	req.Signature = base64.RawStdEncoding.EncodeToString(sig)
	return nil
}

func VerifyCustodyProof(req *PlainMessageSignRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	if req.Version != 1 || req.Operation != "sign_plain_message" {
		return fmt.Errorf("unsupported_operation")
	}
	digest, err := custodyRequestDigest(req)
	if err != nil {
		return err
	}
	if digest != strings.TrimSpace(req.RequestDigest) {
		return fmt.Errorf("message_digest_mismatch")
	}
	pub, err := ExtractPublicKey(strings.TrimSpace(req.SessionDIDKey))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	canonical, err := custodyProofCanonical(req)
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(req.Signature))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return fmt.Errorf("bad_signature")
	}
	return nil
}

// E2EEEnvelopeCreateRequest is the structured local-custody request for
// building and signing an encrypted-v2 mail/chat envelope. The service builds
// the envelope itself; callers never supply encrypted envelope bytes to sign.
type E2EEEnvelopeCreateRequest struct {
	Version             int                `json:"v"`
	Operation           string             `json:"op"`
	GrantID             string             `json:"grant_id"`
	SessionDIDKey       string             `json:"session_did_key"`
	TeamID              string             `json:"team_id"`
	SubjectDIDAW        string             `json:"subject_did_aw,omitempty"`
	SubjectDIDKey       string             `json:"subject_did_key"`
	Audience            string             `json:"aud"`
	Nonce               string             `json:"nonce"`
	Timestamp           string             `json:"timestamp"`
	RequestDigest       string             `json:"request_digest"`
	Signature           string             `json:"signature"`
	Kind                string             `json:"kind"`
	Subject             string             `json:"subject,omitempty"`
	Body                string             `json:"body"`
	MessageID           string             `json:"message_id"`
	ConversationID      string             `json:"conversation_id"`
	ReplyToMessageID    string             `json:"reply_to_message_id,omitempty"`
	Recipients          []E2EERecipientKey `json:"recipients"`
	DeliveryOrigin      string             `json:"delivery_origin,omitempty"`
	ObservedInboundMode string             `json:"sender_observed_inbound_mode,omitempty"`
}

type E2EEEnvelopeCreateResponse struct {
	ContentMode       string               `json:"content_mode"`
	MessageVersion    int                  `json:"message_version"`
	EncryptedEnvelope *E2EEMessageEnvelope `json:"encrypted_envelope"`
}

type E2EEUnwrapRequest struct {
	Version        int                  `json:"v"`
	Operation      string               `json:"op"`
	GrantID        string               `json:"grant_id"`
	SessionDIDKey  string               `json:"session_did_key"`
	TeamID         string               `json:"team_id"`
	SubjectDIDAW   string               `json:"subject_did_aw,omitempty"`
	SubjectDIDKey  string               `json:"subject_did_key"`
	Audience       string               `json:"aud"`
	Nonce          string               `json:"nonce"`
	Timestamp      string               `json:"timestamp"`
	RequestDigest  string               `json:"request_digest"`
	Signature      string               `json:"signature"`
	Kind           string               `json:"kind"`
	MessageID      string               `json:"message_id"`
	ConversationID string               `json:"conversation_id"`
	OutputMode     string               `json:"output_mode"`
	Envelope       *E2EEMessageEnvelope `json:"encrypted_envelope"`
}

type E2EEUnwrapResponse struct {
	Kind           string `json:"kind"`
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id"`
	Subject        string `json:"subject,omitempty"`
	Body           string `json:"body"`
	ContentNotice  string `json:"content_notice,omitempty"`
}

type E2EECustodyClient interface {
	CreateE2EEEnvelope(ctx context.Context, req *E2EEEnvelopeCreateRequest) (*E2EEEnvelopeCreateResponse, error)
	UnwrapE2EEMessage(ctx context.Context, req *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error)
}

func (c *UnixCustodyClient) CreateE2EEEnvelope(ctx context.Context, req *E2EEEnvelopeCreateRequest) (*E2EEEnvelopeCreateResponse, error) {
	var out E2EEEnvelopeCreateResponse
	if err := c.do(ctx, http.MethodPost, "/create_e2ee_envelope", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *UnixCustodyClient) UnwrapE2EEMessage(ctx context.Context, req *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error) {
	var out E2EEUnwrapResponse
	if err := c.do(ctx, http.MethodPost, "/unwrap_e2ee_message", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func custodyDigestValue(operation string, payload map[string]any) (string, error) {
	payload["op"] = operation
	canonical, err := CanonicalJSONValue(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func signCustodyProofFields(key ed25519.PrivateKey, version int, operation string, fields map[string]string, requestDigest *string, nonce *string, timestamp *string, signature *string) error {
	if key == nil {
		return fmt.Errorf("signing key is required")
	}
	if version == 0 {
		version = 1
	}
	if strings.TrimSpace(fields["session_did_key"]) == "" {
		fields["session_did_key"] = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	if strings.TrimSpace(*timestamp) == "" {
		*timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(*nonce) == "" {
		n, err := GenerateUUID4()
		if err != nil {
			return err
		}
		*nonce = n
	}
	proof := map[string]any{"v": version, "op": operation, "grant_id": fields["grant_id"], "session_did_key": fields["session_did_key"], "team_id": fields["team_id"], "subject_did_aw": fields["subject_did_aw"], "subject_did_key": fields["subject_did_key"], "aud": fields["aud"], "nonce": *nonce, "timestamp": *timestamp, "request_digest": *requestDigest}
	canonical, err := CanonicalJSONValue(proof)
	if err != nil {
		return err
	}
	*signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(canonical)))
	return nil
}

func verifyCustodyProofFields(version int, operation string, fields map[string]string, nonce, timestamp, requestDigest, signature string, expectedDigest string) error {
	if version != 1 || operation == "" {
		return fmt.Errorf("unsupported_operation")
	}
	if strings.TrimSpace(requestDigest) != strings.TrimSpace(expectedDigest) {
		return fmt.Errorf("message_digest_mismatch")
	}
	pub, err := ExtractPublicKey(strings.TrimSpace(fields["session_did_key"]))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	proof := map[string]any{"v": version, "op": operation, "grant_id": fields["grant_id"], "session_did_key": fields["session_did_key"], "team_id": fields["team_id"], "subject_did_aw": fields["subject_did_aw"], "subject_did_key": fields["subject_did_key"], "aud": fields["aud"], "nonce": nonce, "timestamp": timestamp, "request_digest": requestDigest}
	canonical, err := CanonicalJSONValue(proof)
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return fmt.Errorf("bad_signature")
	}
	return nil
}

func SignE2EECreateCustodyProof(key ed25519.PrivateKey, req *E2EEEnvelopeCreateRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = "create_e2ee_envelope"
	}
	if strings.TrimSpace(req.SessionDIDKey) == "" {
		req.SessionDIDKey = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "subject": req.Subject, "body": req.Body, "message_id": req.MessageID, "conversation_id": req.ConversationID, "reply_to_message_id": req.ReplyToMessageID, "recipients": req.Recipients, "delivery_origin": req.DeliveryOrigin, "sender_observed_inbound_mode": req.ObservedInboundMode}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	req.RequestDigest = d
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	if err := signCustodyProofFields(key, req.Version, req.Operation, fields, &req.RequestDigest, &req.Nonce, &req.Timestamp, &req.Signature); err != nil {
		return err
	}
	req.SessionDIDKey = fields["session_did_key"]
	return nil
}

func VerifyE2EECreateCustodyProof(req *E2EEEnvelopeCreateRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "subject": req.Subject, "body": req.Body, "message_id": req.MessageID, "conversation_id": req.ConversationID, "reply_to_message_id": req.ReplyToMessageID, "recipients": req.Recipients, "delivery_origin": req.DeliveryOrigin, "sender_observed_inbound_mode": req.ObservedInboundMode}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	return verifyCustodyProofFields(req.Version, req.Operation, fields, req.Nonce, req.Timestamp, req.RequestDigest, req.Signature, d)
}

func SignE2EEUnwrapCustodyProof(key ed25519.PrivateKey, req *E2EEUnwrapRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = "unwrap_e2ee_message"
	}
	if strings.TrimSpace(req.SessionDIDKey) == "" {
		req.SessionDIDKey = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "message_id": req.MessageID, "conversation_id": req.ConversationID, "output_mode": req.OutputMode, "encrypted_envelope": req.Envelope}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	req.RequestDigest = d
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	if err := signCustodyProofFields(key, req.Version, req.Operation, fields, &req.RequestDigest, &req.Nonce, &req.Timestamp, &req.Signature); err != nil {
		return err
	}
	req.SessionDIDKey = fields["session_did_key"]
	return nil
}

func VerifyE2EEUnwrapCustodyProof(req *E2EEUnwrapRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "message_id": req.MessageID, "conversation_id": req.ConversationID, "output_mode": req.OutputMode, "encrypted_envelope": req.Envelope}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	return verifyCustodyProofFields(req.Version, req.Operation, fields, req.Nonce, req.Timestamp, req.RequestDigest, req.Signature, d)
}
