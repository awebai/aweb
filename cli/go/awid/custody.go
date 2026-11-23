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

	"github.com/awebai/aw/internal/custodypath"
	"github.com/awebai/aw/signaturewire"
)

// ErrAppToolDenied identifies a structured resident-custody refusal. Display
// advice may change without changing the caller's recovery decision.
var ErrAppToolDenied = errors.New(string(CustodyRefusalAppToolDenied))

// CustodyRefusalCode names a resident-custody rule independently of its advice.
type CustodyRefusalCode string

const CustodyRefusalAppToolDenied CustodyRefusalCode = "app_tool_denied"

// CustodyError keeps a stable refusal code separate from recovery guidance.
type CustodyError struct{ Code, Message string }

// CustodyRecipientBindingUnavailable is the refusal of a custody host that
// cannot bind an addressless recipient (custody hosts before aw 1.36.30).
const CustodyRecipientBindingUnavailable = "recipient_binding_unavailable"

// Error returns the stable custody refusal code together with any recovery guidance.
func (e *CustodyError) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Is exposes the known structured refusal without classifying by display text.
func (e *CustodyError) Is(target error) bool {
	return target == ErrAppToolDenied && CustodyRefusalCode(e.Code) == CustodyRefusalAppToolDenied
}

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

// PlainMessageSignResponse contains the resident-signed envelope fields returned to a grant client.
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

// PlainMessageSigner signs structured mail and chat requests through resident custody.
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

// SetGrantSubject records the resident identity for custody requests while retaining the session signing DID.
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

// SetPlainMessageSigner installs the resident signer used by grant clients for message signing.
func (c *Client) SetPlainMessageSigner(signer PlainMessageSigner) {
	if c != nil {
		c.plainMessageSigner = signer
	}
}

// UnixCustodyClient calls a local resident custody service over a Unix socket.
type UnixCustodyClient struct{ SocketPath string }

// ServiceAudience reads the resident service ID and returns its custody audience binding.
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

// SignPlainMessage sends one structured envelope to the resident service for signing.
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
	if err := custodypath.Check(strings.TrimSpace(c.SocketPath)); err != nil {
		return err
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
			Error   string `json:"error"`
			Detail  string `json:"detail"`
			Message string `json:"message"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
			return fmt.Errorf("custody_error_%d: decode refusal: %w", resp.StatusCode, err)
		}
		if er.Error != "" {
			return &CustodyError{Code: er.Error, Message: er.Message}
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
	canonical, err := CanonicalJSONValueEscapingLineSeparators(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// custodyProofMetadata is the identity binding shared by every custody proof.
type custodyProofMetadata struct {
	GrantID, SessionDIDKey, TeamID        string
	SubjectDIDAW, SubjectDIDKey, Audience string
}

type custodyProofData struct {
	Version                         int
	Operation                       string
	Metadata                        custodyProofMetadata
	Nonce, Timestamp, RequestDigest string
}

// canonical owns the released custody proof bytes, including empty fields and
// escaped line separators (docs/identity.md: structured local custody requests).
func (p custodyProofData) canonical() (string, error) {
	return CanonicalJSONValueEscapingLineSeparators(map[string]any{
		"v": p.Version, "op": p.Operation, "grant_id": p.Metadata.GrantID,
		"session_did_key": p.Metadata.SessionDIDKey, "team_id": p.Metadata.TeamID,
		"subject_did_aw": p.Metadata.SubjectDIDAW, "subject_did_key": p.Metadata.SubjectDIDKey,
		"aud": p.Metadata.Audience, "nonce": p.Nonce, "timestamp": p.Timestamp,
		"request_digest": p.RequestDigest,
	})
}

func custodyProofCanonical(req *PlainMessageSignRequest) (string, error) {
	return (custodyProofData{
		Version: req.Version, Operation: req.Operation,
		Metadata: custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey,
			TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience},
		Nonce: req.Nonce, Timestamp: req.Timestamp, RequestDigest: req.RequestDigest,
	}).canonical()
}

// SignCustodyProof binds a plain-message custody request to the session key, nonce and timestamp.
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
	sig := signaturewire.SignBytes(key, []byte(canonical))
	req.Signature = base64.RawStdEncoding.EncodeToString(sig)
	return nil
}

// VerifyCustodyProof checks the session signature and digest binding of a plain-message custody request.
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
	sig, err := signaturewire.DecodeStd(strings.TrimSpace(req.Signature))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	if !signaturewire.Verify(signaturewire.Proof{PublicKey: pub, Payload: []byte(canonical), Signature: sig}) {
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

// E2EEEnvelopeCreateResponse carries the encrypted envelope produced by resident custody.
type E2EEEnvelopeCreateResponse struct {
	ContentMode       string               `json:"content_mode"`
	MessageVersion    int                  `json:"message_version"`
	EncryptedEnvelope *E2EEMessageEnvelope `json:"encrypted_envelope"`
}

// E2EEUnwrapRequest binds a decryption request to a grant, subject, audience and encrypted envelope.
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

// E2EEUnwrapResponse contains the plaintext and message identities released by resident custody.
type E2EEUnwrapResponse struct {
	Attachments    json.RawMessage   `json:"attachments,omitempty"`
	Kind           string            `json:"kind"`
	MessageID      string            `json:"message_id"`
	ConversationID string            `json:"conversation_id"`
	CreatedAt      string            `json:"created_at,omitempty"`
	From           E2EEIdentityRef   `json:"from,omitempty"`
	Recipients     []E2EEIdentityRef `json:"recipients,omitempty"`
	Subject        string            `json:"subject,omitempty"`
	Body           string            `json:"body"`
	ContentNotice  string            `json:"content_notice,omitempty"`
}

// E2EECustodyClient creates and decrypts encrypted envelopes within resident custody.
type E2EECustodyClient interface {
	CreateE2EEEnvelope(ctx context.Context, req *E2EEEnvelopeCreateRequest) (*E2EEEnvelopeCreateResponse, error)
	UnwrapE2EEMessage(ctx context.Context, req *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error)
}

// CreateE2EEEnvelope submits a session-authenticated request for resident envelope encryption.
func (c *UnixCustodyClient) CreateE2EEEnvelope(ctx context.Context, req *E2EEEnvelopeCreateRequest) (*E2EEEnvelopeCreateResponse, error) {
	var out E2EEEnvelopeCreateResponse
	if err := c.do(ctx, http.MethodPost, "/create_e2ee_envelope", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UnwrapE2EEMessage submits a session-authenticated request for resident envelope decryption.
func (c *UnixCustodyClient) UnwrapE2EEMessage(ctx context.Context, req *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error) {
	var out E2EEUnwrapResponse
	if err := c.do(ctx, http.MethodPost, "/unwrap_e2ee_message", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func custodyDigestValue(operation string, payload map[string]any) (string, error) {
	payload["op"] = operation
	canonical, err := CanonicalJSONValueEscapingLineSeparators(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type custodyProofSigning struct {
	Version                     int
	Operation                   string
	Metadata                    *custodyProofMetadata
	RequestDigest               string
	Nonce, Timestamp, Signature *string
}

func signCustodyProofFields(key ed25519.PrivateKey, request custodyProofSigning) error {
	if key == nil {
		return fmt.Errorf("signing key is required")
	}
	version := request.Version
	if version == 0 {
		version = 1
	}
	if strings.TrimSpace(request.Metadata.SessionDIDKey) == "" {
		publicKey, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("unsupported signing key")
		}
		request.Metadata.SessionDIDKey = ComputeDIDKey(publicKey)
	}
	if strings.TrimSpace(*request.Timestamp) == "" {
		*request.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(*request.Nonce) == "" {
		nonce, err := GenerateUUID4()
		if err != nil {
			return err
		}
		*request.Nonce = nonce
	}
	canonical, err := (custodyProofData{Version: version, Operation: request.Operation,
		Metadata: *request.Metadata, Nonce: *request.Nonce, Timestamp: *request.Timestamp, RequestDigest: request.RequestDigest}).canonical()
	if err != nil {
		return err
	}
	*request.Signature = signaturewire.SignStd(key, []byte(canonical))
	return nil
}

type custodyOperation string

const (
	custodyOperationUnspecified custodyOperation = ""
	custodyCreateEnvelope       custodyOperation = "create_e2ee_envelope"
	custodyUnwrapEnvelope       custodyOperation = "unwrap_e2ee_message"
	custodySignAppRequest       custodyOperation = "sign_app_request"
)

type custodyProofVerification struct {
	Proof                     custodyProofData
	Signature, ExpectedDigest string
}

func verifyCustodyProofFields(request custodyProofVerification) error {
	proof := request.Proof
	if proof.Version != 1 || proof.Operation == string(custodyOperationUnspecified) {
		return fmt.Errorf("unsupported_operation")
	}
	if strings.TrimSpace(proof.RequestDigest) != strings.TrimSpace(request.ExpectedDigest) {
		return fmt.Errorf("message_digest_mismatch")
	}
	publicKey, err := ExtractPublicKey(strings.TrimSpace(proof.Metadata.SessionDIDKey))
	if err != nil {
		return fmt.Errorf("bad_signature")
	}
	canonical, err := proof.canonical()
	if err != nil {
		return err
	}
	signature, err := signaturewire.DecodeStd(strings.TrimSpace(request.Signature))
	if err != nil || !signaturewire.Verify(signaturewire.Proof{PublicKey: publicKey, Payload: []byte(canonical), Signature: signature}) {
		return fmt.Errorf("bad_signature")
	}
	return nil
}

// SignE2EECreateCustodyProof binds the encryption request digest to the session key and proof fields.
func SignE2EECreateCustodyProof(key ed25519.PrivateKey, req *E2EEEnvelopeCreateRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = string(custodyCreateEnvelope)
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
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	if err := signCustodyProofFields(key, custodyProofSigning{Version: req.Version, Operation: req.Operation, Metadata: &fields, RequestDigest: req.RequestDigest, Nonce: &req.Nonce, Timestamp: &req.Timestamp, Signature: &req.Signature}); err != nil {
		return err
	}
	req.SessionDIDKey = fields.SessionDIDKey
	return nil
}

// VerifyE2EECreateCustodyProof checks the encryption request digest and session signature.
func VerifyE2EECreateCustodyProof(req *E2EEEnvelopeCreateRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "subject": req.Subject, "body": req.Body, "message_id": req.MessageID, "conversation_id": req.ConversationID, "reply_to_message_id": req.ReplyToMessageID, "recipients": req.Recipients, "delivery_origin": req.DeliveryOrigin, "sender_observed_inbound_mode": req.ObservedInboundMode}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	return verifyCustodyProofFields(custodyProofVerification{Proof: custodyProofData{Version: req.Version, Operation: req.Operation, Metadata: fields, Nonce: req.Nonce, Timestamp: req.Timestamp, RequestDigest: req.RequestDigest}, Signature: req.Signature, ExpectedDigest: d})
}

// SignE2EEUnwrapCustodyProof binds the decryption request digest to the session key and proof fields.
func SignE2EEUnwrapCustodyProof(key ed25519.PrivateKey, req *E2EEUnwrapRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = string(custodyUnwrapEnvelope)
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
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	if err := signCustodyProofFields(key, custodyProofSigning{Version: req.Version, Operation: req.Operation, Metadata: &fields, RequestDigest: req.RequestDigest, Nonce: &req.Nonce, Timestamp: &req.Timestamp, Signature: &req.Signature}); err != nil {
		return err
	}
	req.SessionDIDKey = fields.SessionDIDKey
	return nil
}

// VerifyE2EEUnwrapCustodyProof checks the decryption request digest and session signature.
func VerifyE2EEUnwrapCustodyProof(req *E2EEUnwrapRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	payload := map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "kind": req.Kind, "message_id": req.MessageID, "conversation_id": req.ConversationID, "output_mode": req.OutputMode, "encrypted_envelope": req.Envelope}
	d, err := custodyDigestValue(req.Operation, payload)
	if err != nil {
		return err
	}
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	return verifyCustodyProofFields(custodyProofVerification{Proof: custodyProofData{Version: req.Version, Operation: req.Operation, Metadata: fields, Nonce: req.Nonce, Timestamp: req.Timestamp, RequestDigest: req.RequestDigest}, Signature: req.Signature, ExpectedDigest: d})
}

// AppRequestSignRequest asks the local resident custody service to sign one
// installed-app manifest tool call. The worker supplies only the app, verb and
// structured tool input; custody re-interprets the call against its own
// mint-time snapshot of the tool and chooses origin, method, path and body.
type AppRequestSignRequest struct {
	Version       int            `json:"v"`
	Operation     string         `json:"op"`
	GrantID       string         `json:"grant_id"`
	SessionDIDKey string         `json:"session_did_key"`
	TeamID        string         `json:"team_id"`
	SubjectDIDAW  string         `json:"subject_did_aw,omitempty"`
	SubjectDIDKey string         `json:"subject_did_key"`
	Audience      string         `json:"aud"`
	Nonce         string         `json:"nonce"`
	Timestamp     string         `json:"timestamp"`
	RequestDigest string         `json:"request_digest"`
	Signature     string         `json:"signature"`
	AppID         string         `json:"app_id"`
	Verb          string         `json:"verb"`
	Args          map[string]any `json:"args"`
	RawBody       string         `json:"raw_body,omitempty"`
}

// AppRequestSignResponse is the exact request the worker must send: custody
// output is authoritative and must not be merged with local manifest data.
type AppRequestSignResponse struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

// AppRequestCustodyClient signs installed-app requests using resident identity custody.
type AppRequestCustodyClient interface {
	SignAppRequest(ctx context.Context, req *AppRequestSignRequest) (*AppRequestSignResponse, error)
}

// SignAppRequest submits one structured app request to the resident service.
func (c *UnixCustodyClient) SignAppRequest(ctx context.Context, req *AppRequestSignRequest) (*AppRequestSignResponse, error) {
	var out AppRequestSignResponse
	if err := c.do(ctx, http.MethodPost, "/sign_app_request", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func appRequestDigestPayload(req *AppRequestSignRequest) map[string]any {
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	return map[string]any{"v": req.Version, "grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience, "app_id": req.AppID, "verb": req.Verb, "args": args, "raw_body": req.RawBody}
}

// SignAppRequestCustodyProof binds the app request digest to the session key and proof fields.
func SignAppRequestCustodyProof(key ed25519.PrivateKey, req *AppRequestSignRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	if req.Version == 0 {
		req.Version = 1
	}
	if req.Operation == "" {
		req.Operation = string(custodySignAppRequest)
	}
	if strings.TrimSpace(req.SessionDIDKey) == "" {
		req.SessionDIDKey = ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	d, err := custodyDigestValue(req.Operation, appRequestDigestPayload(req))
	if err != nil {
		return err
	}
	req.RequestDigest = d
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	if err := signCustodyProofFields(key, custodyProofSigning{Version: req.Version, Operation: req.Operation, Metadata: &fields, RequestDigest: req.RequestDigest, Nonce: &req.Nonce, Timestamp: &req.Timestamp, Signature: &req.Signature}); err != nil {
		return err
	}
	req.SessionDIDKey = fields.SessionDIDKey
	return nil
}

// VerifyAppRequestCustodyProof checks the app request digest and session signature.
func VerifyAppRequestCustodyProof(req *AppRequestSignRequest) error {
	if req == nil {
		return fmt.Errorf("bad_request")
	}
	d, err := custodyDigestValue(req.Operation, appRequestDigestPayload(req))
	if err != nil {
		return err
	}
	fields := custodyProofMetadata{GrantID: req.GrantID, SessionDIDKey: req.SessionDIDKey, TeamID: req.TeamID, SubjectDIDAW: req.SubjectDIDAW, SubjectDIDKey: req.SubjectDIDKey, Audience: req.Audience}
	return verifyCustodyProofFields(custodyProofVerification{Proof: custodyProofData{Version: req.Version, Operation: req.Operation, Metadata: fields, Nonce: req.Nonce, Timestamp: req.Timestamp, RequestDigest: req.RequestDigest}, Signature: req.Signature, ExpectedDigest: d})
}

// SignAppRequestViaCustody asks the grant's local custody service to sign one
// installed-app tool call. It fails with custody_unavailable when the grant has
// no custody service; it never signs with the session key.
func (c *Client) SignAppRequestViaCustody(ctx context.Context, appID, verb string, args map[string]any, rawBody []byte) (*AppRequestSignResponse, error) {
	if c == nil || strings.TrimSpace(c.grantID) == "" {
		return nil, fmt.Errorf("app request custody signing requires a grant client")
	}
	custody, _ := c.plainMessageSigner.(AppRequestCustodyClient)
	if custody == nil {
		return nil, fmt.Errorf("custody_unavailable")
	}
	audience, err := c.custodyAudience(ctx)
	if err != nil {
		return nil, err
	}
	req := &AppRequestSignRequest{
		Version:       1,
		Operation:     "sign_app_request",
		GrantID:       strings.TrimSpace(c.grantID),
		SessionDIDKey: strings.TrimSpace(c.did),
		TeamID:        firstNonEmptyString(c.custodySubject.TeamID, c.teamID),
		SubjectDIDAW:  firstNonEmptyString(c.custodySubject.DIDAW, c.stableID),
		SubjectDIDKey: strings.TrimSpace(c.custodySubject.DIDKey),
		Audience:      audience,
		AppID:         strings.TrimSpace(appID),
		Verb:          strings.TrimSpace(verb),
		Args:          args,
	}
	if len(rawBody) > 0 {
		req.RawBody = base64.StdEncoding.EncodeToString(rawBody)
	}
	if err := SignAppRequestCustodyProof(c.signingKey, req); err != nil {
		return nil, err
	}
	out, err := custody.SignAppRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	if out == nil || strings.TrimSpace(out.Method) == "" || strings.TrimSpace(out.URL) == "" || len(out.Headers) == 0 {
		return nil, fmt.Errorf("custody returned an incomplete app request")
	}
	return out, nil
}
