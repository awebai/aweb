package a2a

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	MethodSendMessage = "SendMessage"
	MethodGetTask     = "GetTask"
	MethodListTasks   = "ListTasks"
	MethodCancelTask  = "CancelTask"

	TaskStateInputRequired = "TASK_STATE_INPUT_REQUIRED"
	TaskStateAuthRequired  = "TASK_STATE_AUTH_REQUIRED"
	TaskStateCompleted     = "TASK_STATE_COMPLETED"
	TaskStateFailed        = "TASK_STATE_FAILED"
	TaskStateCanceled      = "TASK_STATE_CANCELED"
	TaskStateRejected      = "TASK_STATE_REJECTED"

	RoleUser = "ROLE_USER"
)

// Client calls a path-routed A2A JSON-RPC endpoint with bounded HTTP requests.
type Client struct {
	HTTPClient *http.Client
	UserAgent  string
	RequestID  string
}

// Credential carries route authentication and an optional task bearer token.
// CallerID identifies a caller scope; it does not authenticate that caller.
type Credential struct {
	APIKey      string
	BearerToken string
	CallerID    string
	TaskToken   string
}

// RPCEnvelope is an A2A JSON-RPC request or response. Result remains raw
// JSON until the caller selects the method-specific result type.
type RPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is the remote JSON-RPC refusal, including its structured code
// and any task retained after a provider fault in Data.
type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	if code, ok := e.Data["code"].(string); ok && code != "" {
		return fmt.Sprintf("a2a rpc error %d %s: %s", e.Code, code, e.Message)
	}
	return fmt.Sprintf("a2a rpc error %d: %s", e.Code, e.Message)
}

// Message is a task conversation message. ContextID is correlation,
// while access to a task requires its credential or issued task token.
type Message struct {
	MessageID string `json:"messageId"`
	ContextID string `json:"contextId,omitempty"`
	TaskID    string `json:"taskId,omitempty"`
	Role      string `json:"role"`
	Parts     []Part `json:"parts"`
}

// Part carries one text or structured-media segment of a message.
type Part struct {
	Text      string `json:"text"`
	MediaType string `json:"mediaType,omitempty"`
}

// SendMessageParams carries the caller message and response preferences.
type SendMessageParams struct {
	Message       Message           `json:"message"`
	Configuration SendConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
}

// SendConfiguration controls waiting and acceptable response media types.
type SendConfiguration struct {
	ReturnImmediately   bool     `json:"returnImmediately,omitempty"`
	AcceptedOutputModes []string `json:"acceptedOutputModes,omitempty"`
}

// Task is a gateway task projection. Its ID alone does not authorize access.
type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitempty"`
	Status    TaskStatus     `json:"status"`
	History   []Message      `json:"history,omitempty"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// TaskStatus reports the gateway state and optional status message.
type TaskStatus struct {
	State     string   `json:"state"`
	Timestamp string   `json:"timestamp,omitempty"`
	Message   *Message `json:"message,omitempty"`
}

// Artifact carries an output produced by a task.
type Artifact struct {
	ArtifactID string `json:"artifactId,omitempty"`
	Name       string `json:"name,omitempty"`
	Parts      []Part `json:"parts,omitempty"`
}

// FetchCard returns the decoded Agent Card and its original JSON bytes.
// It does not establish address ownership; verify the card publication separately.
func FetchCard(ctx context.Context, httpClient *http.Client, rawURL string) (Card, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(rawURL), nil)
	if err != nil {
		return Card{}, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := effectiveHTTPClient(httpClient).Do(req)
	if err != nil {
		return Card{}, nil, err
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, 2<<20)
	if err != nil {
		return Card{}, nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Card{}, nil, fmt.Errorf("fetch agent card: http %d", resp.StatusCode)
	}
	var card Card
	if err := json.Unmarshal(body, &card); err != nil {
		return Card{}, nil, err
	}
	return card, body, nil
}

// Call sends an authenticated JSON-RPC request and decodes its method result.
// Before selecting credentials from a card, callers must check ValidateRPCOrigin.
func (c *Client) Call(ctx context.Context, rpcURL, method string, params any, credential Credential, out any) error {
	return c.call(ctx, rpcCall{URL: rpcURL, Method: method, Params: params, Credential: credential, Out: out})
}

type rpcCall struct {
	URL, Method string
	Params      any
	Credential  Credential
	Out         any
}

// call owns credential-bearing RPC transport (docs/a2a.md:973-978). Call keeps
// the published Go signature while this implementation uses named inputs.
func (c *Client) call(ctx context.Context, input rpcCall) error {
	rpcURL, method, params, credential, out := input.URL, input.Method, input.Params, input.Credential, input.Out
	httpClient := effectiveHTTPClient(c.HTTPClient)
	if credential.APIKey != "" || credential.BearerToken != "" || credential.TaskToken != "" {
		if err := ValidateCredentialURL(rpcURL); err != nil {
			return err
		}
		httpClient = CredentialHTTPClient(httpClient)
	}
	requestID := strings.TrimSpace(c.RequestID)
	if requestID == "" {
		requestID = "aw-a2a-" + randomHexString(12)
	}
	reqBody, err := json.Marshal(RPCEnvelope{JSONRPC: "2.0", ID: requestID, Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(rpcURL), bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", requestID)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if credential.APIKey != "" {
		req.Header.Set("X-A2A-API-Key", credential.APIKey)
	}
	if credential.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+credential.BearerToken)
	}
	if credential.CallerID != "" {
		req.Header.Set("X-A2A-Caller-ID", credential.CallerID)
	}
	if credential.TaskToken != "" {
		req.Header.Set("X-A2A-Task-Token", credential.TaskToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ReadBoundedBody(resp.Body, 4<<20)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("a2a rpc http %d", resp.StatusCode)
	}
	var envelope RPCEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if out == nil {
		return nil
	}
	if len(envelope.Result) == 0 {
		return fmt.Errorf("a2a rpc response missing result")
	}
	return json.Unmarshal(envelope.Result, out)
}

// SelectJSONRPCInterface selects the supported JSON-RPC interface.
// Callers must validate its origin before sending stored credentials.
func SelectJSONRPCInterface(card Card) (Interface, error) {
	for _, iface := range card.SupportedInterfaces {
		if iface.ProtocolBinding == ProtocolBindingJSONRPC && iface.ProtocolVersion == ProtocolVersion10 && strings.TrimSpace(iface.URL) != "" {
			return iface, nil
		}
	}
	return Interface{}, fmt.Errorf("agent card has no JSONRPC 1.0 interface")
}

// NewUserTextMessage creates a user message with a fresh message ID.
func NewUserTextMessage(contextID, text string) Message {
	return Message{
		MessageID: "msg-" + randomHexString(16),
		ContextID: strings.TrimSpace(contextID),
		Role:      RoleUser,
		Parts:     []Part{{Text: text, MediaType: "text/plain"}},
	}
}

func effectiveHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func randomHexString(n int) string {
	if n <= 0 {
		n = 16
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// IsTerminalState reports whether a task state ends further execution.
func IsTerminalState(state string) bool {
	switch state {
	case TaskStateCompleted, TaskStateFailed, TaskStateCanceled, TaskStateRejected:
		return true
	default:
		return false
	}
}

// SameOriginRPCFromCardURL derives the conventional RPC path beside a direct
// card. Callers validate an advertised endpoint with ValidateRPCOrigin before
// selecting a stored credential.
func SameOriginRPCFromCardURL(cardURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(cardURL))
	if err != nil {
		return ""
	}
	if strings.HasSuffix(parsed.Path, "/agent-card.json") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/agent-card.json") + "/rpc"
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	return ""
}
