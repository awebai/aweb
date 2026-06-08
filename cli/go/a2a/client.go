package a2a

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

type Client struct {
	HTTPClient *http.Client
	UserAgent  string
	RequestID  string
}

type Credential struct {
	APIKey      string
	BearerToken string
	CallerID    string
	TaskToken   string
}

type RPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	if code, _ := e.Data["code"].(string); code != "" {
		return fmt.Sprintf("a2a rpc error %d %s: %s", e.Code, code, e.Message)
	}
	return fmt.Sprintf("a2a rpc error %d: %s", e.Code, e.Message)
}

type Message struct {
	MessageID string `json:"messageId"`
	ContextID string `json:"contextId,omitempty"`
	TaskID    string `json:"taskId,omitempty"`
	Role      string `json:"role"`
	Parts     []Part `json:"parts"`
}

type Part struct {
	Text      string `json:"text"`
	MediaType string `json:"mediaType,omitempty"`
}

type SendMessageParams struct {
	Message       Message           `json:"message"`
	Configuration SendConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
}

type SendConfiguration struct {
	ReturnImmediately   bool     `json:"returnImmediately,omitempty"`
	AcceptedOutputModes []string `json:"acceptedOutputModes,omitempty"`
}

type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitempty"`
	Status    TaskStatus     `json:"status"`
	History   []Message      `json:"history,omitempty"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type TaskStatus struct {
	State     string   `json:"state"`
	Timestamp string   `json:"timestamp,omitempty"`
	Message   *Message `json:"message,omitempty"`
}

type Artifact struct {
	ArtifactID string `json:"artifactId,omitempty"`
	Name       string `json:"name,omitempty"`
	Parts      []Part `json:"parts,omitempty"`
}

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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
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

func (c *Client) Call(ctx context.Context, rpcURL, method string, params any, credential Credential, out any) error {
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
	resp, err := effectiveHTTPClient(c.HTTPClient).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
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

func SelectJSONRPCInterface(card Card) (Interface, error) {
	for _, iface := range card.SupportedInterfaces {
		if iface.ProtocolBinding == ProtocolBindingJSONRPC && iface.ProtocolVersion == ProtocolVersion10 && strings.TrimSpace(iface.URL) != "" {
			return iface, nil
		}
	}
	return Interface{}, fmt.Errorf("agent card has no JSONRPC 1.0 interface")
}

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

func NewUserTextMessage(contextID, text string) Message {
	return Message{
		MessageID: "msg-" + randomHexString(16),
		ContextID: strings.TrimSpace(contextID),
		Role:      RoleUser,
		Parts:     []Part{{Text: text, MediaType: "text/plain"}},
	}
}

func IsTerminalState(state string) bool {
	switch state {
	case TaskStateCompleted, TaskStateFailed, TaskStateCanceled, TaskStateRejected:
		return true
	default:
		return false
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
