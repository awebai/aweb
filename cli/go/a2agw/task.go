package a2agw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	TaskStateSubmitted     = "TASK_STATE_SUBMITTED"
	TaskStateWorking       = "TASK_STATE_WORKING"
	TaskStateInputRequired = "TASK_STATE_INPUT_REQUIRED"
	TaskStateAuthRequired  = "TASK_STATE_AUTH_REQUIRED"
	TaskStateCompleted     = "TASK_STATE_COMPLETED"
	TaskStateFailed        = "TASK_STATE_FAILED"
	TaskStateCanceled      = "TASK_STATE_CANCELED"
	TaskStateRejected      = "TASK_STATE_REJECTED"

	RoleUser  = "ROLE_USER"
	RoleAgent = "ROLE_AGENT"
)

const (
	defaultMaxMessageBytes = 1 << 20
	defaultTaskTTL         = time.Hour
	defaultResponseTimeout = 30 * time.Second
)

var errBridgeNotConfigured = errors.New("a2a bridge is not configured")

type Bridge interface {
	SendTask(context.Context, BridgeTask) error
	CancelTask(context.Context, BridgeCancel) error
}

type BridgeTask struct {
	RequestID   string
	RouteID     string
	Address     string
	TaskID      string
	ContextID   string
	MessageID   string
	CallerScope string
	Text        string
}

type BridgeCancel struct {
	RequestID string
	RouteID   string
	Address   string
	TaskID    string
	ContextID string
}

type BridgeReply struct {
	TaskID    string
	ContextID string
	State     string
	Text      string
	Artifacts []Artifact
}

type Task struct {
	ID        string         `json:"id"`
	ContextID string         `json:"contextId,omitempty"`
	Status    TaskStatus     `json:"status"`
	History   []A2AMessage   `json:"history,omitempty"`
	Artifacts []Artifact     `json:"artifacts,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type TaskStatus struct {
	State     string      `json:"state"`
	Timestamp string      `json:"timestamp"`
	Message   *A2AMessage `json:"message,omitempty"`
}

type A2AMessage struct {
	MessageID string    `json:"messageId"`
	ContextID string    `json:"contextId,omitempty"`
	TaskID    string    `json:"taskId,omitempty"`
	Role      string    `json:"role"`
	Parts     []A2APart `json:"parts"`
}

type A2APart struct {
	Text      string `json:"text"`
	MediaType string `json:"mediaType"`
}

type Artifact struct {
	ArtifactID string    `json:"artifactId,omitempty"`
	Name       string    `json:"name,omitempty"`
	Parts      []A2APart `json:"parts"`
}

type taskRecord struct {
	Task
	RouteID      string
	CallerScope  string
	TaskToken    string
	RequestID    string
	MessageID    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ExpiresAt    time.Time
	Terminal     bool
	Cancellation bool
}

type taskStore struct {
	mu    sync.Mutex
	tasks map[string]*taskRecord
	order []string
	now   func() time.Time
}

func newTaskStore(now func() time.Time) *taskStore {
	if now == nil {
		now = time.Now
	}
	return &taskStore{tasks: map[string]*taskRecord{}, now: now}
}

func (s *taskStore) create(routeID, callerScope, requestID string, message A2AMessage, ttl time.Duration) (*taskRecord, error) {
	taskID, err := newUUIDv4()
	if err != nil {
		return nil, err
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if ttl <= 0 {
		ttl = defaultTaskTTL
	}
	record := &taskRecord{
		Task: Task{
			ID:        taskID,
			ContextID: message.ContextID,
			Status:    TaskStatus{State: TaskStateSubmitted, Timestamp: formatTime(now)},
			History:   []A2AMessage{message},
			Metadata:  map[string]any{"request_id": requestID},
		},
		RouteID:     routeID,
		CallerScope: callerScope,
		TaskToken:   token,
		RequestID:   requestID,
		MessageID:   message.MessageID,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
	if callerScope == "" || callerScope == "anonymous:unscoped" {
		record.Task.Metadata["task_bearer_token"] = token
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks[taskID] = record
	s.order = append(s.order, taskID)
	return cloneRecord(record), nil
}

func (s *taskStore) getVisible(routeID, callerScope, token, taskID string) (*taskRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tasks[taskID]
	if !ok || record.RouteID != routeID || s.expiredLocked(record) {
		return nil, false
	}
	if !record.visibleTo(callerScope, token) {
		return nil, false
	}
	return cloneRecord(record), true
}

func (s *taskStore) listVisible(routeID, callerScope, status, contextID string, limit int, includeArtifacts bool) []Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	out := make([]Task, 0, limit)
	for _, taskID := range s.order {
		record := s.tasks[taskID]
		if record == nil || record.RouteID != routeID || s.expiredLocked(record) || !record.visibleTo(callerScope, "") {
			continue
		}
		if status != "" && record.Status.State != status {
			continue
		}
		if contextID != "" && record.ContextID != contextID {
			continue
		}
		task := cloneTask(record.Task)
		if !includeArtifacts {
			task.Artifacts = nil
		}
		out = append(out, task)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (s *taskStore) activeCount(routeID, callerScope string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, record := range s.tasks {
		if record == nil || record.RouteID != routeID || record.Terminal || s.expiredLocked(record) {
			continue
		}
		if callerScope == "" || record.CallerScope == callerScope {
			count++
		}
	}
	return count
}

func (s *taskStore) updateWorking(taskID string) (*taskRecord, bool) {
	return s.updateState(taskID, TaskStateWorking, nil, nil)
}

func (s *taskStore) failTask(taskID, text string) (*taskRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tasks[taskID]
	if !ok || s.expiredLocked(record) || record.Terminal {
		return nil, false
	}
	now := s.now().UTC()
	msg := statusMessage(taskID, record.ContextID, TaskStateFailed, text)
	record.Status = TaskStatus{State: TaskStateFailed, Timestamp: formatTime(now), Message: &msg}
	record.UpdatedAt = now
	record.Terminal = true
	return cloneRecord(record), true
}

func (s *taskStore) cancelTask(routeID, callerScope, token, taskID string) (*taskRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tasks[taskID]
	if !ok || record.RouteID != routeID || s.expiredLocked(record) || !record.visibleTo(callerScope, token) || record.Terminal {
		return nil, false
	}
	now := s.now().UTC()
	record.Status = TaskStatus{State: TaskStateCanceled, Timestamp: formatTime(now)}
	record.UpdatedAt = now
	record.Terminal = true
	record.Cancellation = true
	return cloneRecord(record), true
}

func (s *taskStore) applyReply(reply BridgeReply) (*taskRecord, bool, error) {
	state, err := normalizeReplyState(reply.State)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tasks[reply.TaskID]
	if !ok || s.expiredLocked(record) || record.Terminal {
		return nil, false, nil
	}
	if record.ContextID != "" && reply.ContextID != record.ContextID {
		return nil, false, nil
	}
	now := s.now().UTC()
	messageText := reply.Text
	if messageText == "" && len(reply.Artifacts) > 0 && len(reply.Artifacts[0].Parts) > 0 {
		messageText = reply.Artifacts[0].Parts[0].Text
	}
	msg := statusMessage(record.ID, record.ContextID, state, messageText)
	record.Status = TaskStatus{State: state, Timestamp: formatTime(now), Message: &msg}
	record.UpdatedAt = now
	record.Terminal = isTerminalState(state)
	if len(reply.Artifacts) > 0 {
		record.Artifacts = cloneArtifacts(reply.Artifacts)
	} else if messageText != "" {
		record.Artifacts = []Artifact{{ArtifactID: mustNewUUIDv4(), Name: "answer", Parts: []A2APart{{Text: messageText, MediaType: "text/plain"}}}}
	}
	return cloneRecord(record), true, nil
}

func (s *taskStore) wait(taskID string, timeout time.Duration) (*taskRecord, bool) {
	deadline := s.now().Add(timeout)
	for {
		s.mu.Lock()
		record, ok := s.tasks[taskID]
		if !ok || s.expiredLocked(record) {
			s.mu.Unlock()
			return nil, false
		}
		if record.Terminal || isInterruptedState(record.Status.State) {
			out := cloneRecord(record)
			s.mu.Unlock()
			return out, true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			out := cloneRecord(record)
			s.mu.Unlock()
			return out, true
		}
		s.mu.Unlock()
		if remaining > 10*time.Millisecond {
			remaining = 10 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

func (s *taskStore) updateState(taskID, state string, message *A2AMessage, artifacts []Artifact) (*taskRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.tasks[taskID]
	if !ok || s.expiredLocked(record) || record.Terminal {
		return nil, false
	}
	now := s.now().UTC()
	record.Status = TaskStatus{State: state, Timestamp: formatTime(now), Message: message}
	record.UpdatedAt = now
	record.Terminal = isTerminalState(state)
	if artifacts != nil {
		record.Artifacts = cloneArtifacts(artifacts)
	}
	return cloneRecord(record), true
}

func (s *taskStore) expiredLocked(record *taskRecord) bool {
	return !record.ExpiresAt.IsZero() && !s.now().Before(record.ExpiresAt)
}

func (r *taskRecord) visibleTo(callerScope, token string) bool {
	if token != "" && token == r.TaskToken {
		return true
	}
	return callerScope != "" && callerScope == r.CallerScope && callerScope != "anonymous:unscoped"
}

type notReadyBridge struct{}

func (notReadyBridge) SendTask(context.Context, BridgeTask) error {
	return errBridgeNotConfigured
}

func (notReadyBridge) CancelTask(context.Context, BridgeCancel) error {
	return nil
}

func normalizeReplyState(state string) (string, error) {
	switch strings.TrimSpace(state) {
	case "completed", TaskStateCompleted:
		return TaskStateCompleted, nil
	case "input_required", TaskStateInputRequired:
		return TaskStateInputRequired, nil
	case "failed", TaskStateFailed:
		return TaskStateFailed, nil
	case "rejected", TaskStateRejected:
		return TaskStateRejected, nil
	default:
		return "", fmt.Errorf("unsupported a2a reply state %q", state)
	}
}

func isTerminalState(state string) bool {
	switch state {
	case TaskStateCompleted, TaskStateFailed, TaskStateCanceled, TaskStateRejected:
		return true
	default:
		return false
	}
}

func isInterruptedState(state string) bool {
	return state == TaskStateInputRequired || state == TaskStateAuthRequired
}

func statusMessage(taskID, contextID, state, text string) A2AMessage {
	if text == "" {
		text = state
	}
	return A2AMessage{
		MessageID: mustNewUUIDv4(),
		ContextID: contextID,
		TaskID:    taskID,
		Role:      RoleAgent,
		Parts:     []A2APart{{Text: text, MediaType: "text/plain"}},
	}
}

func cloneRecord(record *taskRecord) *taskRecord {
	if record == nil {
		return nil
	}
	clone := *record
	clone.Task = cloneTask(record.Task)
	return &clone
}

func cloneTask(task Task) Task {
	task.History = cloneMessages(task.History)
	task.Artifacts = cloneArtifacts(task.Artifacts)
	if task.Metadata != nil {
		meta := make(map[string]any, len(task.Metadata))
		for k, v := range task.Metadata {
			meta[k] = v
		}
		task.Metadata = meta
	}
	if task.Status.Message != nil {
		msg := cloneMessage(*task.Status.Message)
		task.Status.Message = &msg
	}
	return task
}

func cloneMessages(values []A2AMessage) []A2AMessage {
	if len(values) == 0 {
		return nil
	}
	out := make([]A2AMessage, len(values))
	for i, value := range values {
		out[i] = cloneMessage(value)
	}
	return out
}

func cloneMessage(value A2AMessage) A2AMessage {
	value.Parts = cloneParts(value.Parts)
	return value
}

func cloneArtifacts(values []Artifact) []Artifact {
	if len(values) == 0 {
		return nil
	}
	out := make([]Artifact, len(values))
	for i, value := range values {
		out[i] = value
		out[i].Parts = cloneParts(value.Parts)
	}
	return out
}

func cloneParts(values []A2APart) []A2APart {
	if len(values) == 0 {
		return nil
	}
	out := make([]A2APart, len(values))
	copy(out, values)
	return out
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func mustNewUUIDv4() string {
	value, err := newUUIDv4()
	if err != nil {
		panic(err)
	}
	return value
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func parseRawObject(raw json.RawMessage, target any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return fmt.Errorf("params object is required")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}
