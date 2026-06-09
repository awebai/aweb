package a2agw

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const jsonRPCVersion = "2.0"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

type sendMessageParams struct {
	Message       A2AMessage        `json:"message"`
	Configuration sendMessageConfig `json:"configuration,omitempty"`
	Metadata      map[string]any    `json:"metadata,omitempty"`
}

type sendMessageConfig struct {
	ReturnImmediately   bool     `json:"returnImmediately,omitempty"`
	AcceptedOutputModes []string `json:"acceptedOutputModes,omitempty"`
}

type getTaskParams struct {
	ID            string `json:"id"`
	HistoryLength *int   `json:"historyLength,omitempty"`
}

type listTasksParams struct {
	ContextID        string `json:"contextId,omitempty"`
	Status           string `json:"status,omitempty"`
	PageSize         int    `json:"pageSize,omitempty"`
	HistoryLength    int    `json:"historyLength,omitempty"`
	IncludeArtifacts bool   `json:"includeArtifacts,omitempty"`
}

type cancelTaskParams struct {
	ID string `json:"id"`
}

func (g *Gateway) serveRPC(w http.ResponseWriter, r *http.Request, routeID string) {
	start := time.Now()
	requestID := requestIDFromHeader(r)
	w.Header().Set("X-Request-ID", requestID)
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed", "request_id": requestID})
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported_media_type", "request_id": requestID})
		return
	}
	route, ok := g.routeConfigs[routeID]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "route_not_found", "request_id": requestID})
		return
	}
	caller := callerScopeFromRequest(r, route)
	g.audit(AuditEvent{
		Stage:             "gateway_ingress",
		RequestID:         requestID,
		RouteID:           route.RouteID,
		CallerScopeClass:  callerScopeClass(caller.Value),
		TargetAddressHash: auditHash(route.Address),
		Outcome:           "accepted",
		VerificationTier:  "unsigned",
	})
	maxBytes := effectiveMaxMessageBytes(route)
	body, err := readLimitedBody(r.Body, maxBytes)
	if err != nil {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: "request_too_large", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request_too_large", "request_id": requestID})
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: "parse_error", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: rawNullID(), Error: jsonRPCError(-32700, "parse error", requestID, nil)})
		return
	}
	if req.JSONRPC != jsonRPCVersion || req.Method == "" {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: "invalid_request", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32600, "invalid request", requestID, nil)})
		return
	}
	if route.Disabled {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: "route_disabled", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32003, "route disabled", requestID, map[string]any{"code": "route_disabled"})})
		return
	}
	if !g.rateLimitAllows(route, caller) {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: "rate_limited", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32029, "rate limited", requestID, map[string]any{"code": "rate_limited"})})
		return
	}
	result, rpcErr := g.handleRPCMethod(r.Context(), route, req, requestID, caller)
	resp := rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID)}
	if rpcErr != nil {
		resp.Error = rpcErr
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "error", Code: rpcErrCode(rpcErr), LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	} else {
		resp.Result = result
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: "ok", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	}
	writeRPC(w, http.StatusOK, resp)
}

func (g *Gateway) handleRPCMethod(ctx context.Context, route Route, req rpcRequest, requestID string, caller callerScope) (any, *rpcError) {
	switch req.Method {
	case "SendMessage":
		return g.rpcSendMessage(ctx, route, req.Params, requestID, caller)
	case "GetTask":
		return g.rpcGetTask(route, req.Params, requestID, caller)
	case "ListTasks":
		return g.rpcListTasks(route, req.Params, requestID, caller)
	case "CancelTask":
		return g.rpcCancelTask(ctx, route, req.Params, requestID, caller)
	default:
		return nil, jsonRPCError(-32601, "method not found", requestID, map[string]any{"method": req.Method})
	}
}

func (g *Gateway) rpcSendMessage(ctx context.Context, route Route, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	if !g.taskExecution {
		return nil, jsonRPCError(-32000, "aweb bridge not configured", requestID, map[string]any{"code": "bridge_not_configured"})
	}
	if acceptUntil := g.AcceptNewTasksUntil(); !acceptUntil.IsZero() && time.Now().After(acceptUntil) {
		return nil, jsonRPCError(-32003, "A2A gateway config is expired", requestID, map[string]any{"code": "ac_config_expired"})
	}
	var params sendMessageParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	if err := validateInboundMessage(params.Message); err != nil {
		return nil, jsonRPCError(-32602, "invalid message", requestID, map[string]any{"detail": err.Error()})
	}
	if !authRequired(route, caller) && route.Limits.MaxConcurrentTasks > 0 && g.tasks.activeCount(route.RouteID, caller.Value) >= route.Limits.MaxConcurrentTasks {
		return nil, jsonRPCError(-32003, "too many active tasks", requestID, map[string]any{"code": "max_concurrent_tasks"})
	}
	record, err := g.tasks.create(route.RouteID, caller.Value, requestID, params.Message, effectiveTaskTTL(route))
	if err != nil {
		return nil, jsonRPCError(-32000, "task id generation failed", requestID, nil)
	}
	if authRequired(route, caller) {
		msg := statusMessage(record.ID, record.ContextID, TaskStateAuthRequired, "This route requires caller authentication.")
		record, _ = g.tasks.updateState(record.ID, TaskStateAuthRequired, &msg, nil)
		return map[string]any{"task": record.Task}, nil
	}
	text := textFromMessage(params.Message)
	if err := g.bridge.SendTask(ctx, BridgeTask{
		RequestID:   requestID,
		RouteID:     route.RouteID,
		Address:     route.Address,
		TaskID:      record.ID,
		ContextID:   record.ContextID,
		MessageID:   params.Message.MessageID,
		CallerScope: caller.Value,
		Text:        text,
	}); err != nil {
		if errors.Is(err, errBridgeNotConfigured) {
			return nil, jsonRPCError(-32000, "aweb bridge not configured", requestID, map[string]any{"code": "bridge_not_configured"})
		}
		g.tasks.failTask(record.ID, "A2A gateway failed to send the durable bridge message.")
		return nil, jsonRPCError(-32000, "bridge send failed", requestID, map[string]any{"detail": err.Error()})
	}
	if updated, ok := g.tasks.updateWorking(record.ID); ok {
		record = updated
	} else {
		return nil, jsonRPCError(-32000, "task unavailable", requestID, nil)
	}
	if params.Configuration.ReturnImmediately {
		return map[string]any{"task": record.Task}, nil
	}
	waited, ok := g.tasks.wait(record.ID, effectiveResponseTimeout(route))
	if !ok {
		return nil, jsonRPCError(-32000, "task unavailable", requestID, nil)
	}
	if !waited.Terminal && !isInterruptedState(waited.Status.State) {
		timeoutText := "A2A route timed out before the agent produced a terminal or interrupted reply."
		waited, _ = g.tasks.failTask(record.ID, timeoutText)
	}
	return map[string]any{"task": waited.Task}, nil
}

func (g *Gateway) rpcGetTask(route Route, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	var params getTaskParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	taskID := strings.TrimSpace(params.ID)
	if taskID == "" {
		return nil, jsonRPCError(-32602, "task id is required", requestID, nil)
	}
	record, ok := g.tasks.getVisible(route.RouteID, caller.Value, caller.TaskToken, taskID)
	if !ok {
		return nil, jsonRPCError(-32004, "task not found", requestID, map[string]any{"code": "task_not_found"})
	}
	task := record.Task
	if params.HistoryLength == nil {
		return task, nil
	}
	if *params.HistoryLength == 0 {
		task.History = nil
	} else if *params.HistoryLength > 0 && len(task.History) > *params.HistoryLength {
		task.History = task.History[len(task.History)-*params.HistoryLength:]
	}
	return task, nil
}

func (g *Gateway) rpcListTasks(route Route, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	if caller.Value == "" || caller.Value == "anonymous:unscoped" {
		return nil, jsonRPCError(-32003, "ListTasks requires an isolated caller scope", requestID, map[string]any{"code": "list_tasks_scope_required"})
	}
	var params listTasksParams
	if len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
		}
	}
	tasks := g.tasks.listVisible(route.RouteID, caller.Value, params.Status, params.ContextID, params.PageSize, params.IncludeArtifacts)
	return map[string]any{"tasks": tasks, "nextPageToken": "", "pageSize": effectivePageSize(params.PageSize), "totalSize": len(tasks)}, nil
}

func (g *Gateway) rpcCancelTask(ctx context.Context, route Route, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	var params cancelTaskParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	record, ok := g.tasks.cancelTask(route.RouteID, caller.Value, caller.TaskToken, strings.TrimSpace(params.ID))
	if !ok {
		return nil, jsonRPCError(-32004, "task not found", requestID, map[string]any{"code": "task_not_found"})
	}
	_ = g.bridge.CancelTask(ctx, BridgeCancel{RequestID: requestID, RouteID: route.RouteID, Address: route.Address, TaskID: record.ID, ContextID: record.ContextID})
	return record.Task, nil
}

func validateInboundMessage(message A2AMessage) error {
	if strings.TrimSpace(message.MessageID) == "" {
		return fmt.Errorf("message.messageId is required")
	}
	if message.Role != "" && message.Role != RoleUser {
		return fmt.Errorf("message.role must be %s", RoleUser)
	}
	if len(message.Parts) == 0 {
		return fmt.Errorf("message.parts must be non-empty")
	}
	for _, part := range message.Parts {
		mediaType := strings.TrimSpace(part.MediaType)
		if mediaType == "" {
			mediaType = "text/plain"
		}
		if mediaType != "text/plain" {
			return fmt.Errorf("unsupported part mediaType %q", part.MediaType)
		}
		if part.Text == "" {
			return fmt.Errorf("text part must not be empty")
		}
	}
	return nil
}

func textFromMessage(message A2AMessage) string {
	parts := make([]string, 0, len(message.Parts))
	for _, part := range message.Parts {
		parts = append(parts, part.Text)
	}
	return strings.Join(parts, "\n\n")
}

func authRequired(route Route, caller callerScope) bool {
	mode := normalizedAuthMode(route.Auth.Mode)
	if mode == "" || mode == "none" {
		return false
	}
	return caller.Value == "" || strings.HasPrefix(caller.Value, "anonymous:")
}

type callerScope struct {
	Value     string
	TaskToken string
}

func callerScopeFromRequest(r *http.Request, route Route) callerScope {
	token := strings.TrimSpace(r.Header.Get("X-A2A-Task-Token"))
	switch normalizedAuthMode(route.Auth.Mode) {
	case "", "none":
		return callerScope{Value: "anonymous:unscoped", TaskToken: token}
	case "static_api_key":
		key := strings.TrimSpace(r.Header.Get("X-A2A-API-Key"))
		if key != "" && route.Auth.StaticAPIKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(route.Auth.StaticAPIKey)) == 1 {
			return callerScope{Value: "auth:" + auditHash("static_api_key:"+key), TaskToken: token}
		}
	case "bearer":
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) {
			bearer := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
			if bearer != "" && route.Auth.BearerToken != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(route.Auth.BearerToken)) == 1 {
				return callerScope{Value: "auth:" + auditHash("bearer:"+bearer), TaskToken: token}
			}
		}
	}
	return callerScope{TaskToken: token}
}

func normalizedAuthMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func (g *Gateway) rateLimitAllows(route Route, caller callerScope) bool {
	if g.rateLimiter == nil || strings.TrimSpace(route.Limits.RateLimit) == "" {
		return true
	}
	scope := caller.Value
	if scope == "" {
		scope = "unauthenticated"
	}
	ok, err := g.rateLimiter.allow(route.RouteID+"|"+scope, route.Limits.RateLimit)
	if err != nil {
		return false
	}
	return ok
}

func isJSONContentType(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return value == "application/json"
}

func requestIDFromHeader(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		return value
	}
	return mustNewUUIDv4()
}

func readLimitedBody(body io.ReadCloser, maxBytes int) ([]byte, error) {
	defer body.Close()
	reader := io.LimitReader(body, int64(maxBytes)+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func effectiveMaxMessageBytes(route Route) int {
	if route.Limits.MaxMessageBytes > 0 {
		return route.Limits.MaxMessageBytes
	}
	return defaultMaxMessageBytes
}

func effectiveTaskTTL(route Route) time.Duration {
	if route.Limits.TaskTTL > 0 {
		return route.Limits.TaskTTL
	}
	return defaultTaskTTL
}

func effectiveResponseTimeout(route Route) time.Duration {
	if route.ResponseTimeout > 0 {
		return route.ResponseTimeout
	}
	return defaultResponseTimeout
}

func effectivePageSize(pageSize int) int {
	if pageSize <= 0 || pageSize > 100 {
		return 50
	}
	return pageSize
}

func normalizedID(id json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(id)) == 0 {
		return rawNullID()
	}
	out := make([]byte, len(id))
	copy(out, id)
	return json.RawMessage(out)
}

func rawNullID() json.RawMessage {
	return json.RawMessage("null")
}

func jsonRPCError(code int, message, requestID string, data map[string]any) *rpcError {
	if data == nil {
		data = map[string]any{}
	}
	data["request_id"] = requestID
	return &rpcError{Code: code, Message: message, Data: data}
}

func writeRPC(w http.ResponseWriter, status int, value rpcResponse) {
	writeJSON(w, status, value)
}

func rpcErrCode(err *rpcError) string {
	if err == nil || err.Data == nil {
		return ""
	}
	if code, _ := err.Data["code"].(string); code != "" {
		return code
	}
	return err.Message
}
