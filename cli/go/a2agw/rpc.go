package a2agw

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/awebai/aw/a2a"
	"io"
	"log"
	"net"
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
	requestID, err := newUUIDv4()
	if err != nil {
		log.Printf("aweb-a2a-gw: request id generation failed: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "request_id_unavailable", "message": "The gateway could not create a request identifier. Restore the host random source and retry."})
		return
	}
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
	// The HTTP server bounds ordinary writes; an A2A wait uses its configured
	// response budget (docs/a2a.md:588) rather than the server's default.
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(effectiveResponseTimeout(route) + 20*time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		log.Printf("aweb-a2a-gw: cannot set response deadline: %v", err)
	}
	caller := callerScopeFromRequest(r, route)
	g.audit(AuditEvent{
		Stage:             "gateway_ingress",
		RequestID:         requestID,
		RouteID:           route.RouteID,
		CallerScopeClass:  callerScopeClass(caller.Value),
		TargetAddressHash: auditHash(route.Address),
		Outcome:           string(AuditAccepted),
		VerificationTier:  "unsigned",
	})
	maxBytes := effectiveMaxMessageBytes(route)
	body, err := readLimitedBody(r.Body, maxBytes)
	if err != nil {
		status, code, message := http.StatusBadRequest, "request_body_failed", "Request body could not be read. Retry the request with a complete JSON body."
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			status, code, message = http.StatusRequestTimeout, "request_body_timeout", "Request body timed out. Retry with a complete JSON body within ten seconds."
		} else if errors.Is(err, a2a.ErrBodyTooLarge) {
			status, code, message = http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large. Reduce the message size to the route's advertised limit and retry."
		}
		log.Printf("aweb-a2a-gw: request body failed request=%s: %v", requestID, err)
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: code, LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeJSON(w, status, map[string]string{"error": code, "message": message, "request_id": requestID})
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: "parse_error", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: rawNullID(), Error: jsonRPCError(-32700, "parse error", requestID, nil)})
		return
	}
	if req.JSONRPC != jsonRPCVersion || req.Method == "" {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: "invalid_request", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32600, "invalid request", requestID, nil)})
		return
	}
	if route.Disabled {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: "route_disabled", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32003, "route disabled", requestID, map[string]any{"code": "route_disabled"})})
		return
	}
	if !g.rateLimitAllows(route, caller) {
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: "rate_limited", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		writeRPC(w, http.StatusOK, rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID), Error: jsonRPCError(-32029, "rate limited", requestID, map[string]any{"code": "rate_limited"})})
		return
	}
	result, rpcErr := g.handleRPCMethod(r.Context(), route, req, requestID, caller)
	resp := rpcResponse{JSONRPC: jsonRPCVersion, ID: normalizedID(req.ID)}
	if rpcErr != nil {
		resp.Error = rpcErr
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(AuditError), Code: rpcErrCode(rpcErr), LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	} else {
		resp.Result = result
		outcome, code := AuditOK, ""
		if authRequired(route, caller) {
			outcome, code = AuditDenied, "authentication_required"
		}
		g.audit(AuditEvent{Stage: "gateway_response", RequestID: requestID, RouteID: route.RouteID, CallerScopeClass: callerScopeClass(caller.Value), TargetAddressHash: auditHash(route.Address), Outcome: string(outcome), Code: code, LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	}
	writeRPC(w, http.StatusOK, resp)
}

func (g *Gateway) handleRPCMethod(ctx context.Context, route runtimeRoute, req rpcRequest, requestID string, caller callerScope) (any, *rpcError) {
	if authRequired(route, caller) {
		text := "Authentication is required. Send the route API key in X-A2A-API-Key or the route bearer in Authorization, as advertised by its card."
		if req.Method == "SendMessage" {
			// Auth refusal is an ephemeral result, with no retained state or bearer token.
			id, err := newUUIDv4()
			if err != nil {
				return nil, taskIdentifierFailure(requestID, err)
			}
			message, err := statusMessage(statusMessageInput{TaskID: id, State: taskAuthRequired, Text: text})
			if err != nil {
				return nil, taskIdentifierFailure(requestID, err)
			}
			return map[string]any{"task": Task{ID: id, Status: TaskStatus{State: TaskStateAuthRequired, Timestamp: formatTime(time.Now()), Message: message}}}, nil
		}
		return nil, jsonRPCError(-32003, text, requestID, map[string]any{"code": "authentication_required"})
	}
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

func (g *Gateway) rpcSendMessage(ctx context.Context, route runtimeRoute, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	if !g.taskExecution {
		return nil, jsonRPCError(-32000, "aweb bridge not configured", requestID, map[string]any{"code": "bridge_not_configured"})
	}
	if acceptUntil := g.AcceptNewTasksUntil(); !acceptUntil.IsZero() && time.Now().After(acceptUntil) {
		return nil, jsonRPCError(-32003, "A2A gateway config is expired", requestID, map[string]any{"code": "managed_config_expired"})
	}
	var params sendMessageParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	if err := validateInboundMessage(params.Message); err != nil {
		return nil, jsonRPCError(-32602, "invalid message", requestID, map[string]any{"detail": err.Error()})
	}
	record, err := g.tasks.create(taskCreation{RouteID: route.RouteID, CallerScope: caller.Value, RequestID: requestID, Message: params.Message, TTL: effectiveTaskTTL(route), MaxActive: route.Limits.MaxConcurrentTasks})
	if err != nil {
		if errors.Is(err, errTaskLimit) {
			return nil, jsonRPCError(-32003, "Too many active tasks. Wait for an existing task to finish or cancel it, then retry.", requestID, map[string]any{"code": "max_concurrent_tasks"})
		}
		return nil, taskIdentifierFailure(requestID, err)
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
		TaskTTL:     effectiveTaskTTL(route),
	}); err != nil {
		if errors.Is(err, errBridgeNotConfigured) {
			return nil, jsonRPCError(-32000, "aweb bridge not configured", requestID, map[string]any{"code": "bridge_not_configured"})
		}
		log.Printf("aweb-a2a-gw: bridge send failed request=%s task=%s: %v", requestID, record.ID, err)
		failureText := "A2A gateway failed to send the durable bridge message."
		var fault *providerReceiptError
		providerFault := errors.As(err, &fault)
		if providerFault {
			failureText = fault.Error()
		}
		failed, retained, statusErr := g.tasks.failTask(taskFailure{TaskID: record.ID, Text: failureText})
		if statusErr != nil {
			log.Printf("aweb-a2a-gw: task failed but its status message id could not be generated request=%s task=%s: %v", requestID, record.ID, statusErr)
		}
		details := map[string]any{"detail": err.Error()}
		if providerFault {
			details["code"] = string(fault.Fault)
			if retained {
				details["task"] = failed.Task
			}
		}
		return nil, jsonRPCError(-32000, "bridge send failed", requestID, details)
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
	return map[string]any{"task": waited.Task}, nil
}

func (g *Gateway) rpcGetTask(route runtimeRoute, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	var params getTaskParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	taskID := strings.TrimSpace(params.ID)
	if taskID == "" {
		return nil, jsonRPCError(-32602, "task id is required", requestID, nil)
	}
	record, ok := g.tasks.getVisible(taskAccess{RouteID: route.RouteID, CallerScope: caller.Value, Token: caller.TaskToken, TaskID: taskID})
	if !ok {
		return nil, jsonRPCError(-32004, "Task not found. Send the route credential or the task token returned by SendMessage, then retry.", requestID, map[string]any{"code": "task_not_found"})
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

func (g *Gateway) rpcListTasks(route runtimeRoute, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	if caller.Value == "" || caller.Value == "anonymous:unscoped" {
		return nil, jsonRPCError(-32003, "ListTasks requires an isolated caller scope", requestID, map[string]any{"code": "list_tasks_scope_required"})
	}
	var params listTasksParams
	if len(raw) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
		}
	}
	tasks := g.tasks.listVisible(taskListQuery{RouteID: route.RouteID, CallerScope: caller.Value, Status: params.Status, ContextID: params.ContextID, Limit: params.PageSize, IncludeArtifacts: params.IncludeArtifacts})
	return map[string]any{"tasks": tasks, "nextPageToken": "", "pageSize": effectivePageSize(params.PageSize), "totalSize": len(tasks)}, nil
}

func (g *Gateway) rpcCancelTask(ctx context.Context, route runtimeRoute, raw json.RawMessage, requestID string, caller callerScope) (any, *rpcError) {
	var params cancelTaskParams
	if err := parseRawObject(raw, &params); err != nil {
		return nil, jsonRPCError(-32602, "invalid params", requestID, map[string]any{"detail": err.Error()})
	}
	record, ok := g.tasks.cancelTask(taskAccess{RouteID: route.RouteID, CallerScope: caller.Value, Token: caller.TaskToken, TaskID: strings.TrimSpace(params.ID)})
	if !ok {
		return nil, jsonRPCError(-32004, "task not found", requestID, map[string]any{"code": "task_not_found"})
	}
	if err := g.bridge.CancelTask(ctx, BridgeCancel{RequestID: requestID, RouteID: route.RouteID, Address: route.Address, TaskID: record.ID, ContextID: record.ContextID}); err != nil {
		log.Printf("aweb-a2a-gw: cancellation notice failed request=%s task=%s: %v", requestID, record.ID, err)
		return nil, jsonRPCError(-32000, "Task canceled locally, but the agent could not be notified. Contact the target agent to confirm it stopped work.", requestID, map[string]any{"code": "cancel_notification_failed", "task_id": record.ID, "state": TaskStateCanceled})
	}
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

func authRequired(route runtimeRoute, caller callerScope) bool {
	mode := route.Auth.Mode
	if mode == AuthModeNone {
		return false
	}
	return caller.Value == "" || strings.HasPrefix(caller.Value, "anonymous:")
}

type callerScope struct {
	Value     string
	TaskToken string
}

func callerScopeFromRequest(r *http.Request, route runtimeRoute) callerScope {
	token := strings.TrimSpace(r.Header.Get("X-A2A-Task-Token"))
	switch route.Auth.Mode {
	case AuthModeNone:
		return callerScope{Value: "anonymous:unscoped", TaskToken: token}
	case AuthModeStaticAPIKey:
		key := strings.TrimSpace(r.Header.Get("X-A2A-API-Key"))
		if key != "" && route.Auth.StaticAPIKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(route.Auth.StaticAPIKey)) == 1 {
			return callerScope{Value: "auth:" + auditHash("static_api_key:"+key), TaskToken: token}
		}
	case AuthModeBearer:
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

func (g *Gateway) rateLimitAllows(route runtimeRoute, caller callerScope) bool {
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

func taskIdentifierFailure(requestID string, err error) *rpcError {
	log.Printf("aweb-a2a-gw: task identifier generation failed request=%s: %v", requestID, err)
	return jsonRPCError(-32000, "The gateway could not create a task identifier. Restore the host random source and retry.", requestID, map[string]any{"code": "task_identifier_unavailable"})
}

func readLimitedBody(body io.ReadCloser, maxBytes int) ([]byte, error) {
	defer body.Close()
	return a2a.ReadBoundedBody(body, int64(maxBytes))
}

func effectiveMaxMessageBytes(route runtimeRoute) int {
	if route.Limits.MaxMessageBytes > 0 {
		return route.Limits.MaxMessageBytes
	}
	return defaultMaxMessageBytes
}

func effectiveTaskTTL(route runtimeRoute) time.Duration {
	if route.Limits.TaskTTL > 0 {
		return route.Limits.TaskTTL
	}
	return defaultTaskTTL
}

func effectiveResponseTimeout(route runtimeRoute) time.Duration {
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
	if code, ok := err.Data["code"].(string); ok && code != "" {
		return code
	}
	return err.Message
}
