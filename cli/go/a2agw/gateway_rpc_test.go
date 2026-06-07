package a2agw

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"
)

func TestGatewayRPCSendMessageImmediateAndScopedGetList(t *testing.T) {
	bridge := &fakeBridge{}
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})

	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{
		"message": testUserMessage("msg-1", "ctx-1", "Where is order 1234?"),
		"configuration": map[string]any{
			"returnImmediately":   true,
			"acceptedOutputModes": []string{"text/plain"},
		},
	}), map[string]string{"X-A2A-Caller-ID": "alice", "X-Request-ID": "trace-1"}, http.StatusOK)
	task := rpcTaskResult(t, resp, "task")
	if got := taskStatus(task); got != TaskStateWorking {
		t.Fatalf("task state: got %s, want %s", got, TaskStateWorking)
	}
	if got := bridge.sent[0].RequestID; got != "trace-1" {
		t.Fatalf("bridge request id: got %s", got)
	}
	if got := bridge.sent[0].Text; got != "Where is order 1234?" {
		t.Fatalf("bridge text: got %q", got)
	}
	taskID := task["id"].(string)

	getAlice := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "GetTask", map[string]any{"id": taskID}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if rpcTaskResult(t, getAlice, "")["id"] != taskID {
		t.Fatal("alice should see her task")
	}
	getBob := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-3", "GetTask", map[string]any{"id": taskID}), map[string]string{"X-A2A-Caller-ID": "bob"}, http.StatusOK)
	if rpcErrorCode(getBob) != "task_not_found" {
		t.Fatalf("bob get error code: got %#v", getBob)
	}
	listBob := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-4", "ListTasks", map[string]any{"pageSize": 50}), map[string]string{"X-A2A-Caller-ID": "bob"}, http.StatusOK)
	if got := int(listBob["result"].(map[string]any)["totalSize"].(float64)); got != 0 {
		t.Fatalf("bob list total: got %d", got)
	}
	listAlice := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-5", "ListTasks", map[string]any{"status": TaskStateWorking}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := int(listAlice["result"].(map[string]any)["totalSize"].(float64)); got != 1 {
		t.Fatalf("alice list total: got %d", got)
	}
}

func TestGatewayRPCConsumesPinnedImmediateFixture(t *testing.T) {
	var fixtures struct {
		JSONRPC []struct {
			Name    string         `json:"name"`
			Kind    string         `json:"kind"`
			Method  string         `json:"method"`
			Payload map[string]any `json:"payload"`
		} `json:"jsonrpc"`
	}
	body, err := os.ReadFile("../../../docs/vectors/a2a-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fixtures); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	for _, fixture := range fixtures.JSONRPC {
		if fixture.Name == "send_message_immediate_request" {
			payload = fixture.Payload
			break
		}
	}
	if payload == nil {
		t.Fatal("send_message_immediate_request fixture missing")
	}
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{supportRoute("r_support")}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", payload, map[string]string{"X-A2A-Caller-ID": "fixture"}, http.StatusOK)
	if resp["jsonrpc"] != "2.0" || resp["id"] != "req-1" {
		t.Fatalf("rpc envelope mismatch: %#v", resp)
	}
	if got := taskStatus(rpcTaskResult(t, resp, "task")); got != TaskStateWorking {
		t.Fatalf("fixture task state: got %s", got)
	}
}

func TestGatewayRPCWaitSuccessInputRequiredAndTimeout(t *testing.T) {
	var gw *Gateway
	bridge := &fakeBridge{onSend: func(task BridgeTask) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _, _ = gw.ApplyBridgeReply(BridgeReply{TaskID: task.TaskID, ContextID: task.ContextID, State: "completed", Text: "Order 1234 shipped Tuesday."})
		}()
	}}
	gw = newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{"message": testUserMessage("msg-1", "ctx-1", "Where is order 1234?")}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := taskStatus(rpcTaskResult(t, resp, "task")); got != TaskStateCompleted {
		t.Fatalf("wait success state: got %s", got)
	}

	var gwInput *Gateway
	inputBridge := &fakeBridge{onSend: func(task BridgeTask) {
		go func() {
			time.Sleep(5 * time.Millisecond)
			_, _, _ = gwInput.ApplyBridgeReply(BridgeReply{TaskID: task.TaskID, ContextID: task.ContextID, State: "input_required", Text: "Which email is the order under?"})
		}()
	}}
	gwInput = newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: inputBridge, Routes: []Route{supportRoute("r_support")}})
	inputResp := postRPC(t, gwInput, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "SendMessage", map[string]any{"message": testUserMessage("msg-2", "ctx-2", "Find order")}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := taskStatus(rpcTaskResult(t, inputResp, "task")); got != TaskStateInputRequired {
		t.Fatalf("input required state: got %s", got)
	}

	timeoutRoute := supportRoute("r_support")
	timeoutRoute.ResponseTimeout = 5 * time.Millisecond
	timeoutBridge := &fakeBridge{}
	gwTimeout := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: timeoutBridge, Routes: []Route{timeoutRoute}})
	timeoutResp := postRPC(t, gwTimeout, "/a2a/agents/r_support/rpc", rpcEnvelope("req-3", "SendMessage", map[string]any{"message": testUserMessage("msg-3", "ctx-3", "Slow order")}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := taskStatus(rpcTaskResult(t, timeoutResp, "task")); got != TaskStateFailed {
		t.Fatalf("timeout state: got %s", got)
	}
}

func TestGatewayRPCCancelTask(t *testing.T) {
	bridge := &fakeBridge{}
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{
		"message":       testUserMessage("msg-1", "ctx-1", "Cancel me"),
		"configuration": map[string]any{"returnImmediately": true},
	}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	taskID := rpcTaskResult(t, resp, "task")["id"].(string)
	cancel := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "CancelTask", map[string]any{"id": taskID}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := taskStatus(rpcTaskResult(t, cancel, "")); got != TaskStateCanceled {
		t.Fatalf("cancel state: got %s", got)
	}
	if len(bridge.canceled) != 1 || bridge.canceled[0].TaskID != taskID {
		t.Fatalf("bridge cancel: %#v", bridge.canceled)
	}
}

func TestGatewayRPCRejectsBadHTTPAndContent(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Routes: []Route{supportRoute("r_support")}})
	fetchJSON(t, gw, "/a2a/agents/r_support/rpc", http.StatusMethodNotAllowed)

	req := httptest.NewRequest(http.MethodPost, "/a2a/agents/r_support/rpc", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status: got %d", rec.Code)
	}
}

func TestGatewayRPCEnforcesMaxBytesBeforeParse(t *testing.T) {
	route := supportRoute("r_support")
	route.Limits.MaxMessageBytes = 16
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{route}})
	req := httptest.NewRequest(http.MethodPost, "/a2a/agents/r_support/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","id":"req","method":"SendMessage","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestGatewayRPCRejectsUnsupportedMethodAndContent(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{supportRoute("r_support")}})
	methodResp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "Unknown", map[string]any{}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if got := methodResp["error"].(map[string]any)["message"]; got != "method not found" {
		t.Fatalf("method error: got %v", got)
	}
	contentResp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "SendMessage", map[string]any{"message": map[string]any{
		"messageId": "msg-1",
		"contextId": "ctx-1",
		"role":      RoleUser,
		"parts":     []map[string]any{{"text": "{}", "mediaType": "application/json"}},
	}}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if contentResp["error"] == nil {
		t.Fatal("unsupported content should return JSON-RPC error")
	}
}

func TestGatewayRPCUnscopedPublicListDisabledAndBearerGet(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{supportRoute("r_support")}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{
		"message":       testUserMessage("msg-1", "ctx-1", "No caller header"),
		"configuration": map[string]any{"returnImmediately": true},
	}), nil, http.StatusOK)
	task := rpcTaskResult(t, resp, "task")
	token := task["metadata"].(map[string]any)["task_bearer_token"].(string)
	taskID := task["id"].(string)
	list := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "ListTasks", map[string]any{}), nil, http.StatusOK)
	if rpcErrorCode(list) != "list_tasks_scope_required" {
		t.Fatalf("list error code: got %#v", list)
	}
	get := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-3", "GetTask", map[string]any{"id": taskID}), map[string]string{"X-A2A-Task-Token": token}, http.StatusOK)
	if rpcTaskResult(t, get, "")["id"] != taskID {
		t.Fatal("bearer token should fetch unscoped task")
	}
}

func TestGatewayRPCTaskIDEntropyAndShape(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{supportRoute("r_support")}})
	seen := map[string]bool{}
	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 64; i++ {
		resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req", "SendMessage", map[string]any{
			"message":       testUserMessage(mustNewUUIDv4(), "ctx", "entropy"),
			"configuration": map[string]any{"returnImmediately": true},
		}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
		taskID := rpcTaskResult(t, resp, "task")["id"].(string)
		if !uuidRE.MatchString(taskID) {
			t.Fatalf("task id %q is not uuidv4", taskID)
		}
		if seen[taskID] {
			t.Fatalf("duplicate task id %q", taskID)
		}
		seen[taskID] = true
	}
}

func TestGatewayRPCTaskExpiryHidesTask(t *testing.T) {
	route := supportRoute("r_support")
	route.Limits.TaskTTL = 5 * time.Millisecond
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Bridge: &fakeBridge{}, Routes: []Route{route}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{
		"message":       testUserMessage("msg-1", "ctx-1", "expires"),
		"configuration": map[string]any{"returnImmediately": true},
	}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	taskID := rpcTaskResult(t, resp, "task")["id"].(string)
	time.Sleep(10 * time.Millisecond)
	get := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-2", "GetTask", map[string]any{"id": taskID}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if rpcErrorCode(get) != "task_not_found" {
		t.Fatalf("expired get: %#v", get)
	}
}

func TestGatewayRPCBridgeNotConfiguredFailsClosed(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Routes: []Route{supportRoute("r_support")}})
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("req-1", "SendMessage", map[string]any{"message": testUserMessage("msg-1", "ctx-1", "hello")}), map[string]string{"X-A2A-Caller-ID": "alice"}, http.StatusOK)
	if rpcErrorCode(resp) != "bridge_not_configured" {
		t.Fatalf("bridge error: %#v", resp)
	}
	if gw.Health().TaskExecution {
		t.Fatal("task execution should be false when bridge is not configured")
	}
}

func rpcEnvelope(id, method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}

func testUserMessage(messageID, contextID, text string) map[string]any {
	return map[string]any{
		"messageId": messageID,
		"contextId": contextID,
		"role":      RoleUser,
		"parts":     []map[string]any{{"text": text, "mediaType": "text/plain"}},
	}
}

func postRPC(t *testing.T, handler http.Handler, path string, payload any, headers map[string]string, wantStatus int) map[string]any {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s status: got %d, want %d; body=%s", path, rec.Code, wantStatus, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func rpcTaskResult(t *testing.T, resp map[string]any, wrapper string) map[string]any {
	t.Helper()
	if resp["error"] != nil {
		t.Fatalf("unexpected rpc error: %#v", resp["error"])
	}
	result := resp["result"].(map[string]any)
	if wrapper != "" {
		return result[wrapper].(map[string]any)
	}
	return result
}

func taskStatus(task map[string]any) string {
	return task["status"].(map[string]any)["state"].(string)
}

func rpcErrorCode(resp map[string]any) string {
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		return ""
	}
	data, _ := errObj["data"].(map[string]any)
	code, _ := data["code"].(string)
	return code
}

type fakeBridge struct {
	mu       sync.Mutex
	sent     []BridgeTask
	canceled []BridgeCancel
	onSend   func(BridgeTask)
}

func (b *fakeBridge) SendTask(_ context.Context, task BridgeTask) error {
	b.mu.Lock()
	b.sent = append(b.sent, task)
	b.mu.Unlock()
	if b.onSend != nil {
		b.onSend(task)
	}
	return nil
}

func (b *fakeBridge) CancelTask(_ context.Context, cancel BridgeCancel) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.canceled = append(b.canceled, cancel)
	return nil
}
