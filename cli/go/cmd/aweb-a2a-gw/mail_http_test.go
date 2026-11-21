package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/a2agw"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

type mailHTTPOptions struct {
	Auth              authConfig
	MaxConcurrent     int
	TargetReference   string
	Disabled          bool
	QuestionReplies   bool
	UnverifiedReplies bool
	PollTimeout       time.Duration
}

type mailHTTPFixture struct {
	server       *httptest.Server
	rpcBaseURL   string
	configPath   string
	auditPath    string
	gateway      *a2agw.Gateway
	runtime      *gatewayRuntime
	mu           sync.Mutex
	mailTasks    map[string]string
	taskMessages map[string]string
	lastNotice   string
	inbox        map[string][]awid.InboxMessage
	corrections  []awid.SendMessageRequest
	targetKey    ed25519.PrivateKey
	targetDID    string
	targetStable string
	gatewayDID   string
	notices      atomic.Int32
	failNotice   atomic.Bool
	resolutions  atomic.Int32
}

type httpRPCResult struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
		Data    struct {
			Code   string      `json:"code"`
			Detail string      `json:"detail"`
			Task   *a2agw.Task `json:"task"`
		} `json:"data"`
	} `json:"error"`
}

type httpRPCInput struct {
	Method  string
	RouteID string
	Params  any
	Headers map[string]string
}

// This fixture couples the production workspace client, mail bridge and HTTP
// gateway. Controlled peers inspect the actual signed mail; they do not replace
// Bridge.SendTask or its cancellation sender. The real-service Docker journey
// remains separate evidence for registry/server interoperability.
func newMailHTTPFixture(t *testing.T, options mailHTTPOptions) *mailHTTPFixture {
	t.Helper()
	f := &mailHTTPFixture{mailTasks: map[string]string{}, taskMessages: map[string]string{}, inbox: map[string][]awid.InboxMessage{}}
	pub, targetKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	targetDID, targetStable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
	f.targetKey, f.targetDID, f.targetStable = targetKey, targetDID, targetStable
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(value any) {
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		switch {
		case r.URL.Path == "/v1/namespaces/a2a.aweb.ai/addresses/personal":
			f.resolutions.Add(1)
			write(map[string]string{"address_id": "target", "domain": "a2a.aweb.ai", "name": "personal", "did_aw": targetStable, "current_did_key": targetDID, "reachability": "open"})
		case strings.HasPrefix(r.URL.Path, "/v1/namespaces/a2a.aweb.ai/teams/default/members/"):
			f.resolutions.Add(1)
			write(map[string]string{"team_id": "default:a2a.aweb.ai", "alias": strings.TrimPrefix(r.URL.Path, "/v1/namespaces/a2a.aweb.ai/teams/default/members/"), "member_did_key": targetDID, "identity_scope": awid.IdentityModeLocal})
		case r.URL.Path == "/v1/did/"+targetStable+"/key":
			write(map[string]string{"did_aw": targetStable, "current_did_key": targetDID})
		case strings.HasPrefix(r.URL.Path, "/v1/messages/conversations/"):
			conversation := strings.TrimPrefix(r.URL.Path, "/v1/messages/conversations/")
			f.mu.Lock()
			messages := append([]awid.InboxMessage(nil), f.inbox[conversation]...)
			f.mu.Unlock()
			write(awid.InboxResponse{Messages: messages})
		case r.URL.Path == "/v1/messages" && r.Method == http.MethodPost:
			var mail awid.SendMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&mail); err != nil {
				t.Error(err)
				http.Error(w, "bad mail", 400)
				return
			}
			var envelope awid.MessageEnvelope
			if err := json.Unmarshal([]byte(mail.SignedPayload), &envelope); err != nil {
				t.Error(err)
				http.Error(w, "bad envelope", 400)
				return
			}
			status, err := awid.VerifySignedPayload(mail.SignedPayload, mail.Signature, mail.FromDID, mail.FromDID)
			if err != nil || status != awid.Verified || mail.ToDID != targetDID || envelope.ConversationID != mail.ConversationID || envelope.MessageID != mail.MessageID || envelope.Body != mail.Body || envelope.ToDID != mail.ToDID || envelope.ToStableID != mail.ToStableID || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Errorf("production mail lacked its signed recipient/certificate: status=%s err=%v", status, err)
				http.Error(w, "invalid signed mail", 403)
				return
			}
			if strings.HasPrefix(mail.Subject, "A2A task canceled ") {
				id := strings.TrimPrefix(mail.Subject, "A2A task canceled ")
				f.notices.Add(1)
				f.mu.Lock()
				conversation := f.mailTasks[id]
				f.mu.Unlock()
				if mail.ConversationID != conversation {
					http.Error(w, "wrong cancellation conversation", 403)
					return
				}
				if f.failNotice.Load() {
					http.Error(w, "cancellation notice refused", 403)
					return
				}
				f.mu.Lock()
				f.lastNotice = envelope.Body
				f.mu.Unlock()
			} else if mail.Subject == "A2A reply needs binding" {
				f.mu.Lock()
				f.corrections = append(f.corrections, mail)
				f.mu.Unlock()
			} else {
				id := strings.TrimPrefix(mail.Subject, "A2A task ")
				f.mu.Lock()
				f.mailTasks[id] = mail.ConversationID
				f.taskMessages[id] = envelope.Body
				f.gatewayDID = mail.FromDID
				f.mu.Unlock()
			}
			write(awid.SendMessageResponse{MessageID: mail.MessageID, ConversationID: mail.ConversationID, Status: "delivered"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(peer.Close)
	root := t.TempDir()
	writeGatewayWorkspace(t, root, peer.URL)
	path := filepath.Join(root, "gateway.yaml")
	writeConfig(t, path, root, peer.URL)
	cfg := mustLoadConfig(t, path)
	if options.TargetReference != "" {
		cfg.Routes[0].Address = options.TargetReference
	}
	cfg.Routes[0].Disabled = options.Disabled
	cfg.Routes[0].Auth = options.Auth
	cfg.Routes[0].Limits.MaxConcurrentTasks = options.MaxConcurrent
	cfg.Routes[0].Limits.RateLimit = ""
	otherRoute := cfg.Routes[0]
	otherRoute.RouteID = "r_other"
	cfg.Routes = append(cfg.Routes, otherRoute)
	cfg.PollInterval, cfg.PollTimeout = "10ms", "30ms"
	if options.PollTimeout > 0 {
		cfg.PollTimeout = options.PollTimeout.String()
	}
	cfg.AllowQuestionReply = options.QuestionReplies
	if options.UnverifiedReplies {
		require := false
		cfg.RequireVerifiedReplies = &require
		cfg.AllowUnverifiedLocalReply = true
	}
	f.auditPath = filepath.Join(root, "audit.jsonl")
	cfg.Audit.JSONL = f.auditPath
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.configPath = path
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.runtime = runtime
	f.gateway = gateway
	f.server = httptest.NewServer(gateway)
	t.Cleanup(runtime.bridge.Close)
	t.Cleanup(f.server.Close)
	return f
}

func (f *mailHTTPFixture) call(input httpRPCInput) (httpRPCResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "request", "method": input.Method, "params": input.Params})
	if err != nil {
		return httpRPCResult{}, err
	}
	baseURL := firstNonEmpty(f.rpcBaseURL, f.server.URL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/a2a/agents/"+firstNonEmpty(input.RouteID, "r_personal")+"/rpc", bytes.NewReader(data))
	if err != nil {
		return httpRPCResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range input.Headers {
		req.Header.Set(name, value)
	}
	response, err := f.server.Client().Do(req)
	if err != nil {
		return httpRPCResult{}, err
	}
	var result httpRPCResult
	decodeErr := json.NewDecoder(response.Body).Decode(&result)
	closeErr := response.Body.Close()
	if decodeErr != nil {
		return result, decodeErr
	}
	if closeErr != nil {
		return result, closeErr
	}
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("gateway HTTP %d", response.StatusCode)
	}
	return result, nil
}

func (f *mailHTTPFixture) callOK(t *testing.T, input httpRPCInput) httpRPCResult {
	t.Helper()
	result, err := f.call(input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func sendHTTPInput(id string) httpRPCInput {
	return httpRPCInput{Method: "SendMessage", Params: map[string]any{"message": map[string]any{"messageId": id, "contextId": "context", "role": "ROLE_USER", "parts": []map[string]string{{"text": id, "mediaType": "text/plain"}}}, "configuration": map[string]bool{"returnImmediately": true}}}
}

func sentHTTPTask(t *testing.T, result httpRPCResult) a2agw.Task {
	t.Helper()
	if result.Error != nil {
		t.Fatalf("send failed: %#v", result.Error)
	}
	var wrapper struct {
		Task a2agw.Task `json:"task"`
	}
	if err := json.Unmarshal(result.Result, &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper.Task
}

func tokenHeaders(t *testing.T, task a2agw.Task) map[string]string {
	t.Helper()
	token, ok := task.Metadata["task_bearer_token"].(string)
	if !ok || token == "" {
		t.Fatal("send did not return a task token")
	}
	return map[string]string{"X-A2A-Task-Token": token}
}

func TestHTTPMailBridgeAuthenticationBeforeMailAndTaskAccess(t *testing.T) {
	for _, tc := range []struct {
		auth    authConfig
		headers map[string]string
	}{
		{auth: authConfig{Mode: " BeArEr ", BearerToken: "route-secret"}, headers: map[string]string{"Authorization": "Bearer route-secret"}},
		{auth: authConfig{Mode: string(a2agw.AuthModeStaticAPIKey), StaticAPIKey: "route-secret"}, headers: map[string]string{"X-A2A-API-Key": "route-secret"}},
	} {
		t.Run(tc.auth.Mode, func(t *testing.T) {
			f := newMailHTTPFixture(t, mailHTTPOptions{Auth: tc.auth})
			for _, headers := range []map[string]string{nil, {"Authorization": "Bearer wrong", "X-A2A-API-Key": "wrong"}} {
				input := sendHTTPInput("denied")
				input.Headers = headers
				task := sentHTTPTask(t, f.callOK(t, input))
				if task.Status.State != a2agw.TaskStateAuthRequired || task.Status.Message == nil || len(task.Status.Message.Parts) == 0 || !strings.Contains(task.Status.Message.Parts[0].Text, "Send the route") {
					t.Fatalf("missing auth refusal: %#v", task)
				}
				if _, present := task.Metadata["task_bearer_token"]; present {
					t.Fatal("auth refusal retained an accessible task token")
				}
				for _, method := range []string{"GetTask", "ListTasks", "CancelTask"} {
					got := f.callOK(t, httpRPCInput{Method: method, Params: map[string]string{"id": task.ID}, Headers: headers})
					if got.Error == nil || got.Error.Data.Code != "authentication_required" {
						t.Fatalf("%s bypassed auth: %#v", method, got)
					}
				}
			}
			audit, err := os.ReadFile(f.auditPath)
			if err != nil {
				t.Fatal(err)
			}
			scanner := json.NewDecoder(bytes.NewReader(audit))
			denials, refusedResults := 0, 0
			for {
				var event a2agw.AuditEvent
				err := scanner.Decode(&event)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if event.Code == "authentication_required" {
					denials++
					if event.Outcome == string(a2agw.AuditDenied) {
						refusedResults++
					}
					if event.Outcome != string(a2agw.AuditDenied) && event.Outcome != string(a2agw.AuditError) {
						t.Fatalf("refusal audited as success: %#v", event)
					}
				}
			}
			if denials != 8 || refusedResults != 2 {
				t.Fatalf("want 8 auth denials, got %d", denials)
			}
			f.mu.Lock()
			posts := len(f.mailTasks)
			f.mu.Unlock()
			if posts != 0 {
				t.Fatal("unauthenticated request reached production mail sender")
			}
			valid := sendHTTPInput("allowed")
			valid.Headers = tc.headers
			task := sentHTTPTask(t, f.callOK(t, valid))
			if task.Status.State != a2agw.TaskStateWorking {
				t.Fatalf("valid caller failed: %#v", task)
			}
			got := f.callOK(t, httpRPCInput{Method: "GetTask", Params: map[string]string{"id": task.ID}, Headers: valid.Headers})
			if got.Error != nil {
				t.Fatalf("valid caller could not read: %#v", got.Error)
			}

			for _, method := range []string{"ListTasks", "CancelTask"} {
				if got := f.callOK(t, httpRPCInput{Method: method, Params: map[string]string{"id": task.ID}, Headers: valid.Headers}); got.Error != nil {
					t.Fatalf("valid caller %s refused: %#v", method, got)
				}
			}

		})
	}
}

func TestHTTPMailBridgeTaskTokenAccess(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("public")))
	for _, method := range []string{"GetTask", "CancelTask"} {
		got := f.callOK(t, httpRPCInput{Method: method, Params: map[string]string{"id": task.ID}})
		if got.Error == nil || got.Error.Data.Code != "task_not_found" {
			t.Fatalf("ID-only %s exposed task: %#v", method, got)
		}
	}
	if got := f.callOK(t, httpRPCInput{Method: "ListTasks", Params: map[string]string{}}); got.Error == nil || got.Error.Data.Code != "list_tasks_scope_required" {
		t.Fatalf("unscoped list admitted: %#v", got)
	}
	for _, method := range []string{"GetTask", "CancelTask"} {
		got := f.callOK(t, httpRPCInput{Method: method, RouteID: "r_other", Params: map[string]string{"id": task.ID}, Headers: tokenHeaders(t, task)})
		if got.Error == nil || got.Error.Data.Code != "task_not_found" {
			t.Fatalf("task token crossed route boundary: %#v", got)
		}
	}
	headers := tokenHeaders(t, task)
	issued := headers["X-A2A-Task-Token"]
	wrong := "0" + issued[1:]
	if wrong == issued {
		wrong = "1" + issued[1:]
	}
	for _, method := range []string{"GetTask", "CancelTask"} {
		got := f.callOK(t, httpRPCInput{Method: method, Params: map[string]string{"id": task.ID}, Headers: map[string]string{"X-A2A-Task-Token": wrong}})
		if got.Error == nil || got.Error.Data.Code != "task_not_found" {
			t.Fatalf("wrong same-length task token admitted %s: %#v", method, got)
		}
	}
	if got := f.callOK(t, httpRPCInput{Method: "GetTask", Params: map[string]string{"id": task.ID}, Headers: headers}); got.Error != nil {
		t.Fatalf("issued token refused: %#v", got)
	}
	got := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": task.ID}, Headers: headers})
	if got.Error != nil {
		t.Fatalf("token cancellation refused: %#v", got.Error)
	}
}

func TestHTTPMailBridgeCancelWithoutBindingDoesNotSend(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{})
	err := f.runtime.bridge.CancelTask(t.Context(), a2agw.BridgeCancel{TaskID: "unknown-task", ContextID: "caller-context", Address: "a2a.aweb.ai/personal", RouteID: "r_personal"})
	if err == nil || !strings.Contains(err.Error(), "Contact the target agent with this task ID") {
		t.Fatalf("missing mail binding did not give recovery guidance: %v", err)
	}
	if f.notices.Load() != 0 {
		t.Fatal("missing mail binding attempted a cancellation notice")
	}
}

func TestHTTPMailBridgeNoticeHTTPFailureKeepsLocalCancellation(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("notice-failure")))
	headers := tokenHeaders(t, task)
	f.failNotice.Store(true)
	got := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": task.ID}, Headers: headers})
	if got.Error == nil || got.Error.Data.Code != "cancel_notification_failed" || !strings.Contains(got.Error.Message, "Contact the target agent") {
		t.Fatalf("real notice failure hidden: %#v", got)
	}
	if f.notices.Load() != 1 {
		t.Fatal("cancellation did not reach the real mail HTTP path")
	}
	get := f.callOK(t, httpRPCInput{Method: "GetTask", Params: map[string]string{"id": task.ID}, Headers: headers})
	var canceled a2agw.Task
	if err := json.Unmarshal(get.Result, &canceled); err != nil {
		t.Fatal(err)
	}
	if canceled.Status.State != a2agw.TaskStateCanceled {
		t.Fatal("notice failure undid local cancellation")
	}
}

func TestHTTPMailBridgeCancelAfterPollingDeadlineKeepsConversation(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("after-polling")))
	time.Sleep(100 * time.Millisecond)
	got := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": task.ID}, Headers: tokenHeaders(t, task)})
	if got.Error != nil {
		t.Fatalf("polling timeout discarded the live task's conversation: %#v", got.Error)
	}
}

func TestHTTPMailBridgeConcurrentAdmissionDoesNotSendRejectedTasks(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{MaxConcurrent: 2})
	const requests = 64
	start := make(chan struct{})
	type response struct {
		result httpRPCResult
		err    error
	}
	results := make(chan response, requests)
	for i := 0; i < requests; i++ {
		go func(id int) {
			<-start
			result, err := f.call(sendHTTPInput(fmt.Sprintf("concurrent-%d", id)))
			results <- response{result, err}
		}(i)
	}
	close(start)
	var accepted []a2agw.Task
	for i := 0; i < requests; i++ {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.result.Error == nil {
			accepted = append(accepted, sentHTTPTask(t, got.result))
		} else if got.result.Error.Data.Code != "max_concurrent_tasks" {
			t.Fatalf("wrong admission refusal: %#v", got.result.Error)
		}
	}
	if len(accepted) != 2 {
		t.Fatalf("concurrent sends admitted %d tasks, want 2", len(accepted))
	}
	f.mu.Lock()
	posts := len(f.mailTasks)
	for _, task := range accepted {
		if _, sent := f.mailTasks[task.ID]; !sent {
			t.Errorf("admitted task %s was not sent", task.ID)
		}
	}
	f.mu.Unlock()
	if posts != len(accepted) {
		t.Fatalf("rejected sends reached the mail peer: posts=%d accepted=%d", posts, len(accepted))
	}
	first := accepted[0]
	if got := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": first.ID}, Headers: tokenHeaders(t, first)}); got.Error != nil {
		t.Fatalf("release task slot: %#v", got.Error)
	}
	after := sentHTTPTask(t, f.callOK(t, sendHTTPInput("after-slot-release")))
	if after.Status.State != a2agw.TaskStateWorking {
		t.Fatal("released slot was not reusable")
	}
}

func TestHTTPMailBridgeRefusesResolvedLocalTargetsBeforeSending(t *testing.T) {
	for _, reference := range []string{"default:a2a.aweb.ai/private", "default:a2a.aweb.ai/personal"} {
		t.Run(reference, func(t *testing.T) {
			f := newMailHTTPFixture(t, mailHTTPOptions{TargetReference: reference})
			got := f.callOK(t, sendHTTPInput("local-target"))
			if got.Error == nil || !strings.Contains(got.Error.Data.Detail, "local agents can't be reached from outside their team") {
				t.Fatalf("resolved local target was not refused actionably: %#v", got)
			}
			f.mu.Lock()
			posts := len(f.mailTasks)
			f.mu.Unlock()
			if posts != 0 {
				t.Fatal("local target received a public A2A task")
			}
		})
	}
}

func TestNativeStartupRefusesLocalTargetBeforeOpeningListener(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{TargetReference: "default:a2a.aweb.ai/private"})
	err := run(t.Context(), []string{"-config", f.configPath, "-listen", "invalid-listen-address"}, os.Stdout, os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "route \"r_personal\"") || !strings.Contains(err.Error(), "An A2A route needs an agent with a public address") {
		t.Fatalf("startup did not refuse local target before listening: %v", err)
	}
}

func TestNativeTargetValidationAllowsPublicOrDisabledRoute(t *testing.T) {
	for _, options := range []mailHTTPOptions{{}, {TargetReference: "default:a2a.aweb.ai/private", Disabled: true}} {
		f := newMailHTTPFixture(t, options)
		if err := f.gateway.ValidateTargets(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeOfflineConfigCheckDoesNotResolveTargets(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{TargetReference: "default:a2a.aweb.ai/private"})
	output, err := os.CreateTemp(t.TempDir(), "diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	before := f.resolutions.Load()
	runErr := run(t.Context(), []string{"-config", f.configPath, "-check"}, output, os.Stderr)
	closeErr := output.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if f.resolutions.Load() != before {
		t.Fatal("offline -check contacted target authority")
	}
}
