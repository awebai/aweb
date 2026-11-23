package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/a2agw"
	"github.com/awebai/aw/awid"
)

type replySignatureBinding int

const (
	conversationSigned replySignatureBinding = iota
	conversationUnsigned
)

type signedHTTPReply struct {
	Task    a2agw.Task
	Body    string
	Binding replySignatureBinding
}

// injectSignedReply models the peer replaying authentic signed mail; verification
// still runs through the production awid conversation reader and MailBridge.
func (f *mailHTTPFixture) injectSignedReply(t *testing.T, input signedHTTPReply) awid.InboxMessage {
	t.Helper()
	f.mu.Lock()
	conversation, gatewayDID := f.mailTasks[input.Task.ID], f.gatewayDID
	f.mu.Unlock()
	messageID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	envelope := &awid.MessageEnvelope{From: "a2a.aweb.ai/personal", FromDID: f.targetDID, FromStableID: f.targetStable, To: gatewayDID, ToDID: gatewayDID, Type: "mail", MessageID: messageID, ConversationID: conversation, Subject: "A2A answer", Body: input.Body, Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if input.Binding == conversationUnsigned {
		envelope.ConversationID = ""
	}
	signature, err := awid.SignMessage(f.targetKey, envelope)
	if err != nil {
		t.Fatal(err)
	}
	message := awid.InboxMessage{MessageID: messageID, ConversationID: conversation, FromDID: f.targetDID, FromStableID: f.targetStable, FromAddress: "a2a.aweb.ai/personal", ToDID: gatewayDID, Subject: envelope.Subject, Body: input.Body, CreatedAt: envelope.Timestamp, SignedPayload: awid.CanonicalJSON(envelope), Signature: signature}
	f.mu.Lock()
	f.inbox[conversation] = append(f.inbox[conversation], message)
	f.mu.Unlock()
	return message
}

func (f *mailHTTPFixture) readTask(t *testing.T, task a2agw.Task) a2agw.Task {
	t.Helper()
	response := f.callOK(t, httpRPCInput{Method: "GetTask", Params: map[string]string{"id": task.ID}, Headers: tokenHeaders(t, task)})
	if response.Error != nil {
		t.Fatalf("read task: %#v", response.Error)
	}
	var out a2agw.Task
	if err := json.Unmarshal(response.Result, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *mailHTTPFixture) waitForTaskReply(t *testing.T, task a2agw.Task) a2agw.Task {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got := f.readTask(t, task)
		if got.Status.State != a2agw.TaskStateWorking {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("signed reply did not update task through production reader")
	return a2agw.Task{}
}

func (f *mailHTTPFixture) auditEvent(t *testing.T, code string) (a2agw.AuditEvent, bool) {
	t.Helper()
	data, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var event a2agw.AuditEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			return event, false
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Code == code {
			return event, true
		}
	}
}

func TestHTTPMailBridgePlainQuestionRequiresSignedTaskBody(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, PollTimeout: 3 * time.Second})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("legacy-question")))
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: "QUESTION: Which order?", Binding: conversationUnsigned})
	f.waitForBindingCorrection(t, task)

	if event, found := f.auditEvent(t, "reply_task_binding_required"); !found || event.Outcome != string(a2agw.AuditDenied) {
		t.Fatalf("missing refusal audit: %#v", event)
	}
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: f.questionForm(t, task), Binding: conversationSigned})
	got := f.waitForTaskReply(t, task)
	if got.Status.State != a2agw.TaskStateInputRequired || got.Metadata["reply_verification"] != string(awid.Verified) {
		t.Fatalf("task-bearing question form refused: %#v", got)
	}
	assertQuestionText(t, got)
}

func TestHTTPMailBridgeLegacyFencedReplyKeepsAcceptance(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, PollTimeout: 3 * time.Second})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("legacy-fence")))
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"answer\"}\n```", task.ID, task.ContextID)
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: body, Binding: conversationUnsigned})
	got := f.waitForTaskReply(t, task)
	if got.Status.State != a2agw.TaskStateCompleted || got.Metadata["reply_verification"] != string(awid.VerifiedLegacy) {
		t.Fatalf("signed task-body neighbor refused: %#v", got)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].Name != "answer" {
		t.Fatalf("completed answer label changed: %#v", got.Artifacts)
	}

}

func TestHTTPMailBridgeExplicitUnverifiedLegacyQuestionIsLabeled(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, UnverifiedReplies: true, PollTimeout: 3 * time.Second})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("unverified-question")))
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: "QUESTION: Which order?", Binding: conversationUnsigned})
	got := f.waitForTaskReply(t, task)
	if got.Status.State != a2agw.TaskStateInputRequired || got.Metadata["reply_verification"] != string(awid.Unverified) {
		t.Fatalf("explicit unverified policy changed: %#v", got)
	}
}

func TestHTTPMailBridgeAuditsTargetResolutionFailure(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{TargetReference: "default:a2a.aweb.ai/private"})
	got := f.callOK(t, sendHTTPInput("refused-target"))
	if got.Error == nil {
		t.Fatal("local target was not refused")
	}
	event, found := f.auditEvent(t, "target_identity_unavailable")
	if !found || event.Stage != "bridge_send" || event.Outcome != string(a2agw.AuditError) || event.TargetAddressHash == "" || event.RequestID == "" {
		t.Fatalf("failed SendTask lacks complete audit: %#v", event)
	}
}

type managedReceiptIdentity int

const (
	completeRecipient managedReceiptIdentity = iota
	missingRecipient
)

type managedHTTPReplyOptions struct {
	UnverifiedReplies      bool
	Receipt                managedReceiptIdentity
	ReusedConversation     string
	BeforeConversationRead func(context.Context)
}

// The generic managed transport talks to a controlled provider over HTTP. Its
// declared capability and malformed response run through the actual config,
// transport, MailBridge and RPC owners, with no replaced bridge methods.
func newManagedHTTPReplyFixture(t *testing.T, options managedHTTPReplyOptions) *mailHTTPFixture {
	t.Helper()
	f := newMailHTTPFixture(t, mailHTTPOptions{PollTimeout: 3 * time.Second, UnverifiedReplies: options.UnverifiedReplies})
	f.server.Close()
	pub, gatewayKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	f.gatewayDID = awid.ComputeDIDKey(pub)
	f.gatewayKey = gatewayKey
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		write := func(value any) {
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		switch {
		case r.URL.Path == "/runtime/config/gw":
			write(map[string]any{"gateway_id": "gw", "gateway_identity": awid.ComputeStableID(pub), "gateway_identity_status": "active", "capabilities": []string{"recipient_identity_v1"}, "config_revision": "1", "expires_at": "2099-01-01T00:00:00Z", "routes": []map[string]any{{"route_id": "r_personal", "host": "a2a.aweb.ai", "address": "a2a.aweb.ai/personal", "mode": "mail", "card": map[string]any{"name": "Agent", "description": "Agent", "provider": map[string]string{"organization": "Aweb", "url": "https://aweb.ai"}, "skills": []map[string]string{{"id": "reply", "name": "Reply", "description": "Reply"}}}}}})
		case r.URL.Path == "/runtime/bridge/gw/messages":
			var request awid.SendMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				http.Error(w, "bad request", 400)
				return
			}
			id, err := awid.GenerateUUID4()
			if err != nil {
				t.Error(err)
				http.Error(w, "id unavailable", 500)
				return
			}
			conversation := request.ConversationID
			if conversation == "" {
				conversation = options.ReusedConversation
			}
			if conversation == "" {
				conversation = id
			}
			var echo *awid.InboxMessage
			if request.Subject == "A2A reply needs binding" {
				envelope := &awid.MessageEnvelope{From: "a2a.aweb.ai/gateway", FromDID: awid.ComputeDIDKey(pub), FromStableID: awid.ComputeStableID(pub), ToDID: f.targetDID, Type: "mail", MessageID: id, ConversationID: conversation, Subject: request.Subject, Body: request.Body, Timestamp: time.Now().UTC().Format(time.RFC3339)}
				signature, err := awid.SignMessage(gatewayKey, envelope)
				if err != nil {
					t.Error(err)
					http.Error(w, "signing unavailable", 500)
					return
				}
				echo = &awid.InboxMessage{MessageID: id, ConversationID: conversation, FromDID: envelope.FromDID, FromStableID: envelope.FromStableID, FromAddress: envelope.From, ToDID: f.targetDID, Subject: envelope.Subject, Body: envelope.Body, CreatedAt: envelope.Timestamp, SignedPayload: awid.CanonicalJSON(envelope), Signature: signature}
			}
			f.mu.Lock()
			if echo != nil {
				f.inbox[conversation] = append(f.inbox[conversation], *echo)
				f.corrections = append(f.corrections, request)
			} else if strings.HasPrefix(request.Subject, "A2A task ") {
				id := strings.TrimPrefix(request.Subject, "A2A task ")
				f.mailTasks[id], f.taskMessages[id] = conversation, request.Body
			}
			f.mu.Unlock()

			response := awid.SendMessageResponse{MessageID: id, ConversationID: conversation, Status: "delivered"}
			if options.Receipt == completeRecipient {
				response.RecipientDID, response.RecipientStableID = f.targetDID, f.targetStable
			}
			write(response)
		case strings.HasPrefix(r.URL.Path, "/runtime/bridge/gw/conversations/"):
			if options.BeforeConversationRead != nil {
				options.BeforeConversationRead(r.Context())
				if r.Context().Err() != nil {
					return
				}
			}
			conversation := strings.TrimPrefix(r.URL.Path, "/runtime/bridge/gw/conversations/")
			f.mu.Lock()
			messages := append([]awid.InboxMessage(nil), f.inbox[conversation]...)
			f.mu.Unlock()
			write(awid.InboxResponse{Messages: messages})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	cfg := mustLoadConfig(t, f.configPath)
	cfg.ManagedConfig = managedConfigForTest(provider.URL, "gw", "provider-token")
	cfg.AllowQuestionReply = true
	if err := applyManagedRuntimeConfig(t.Context(), &cfg); err != nil {
		t.Fatal(err)
	}
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

func TestHTTPManagedProviderOpensHostedReply(t *testing.T) {
	f := newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("hosted-reply")))
	f.mu.Lock()
	conversation := f.mailTasks[task.ID]
	f.mu.Unlock()

	now := time.Now().UTC().Truncate(time.Second)
	gatewayStable := awid.ComputeStableID(f.gatewayKey.Public().(ed25519.PublicKey))
	sender := awid.E2EESenderKey{
		Address: "a2a.aweb.ai/personal", DID: f.targetDID, StableID: f.targetStable,
		SigningKey: f.targetKey,
	}
	_, senderPublic, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	sender.EncryptionKey, err = awid.BuildEncryptionKeyAssertion(f.targetKey, f.targetDID, f.targetStable, senderPublic, "", now)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPrivate, gatewayPublic, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	gatewayAssertion, err := awid.BuildEncryptionKeyAssertion(f.gatewayKey, f.gatewayDID, gatewayStable, gatewayPublic, "", now)
	if err != nil {
		t.Fatal(err)
	}
	messageID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"Opened by the hosted provider\"}\n```", task.ID, task.ContextID)
	envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
		Sender: sender, Recipients: []awid.E2EERecipientKey{{
			DID: f.gatewayDID, StableID: gatewayStable, EncryptionKey: gatewayAssertion,
		}},
		Subject: "A2A answer", Body: body, ConversationID: conversation, MessageID: messageID, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Open under the provider's recipient key. The gateway receives the
	// projection and original signed envelope, never this private key.
	opened, err := awid.DecryptE2EEMessage(envelope, awid.E2EEDecryptIdentity{
		DID: f.gatewayDID, StableID: gatewayStable, EncryptionKeyID: gatewayAssertion.EncryptionKeyID, PrivateKey: gatewayPrivate,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.inbox[conversation] = append(f.inbox[conversation], awid.InboxMessage{
		MessageID: messageID, ConversationID: conversation, ContentMode: awid.ContentModeEncryptedV2,
		MessageVersion: awid.E2EEMessageVersion, Encrypted: envelope, Decryptable: true,
		Subject: opened.Subject, Body: opened.Body, FromDID: f.targetDID, FromStableID: f.targetStable,
		FromAddress: sender.Address, ToDID: f.gatewayDID, ToStableID: gatewayStable,
		VerificationStatus: awid.VerifiedCustodial,
	})
	f.mu.Unlock()

	got := f.waitForTaskReply(t, task)
	if got.Status.State != a2agw.TaskStateCompleted || got.Metadata["reply_verification"] != string(awid.Verified) ||
		len(got.Artifacts) != 1 || len(got.Artifacts[0].Parts) != 1 || got.Artifacts[0].Parts[0].Text != "Opened by the hosted provider" {
		t.Fatalf("managed reply did not retain the completed answer and independently verified tier: %#v", got)
	}
}

func TestHTTPManagedProviderMissingRecipientFailsTask(t *testing.T) {
	f := newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{Receipt: missingRecipient})
	got := f.callOK(t, sendHTTPInput("provider-fault"))
	if got.Error == nil || got.Error.Data.Code != "missing_recipient_identity" || !strings.Contains(got.Error.Data.Detail, "provider") || !strings.Contains(got.Error.Data.Detail, "Repair") {
		t.Fatalf("missing recipient was not an actionable provider fault: %#v", got)
	}
	task := got.Error.Data.Task
	if task == nil || task.Status.State != a2agw.TaskStateFailed {
		t.Fatalf("provider fault did not return its failed task: %#v", task)
	}
	if task.Status.Message == nil || len(task.Status.Message.Parts) == 0 || !strings.Contains(task.Status.Message.Parts[0].Text, "recipient identity") {
		t.Fatal("failed task message misstates provider fault")
	}
	event, found := f.auditEvent(t, "missing_recipient_identity")
	if !found || event.Outcome != string(a2agw.AuditError) || event.Stage != "bridge_send" {
		t.Fatalf("provider fault not audited: %#v", event)
	}
	read := f.readTask(t, *task)
	if read.Status.State != a2agw.TaskStateFailed {
		t.Fatal("provider fault stranded task without readable failure")
	}
}

func TestHTTPManagedVerifiedQuestionRequiresTaskBodyInSharedConversation(t *testing.T) {
	f := newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{ReusedConversation: "shared-native-conversation"})
	first := sentHTTPTask(t, f.callOK(t, sendHTTPInput("first-task")))
	second := sentHTTPTask(t, f.callOK(t, sendHTTPInput("second-task")))
	f.injectSignedReply(t, signedHTTPReply{Task: first, Body: "QUESTION: Which order?", Binding: conversationSigned})
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, task := range []a2agw.Task{first, second} {
			if got := f.readTask(t, task); got.Status.State != a2agw.TaskStateWorking {
				t.Fatalf("ambiguous QUESTION chose a task: %#v", got)
			}
		}
		f.mu.Lock()
		notices := len(f.corrections)
		f.mu.Unlock()
		if notices > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ambiguous QUESTION was silently dropped")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if event, found := f.auditEvent(t, "reply_task_binding_required"); !found || event.Outcome != string(a2agw.AuditDenied) {
		t.Fatalf("ambiguous reply not audited: %#v", event)
	}
	// A task-naming body remains valid in the same shared conversation.
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"answer\"}\n```", second.ID, second.ContextID)
	f.injectSignedReply(t, signedHTTPReply{Task: second, Body: body, Binding: conversationSigned})
	if got := f.waitForTaskReply(t, second); got.Status.State != a2agw.TaskStateCompleted {
		t.Fatalf("explicit task body refused: %#v", got)
	}
	if event, found := f.auditEvent(t, "malformed_reply"); found {
		t.Fatalf("gateway parsed its own correction as a malformed target reply: %#v", event)
	}

	if got := f.readTask(t, first); got.Status.State != a2agw.TaskStateWorking {
		t.Fatal("reply also mutated another task")
	}
	f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": first.ID}, Headers: tokenHeaders(t, first)})
}

func TestHTTPManagedReusedConversationDoesNotReplayEarlierQuestion(t *testing.T) {
	f := newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{ReusedConversation: "shared-native-conversation"})
	first := sentHTTPTask(t, f.callOK(t, sendHTTPInput("earlier-task")))
	f.injectSignedReply(t, signedHTTPReply{Task: first, Body: f.questionForm(t, first), Binding: conversationSigned})
	if got := f.waitForTaskReply(t, first); got.Status.State != a2agw.TaskStateInputRequired {
		t.Fatalf("first bound question failed: %#v", got)
	}
	f.injectSignedReply(t, signedHTTPReply{Task: first, Body: "QUESTION: Earlier question", Binding: conversationSigned})
	second := sentHTTPTask(t, f.callOK(t, sendHTTPInput("later-task")))
	// The provider's conversation response retains authentic earlier mail.
	// It must not become the answer to a different task in that conversation.
	f.waitForBindingCorrection(t, second)
	completion := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"The later task answer\"}\n```", second.ID, second.ContextID)
	f.injectSignedReply(t, signedHTTPReply{Task: second, Body: completion, Binding: conversationSigned})
	got := f.waitForTaskReply(t, second)
	if got.Status.State != a2agw.TaskStateCompleted || got.Metadata["reply_verification"] != string(awid.Verified) || len(got.Artifacts) != 1 || len(got.Artifacts[0].Parts) != 1 || got.Artifacts[0].Parts[0].Text != "The later task answer" {
		t.Fatalf("second-task processing witness failed: %#v", got)
	}
	if firstAfter := f.readTask(t, first); firstAfter.Status.State != a2agw.TaskStateInputRequired || len(firstAfter.Artifacts) != 1 || firstAfter.Artifacts[0].Name != "question" {
		t.Fatalf("later answer mutated the earlier task: %#v", firstAfter)
	}
}

// Pause after the real task-store application, before the bridge's final audit.
// A visible state alone therefore cannot stand in for a joined reply worker.
type pausedReplyApplication struct {
	gateway *a2agw.Gateway
	applied chan struct{}
	release chan struct{}
}

func (p *pausedReplyApplication) ApplyBridgeReply(reply a2agw.BridgeReply) (a2agw.Task, bool, error) {
	task, applied, err := p.gateway.ApplyBridgeReply(reply)
	close(p.applied)
	<-p.release
	return task, applied, err
}

func TestHTTPGatewayShutdownJoinsReplyAudit(t *testing.T) {
	t.Run("native", func(t *testing.T) {
		assertShutdownJoinsReplyAudit(t, newMailHTTPFixture(t, mailHTTPOptions{PollTimeout: 3 * time.Second}))
	})
	t.Run("managed", func(t *testing.T) {
		assertShutdownJoinsReplyAudit(t, newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{}))
	})
}

func assertShutdownJoinsReplyAudit(t *testing.T, f *mailHTTPFixture) {
	t.Helper()
	f.server.Close()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	server := gatewayHTTPServer("127.0.0.1:0", f.gateway)
	defer server.Close()
	listening := make(chan string, 1)
	server.BaseContext = func(listener net.Listener) context.Context {
		listening <- "http://" + listener.Addr().String()
		return context.Background()
	}
	admissionStopped := make(chan struct{})
	server.RegisterOnShutdown(func() { close(admissionStopped) })
	done := make(chan error, 1)
	go func() { done <- serveGateway(ctx, server, f.runtime.bridge, nil) }()
	select {
	case f.rpcBaseURL = <-listening:
	case err := <-done:
		t.Fatalf("gateway failed before it was ready: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not listen")
	}

	paused := &pausedReplyApplication{gateway: f.gateway, applied: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(paused.release) }) }
	defer unblock()
	f.runtime.bridge.SetReplyApplier(paused)
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("pending-transition-audit")))
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"answer\"}\n```", task.ID, task.ContextID)
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: body, Binding: conversationSigned})
	select {
	case <-paused.applied:
	case <-time.After(2 * time.Second):
		t.Fatal("production reader did not apply the reply")
	}
	if got := f.readTask(t, task); got.Status.State != a2agw.TaskStateCompleted {
		t.Fatalf("reply was not visible before its final audit: %#v", got)
	}
	stop()
	select {
	case <-admissionStopped:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not close its HTTP listener after shutdown was requested")
	}
	select {
	case err := <-done:
		t.Fatalf("gateway stopped with a pending reply audit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gateway shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not finish after the reply worker was released")
	}
	audit, err := os.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	decoder := json.NewDecoder(audit)
	for {
		var event a2agw.AuditEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			t.Fatal("gateway stopped before writing the task transition audit")
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Stage == "task_state_transition" && event.TaskID == task.ID && event.Outcome == string(a2agw.AuditOK) {
			return
		}
	}
}

func (f *mailHTTPFixture) questionForm(t *testing.T, task a2agw.Task) string {
	t.Helper()
	f.mu.Lock()
	body := f.taskMessages[task.ID]
	f.mu.Unlock()
	start := strings.Index(body, "```a2a-reply\n")
	if start < 0 {
		t.Fatal("task did not teach the exact question form")
	}
	tail := body[start+len("```a2a-reply\n"):]
	end := strings.Index(tail, "\n```")
	if end < 0 {
		t.Fatal("task question form is unfinished")
	}
	form := "```a2a-reply\n" + tail[:end] + "\n```"
	if !strings.Contains(form, "input_required") || !strings.Contains(form, task.ID) {
		t.Fatal("task instructions did not carry the question state and task")
	}
	return strings.ReplaceAll(form, "Your question here", "Which order?")
}

func (f *mailHTTPFixture) waitForBindingCorrection(t *testing.T, task a2agw.Task) awid.SendMessageRequest {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := f.readTask(t, task)
		if got.Status.State != a2agw.TaskStateWorking {
			t.Fatalf("legacy replay changed task: %#v", got.Status)
		}
		f.mu.Lock()
		notices := append([]awid.SendMessageRequest(nil), f.corrections...)
		f.mu.Unlock()
		if len(notices) > 0 {
			notice := notices[0]
			if !strings.Contains(notice.Body, "aw 1.19.0 or later") || !strings.Contains(notice.Body, "a2a-reply") || !strings.Contains(notice.Body, "task_id") {
				t.Fatalf("target received no binding recovery: %s", notice.Body)
			}
			f.mu.Lock()
			conversation := f.mailTasks[task.ID]
			f.mu.Unlock()
			if notice.ConversationID != conversation || notice.ToAddress != "a2a.aweb.ai/personal" {
				t.Fatal("correction notice lost its configured address or original conversation")
			}
			// Native mail carries the DID; the managed provider wire selects the
			// already-bound route/address and signs the recipient in its own owner.
			if f.runtime.managedTransport == nil && notice.ToDID != f.targetDID {
				t.Fatal("native correction lost its bound signing identity")
			}
			return notice
		}
		if time.Now().After(deadline) {
			t.Fatal("legacy QUESTION was silently dropped without target correction")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTPMailBridgeCurrentPlainQuestionAlsoRequiresTaskBody(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{PollTimeout: 3 * time.Second})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("current-question")))
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: "QUESTION: Which order?", Binding: conversationSigned})
	f.waitForBindingCorrection(t, task)
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: f.questionForm(t, task), Binding: conversationSigned})
	if got := f.waitForTaskReply(t, task); got.Status.State != a2agw.TaskStateInputRequired || got.Metadata["reply_verification"] != string(awid.Verified) {
		t.Fatalf("task-bound current question failed: %#v", got)
	}
}

func TestHTTPManagedCapabilityRefusalNamesProviderBeforeSend(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{})
	f.server.Close()
	var requests atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); http.Error(w, "unexpected send", 500) }))
	t.Cleanup(provider.Close)
	cfg := mustLoadConfig(t, f.configPath)
	cfg.ManagedConfig = managedConfigForTest(provider.URL, "gw", "provider-token")
	cfg.ManagedConfig.ConfigURL += "?operator_secret=must-not-escape"
	cfg.ManagedRuntime.ExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	// Exercise the library/embedding construction boundary; normal managed
	// startup also enforces the declared runtime capability before listening.
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(gateway)
	t.Cleanup(f.server.Close)
	got := f.callOK(t, sendHTTPInput("incapable-provider"))
	if got.Error == nil || !strings.Contains(got.Error.Data.Detail, provider.URL) || !strings.Contains(got.Error.Data.Detail, "Upgrade") || !strings.Contains(got.Error.Data.Detail, "recipient_identity_v1") {
		t.Fatalf("capability refusal does not name provider/recovery: %#v", got.Error)
	}
	if strings.Contains(got.Error.Data.Detail, "must-not-escape") {
		t.Fatal("provider fault exposed a private configuration URL query")
	}

	if requests.Load() != 0 {
		t.Fatal("unsupported provider received durable mail")
	}
	if event, found := f.auditEvent(t, "target_identity_unavailable"); !found || event.Outcome != string(a2agw.AuditError) {
		t.Fatalf("capability SendTask failure not audited: %#v", event)
	}
}

func assertQuestionText(t *testing.T, task a2agw.Task) {
	t.Helper()
	if task.Status.Message == nil || len(task.Status.Message.Parts) == 0 || task.Status.Message.Parts[0].Text != "Which order?" {
		t.Fatalf("fenced input_required did not carry the question text: %#v", task.Status)
	}
}

func TestHTTPManagedUnverifiedQuestionRefusesAmbiguousTask(t *testing.T) {
	firstRead, secondRead := make(chan struct{}), make(chan struct{})
	releaseFirst, secondCanceled := make(chan struct{}), make(chan struct{})
	var reads atomic.Int32
	var release sync.Once
	unblockFirst := func() { release.Do(func() { close(releaseFirst) }) }
	defer unblockFirst()
	f := newManagedHTTPReplyFixture(t, managedHTTPReplyOptions{
		ReusedConversation: "unverified-shared",
		UnverifiedReplies:  true,
		BeforeConversationRead: func(ctx context.Context) {
			switch reads.Add(1) {
			case 1:
				close(firstRead)
				select {
				case <-releaseFirst:
				case <-ctx.Done():
				}
			case 2:
				close(secondRead)
				<-ctx.Done()
				close(secondCanceled)
			}
		},
	})
	waitForRead := func(stage string, done <-chan struct{}) {
		t.Helper()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("provider did not observe %s", stage)
		}
	}
	// Park the first read before sending the second task, so each in-flight
	// request belongs to a known poller even though they share a conversation.
	first := sentHTTPTask(t, f.callOK(t, sendHTTPInput("first-unverified-task")))
	waitForRead("the first task's poll", firstRead)
	second := sentHTTPTask(t, f.callOK(t, sendHTTPInput("second-unverified-task")))
	waitForRead("the second task's poll", secondRead)
	f.injectSignedReply(t, signedHTTPReply{Task: first, Body: "QUESTION: Which order?", Binding: conversationUnsigned})
	unblockFirst()
	deadline := time.Now().Add(2 * time.Second)
	var notice awid.SendMessageRequest
	for {
		for _, task := range []a2agw.Task{first, second} {
			if got := f.readTask(t, task); got.Status.State != a2agw.TaskStateWorking {
				t.Fatalf("ambiguous unverified question changed task: %#v", got)
			}
		}
		f.mu.Lock()
		if len(f.corrections) > 0 {
			notice = f.corrections[0]
		}
		f.mu.Unlock()
		if notice.Body != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ambiguous question had no target correction")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(notice.Body, first.ID) || !strings.Contains(notice.Body, second.ID) || !strings.Contains(notice.Body, "a2a-reply") || notice.ToAddress != "a2a.aweb.ai/personal" || notice.ConversationID != "unverified-shared" {
		t.Fatalf("correction did not preserve both task forms and configured route/conversation: %#v", notice)
	}
	if event, found := f.auditEvent(t, "reply_task_ambiguous"); !found || event.Outcome != string(a2agw.AuditDenied) {
		t.Fatalf("ambiguity refusal not audited: %#v", event)
	}
	f.injectSignedReply(t, signedHTTPReply{Task: second, Body: f.questionForm(t, second), Binding: conversationUnsigned})
	got := f.waitForTaskReply(t, second)
	if got.Status.State != a2agw.TaskStateInputRequired || got.Metadata["reply_verification"] != string(awid.Unverified) {
		t.Fatalf("task-bearing unverified neighbor failed: %#v", got)
	}
	if got := f.readTask(t, first); got.Status.State != a2agw.TaskStateWorking {
		t.Fatalf("task-named question changed its neighbor: %#v", got)
	}
	f.waitForAppliedTransition(t, second.ID)
	// Only the first poller read the fenced question. Applying it must cancel
	// the second poller and still leave the first to read the next question.
	waitForRead("cancellation of the second task's in-flight poll", secondCanceled)
	f.injectSignedReply(t, signedHTTPReply{Task: first, Body: "QUESTION: Which shipment?", Binding: conversationUnsigned})
	if got := f.waitForTaskReply(t, first); got.Status.State != a2agw.TaskStateInputRequired || got.Status.Message == nil || len(got.Status.Message.Parts) != 1 || got.Status.Message.Parts[0].Text != "Which shipment?" {
		t.Fatalf("retained, interrupted task blocked a question for its working neighbor: %#v", got.Status)
	}
	if result := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": first.ID}, Headers: tokenHeaders(t, first)}); result.Error != nil {
		t.Fatalf("question cancellation failed: %#v", result.Error)
	}
}

func TestHTTPMailBridgeQuestionsHaveQuestionArtifacts(t *testing.T) {
	for _, form := range []string{"fenced-text", "fenced-artifact", "unverified-plain"} {
		t.Run(form, func(t *testing.T) {
			f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, UnverifiedReplies: form == "unverified-plain", PollTimeout: 3 * time.Second})
			task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("artifact-question")))
			body := "QUESTION: Which order?"
			switch form {
			case "fenced-text":
				body = fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"input_required\",\"text\":\"Which order?\"}\n```", task.ID, task.ContextID)
			case "fenced-artifact":
				body = f.questionForm(t, task)
			}
			f.injectSignedReply(t, signedHTTPReply{Task: task, Body: body, Binding: conversationSigned})
			got := f.waitForTaskReply(t, task)
			if got.Status.State != a2agw.TaskStateInputRequired || len(got.Artifacts) != 1 || got.Artifacts[0].Name != "question" || len(got.Artifacts[0].Parts) != 1 || got.Artifacts[0].Parts[0].Text != "Which order?" {
				t.Fatalf("question mislabelled as answer: %#v", got)
			}
		})
	}
}

func (f *mailHTTPFixture) waitForAppliedTransition(t *testing.T, taskID string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(f.auditPath)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		for {
			var event a2agw.AuditEvent
			if err := decoder.Decode(&event); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			if event.Stage == "task_state_transition" && event.TaskID == taskID && event.Outcome == string(a2agw.AuditOK) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("question transition did not finish its bridge ingestion")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHTTPMailBridgeQuestionCannotContinueSameTask(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, PollTimeout: 3 * time.Second})
	task := sentHTTPTask(t, f.callOK(t, sendHTTPInput("question-task")))
	f.injectSignedReply(t, signedHTTPReply{Task: task, Body: f.questionForm(t, task), Binding: conversationSigned})
	question := f.waitForTaskReply(t, task)
	if question.Status.State != a2agw.TaskStateInputRequired || len(question.Artifacts) != 1 || question.Artifacts[0].Name != "question" {
		t.Fatalf("question failed: %#v", question)
	}
	f.waitForAppliedTransition(t, task.ID)
	completion := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":%q,\"state\":\"completed\",\"text\":\"A late target answer\"}\n```", task.ID, task.ContextID)
	late := f.injectSignedReply(t, signedHTTPReply{Task: task, Body: completion, Binding: conversationSigned})
	client, _, err := mailTransportFromConfig(mustLoadConfig(t, f.configPath))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	conversation := f.mailTasks[task.ID]
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	inbox, err := client.MailConversation(ctx, conversation, 20)
	if err != nil {
		t.Fatal(err)
	}
	var lateMessage *awid.InboxMessage
	for _, message := range inbox.Messages {
		if message.MessageID == late.MessageID {
			copy := message
			lateMessage = &copy
		}
	}
	if lateMessage == nil || lateMessage.VerificationStatus != awid.Verified || lateMessage.FromDID != f.targetDID {
		t.Fatalf("late answer did not pass the production HTTP mail reader: %#v", lateMessage)
	}
	// Explicit ingestion of an authentic late answer cannot resume the question.
	if _, applied, err := f.runtime.bridge.IngestInboxMessage(ctx, *lateMessage); err != nil || applied {
		t.Fatalf("same-task late answer applied=%v err=%v", applied, err)
	}
	after := f.readTask(t, task)
	if after.Status.State != a2agw.TaskStateInputRequired || after.Status.Timestamp != question.Status.Timestamp || len(after.Artifacts) != 1 || after.Artifacts[0].Name != "question" || len(after.Artifacts[0].Parts) != 1 || after.Artifacts[0].Parts[0].Text != "Which order?" {
		t.Fatalf("question task moved after late completion: %#v", after)
	}
	newTask := sentHTTPTask(t, f.callOK(t, httpRPCInput{Method: "SendMessage", Params: map[string]any{"message": a2agw.A2AMessage{MessageID: "caller-answer", TaskID: task.ID, ContextID: task.ContextID, Role: a2agw.RoleUser, Parts: []a2agw.A2APart{{Text: "Order 42", MediaType: "text/plain"}}}, "configuration": map[string]bool{"returnImmediately": true}}}))
	if newTask.ID == task.ID || newTask.Status.State != a2agw.TaskStateWorking {
		t.Fatalf("new answer task resumed the old task: %#v", newTask)
	}
	f.mu.Lock()
	delivered := f.taskMessages[newTask.ID]
	f.mu.Unlock()
	if !strings.Contains(delivered, "Order 42") || !strings.Contains(delivered, newTask.ID) {
		t.Fatal("new task did not deliver the caller answer in its own signed envelope")
	}
	if got := f.readTask(t, task); got.Status.State != a2agw.TaskStateInputRequired {
		t.Fatalf("new task changed question task: %#v", got)
	}
	for _, cancel := range []a2agw.Task{task, newTask} {
		before := f.notices.Load()
		result := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": cancel.ID}, Headers: tokenHeaders(t, cancel)})
		if result.Error != nil || f.notices.Load() != before+1 || f.readTask(t, cancel).Status.State != a2agw.TaskStateCanceled {
			t.Fatalf("cancellation did not notify the target in the task's signed conversation: %#v", result.Error)
		}
	}
}

func TestHTTPMailBridgeControlIDsKeepCallerTextOut(t *testing.T) {
	f := newMailHTTPFixture(t, mailHTTPOptions{QuestionReplies: true, PollTimeout: 3 * time.Second})
	callerContext := strings.Repeat("customer context ` ñ ", 20)
	const externalID = "caller-selected-trace"
	requestIDs := map[string]bool{externalID: true}
	auditIDs := map[string]string{}
	controlToken := regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	parseControl := func(body, fence string) map[string]string {
		t.Helper()
		body, ok := strings.CutPrefix(body, "```"+fence+"\n")
		payload, _, closed := strings.Cut(body, "\n```\n")
		var fields map[string]string
		if !ok || !closed || json.Unmarshal([]byte(payload), &fields) != nil {
			t.Fatalf("invalid %s control block", fence)
		}
		return fields
	}
	for _, id := range []string{"first-context", "second-context"} {
		task := sentHTTPTask(t, f.callOK(t, httpRPCInput{Method: "SendMessage", Headers: map[string]string{"X-Request-ID": externalID}, Params: map[string]any{
			"message":       a2agw.A2AMessage{MessageID: id, ContextID: callerContext, Role: a2agw.RoleUser, Parts: []a2agw.A2APart{{Text: "Customer message", MediaType: "text/plain"}}},
			"configuration": map[string]bool{"returnImmediately": true},
		}}))
		f.mu.Lock()
		body := f.taskMessages[task.ID]
		f.mu.Unlock()
		fields := parseControl(body, "a2a-task")
		requestID, contextID := fields["request_id"], fields["context_id"]
		if !controlToken.MatchString(requestID) || requestIDs[requestID] || task.Metadata["request_id"] != requestID {
			t.Errorf("task did not get a unique gateway request ID: %q", requestID)
		}
		requestIDs[requestID] = true
		auditIDs[requestID] = "bridge_send"
		if !controlToken.MatchString(contextID) || strings.Contains(body, callerContext) || task.ContextID != callerContext {
			t.Errorf("caller context leaked into the control block or changed in the RPC result: %q", contextID)
		}
		f.injectSignedReply(t, signedHTTPReply{Task: task, Body: f.questionForm(t, task), Binding: conversationSigned})
		if got := f.waitForTaskReply(t, task); got.Status.State != a2agw.TaskStateInputRequired || got.ContextID != callerContext {
			t.Fatalf("control context did not bind the question to the original RPC task: %#v", got.Status)
		}
		f.waitForAppliedTransition(t, task.ID)
		headers := tokenHeaders(t, task)
		headers["X-Request-ID"] = externalID
		result := f.callOK(t, httpRPCInput{Method: "CancelTask", Params: map[string]string{"id": task.ID}, Headers: headers})
		if result.Error != nil {
			t.Fatalf("question cancellation failed: %#v", result.Error)
		}
		f.mu.Lock()
		notice := f.lastNotice
		f.mu.Unlock()
		canceled := parseControl(notice, "a2a-cancel")
		cancelID := canceled["request_id"]
		if canceled["context_id"] != contextID || canceled["task_id"] != task.ID || !controlToken.MatchString(cancelID) || requestIDs[cancelID] {
			t.Fatalf("cancel notice lost its task binding or gateway request ID: %#v", canceled)
		}
		requestIDs[cancelID] = true
		auditIDs[cancelID] = "bridge_cancel"
	}
	audit, err := os.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	decoder := json.NewDecoder(audit)
	for {
		var event a2agw.AuditEvent
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if event.RequestID == externalID {
			t.Fatal("caller-supplied request ID reached the audit log")
		}
		if auditIDs[event.RequestID] == event.Stage {
			delete(auditIDs, event.RequestID)
		}
	}
	if len(auditIDs) != 0 {
		t.Fatalf("signed control IDs are missing from the matching audit events: %#v", auditIDs)
	}
}
