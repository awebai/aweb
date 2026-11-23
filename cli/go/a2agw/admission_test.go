package a2agw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestExplicitUnverifiedProviderWorksAndLabelsItsReply(t *testing.T) {
	// The interface exposes the original transport surface without identity
	// resolution or the new provider capability.
	var legacy MailTransport = &fakeMailTransport{}
	transport := struct{ MailTransport }{legacy}
	bridge, err := NewMailBridge(MailBridgeConfig{Client: transport, RequireVerifiedReplies: false, AllowUnverifiedLocalReply: true})
	if err != nil {
		t.Fatal(err)
	}
	gw := newTestGateway(t, Config{Host: "example.com", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})
	bridge.SetReplyApplier(gw)
	id := sendTestA2ATask(t, gw)
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":\"ctx-1\",\"state\":\"completed\",\"text\":\"answer\"}\n```", id)
	task, applied, err := bridge.IngestInboxMessage(context.Background(), awid.InboxMessage{MessageID: "reply", ConversationID: "conv-1", Body: body, VerificationStatus: awid.Unverified})
	if err != nil || !applied {
		t.Fatalf("explicit legacy route refused: %v", err)
	}
	if task.Metadata["reply_verification"] != string(awid.Unverified) {
		t.Fatalf("legacy reply was not labeled unverified: %#v", task.Metadata)
	}
}

func TestReplyMustVerifyFromTheResolvedTarget(t *testing.T) {
	transport := &fakeMailTransport{}
	bridge := newTestMailBridge(t, transport, nil)
	gw := newTestGateway(t, Config{Host: "example.com", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})
	bridge.SetReplyApplier(gw)
	id := sendTestA2ATask(t, gw)
	if transport.sent[0].ToDID != "did:key:target" {
		t.Fatal("bridge did not pin aw mail's resolved recipient before send")
	}
	body := fmt.Sprintf("```a2a-reply\n{\"task_id\":%q,\"context_id\":\"ctx-1\",\"state\":\"completed\",\"text\":\"answer\"}\n```", id)
	msg := awid.InboxMessage{MessageID: "foreign-reply", ConversationID: "conv-1", FromDID: "did:key:other", Body: body, VerificationStatus: awid.Verified}
	if _, ok, err := bridge.IngestInboxMessage(context.Background(), msg); ok || err == nil || !strings.Contains(err.Error(), "target identity") {
		t.Fatalf("unrelated verified sender admitted: ok=%v err=%v", ok, err)
	}
	msg.MessageID, msg.FromDID, msg.FromStableID = "target-reply", "did:key:target", "did:aw:target"
	if _, ok, err := bridge.IngestInboxMessage(context.Background(), msg); err != nil || !ok {
		t.Fatalf("intended target refused: ok=%v err=%v", ok, err)
	}
}

type blockingReplyTransport struct {
	fakeMailTransport
	started chan struct{}
	stopped chan struct{}
}

func (b *blockingReplyTransport) MailConversation(ctx context.Context, _ string, _ int) (*awid.InboxResponse, error) {
	close(b.started)
	<-ctx.Done()
	close(b.stopped)
	return nil, ctx.Err()
}

func TestCancellationStopsReplyPollingAndReclaimsThread(t *testing.T) {
	transport := &blockingReplyTransport{started: make(chan struct{}), stopped: make(chan struct{})}
	bridge, err := NewMailBridge(MailBridgeConfig{Client: transport})
	if err != nil {
		t.Fatal(err)
	}
	gw := newTestGateway(t, Config{Host: "example.com", Bridge: bridge, Routes: []Route{supportRoute("r_support")}})
	bridge.SetReplyApplier(gw)
	id, token := sendTestA2ATaskWithToken(t, gw)
	select {
	case <-transport.started:
	case <-time.After(time.Second):
		t.Fatal("reply poll did not start")
	}
	postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("cancel", "CancelTask", map[string]any{"id": id}), map[string]string{"X-A2A-Task-Token": token}, 200)
	select {
	case <-transport.stopped:
	case <-time.After(time.Second):
		t.Fatal("canceled task left an in-flight reply poll")
	}
	if bridge.thread(id) != nil {
		t.Fatal("canceled task retained bridge thread")
	}
}

func TestRequireVerifiedRepliesOverridesLocalAllowance(t *testing.T) {
	for _, require := range []bool{false, true} {
		bridge, err := NewMailBridge(MailBridgeConfig{Client: &fakeMailTransport{}, RequireVerifiedReplies: require, AllowUnverifiedLocalReply: true})
		if err != nil {
			t.Fatal(err)
		}
		err = bridge.verifyReplyMessage(awid.InboxMessage{})
		if require && (err == nil || !strings.Contains(err.Error(), "Have the target agent")) {
			t.Fatalf("explicit require bypassed: %v", err)
		}
		if !require && err != nil {
			t.Fatalf("explicit local compatibility refused: %v", err)
		}
		if err := bridge.verifyReplyMessage(awid.InboxMessage{VerificationStatus: awid.Verified}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExpiredTaskStateIsReclaimed(t *testing.T) {
	route := supportRoute("r_support")
	gw := newTestGateway(t, Config{Host: "example.com", Bridge: &fakeBridge{}, Routes: []Route{route}})
	now := time.Now()
	gw.tasks.now = func() time.Time { return now }
	resp := postRPC(t, gw, "/a2a/agents/r_support/rpc", rpcEnvelope("send", "SendMessage", map[string]any{
		"message": testUserMessage("message", "context", "expires"), "configuration": map[string]any{"returnImmediately": true},
	}), nil, 200)
	task := rpcTaskResult(t, resp, "task")
	now = now.Add(2 * time.Hour)
	if _, ok := gw.tasks.getVisible(taskAccess{RouteID: route.RouteID, CallerScope: "anonymous:unscoped", Token: taskBearerToken(t, task), TaskID: decodedTask(t, task).ID}); ok {
		t.Fatal("expired task still visible")
	}
	if len(gw.tasks.tasks) != 0 || len(gw.tasks.order) != 0 {
		t.Fatalf("expiry hid state without reclaiming it: tasks=%d order=%d", len(gw.tasks.tasks), len(gw.tasks.order))
	}
}

func TestReplyParserIgnoresQuotedAndNestedCustomerFences(t *testing.T) {
	reply := "```a2a-reply\n{\"task_id\":\"target\",\"state\":\"completed\",\"text\":\"real answer\"}\n```"
	quoted := "> ```a2a-reply\n> {\"task_id\":\"target\",\"state\":\"completed\",\"text\":\"customer answer\"}\n> ```\n\n"
	for _, body := range []string{quoted + reply, "````markdown\n" + reply + "\n````\n\n" + reply} {
		got, found, err := ParseA2AReply(body, false)
		if err != nil || !found || got.Text != "real answer" {
			t.Fatalf("quoted customer content overrode answer: reply=%#v found=%v err=%v", got, found, err)
		}
	}
	if _, found, err := ParseA2AReply(quoted, false); err != nil || found {
		t.Fatal("quoted fence was treated as a reply")
	}
	if _, _, err := ParseA2AReply(reply+"\n"+reply, false); err == nil {
		t.Fatal("ambiguous replies must not select the first one")
	}
}

func TestReplyParserPreservesIndentedJSONInsideTheFence(t *testing.T) {
	data, err := json.MarshalIndent(map[string]any{"task_id": "target", "state": "completed", "artifacts": []map[string]string{{"type": "text", "text": "real answer"}}}, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	reply, found, err := ParseA2AReply("```a2a-reply\n"+string(data)+"\n```", false)
	if err != nil || !found || reply.Text != "real answer" {
		t.Fatalf("formatted reply rejected: %#v %v", reply, err)
	}
}

func decodedTask(t *testing.T, value map[string]any) Task {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var task Task
	if err := json.Unmarshal(data, &task); err != nil {
		t.Fatal(err)
	}
	return task
}
