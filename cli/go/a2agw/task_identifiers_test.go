package a2agw

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"github.com/awebai/aw/awid"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTaskIdentifierSourceFailureReturnsErrorWithoutPanicking(t *testing.T) {
	_, err := readUUIDv4(strings.NewReader("short"))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error=%v", err)
	}
	id, err := readUUIDv4(bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if id != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("version/variant encoding=%s", id)
	}
}

// The subprocess contains the random-source failure so it cannot affect another
// test's HTTP peers or background reply pollers.
func TestGatewayRandomFailureIsRecoverableWithoutLosingAcceptedTask(t *testing.T) {
	if os.Getenv("AW_TEST_GATEWAY_RANDOM_FAILURE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGatewayRandomFailureIsRecoverableWithoutLosingAcceptedTask$")
		cmd.Env = append(os.Environ(), "AW_TEST_GATEWAY_RANDOM_FAILURE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("random-source recovery: %v\n%s", err, out)
		}
		return
	}
	route := supportRoute("r_support")
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Routes: []Route{route}})
	saved := rand.Reader
	rand.Reader = strings.NewReader("")
	response := httptest.NewRecorder()
	gw.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/a2a/agents/r_support/rpc", strings.NewReader("{}")))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "Restore the host random source and retry") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	rand.Reader = saved
	// A real store transition must leave the record intact on identifier failure.
	record, err := gw.tasks.create(taskCreation{RouteID: "r_support", Message: A2AMessage{MessageID: "msg", ContextID: "ctx", Role: RoleUser, Parts: []A2APart{{Text: "hello", MediaType: "text/plain"}}}})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewMailBridge(MailBridgeConfig{Client: &fakeMailTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	bridge.SetReplyApplier(gw)
	retention, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bridge.threads[record.ID] = &mailBridgeThread{TaskID: record.ID, ContextID: "ctx", CallerContextID: "ctx", TargetDID: "did:key:target", ConversationID: "conversation", SeenMessages: map[string]bool{}, RetentionContext: retention}
	body := "```a2a-reply\n{\"task_id\":\"" + record.ID + "\",\"context_id\":\"ctx\",\"state\":\"completed\",\"text\":\"answer\"}\n```"
	reply := awid.InboxMessage{MessageID: "reply", FromDID: "did:key:target", ConversationID: "conversation", Body: body, VerificationStatus: awid.Verified}
	rand.Reader = strings.NewReader("")
	if _, ok, err := bridge.IngestInboxMessage(context.Background(), reply); err == nil || ok {
		t.Fatalf("failed transition ok=%v err=%v", ok, err)
	}
	rand.Reader = saved
	if task, ok, err := bridge.IngestInboxMessage(context.Background(), reply); err != nil || !ok || task.Status.State != TaskStateCompleted {
		t.Fatalf("retry task=%#v ok=%v err=%v", task, ok, err)
	}
}
