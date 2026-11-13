package handoff

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const admitOperationID = "22222222-2222-4222-8222-222222222222"

// admitBody is a bounded admission aw prepares: a local child unless childID
// names a registered one.
func admitBody(childID any) map[string]any {
	return map[string]any{
		"operation_id": admitOperationID, "operation": "team.agent.admit", "variant": "default",
		"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
			"authority": map[string]any{"kind": "team_controller", "id": "eng:example.com", "domain": "example.com"},
			"human":     map[string]any{"id": "did:aw:human", "domain": "example.com"}, "generation": 1},
		"audience": "https://registry.example.com",
		"subject": map[string]any{"team_id": "eng:example.com", "root_id": "did:aw:root", "root_key": "did:key:zroot",
			"child_id": childID, "child_key": "did:key:zchild", "member_alias": "worker",
			"admission_policy_digest": "sha256:" + strings.Repeat("ab", 32), "expected_policy_version": 3},
	}
}

func admitRaw(t *testing.T, body map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// admitStub stands in for the protected service's bounded routes: it answers
// prepare with the operation frozen as the contract says (changed by tamper),
// each execute with the next scripted answer, and each receipt read likewise.
// "drop" closes the connection unanswered; "<status>:<body>" answers that.
type admitStub struct {
	mu       sync.Mutex
	server   *httptest.Server
	tamper   string
	sent     map[string]any
	prepares int
	executes []string
	execs    int
	receipts []string
	reads    int
	bodies   [][]byte
	dropPrep bool
	// expiresIn is the prepared operation's lifetime (default a minute).
	expiresIn time.Duration
}

func newAdmitStub(t *testing.T) *admitStub {
	s := &admitStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations":
			s.prepares++
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &s.sent)
			if s.dropPrep {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			_, _ = w.Write([]byte(s.answer()))
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations/"+admitOperationID+"/execute":
			body, _ := io.ReadAll(r.Body)
			s.bodies = append(s.bodies, body)
			s.reply(w, s.executes, &s.execs)
		case r.Method == http.MethodGet && r.URL.Path == "/request/protected-operations/"+admitOperationID:
			s.reply(w, s.receipts, &s.reads)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *admitStub) reply(w http.ResponseWriter, script []string, count *int) {
	answer := script[min(*count, len(script)-1)]
	*count++
	if answer == "drop" {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
		return
	}
	status, body, _ := strings.Cut(answer, ":")
	code := http.StatusOK
	switch status {
	case "403":
		code = http.StatusForbidden
	case "503":
		w.Header().Set("Retry-After", "0")
		code = http.StatusServiceUnavailable
	case "503h1":
		w.Header().Set("Retry-After", "1")
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// answer freezes what was sent as the service does for an admission.
func (s *admitStub) answer() string {
	request := map[string]any{}
	for k, v := range s.sent {
		request[k] = v
	}
	subject, _ := s.sent["subject"].(map[string]any)
	request["requester"] = "did:aw:root"
	request["policy_ref"] = "aweb.human-assurance/1"
	request["policy_version"] = 1
	request["request_id"] = s.sent["operation_id"]
	request["admission_policy_version"] = subject["expected_policy_version"]
	artifact := map[string]any{"version": 1, "certificate_id": "33333333-3333-4333-8333-333333333333", "team_id": subject["team_id"],
		"team_did_key": "did:key:zteam", "member_did_key": subject["child_key"], "alias": subject["member_alias"],
		"identity_scope": "local", "issued_at": "2099-01-01T00:00:00Z"}
	if subject["child_id"] != nil {
		artifact["member_did_aw"] = subject["child_id"]
		artifact["identity_scope"] = "global"
	}
	switch s.tamper {
	case "request-id":
		request["request_id"] = "44444444-4444-4444-8444-444444444444"
	case "policy-version":
		request["admission_policy_version"] = 4
	case "certificate-fields":
		request["certificate_fields"] = map[string]any{}
	case "no-request-id":
		delete(request, "request_id")
	case "team":
		artifact["team_id"] = "other:example.com"
	case "member-key":
		artifact["member_did_key"] = "did:key:zother"
	case "alias":
		artifact["alias"] = "other"
	case "scope":
		artifact["identity_scope"] = "global"
	case "stable-id":
		artifact["member_did_aw"] = "did:aw:other"
	case "address":
		artifact["member_address"] = "example.com/worker"
	case "signature":
		artifact["signature"] = "c2ln"
	case "no-certificate-id":
		delete(artifact, "certificate_id")
	case "version":
		artifact["version"] = 2
	}
	request["artifact"] = artifact
	payload := map[string]any{"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}, "request": request}
	raw, _ := json.Marshal(map[string]any{
		"operation_id": s.sent["operation_id"], "handoff_id": "h1", "digest": coveredDigestOf(payload), "payload": payload,
		"expires_at": time.Now().Add(cmp.Or(s.expiresIn, time.Minute)).UTC().Format(time.RFC3339Nano),
	})
	return string(raw)
}

func (s *admitStub) options(t *testing.T) GovernanceOptions {
	return GovernanceOptions{
		Request: s.server.URL + "/request", Human: s.server.URL + "/human",
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(string(body)))
			return http.DefaultClient.Do(req)
		},
		Open:         func(string) error { t.Fatal("a bounded operation opened a page"); return nil },
		Notify:       io.Discard,
		PollInterval: 10 * time.Millisecond,
	}
}

const (
	admitCommitted = `{"state":"committed","result":{"signing":"c2lnbmluZw==","signature":"c2ln"}}`
	admitPending   = `{"state":"pending","reason":"effect_in_progress","expires_at":"2099-01-01T00:00:00Z"}`
)

func TestABoundedAdmissionIsPreparedThenExecutedOnceWithoutAPage(t *testing.T) {
	for _, child := range []any{nil, "did:aw:child"} {
		stub := newAdmitStub(t)
		stub.executes = []string{"200:" + admitCommitted}
		receipt, prepared, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(child)))
		if err != nil || receipt.State != "committed" || string(receipt.Result) != `{"signature":"c2ln","signing":"c2lnbmluZw=="}` {
			t.Fatalf("child %v: receipt %+v err %v", child, receipt, err)
		}
		if prepared == nil || prepared.OperationID != admitOperationID || stub.prepares != 1 || stub.execs != 1 || len(stub.bodies[0]) != 0 {
			t.Fatalf("child %v: prepared %+v, %d prepares, %d executes, bodies %q", child, prepared, stub.prepares, stub.execs, stub.bodies)
		}
	}
}

func TestAPreparedAdmissionThatIsNotWhatAwSentIsNeverExecuted(t *testing.T) {
	for _, tamper := range []string{"request-id", "policy-version", "certificate-fields", "no-request-id", "team", "member-key",
		"alias", "scope", "stable-id", "address", "signature", "no-certificate-id", "version"} {
		stub := newAdmitStub(t)
		stub.tamper = tamper
		stub.executes = []string{"200:" + admitCommitted}
		_, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
		if ErrorCode(err) != "operation_mismatch" || stub.execs != 0 {
			t.Errorf("%s: err %v after %d executes", tamper, err, stub.execs)
		}
	}
}

func TestTheCallersCheckOfThePreparedRequestPrecedesExecution(t *testing.T) {
	stub := newAdmitStub(t)
	stub.executes = []string{"200:" + admitCommitted}
	refuse := errors.New("not this team key")
	opts := stub.options(t)
	opts.CheckPrepared = func(_ context.Context, request map[string]any) error {
		if request["artifact"].(map[string]any)["team_did_key"] != "did:key:zteam" {
			t.Fatalf("request %v", request)
		}
		return refuse
	}
	_, _, err := Execute(context.Background(), opts, admitRaw(t, admitBody(nil)))
	if !errors.Is(err, refuse) || stub.execs != 0 {
		t.Fatalf("err %v after %d executes", err, stub.execs)
	}
}

func TestALostExecuteAnswerIsSettledByTheReceiptWithoutExecutingAgain(t *testing.T) {
	stub := newAdmitStub(t)
	stub.executes = []string{"drop"}
	stub.receipts = []string{"200:" + admitCommitted}
	receipt, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if err != nil || receipt.State != "committed" || stub.execs != 1 {
		t.Fatalf("receipt %+v err %v after %d executes", receipt, err, stub.execs)
	}

	stub = newAdmitStub(t)
	stub.executes = []string{"drop"}
	stub.receipts = []string{"200:" + admitPending}
	receipt, _, err = Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if ErrorCode(err) != "receipt_unavailable" || receipt.State != "unknown" || receipt.OperationID != admitOperationID || stub.execs != 1 {
		t.Fatalf("pending: receipt %+v err %v after %d executes", receipt, err, stub.execs)
	}
}

func TestAnAdmissionStillInProgressIsReadUntilItIsFinal(t *testing.T) {
	stub := newAdmitStub(t)
	stub.executes = []string{"200:" + admitPending}
	stub.receipts = []string{"200:" + admitPending, "200:" + admitCommitted}
	receipt, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if err != nil || receipt.State != "committed" || stub.execs != 1 || stub.reads != 2 {
		t.Fatalf("receipt %+v err %v after %d executes, %d reads", receipt, err, stub.execs, stub.reads)
	}
}

func TestAThrottledExecuteIsSentAgainAfterItsHint(t *testing.T) {
	stub := newAdmitStub(t)
	stub.executes = []string{`503:{"detail":"receipt_unavailable"}`, "200:" + admitCommitted}
	receipt, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if err != nil || receipt.State != "committed" || stub.execs != 2 {
		t.Fatalf("receipt %+v err %v after %d executes", receipt, err, stub.execs)
	}
}

func TestAnExecuteRefusalOrRefusedReceiptKeepsItsCode(t *testing.T) {
	for answer, code := range map[string]string{
		`403:{"detail":"live_approval_required"}`:                  "live_approval_required",
		`200:{"state":"refused","code":"admission_limit_reached"}`: "admission_limit_reached",
	} {
		stub := newAdmitStub(t)
		stub.executes = []string{answer}
		_, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
		if ErrorCode(err) != code || stub.execs != 1 {
			t.Errorf("%s: err %v after %d executes", answer, err, stub.execs)
		}
	}
}

func TestALostAdmissionPrepareIsReconciledByItsReceiptAndNotExecuted(t *testing.T) {
	stub := newAdmitStub(t)
	stub.dropPrep = true
	stub.receipts = []string{"200:" + `{"state":"pending","reason":"awaiting_execute","expires_at":"2099-01-01T00:00:00Z"}`}
	receipt, prepared, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if ErrorCode(err) != "prepare_unconfirmed" || receipt.OperationID != admitOperationID || prepared != nil || stub.execs != 0 || stub.prepares != 1 {
		t.Fatalf("receipt %+v prepared %+v err %v after %d prepares, %d executes", receipt, prepared, err, stub.prepares, stub.execs)
	}
}

func TestACommittedReceiptAfterALostPrepareIsNotTakenWithoutItsPreparedRequest(t *testing.T) {
	stub := newAdmitStub(t)
	stub.dropPrep = true
	stub.receipts = []string{"200:" + admitCommitted}
	opts := stub.options(t)
	opts.Forget = func(string) error { t.Fatal("the saved request was forgotten"); return nil }
	receipt, prepared, err := Execute(context.Background(), opts, admitRaw(t, admitBody(nil)))
	if ErrorCode(err) != "prepare_unconfirmed" || prepared != nil || receipt.State == "committed" || stub.execs != 0 {
		t.Fatalf("receipt %+v prepared %+v err %v after %d executes", receipt, prepared, err, stub.execs)
	}
}

func TestAnExecuteIsNeverRetriedPastThePreparedOperationsExpiry(t *testing.T) {
	stub := newAdmitStub(t)
	stub.expiresIn = 500 * time.Millisecond
	stub.executes = []string{`503h1:{"detail":"receipt_unavailable"}`, "200:" + admitCommitted}
	started := time.Now()
	receipt, _, err := Execute(context.Background(), stub.options(t), admitRaw(t, admitBody(nil)))
	if ErrorCode(err) != "receipt_unavailable" || receipt.State != "unknown" || stub.execs != 1 || time.Since(started) > 400*time.Millisecond {
		t.Fatalf("receipt %+v err %v after %d executes in %s", receipt, err, stub.execs, time.Since(started))
	}
}
