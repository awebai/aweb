package handoff

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// signerStub stands in for the protected service, to observe what aw sends and
// how it treats each receipt; the real service is proven by the journey.
type signerStub struct {
	mu       sync.Mutex
	prepared map[string]any
	receipts []string
	reads    int
	server   *httptest.Server
	wake     bool
	// tamper changes the prepare answer (see the cases below).
	tamper string
	// dropPrepare records the first prepare, then drops the connection
	// unanswered. A repeated operation id must carry the identical body.
	dropPrepare bool
	firstBody   []byte
	posts       atomic.Int32
	expiresIn   time.Duration
	// postThrottle answers the next prepares 503 receipt_unavailable with
	// these Retry-After values, before any effect, in order.
	postThrottle []string
	postBodies   [][]byte
	// auths is each request's own signing mark, in order.
	auths []string
	// blockPrepare holds every unthrottled prepare open until the client
	// gives up on it.
	blockPrepare bool
}

func newSignerStub(t *testing.T, receipts ...string) *signerStub {
	s := &signerStub{receipts: receipts}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		s.auths = append(s.auths, r.Header.Get("X-Test-Auth"))
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations":
			s.posts.Add(1)
			body, _ := io.ReadAll(r.Body)
			s.postBodies = append(s.postBodies, body)
			if len(s.postThrottle) > 0 {
				w.Header().Set("Retry-After", s.postThrottle[0])
				s.postThrottle = s.postThrottle[1:]
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"detail":"receipt_unavailable"}`))
				return
			}
			if s.blockPrepare {
				s.mu.Unlock()
				<-r.Context().Done()
				s.mu.Lock()
				return
			}
			if s.firstBody != nil && !bytes.Equal(body, s.firstBody) {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"operation_conflict"}`))
				return
			}
			first := s.firstBody == nil
			s.firstBody = body
			_ = json.Unmarshal(body, &s.prepared)
			if s.dropPrepare && first {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			_, _ = w.Write([]byte(s.answer()))
			if redirect, ok := s.prepared["redirect_uri"].(string); ok && s.wake {
				go func() {
					time.Sleep(20 * time.Millisecond)
					if resp, err := http.Get(redirect + "?handoff_id=h1"); err == nil {
						resp.Body.Close()
					}
				}()
			}
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/request/protected-operations/"):
			reply := s.receipts[min(s.reads, len(s.receipts)-1)]
			s.reads++
			// "!<status>:<code>[:<Retry-After>]" answers that refusal; "!503" is busy.
			if strings.HasPrefix(reply, "!") {
				status, rest, _ := strings.Cut(reply[1:], ":")
				code, hint, hinted := strings.Cut(rest, ":")
				if hinted {
					w.Header().Set("Retry-After", hint)
				}
				n, _ := strconv.Atoi(status)
				w.WriteHeader(n)
				_, _ = w.Write([]byte(`{"detail":"` + cmp.Or(code, "busy") + `"}`))
				return
			}
			_, _ = w.Write([]byte(reply))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

// answer is the prepare answer for what was sent, changed by s.tamper.
func (s *signerStub) answer() string {
	request := map[string]any{}
	for k, v := range s.prepared {
		request[k] = v
	}
	request["requester"] = "did:aw:requester"
	request["policy_ref"] = "aweb.human-assurance/1"
	request["policy_version"] = 1
	authority, _ := s.prepared["scope"].(map[string]any)["authority"].(map[string]any)
	artifact := map[string]any{"v": 1, "type": "aweb.owner-act", "act": s.prepared["operation"], "team_id": authority["id"],
		"team_key_did": "did:key:zteam", "aud": s.prepared["audience"], "subject": s.prepared["subject"], "nonce": "n",
		"issued_at": "2099-01-01T00:00:00Z", "expires_at": "2099-01-01T00:05:00Z"}
	policy := map[string]any{"ref": "aweb.human-assurance/1", "version": 1}
	switch s.tamper {
	case "act":
		artifact["act"] = "human-role.designate"
	case "team":
		artifact["team_id"] = "other:example.com"
	case "artifact-type":
		artifact["type"] = "aweb.other"
	case "artifact-extra":
		artifact["extra"] = true
	case "artifact-missing-nonce":
		delete(artifact, "nonce")
	case "policy-extra":
		policy["extra"] = true
	}
	request["artifact"] = freezeTestArtifactIntent(artifact, s.prepared["audience"], "/.well-known/aweb-owner-act", []string{"/issued_at"}, "/expires_at")
	switch s.tamper {
	case "intent":
		request["subject"] = map[string]any{"app_id": "other"}
	case "extra":
		request["approver"] = "did:aw:someone"
	case "no-artifact":
		delete(request, "artifact")
	case "no-variant":
		delete(request, "variant")
	case "no-requester":
		delete(request, "requester")
	}
	payload := map[string]any{"policy": policy, "request": request}
	digest := coveredDigestOf(payload)
	switch s.tamper {
	case "digest":
		digest = testDigest
	case "digest-upper":
		digest = strings.ToUpper(digest)
	}
	expiresIn := s.expiresIn
	if expiresIn == 0 {
		expiresIn = time.Minute
	}
	fields := map[string]any{
		"operation_id": s.prepared["operation_id"], "handoff_id": "h1", "digest": digest, "payload": payload,
		"expires_at": time.Now().Add(expiresIn).UTC().Format(time.RFC3339Nano),
	}
	switch s.tamper {
	case "answer-extra":
		fields["url"] = "https://evil.example/page"
	case "answer-missing-handoff":
		delete(fields, "handoff_id")
	}
	raw, _ := json.Marshal(fields)
	answer := string(raw)
	switch s.tamper {
	case "answer-duplicate":
		// encoding/json keeps the last of duplicates: the first is a decoy.
		answer = strings.Replace(answer, `{"digest":`, `{"digest":"`+testDigest+`","digest":`, 1)
	case "request-duplicate":
		answer = strings.Replace(answer, `"request":{`, `"request":{"requester":"did:aw:decoy",`, 1)
	}
	return answer
}

// coveredDigestOf is the digest of payload as its JSON bytes decode, the way
// the service's answer reaches aw.
func coveredDigestOf(payload map[string]any) string {
	raw, _ := json.Marshal(payload)
	decoded, _ := decodeObject(raw)
	digest, _ := CoveredRequestDigest(decoded)
	return digest
}

func (s *signerStub) options(opened *string) GovernanceOptions {
	var signed atomic.Int32
	return GovernanceOptions{
		Request: s.server.URL + "/request", Human: s.server.URL + "/human",
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			// Each request is signed on its own, as the requester signer does.
			req.Header.Set("X-Test-Auth", strconv.Itoa(int(signed.Add(1))))
			return http.DefaultClient.Do(req)
		},
		Open:         func(u string) error { *opened = u; return nil },
		Notify:       io.Discard,
		PollInterval: 10 * time.Millisecond,
	}
}

var (
	pendingReceipt   = `{"state":"pending","reason":"awaiting_human","expires_at":"2099-01-01T00:00:00Z"}`
	committedReceipt = `{"state":"committed","result":{"signing":"c2lnbmluZw==","signature":"c2ln"}}`
	refusedReceipt   = `{"state":"refused","code":"human_refused"}`
	unknownReceipt   = `{"state":"unknown","code":"external_effect_unresolved"}`
)

func revokeIntent() map[string]any {
	return map[string]any{
		"operation": "human-role.revoke", "variant": "default", "approval_format": "intent_v1",
		"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
			"authority": map[string]any{"kind": "team_controller", "id": "h:example.com", "domain": "example.com"}},
		"audience": "https://console.example",
		"subject":  map[string]any{"app_id": "example", "installation_id": "i", "role": "example.owner", "principal": "did:aw:holder"},
	}
}

func TestAPreparedOperationThatIsNotWhatAwSentShowsNoLink(t *testing.T) {
	for tamper, code := range map[string]string{
		"digest": "operation_mismatch", "digest-upper": "operation_mismatch", "intent": "operation_mismatch",
		"extra": "operation_mismatch", "act": "operation_mismatch", "team": "operation_mismatch",
		"artifact-type": "operation_mismatch", "artifact-extra": "operation_mismatch",
		"artifact-missing-nonce": "operation_mismatch", "policy-extra": "operation_mismatch",
		"no-artifact": "operation_mismatch", "no-variant": "operation_mismatch", "no-requester": "operation_mismatch",
		"answer-extra": "handoff_result_invalid", "answer-missing-handoff": "handoff_result_invalid",
		"answer-duplicate": "handoff_result_invalid", "request-duplicate": "handoff_result_invalid",
	} {
		stub := newSignerStub(t, committedReceipt)
		stub.tamper = tamper
		var opened string
		_, err := Approve(context.Background(), stub.options(&opened), "44444444-4444-4444-8444-444444444444", revokeIntent())
		if ErrorCode(err) != code || opened != "" || stub.reads != 0 {
			t.Errorf("%s: err %v opened %q reads %d", tamper, err, opened, stub.reads)
		}
	}
}

func TestASentNullMemberMustBePresentInTheFrozenRequest(t *testing.T) {
	stub := newSignerStub(t, committedReceipt)
	stub.tamper = "no-variant"
	intent := revokeIntent()
	intent["variant"] = nil
	var opened string
	_, err := Approve(context.Background(), stub.options(&opened), "45454545-4545-4545-8545-454545454545", intent)
	if ErrorCode(err) != "operation_mismatch" || opened != "" {
		t.Fatalf("err %v opened %q", err, opened)
	}
}

func TestAnIntentNamingAMemberAwSetsIsRefusedBeforeAnythingIsSent(t *testing.T) {
	for _, reserved := range []string{"operation_id", "redirect_uri"} {
		stub := newSignerStub(t, committedReceipt)
		intent := revokeIntent()
		intent[reserved] = "chosen-by-caller"
		var opened string
		receipt, err := Approve(context.Background(), stub.options(&opened), "55555555-5555-4555-8555-555555555555", intent)
		if ErrorCode(err) != "intent_invalid" || receipt != nil || stub.posts.Load() != 0 || stub.reads != 0 {
			t.Errorf("%s: receipt %+v err %v posts %d", reserved, receipt, err, stub.posts.Load())
		}
	}
}

func TestAMalformedReceiptIsNeverTakenAsAnOutcome(t *testing.T) {
	for _, reply := range []string{
		`{"state":"committed","result":null}`,
		`{"state":"committed"}`,
		`{"state":"committed","result":"c2ln"}`,
		`{"state":"committed","result":{"n":1.5}}`,
		`{"state":"committed","result":{"n":9007199254740992}}`,
		`{"state":"pending","state":"committed","result":{"signing":"c2lnbmluZw==","signature":"c2ln"}}`,
		`{"state":"committed","result":{"signing":"c2lnbmluZw==","signature":"c2ln"},"code":"x"}`,
		`{"state":"refused"}`,
		`{"state":"refused","code":""}`,
		`{"state":"unknown","code":null}`,
		`{"state":"pending","reason":"awaiting_human"}`,
		`{"state":"pending","reason":"awaiting_human","expires_at":"soon"}`,
		`{"state":"done"}`,
		`[]`,
	} {
		stub := newSignerStub(t, reply)
		var opened string
		receipt, err := Approve(context.Background(), stub.options(&opened), "66666666-6666-4666-8666-666666666666", revokeIntent())
		if ErrorCode(err) != "receipt_invalid" || receipt == nil || receipt.State != "unknown" || receipt.OperationID != "66666666-6666-4666-8666-666666666666" {
			t.Errorf("%s: receipt %+v err %v", reply, receipt, err)
		}
	}
}

func TestALostPrepareAnswerIsReconciledByItsReceiptWithoutPreparingAgain(t *testing.T) {
	const id = "77777777-7777-4777-8777-777777777777"
	for receipts, code := range map[string]string{pendingReceipt: "prepare_unconfirmed", "!503": "receipt_unavailable"} {
		stub := newSignerStub(t, receipts)
		stub.dropPrepare = true
		var opened string
		var notes bytes.Buffer
		opts := stub.options(&opened)
		opts.Notify = &notes
		receipt, err := Approve(context.Background(), opts, id, revokeIntent())
		if ErrorCode(err) != code || receipt == nil || receipt.OperationID != id {
			t.Errorf("%s: receipt %+v err %v", receipts, receipt, err)
			continue
		}
		if code == "receipt_unavailable" && receipt.State != "unknown" {
			t.Errorf("an unreadable receipt is %q, not unknown", receipt.State)
		}
		if stub.posts.Load() != 1 || stub.reads != 1 || opened != "" {
			t.Errorf("%s: posts %d reads %d opened %q", receipts, stub.posts.Load(), stub.reads, opened)
		}
		if !strings.Contains(notes.String(), id) {
			t.Errorf("the operation id was not reported: %q", notes.String())
		}
	}
}

func TestALostPrepareIsResumedWithItsSavedBodyAndTheServiceAnswersTheOriginal(t *testing.T) {
	const id = "12121212-1212-4212-8212-121212121212"
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	stub.dropPrepare = true
	var opened string
	var saved []byte
	opts := stub.options(&opened)
	opts.Save = func(operationID string, body []byte) error {
		if operationID != id || stub.posts.Load() != 0 {
			t.Errorf("saved %s after %d posts", operationID, stub.posts.Load())
		}
		saved = append([]byte{}, body...)
		return nil
	}
	receipt, err := Approve(context.Background(), opts, id, revokeIntent())
	if ErrorCode(err) != "prepare_unconfirmed" || receipt.OperationID != id || saved == nil || opened != "" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
	opts.Save = nil
	receipt, err = Resume(context.Background(), opts, saved)
	if err != nil || receipt.State != "committed" || receipt.OperationID != id {
		t.Fatalf("resumed %+v err %v", receipt, err)
	}
	if stub.posts.Load() != 2 || opened != stub.server.URL+"/human/handoff/h1" {
		t.Fatalf("posts %d opened %q", stub.posts.Load(), opened)
	}

	// A fresh approval under the same id is a new body: the service refuses it.
	_, err = Approve(context.Background(), opts, id, revokeIntent())
	if ErrorCode(err) != "operation_conflict" {
		t.Fatalf("a second approval under the same id: %v", err)
	}
}

func TestResumeSendsTheSavedBytesUnchanged(t *testing.T) {
	stub := newSignerStub(t, committedReceipt)
	var opened string
	intent := revokeIntent()
	intent["operation_id"] = "14141414-1414-4414-8414-141414141414"
	intent["redirect_uri"] = "http://127.0.0.1:1/callback"
	// Key order and spacing no Go encoder writes: only the saved bytes match.
	saved := []byte(" {\"subject\": " + mustJSON(intent["subject"]) + ",\"operation\":\"human-role.revoke\",\"variant\":\"default\",\"approval_format\":\"intent_v1\"," +
		"\"scope\":" + mustJSON(intent["scope"]) + ",\"audience\":\"https://console.example\"," +
		"\"operation_id\":\"14141414-1414-4414-8414-141414141414\",\"redirect_uri\":\"http://127.0.0.1:1/callback\"}")
	if _, err := Resume(context.Background(), stub.options(&opened), saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stub.firstBody, saved) {
		t.Fatalf("sent %s, not the saved bytes", stub.firstBody)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestAPermanentReceiptRefusalEndsTheWaitWithItsCode(t *testing.T) {
	for reply, code := range map[string]string{
		"!401:requester_invalid": "requester_invalid", "!403:scope_refused": "scope_refused",
		"!404:operation_not_found": "operation_not_found",
	} {
		stub := newSignerStub(t, reply)
		var opened string
		receipt, err := Approve(context.Background(), stub.options(&opened), "15151515-1515-4515-8515-151515151515", revokeIntent())
		if ErrorCode(err) != code || receipt == nil || receipt.State != "unknown" || receipt.Code != code || stub.reads != 1 {
			t.Errorf("%s: receipt %+v err %v reads %d", reply, receipt, err, stub.reads)
		}
	}
	stub := newSignerStub(t, "!429:rate_limited", committedReceipt)
	var opened string
	if receipt, err := Approve(context.Background(), stub.options(&opened), "16161616-1616-4616-8616-161616161616", revokeIntent()); err != nil || receipt.State != "committed" {
		t.Fatalf("a rate-limited read is read again: %+v %v", receipt, err)
	}
}

func TestAnApprovalWhoseBodyCannotBeSavedSendsNothing(t *testing.T) {
	stub := newSignerStub(t, committedReceipt)
	var opened string
	opts := stub.options(&opened)
	opts.Save = func(string, []byte) error { return errors.New("disk full") }
	if _, err := Approve(context.Background(), opts, "13131313-1313-4313-8313-131313131313", revokeIntent()); err == nil || stub.posts.Load() != 0 {
		t.Fatalf("err %v posts %d", err, stub.posts.Load())
	}
}

func TestOnlyAFinalReceiptForgetsTheSavedOperation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		receipts []string
		drop     bool
		forgets  bool
	}{
		{"committed", []string{committedReceipt}, false, true},
		{"refused", []string{refusedReceipt}, false, true},
		{"unknown", []string{unknownReceipt}, false, false},
		{"unreadable until expiry", []string{"!503"}, false, false},
		{"lost answer, pending", []string{pendingReceipt}, true, false},
		{"lost answer, committed", []string{committedReceipt}, true, true},
	} {
		stub := newSignerStub(t, tc.receipts...)
		stub.dropPrepare = tc.drop
		stub.expiresIn = 300 * time.Millisecond
		var opened string
		var forgotten []string
		opts := stub.options(&opened)
		opts.Save = func(string, []byte) error { return nil }
		opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
		_, _ = Approve(context.Background(), opts, "17171717-1717-4717-8717-171717171717", revokeIntent())
		if tc.forgets != (len(forgotten) == 1 && forgotten[0] == "17171717-1717-4717-8717-171717171717") || len(forgotten) > 1 {
			t.Errorf("%s: forgotten %v", tc.name, forgotten)
		}
	}
}

func TestAnUnreadableReceiptIsReadAgainUntilTheOperationExpires(t *testing.T) {
	stub := newSignerStub(t, "!503", committedReceipt)
	var opened string
	receipt, err := Approve(context.Background(), stub.options(&opened), "88888888-8888-4888-8888-888888888888", revokeIntent())
	if err != nil || receipt.State != "committed" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}

	stub = newSignerStub(t, "!503")
	stub.expiresIn = 300 * time.Millisecond
	receipt, err = Approve(context.Background(), stub.options(&opened), "99999999-9999-4999-8999-999999999999", revokeIntent())
	if ErrorCode(err) != "receipt_unavailable" || receipt == nil || receipt.State != "unknown" || receipt.OperationID != "99999999-9999-4999-8999-999999999999" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
	if stub.posts.Load() != 1 {
		t.Fatalf("posts %d", stub.posts.Load())
	}
}

func TestAnApprovalPreparesWithItsOwnIDAndOpensThePinnedPage(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	var opened string
	receipt, err := Approve(context.Background(), stub.options(&opened), "11111111-1111-4111-8111-111111111111", revokeIntent())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != "committed" || !strings.Contains(string(receipt.Result), "signing") {
		t.Fatalf("receipt %+v", receipt)
	}
	if stub.prepared["operation_id"] != "11111111-1111-4111-8111-111111111111" || stub.prepared["operation"] != "human-role.revoke" {
		t.Fatalf("prepared %v", stub.prepared)
	}
	if opened != stub.server.URL+"/human/handoff/h1" {
		t.Fatalf("opened %q, not the pinned page", opened)
	}
}

func TestAnApprovalWhosePreparedRequestTheCallerRefusesShowsNoLink(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	var opened string
	var notified bytes.Buffer
	opts := stub.options(&opened)
	opts.Notify = &notified
	refuse := errors.New("the frozen policy is not the policy read")
	opts.CheckPrepared = func(_ context.Context, request map[string]any) error {
		if request["operation_id"] != "11111111-1111-4111-8111-111111111111" {
			t.Fatalf("request %v", request)
		}
		return refuse
	}
	_, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if !errors.Is(err, refuse) || opened != "" || strings.Contains(notified.String(), "/handoff/") || stub.reads != 0 {
		t.Fatalf("err %v, opened %q, notified %q, %d receipt reads", err, opened, notified.String(), stub.reads)
	}
}

func TestTheCallersCheckRunsUnderTheCallersContextUntilTheOperationExpires(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	stub.expiresIn = 300 * time.Millisecond
	var opened string
	opts := stub.options(&opened)
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "caller")
	var deadline time.Time
	opts.CheckPrepared = func(checkCtx context.Context, _ map[string]any) error {
		if checkCtx.Value(key{}) != "caller" {
			t.Fatal("the check does not run under the caller's context")
		}
		deadline, _ = checkCtx.Deadline()
		select { // a policy read that never answers
		case <-checkCtx.Done():
			return checkCtx.Err()
		case <-time.After(2 * time.Second):
			return errors.New("the check was never bounded by the operation's expiry")
		}
	}
	started := time.Now()
	_, err := Approve(ctx, opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if !errors.Is(err, context.DeadlineExceeded) || opened != "" || deadline.IsZero() || deadline.After(started.Add(time.Second)) || stub.reads != 0 {
		t.Fatalf("err %v, opened %q, deadline %v, %d reads", err, opened, deadline, stub.reads)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	opts = newSignerStub(t, pendingReceipt, committedReceipt).options(&opened)
	opts.CheckPrepared = func(checkCtx context.Context, _ map[string]any) error {
		cancel()
		<-checkCtx.Done()
		return checkCtx.Err()
	}
	if _, err := Approve(cancelled, opts, "11111111-1111-4111-8111-111111111111", revokeIntent()); !errors.Is(err, context.Canceled) || opened != "" {
		t.Fatalf("cancelled: err %v opened %q", err, opened)
	}
}

func TestACallerCancelledDuringASuccessfulCheckIsShownNoPage(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	var opened string
	var notified bytes.Buffer
	opts := stub.options(&opened)
	opts.Notify = &notified
	ctx, cancel := context.WithCancel(context.Background())
	opts.CheckPrepared = func(context.Context, map[string]any) error {
		cancel() // the caller gives up while the check succeeds
		return nil
	}
	_, err := Approve(ctx, opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	if !errors.Is(err, context.Canceled) || opened != "" || strings.Contains(notified.String(), "/handoff/") || stub.reads != 0 {
		t.Fatalf("err %v, opened %q, notified %q, %d reads", err, opened, notified.String(), stub.reads)
	}
}

func TestAnOperationThatExpiresDuringTheCallersCheckShowsNoPage(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	stub.expiresIn = 200 * time.Millisecond
	var opened string
	opts := stub.options(&opened)
	opts.CheckPrepared = func(context.Context, map[string]any) error {
		time.Sleep(300 * time.Millisecond) // a check that ignores its context and answers late
		return nil
	}
	if _, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent()); ErrorCode(err) != "operation_expired" || opened != "" {
		t.Fatalf("err %v opened %q", err, opened)
	}
}

func TestAWakeIsOnlyAHintTheReceiptDecides(t *testing.T) {
	stub := newSignerStub(t, refusedReceipt)
	stub.wake = true
	var opened string
	receipt, err := Approve(context.Background(), stub.options(&opened), "22222222-2222-4222-8222-222222222222", revokeIntent())
	if ErrorCode(err) != "human_refused" || receipt == nil || receipt.State != "refused" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
	if _, ok := stub.prepared["redirect_uri"]; !ok {
		t.Fatal("no wake loopback registered")
	}
}

func TestAnUnknownOutcomeIsReportedWithItsOperationID(t *testing.T) {
	stub := newSignerStub(t, unknownReceipt)
	var opened string
	receipt, err := Approve(context.Background(), stub.options(&opened), "33333333-3333-4333-8333-333333333333", revokeIntent())
	if ErrorCode(err) != "external_effect_unresolved" || receipt.OperationID != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("receipt %+v err %v", receipt, err)
	}
}

func TestTheFingerprintIsTheDigestsFirstSixteenHexInFours(t *testing.T) {
	if got := Fingerprint(testDigest); got != "0123 4567 89ab cdef" {
		t.Fatalf("fingerprint %q", got)
	}
}

// The prepare response distinguishes an unavailable operation from an origin
// without a protected route. It never invents this code for a detail-less 404.
func TestAnUnservedPrepareKeepsItsCodeAndExplainsTheServiceUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		code    string
		upgrade bool
	}{
		{"operation", 400, `{"detail":"operation_not_served"}`, "operation_not_served", true},
		{"wrong-origin", 404, "not found", "handoff_http_404", false},
		{"scope-denial", 403, `{"detail":"scope_refused"}`, "scope_refused", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/protected-operations" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			saved := 0
			opts := GovernanceOptions{Request: server.URL, Human: "https://human.example", NoWait: true, Notify: io.Discard,
				Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
					req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
					if err != nil {
						return nil, err
					}
					return http.DefaultClient.Do(req)
				},
				Open:   func(string) error { t.Error("unserved operation opened an approval page"); return nil },
				Save:   func(string, []byte) error { saved++; return nil },
				Forget: func(string) error { t.Error("unserved operation forgot its saved request"); return nil },
			}
			receipt, err := Approve(context.Background(), opts, "44444444-4444-4444-8444-444444444444", revokeIntent())
			if receipt != nil || ErrorCode(err) != tc.code || calls.Load() != 1 || saved != 1 {
				t.Fatalf("receipt=%#v error=%v requests=%d saved=%d", receipt, err, calls.Load(), saved)
			}
			if strings.Contains(err.Error(), "upgrade the service") != tc.upgrade {
				t.Fatalf("wrong user guidance: %v", err)
			}
		})
	}
}

func TestAnUndefinedOperationCannotBorrowTheOwnerActPreparedShape(t *testing.T) {
	stub := newSignerStub(t, `{"state":"committed","result":{"signing":"x","signature":"y"}}`)
	intent := revokeIntent()
	intent["operation"] = "operation.without.a.pinned.definition"
	var opened string
	_, err := Approve(context.Background(), stub.options(&opened), "11111111-1111-4111-8111-111111111111", intent)
	if ErrorCode(err) != "operation_mismatch" || opened != "" {
		t.Fatalf("undefined prepared operation accepted: opened=%q err=%v", opened, err)
	}
}

// The terminal leads with what happens, keeps the fingerprint in sight and the
// full digest in --json (Juan 2026-11-13, via coordinator). It never claims a
// notice was mailed: the prepare answer carries no evidence of that, and a
// service that does not mail still needs the approver to have a page to open.
// The page is the public handoff locator, not the approver's personal link.
func TestAnApprovalNamesThePageAndOnlyTheFingerprint(t *testing.T) {
	stub := newSignerStub(t, pendingReceipt, committedReceipt)
	var opened string
	var notified bytes.Buffer
	opts := stub.options(&opened)
	opts.Notify = &notified
	var presented *Prepared
	opts.OnPresented = func(prepared *Prepared, _ string) { presented = prepared }
	if _, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent()); err != nil {
		t.Fatal(err)
	}
	text := notified.String()
	for _, want := range []string{"expires at", "details: operation 11111111-1111-4111-8111-111111111111",
		"fingerprint " + Fingerprint(presented.Digest), stub.server.URL + "/human/handoff/h1"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q lacks %q", text, want)
		}
	}
	for _, unwanted := range []string{presented.Digest, "emailed"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("%q shows %q", text, unwanted)
		}
	}
}

// expiredApproval reruns a saved approval whose operation has already
// expired, recording what it forgets and opens.
func expiredApproval(t *testing.T, receipt string) (*Receipt, error, string, []string, *signerStub) {
	t.Helper()
	stub := newSignerStub(t, receipt)
	stub.expiresIn = -time.Minute
	var opened string
	var forgotten []string
	opts := stub.options(&opened)
	opts.Forget = func(id string) error { forgotten = append(forgotten, id); return nil }
	got, err := Approve(context.Background(), opts, "11111111-1111-4111-8111-111111111111", revokeIntent())
	return got, err, opened, forgotten, stub
}

func TestAnExpiredApprovalWhoseResultCommittedIsTakenWithoutAPage(t *testing.T) {
	receipt, err, opened, forgotten, stub := expiredApproval(t, committedReceipt)
	if err != nil || receipt.State != "committed" || opened != "" || stub.reads != 1 {
		t.Fatalf("%+v %v, opened %q, %d reads", receipt, err, opened, stub.reads)
	}
	if len(forgotten) != 1 {
		t.Fatalf("forgotten %v", forgotten)
	}
}

func TestAnExpiredUndecidedApprovalIsSettledAndForgotten(t *testing.T) {
	receipt, err, opened, forgotten, _ := expiredApproval(t, `{"state":"refused","code":"operation_expired"}`)
	if ErrorCode(err) != "operation_expired" || receipt == nil || receipt.State != "refused" || opened != "" || len(forgotten) != 1 {
		t.Fatalf("%+v %v, opened %q, forgotten %v", receipt, err, opened, forgotten)
	}
}

// The service's own receipt, not this machine's clock, says the operation is
// still open: it is not settled, and its id is kept for the next run.
func TestAnApprovalTheServiceStillHoldsPendingIsKept(t *testing.T) {
	_, err, _, forgotten, _ := expiredApproval(t, pendingReceipt)
	if err == nil || len(forgotten) != 0 {
		t.Fatalf("%v, forgotten %v", err, forgotten)
	}
}
