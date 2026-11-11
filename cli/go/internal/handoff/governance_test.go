package handoff

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// dropPrepare records the prepare, then drops the connection unanswered.
	dropPrepare bool
	posts       atomic.Int32
	expiresIn   time.Duration
}

func newSignerStub(t *testing.T, receipts ...string) *signerStub {
	s := &signerStub{receipts: receipts}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations":
			s.posts.Add(1)
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &s.prepared)
			if s.dropPrepare {
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
			if reply == "!503" {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"detail":"busy"}`))
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
	request["artifact"] = artifact
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
	return GovernanceOptions{
		Request: s.server.URL + "/request", Human: s.server.URL + "/human",
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
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
		"operation": "human-role.revoke", "variant": "default",
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
