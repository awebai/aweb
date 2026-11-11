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
	// tamper changes the prepare answer: "digest" or "intent" or "extra".
	tamper string
}

func newSignerStub(t *testing.T, receipts ...string) *signerStub {
	s := &signerStub{receipts: receipts}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &s.prepared)
			request := map[string]any{}
			for k, v := range s.prepared {
				request[k] = v
			}
			request["requester"] = "did:aw:requester"
			request["policy_ref"] = "aweb.human-assurance/1"
			request["policy_version"] = 1
			authority, _ := s.prepared["scope"].(map[string]any)["authority"].(map[string]any)
			artifact := map[string]any{"v": 1, "type": "aweb.owner-act", "act": s.prepared["operation"], "team_id": authority["id"], "aud": s.prepared["audience"], "subject": s.prepared["subject"], "nonce": "n"}
			switch s.tamper {
			case "act":
				artifact["act"] = "human-role.designate"
			case "team":
				artifact["team_id"] = "other:example.com"
			}
			request["artifact"] = artifact
			switch s.tamper {
			case "intent":
				request["subject"] = map[string]any{"app_id": "other"}
			case "extra":
				request["approver"] = "did:aw:someone"
			}
			payload := map[string]any{"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}, "request": request}
			digest, _ := CoveredRequestDigest(payload)
			if s.tamper == "digest" {
				digest = testDigest
			}
			answer, _ := json.Marshal(map[string]any{
				"operation_id": s.prepared["operation_id"], "handoff_id": "h1", "digest": digest, "payload": payload,
				"expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339), "url": "https://evil.example/page",
			})
			_, _ = w.Write(answer)
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
			_, _ = w.Write([]byte(reply))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
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
	for _, tamper := range []string{"digest", "intent", "extra", "act", "team"} {
		stub := newSignerStub(t, committedReceipt)
		stub.tamper = tamper
		var opened string
		_, err := Approve(context.Background(), stub.options(&opened), "44444444-4444-4444-8444-444444444444", revokeIntent())
		if ErrorCode(err) != "operation_mismatch" || opened != "" {
			t.Errorf("%s: err %v opened %q", tamper, err, opened)
		}
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
