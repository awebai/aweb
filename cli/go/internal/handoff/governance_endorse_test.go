package handoff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

const (
	endorseOperationID = "33333333-3333-4333-8333-333333333333"
	endorseHuman       = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
	endorseStatement   = "Agents it adds count as yours. It gets no other access."
)

// endorseIntent is a root endorsement aw prepares.
func endorseIntent() map[string]any {
	return map[string]any{
		"operation": "identity.root.endorse", "variant": "default", "approval_format": "intent_v1",
		"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "customer-signer",
			"authority": map[string]any{"kind": "human_identity", "id": endorseHuman, "domain": "customer.example"},
			"human":     map[string]any{"id": endorseHuman, "domain": "customer.example"}, "generation": 1},
		"audience": "https://registry.customer.example",
		"subject": map[string]any{"domain": "customer.example", "root_id": "did:aw:root", "root_key": "did:key:zroot",
			"teams": []any{"engineering:customer.example"}, "deployment_label": "lab"},
	}
}

// endorsePolicy is the service's default admission policy, its digest its own.
func endorsePolicy(change func(map[string]any)) map[string]any {
	policy := map[string]any{
		"version": json.Number("3"), "teams": []any{"engineering:customer.example", "zeta:customer.example"},
		"root_selector": map[string]any{"kind": "service_endorsed_root", "service_id": "customer-signer"},
		"subject_kinds": []any{"local_agent"}, "member_role": "member",
		"bounds": map[string]any{"max_active": json.Number("20"), "rate_window_seconds": json.Number("3600"), "max_per_window": json.Number("5")},
	}
	if change != nil {
		change(policy)
	}
	canonical, _ := awid.StrictCanonicalJSON(policy)
	sum := sha256.Sum256(append([]byte("aweb.admission-policy/1\n"), canonical...))
	policy["digest"] = "sha256:" + hex.EncodeToString(sum[:])
	return policy
}

// endorseStub answers prepare with the endorsement frozen as the contract
// says, changed by tamper, and every receipt read with receipt.
type endorseStub struct {
	mu       sync.Mutex
	server   *httptest.Server
	tamper   string
	sent     map[string]any
	receipt  string
	prepares int
}

func newEndorseStub(t *testing.T) *endorseStub {
	s := &endorseStub{receipt: committedReceipt}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/request/protected-operations":
			s.prepares++
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &s.sent)
			_, _ = w.Write([]byte(s.answer()))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(s.receipt))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *endorseStub) answer() string {
	request := map[string]any{}
	for k, v := range s.sent {
		request[k] = v
	}
	subject := s.sent["subject"].(map[string]any)
	request["requester"], request["policy_ref"], request["policy_version"] = subject["root_id"], "aweb.human-assurance/1", 1
	request["registry"] = s.sent["audience"]
	request["expected_head"] = nil
	request["responsibility_statement"] = endorseStatement
	request["admission_policy"] = endorsePolicy(nil)
	artifact := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": subject["root_id"], "domain": subject["domain"],
		"parent": map[string]any{"kind": "identity", "id": endorseHuman}, "kind": "agent",
		"issuer_key": "did:key:zhuman", "issued_at": "2026-11-13T10:00:00Z"}
	switch s.tamper {
	case "head":
		request["expected_head"] = "sha256:" + strings.Repeat("ab", 32)
	case "bad head":
		request["expected_head"] = "abc"
	case "registry":
		request["registry"] = "https://other.example"
	case "statement":
		request["responsibility_statement"] = "Everything this root spawns counts as yours for human responsibility; this grants no resource permissions."
	case "policy without the team":
		request["admission_policy"] = endorsePolicy(func(p map[string]any) { p["teams"] = []any{"zeta:customer.example"} })
	case "policy digest":
		policy := endorsePolicy(nil)
		policy["version"] = json.Number("4")
		request["admission_policy"] = policy
	case "extra member":
		request["parent"] = map[string]any{}
	case "artifact id":
		artifact["id"] = "did:aw:other"
	case "artifact domain":
		artifact["domain"] = "other.example"
	case "artifact parent":
		artifact["parent"] = map[string]any{"kind": "identity", "id": "did:aw:other"}
	case "artifact namespace parent":
		artifact["parent"] = map[string]any{"kind": "namespace", "id": "customer.example"}
	case "artifact human":
		artifact["kind"] = "human"
	case "artifact type":
		artifact["type"] = "aweb.owner-act"
	case "artifact extra":
		artifact["root_key"] = "did:key:zroot"
	}
	request["artifact"] = freezeTestArtifactIntent(artifact, s.sent["audience"], "/v1/id-certificates/register", []string{"/issued_at"}, "")
	if s.tamper == "artifact supplied issued_at" {
		request["artifact"].(map[string]any)["template"].(map[string]any)["issued_at"] = "2026-11-13T10:00:00Z"
	}
	payload := map[string]any{"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}, "request": request}
	raw, _ := json.Marshal(map[string]any{"operation_id": s.sent["operation_id"], "handoff_id": "h1",
		"digest": coveredDigestOf(payload), "payload": payload, "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)})
	return string(raw)
}

func (s *endorseStub) options(opened *string) GovernanceOptions {
	return GovernanceOptions{
		Request: s.server.URL + "/request", Human: s.server.URL + "/human",
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			return http.DefaultClient.Do(req)
		},
		Open:         func(u string) error { *opened = u; return nil },
		Notify:       io.Discard,
		PollInterval: 10 * time.Millisecond,
	}
}

func TestAnEndorsementFrozenAsAwAskedShowsItsPage(t *testing.T) {
	for _, tamper := range []string{"", "head"} {
		stub := newEndorseStub(t)
		stub.tamper = tamper
		var opened string
		receipt, err := Approve(context.Background(), stub.options(&opened), endorseOperationID, endorseIntent())
		if err != nil || receipt.State != "committed" || opened == "" {
			t.Fatalf("%q: receipt %+v err %v opened %q", tamper, receipt, err, opened)
		}
	}
}

func TestAnEndorsementThatIsNotWhatAwSentShowsNoPage(t *testing.T) {
	for _, tamper := range []string{"bad head", "registry", "statement", "policy without the team", "policy digest", "extra member",
		"artifact id", "artifact domain", "artifact parent", "artifact namespace parent", "artifact human", "artifact type",
		"artifact extra", "artifact supplied issued_at"} {
		stub := newEndorseStub(t)
		stub.tamper = tamper
		var opened string
		if _, err := Approve(context.Background(), stub.options(&opened), endorseOperationID, endorseIntent()); ErrorCode(err) != "operation_mismatch" || opened != "" {
			t.Errorf("%s: err %v opened %q", tamper, err, opened)
		}
	}
}
