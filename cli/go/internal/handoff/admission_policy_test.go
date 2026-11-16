package handoff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

const testTeam = "engineering:customer.example"

// testPolicy is a protected team's policy, its digest computed as the
// contract states: SHA-256 over "aweb.admission-policy/1" LF and the canonical
// policy without its digest.
func testPolicy(t *testing.T, change func(map[string]any)) map[string]any {
	t.Helper()
	policy := map[string]any{
		"version":       json.Number("3"),
		"teams":         []any{testTeam, "zeta:customer.example"},
		"root_selector": map[string]any{"kind": "service_endorsed_root", "service_id": "customer-signer"},
		"subject_kinds": []any{"local_agent", "registered_agent"},
		"member_role":   "member",
		"bounds":        map[string]any{"max_active": json.Number("20"), "rate_window_seconds": json.Number("3600"), "max_per_window": json.Number("5")},
	}
	if change != nil {
		change(policy)
	}
	canonical, err := awid.StrictCanonicalJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("aweb.admission-policy/1\n"), canonical...))
	policy["digest"] = "sha256:" + hex.EncodeToString(sum[:])
	return policy
}

// policyAnswer is the service's read of testTeam with policy.
func policyAnswer(t *testing.T, policy any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"service_id": "customer-signer", "team_id": testTeam, "mode": "protected", "policy": policy})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// policyStub answers every policy read with status and body, and records
// what aw sent.
type policyStub struct {
	server              *httptest.Server
	method, path, query string
	body                []byte
	reads               int
}

func newPolicyStub(t *testing.T, status int, answer string, headers ...string) *policyStub {
	t.Helper()
	s := &policyStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.reads++
		s.method, s.path, s.query = r.Method, r.URL.Path, r.URL.RawQuery
		s.body, _ = io.ReadAll(r.Body)
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *policyStub) options() GovernanceOptions {
	return GovernanceOptions{
		Request: s.server.URL + "/request",
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), strings.NewReader(string(body)))
			return http.DefaultClient.Do(req)
		},
	}
}

func TestAPolicyReadAsksForItsTeamAndAnswersTheServicesPolicy(t *testing.T) {
	policy := testPolicy(t, nil)
	stub := newPolicyStub(t, http.StatusOK, policyAnswer(t, policy))
	read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam)
	if err != nil {
		t.Fatal(err)
	}
	if stub.method != http.MethodGet || stub.path != "/request/protected-admission-policies" || stub.query != "team_id=engineering%3Acustomer.example" || len(stub.body) != 0 {
		t.Fatalf("sent %s %s?%s body %q", stub.method, stub.path, stub.query, stub.body)
	}
	if read.ServiceID != "customer-signer" || read.TeamID != testTeam || read.Mode != "protected" || read.Policy == nil {
		t.Fatalf("read %+v", read)
	}
	if read.Policy.Version != 3 || read.Policy.Digest != policy["digest"] || !reflect.DeepEqual(read.Policy.Teams, []string{testTeam, "zeta:customer.example"}) {
		t.Fatalf("policy %+v", read.Policy)
	}
}

func TestAnExplicitlyAbsentPolicyIsAnAnswerNotAnError(t *testing.T) {
	for _, mode := range []string{"protected", "legacy"} {
		stub := newPolicyStub(t, http.StatusOK, `{"service_id":"customer-signer","team_id":"engineering:customer.example","mode":"`+mode+`","policy":null}`)
		read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam)
		if err != nil || read.Mode != mode || read.Policy != nil {
			t.Fatalf("%s: read %+v err %v", mode, read, err)
		}
	}
}

func TestAPolicyAnswerThatIsNotExactlyThisTeamsPolicyIsRefused(t *testing.T) {
	valid := policyAnswer(t, testPolicy(t, nil))
	changed := func(change func(map[string]any)) string { return policyAnswer(t, testPolicy(t, change)) }
	set := func(name string, value any) func(map[string]any) {
		return func(p map[string]any) { p[name] = value }
	}
	member := func(object, name string, value any) func(map[string]any) {
		return func(p map[string]any) {
			inner := map[string]any{}
			for k, v := range p[object].(map[string]any) {
				inner[k] = v
			}
			if value == nil {
				delete(inner, name)
			} else {
				inner[name] = value
			}
			p[object] = inner
		}
	}
	digestOf := testPolicy(t, nil)["digest"].(string)
	for name, answer := range map[string]string{
		"other service":           strings.Replace(valid, `"service_id":"customer-signer"`, `"service_id":"other-signer"`, 1),
		"other team":              strings.Replace(valid, `"team_id":"engineering:customer.example"`, `"team_id":"sales:customer.example"`, 1),
		"unknown mode":            strings.Replace(valid, `"protected"`, `"open"`, 1),
		"unknown member":          strings.Replace(valid, `"mode"`, `"extra":1,"mode"`, 1),
		"duplicate member":        strings.Replace(valid, `"mode":"protected"`, `"mode":"protected","mode":"protected"`, 1),
		"policy text":             policyAnswer(t, "none"),
		"float version":           strings.Replace(valid, `"version":3`, `"version":3.0`, 1),
		"zero version":            changed(set("version", json.Number("0"))),
		"changed after digest":    strings.Replace(valid, `"max_active":20`, `"max_active":21`, 1),
		"digest unprefixed":       strings.Replace(valid, digestOf, strings.TrimPrefix(digestOf, "sha256:"), 1),
		"digest upper":            strings.Replace(valid, digestOf, "sha256:"+strings.ToUpper(strings.TrimPrefix(digestOf, "sha256:")), 1),
		"extra policy member":     changed(set("admin", false)),
		"no teams":                changed(func(p map[string]any) { delete(p, "teams") }),
		"teams without this team": changed(set("teams", []any{"zeta:customer.example"})),
		"teams unsorted":          changed(set("teams", []any{"zeta:customer.example", testTeam})),
		"teams repeated":          changed(set("teams", []any{testTeam, testTeam})),
		"team not canonical":      changed(set("teams", []any{testTeam, "zeta:Customer.example"})),
		"selector other kind":     changed(member("root_selector", "kind", "any_root")),
		"selector other service":  changed(member("root_selector", "service_id", "other-signer")),
		"selector extra":          changed(member("root_selector", "root_id", "did:aw:x")),
		"no subject kinds":        changed(set("subject_kinds", []any{})),
		"unknown subject kind":    changed(set("subject_kinds", []any{"human"})),
		"subject kinds unsorted":  changed(set("subject_kinds", []any{"registered_agent", "local_agent"})),
		"subject kinds repeated":  changed(set("subject_kinds", []any{"local_agent", "local_agent"})),
		"admin role":              changed(set("member_role", "admin")),
		"bound missing":           changed(member("bounds", "max_per_window", nil)),
		"bound zero":              changed(member("bounds", "max_active", json.Number("0"))),
		"bound extra":             changed(member("bounds", "max_total", json.Number("9"))),
		"not an object":           `[]`,
		"empty":                   ``,
	} {
		if answer == valid {
			t.Fatalf("%s: mutation did not apply", name)
		}
		stub := newPolicyStub(t, http.StatusOK, answer)
		if read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam); ErrorCode(err) != "handoff_result_invalid" {
			t.Errorf("%s: read %+v err %v", name, read, err)
		}
	}
}

func TestAPolicyReadThatCannotBeAnsweredIsUnknownNeverAbsent(t *testing.T) {
	for name, stub := range map[string]*policyStub{
		"unavailable": newPolicyStub(t, http.StatusServiceUnavailable, `{"detail":"receipt_unavailable"}`, "Retry-After", "5"),
		"throttled":   newPolicyStub(t, http.StatusTooManyRequests, `{"detail":"receipt_unavailable"}`),
		"bare 502":    newPolicyStub(t, http.StatusBadGateway, ``),
	} {
		read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam)
		if ErrorCode(err) != "receipt_unavailable" || read != nil || stub.reads != 1 {
			t.Errorf("%s: read %+v err %v after %d reads", name, read, err, stub.reads)
		}
	}
	stub := newPolicyStub(t, http.StatusOK, policyAnswer(t, testPolicy(t, nil)))
	stub.server.Close()
	if read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam); ErrorCode(err) != "receipt_unavailable" || read != nil {
		t.Errorf("unreachable: read %+v err %v", read, err)
	}
}

func TestAPolicyReadRefusalKeepsTheServicesCode(t *testing.T) {
	for status, code := range map[int]string{
		http.StatusUnauthorized: "requester_invalid",
		http.StatusForbidden:    "scope_refused",
		http.StatusBadRequest:   "request_invalid",
	} {
		stub := newPolicyStub(t, status, `{"detail":"`+code+`"}`)
		if read, err := ReadAdmissionPolicy(context.Background(), stub.options(), "customer-signer", testTeam); ErrorCode(err) != code || read != nil {
			t.Errorf("%d: read %+v err %v", status, read, err)
		}
	}
}

func TestOnlyAProtectedTeamWithoutAPolicyIsMissingOne(t *testing.T) {
	for _, tc := range []struct {
		read AdmissionPolicyRead
		code string
	}{
		{AdmissionPolicyRead{Mode: "protected"}, "admission_policy_missing"},
		{AdmissionPolicyRead{Mode: "protected", Policy: &AdmissionPolicy{Version: 1}}, ""},
		{AdmissionPolicyRead{Mode: "legacy"}, ""},
	} {
		policy, err := tc.read.RequireAdmissionPolicy()
		if ErrorCode(err) != tc.code || (err == nil && policy != tc.read.Policy) {
			t.Errorf("%+v: policy %+v err %v", tc.read, policy, err)
		}
	}
}

// countedAnswer is the service's read of testTeam with policy and the
// root's own admissions.
func countedAnswer(t *testing.T, policy, admissions any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"service_id": "customer-signer", "team_id": testTeam, "mode": "protected",
		"policy": policy, "admissions": admissions})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestTheRootsCountsAreReadOnlyWhenAskedAndComeWithTheirBounds(t *testing.T) {
	policy := testPolicy(t, nil)
	stub := newPolicyStub(t, 200, countedAnswer(t, policy, map[string]any{
		"active": 20, "in_window": 5, "next_at": "2026-11-13T14:40:00Z"}))
	counts, err := ReadAdmissionCounts(context.Background(), stub.options(), "customer-signer", testTeam)
	if err != nil {
		t.Fatal(err)
	}
	if stub.method != http.MethodGet || stub.query != "team_id=engineering%3Acustomer.example&include=admissions" {
		t.Fatalf("asked %s ?%s", stub.method, stub.query)
	}
	want := AdmissionCounts{Active: 20, MaxActive: 20, InWindow: 5, MaxPerWindow: 5, WindowSeconds: 3600,
		NextAt: time.Date(2026, 11, 13, 14, 40, 0, 0, time.UTC)}
	if counts == nil || *counts != want {
		t.Fatalf("counts %+v", counts)
	}
	// The plain read is unchanged: it never asks for counts.
	plain := newPolicyStub(t, 200, policyAnswer(t, policy))
	if _, err := ReadAdmissionPolicy(context.Background(), plain.options(), "customer-signer", testTeam); err != nil || strings.Contains(plain.query, "include") {
		t.Fatalf("plain read asked %q: %v", plain.query, err)
	}
}

func TestNoCountsIsAnAnswerAndAServerWithoutThemRefuses(t *testing.T) {
	policy := testPolicy(t, nil)
	none := newPolicyStub(t, 200, countedAnswer(t, policy, nil))
	if counts, err := ReadAdmissionCounts(context.Background(), none.options(), "customer-signer", testTeam); err != nil || counts != nil {
		t.Fatalf("a root not yet endorsed: %+v %v", counts, err)
	}
	older := newPolicyStub(t, 400, `{"detail":"request_invalid"}`)
	if _, err := ReadAdmissionCounts(context.Background(), older.options(), "customer-signer", testTeam); ErrorCode(err) != "request_invalid" {
		t.Fatalf("a server that predates counts: %v", err)
	}
	for _, bad := range []any{"5", map[string]any{"active": -1, "in_window": 0, "next_at": nil},
		map[string]any{"active": 1, "in_window": 0}, map[string]any{"active": 1, "in_window": 0, "next_at": "yesterday"}} {
		stub := newPolicyStub(t, 200, countedAnswer(t, policy, bad))
		if _, err := ReadAdmissionCounts(context.Background(), stub.options(), "customer-signer", testTeam); ErrorCode(err) != "handoff_result_invalid" {
			t.Errorf("%v: %v", bad, err)
		}
	}
}
