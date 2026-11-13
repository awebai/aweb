package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

// policyTestPolicy is a valid policy for engineering:customer.example, its
// digest computed as the contract states.
func policyTestPolicy(t *testing.T) string {
	t.Helper()
	unsigned := `{"bounds":{"max_active":20,"max_per_window":5,"rate_window_seconds":3600},"member_role":"member",` +
		`"root_selector":{"kind":"service_endorsed_root","service_id":"customer-signer"},` +
		`"subject_kinds":["local_agent","registered_agent"],"teams":["engineering:customer.example"],"version":3}`
	sum := sha256.Sum256([]byte("aweb.admission-policy/1\n" + unsigned))
	return strings.Replace(unsigned, `"bounds"`, `"digest":"sha256:`+hex.EncodeToString(sum[:])+`","bounds"`, 1)
}

// policyService answers each policy read with answer and records the signed
// envelope's path.
func policyService(t *testing.T, answer string) (*httptest.Server, *[]string) {
	t.Helper()
	var signedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
		var envelope map[string]any
		_ = json.Unmarshal(raw, &envelope)
		path, _ := envelope["path"].(string)
		signedPaths = append(signedPaths, path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(server.Close)
	return server, &signedPaths
}

func policyRequester(t *testing.T) *localSigningIdentity {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &localSigningIdentity{SigningKey: key, DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), StableID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"}
}

func policyOptions(profile *handoff.Profile, server *httptest.Server, team string, identity *localSigningIdentity) handoff.GovernanceOptions {
	return handoff.GovernanceOptions{
		Request: server.URL,
		Sign:    protectedRequesterSigner(profile, admissionPolicyScope(profile, team), identity),
	}
}

func TestThePolicyReadIsSignedOverItsPathAndQuery(t *testing.T) {
	profile, _ := vectorProfile(t)
	team := "engineering:customer.example"
	server, signed := policyService(t, `{"service_id":"customer-signer","team_id":"engineering:customer.example","mode":"legacy","policy":null}`)
	if _, err := admissionPolicyReport(context.Background(), policyOptions(profile, server, team, policyRequester(t)), profile, team); err != nil {
		t.Fatal(err)
	}
	if len(*signed) != 1 || (*signed)[0] != "/protected-admission-policies?team_id=engineering%3Acustomer.example" {
		t.Fatalf("signed paths %v", *signed)
	}
}

func TestThePolicyReportCarriesTheVersionAndDigestAnAdmissionBinds(t *testing.T) {
	profile, _ := vectorProfile(t)
	team := "engineering:customer.example"
	policy := policyTestPolicy(t)
	server, _ := policyService(t, `{"service_id":"customer-signer","team_id":"engineering:customer.example","mode":"protected","policy":`+policy+`}`)
	report, err := admissionPolicyReport(context.Background(), policyOptions(profile, server, team, policyRequester(t)), profile, team)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(report)
	var canonicalPolicy map[string]any
	_ = json.Unmarshal([]byte(policy), &canonicalPolicy)
	wantPolicy, _ := json.Marshal(canonicalPolicy)
	want := `{"mode":"protected","policy":` + string(wantPolicy) + `,"service_id":"customer-signer","team_id":"engineering:customer.example"}`
	if string(got) != want {
		t.Fatalf("report %s\nwant   %s", got, want)
	}
}

func TestAProtectedTeamWithoutAPolicyIsReportedMissing(t *testing.T) {
	profile, _ := vectorProfile(t)
	team := "engineering:customer.example"
	server, _ := policyService(t, `{"service_id":"customer-signer","team_id":"engineering:customer.example","mode":"protected","policy":null}`)
	if _, err := admissionPolicyReport(context.Background(), policyOptions(profile, server, team, policyRequester(t)), profile, team); handoff.ErrorCode(err) != "admission_policy_missing" {
		t.Fatalf("err %v", err)
	}
}

func TestAPolicyReadForATeamTheProfileDoesNotBindSendsNothing(t *testing.T) {
	profile, _ := vectorProfile(t)
	team := "sales:customer.example"
	server, signed := policyService(t, `{}`)
	if _, err := admissionPolicyReport(context.Background(), policyOptions(profile, server, team, policyRequester(t)), profile, team); handoff.ErrorCode(err) != "profile_scope_refused" {
		t.Fatalf("err %v", err)
	}
	if len(*signed) != 0 {
		t.Fatalf("sent %v", *signed)
	}
}
