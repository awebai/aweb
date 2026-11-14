package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
)

func vectorProfile(t *testing.T) (*handoff.Profile, string) {
	t.Helper()
	path := "../../../../docs/vectors/protected-service-profile-v1.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := handoff.ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return profile, path
}

func TestTheProtectedScopeIsTheBindingForThisTeamAndTheNamedApprover(t *testing.T) {
	profile, _ := vectorProfile(t)
	binding, err := protectedBinding(profile, "engineering:customer.example", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w")
	if err != nil {
		t.Fatal(err)
	}
	if binding.Scope["service_id"] != "customer-signer" {
		t.Fatalf("binding %+v", binding)
	}
	for name, args := range map[string][2]string{
		"another team":     {"other:customer.example", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"},
		"another approver": {"engineering:customer.example", "did:aw:44aKNQyvo1xh8rv6TfdfzjTn6nRp"},
		"no approver":      {"engineering:customer.example", ""},
	} {
		if _, err := protectedBinding(profile, args[0], args[1]); err == nil {
			t.Errorf("%s: a binding was chosen", name)
		}
	}
}

func TestTheRevokeIntentNamesTheActScopeAudienceAndSubject(t *testing.T) {
	profile, _ := vectorProfile(t)
	binding := profile.Bindings[0]
	subject := map[string]any{"app_id": "customer-app", "installation_id": "22222222-2222-4222-8222-222222222222", "role": "customer.owner", "principal": "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"}
	intent := protectedRoleIntent("human-role.revoke", binding.Scope, "https://app.customer.example", subject)
	if len(intent) != 6 || intent["operation"] != "human-role.revoke" || intent["variant"] != "default" || intent["audience"] != "https://app.customer.example" ||
		intent["approval_format"] != "intent_v1" {
		t.Fatalf("intent %v", intent)
	}
	if _, ok := intent["operation_id"]; ok {
		t.Fatal("the intent names operation_id, which Approve sets")
	}
}

func TestResumeRefusesAProfileWithOtherOriginsThanTheSavedOperation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	profile, _ := vectorProfile(t)
	saved := &awconfig.PendingGovernanceOperation{
		OperationID: "11111111-1111-4111-8111-111111111111", RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin,
		Body: []byte(`{"operation_id":"11111111-1111-4111-8111-111111111111"}`),
	}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	if _, err := pendingOperationFor(profile, saved.OperationID); err != nil {
		t.Fatalf("matching profile refused: %v", err)
	}
	other := *profile
	other.RequestOrigin = "https://elsewhere.example"
	if _, err := pendingOperationFor(&other, saved.OperationID); err == nil || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("a profile with another request origin resumed: %v", err)
	}
	if _, err := pendingOperationFor(profile, "22222222-2222-4222-8222-222222222222"); err == nil {
		t.Fatal("an unknown operation resumed")
	}
}

func TestASavedBodysScopeIsTheScopeItsReceiptIsReadUnder(t *testing.T) {
	profile, _ := vectorProfile(t)
	body := `{"operation_id":"11111111-1111-4111-8111-111111111111","scope":{"v":1,"kind":"protected_key","service_id":"customer-signer","authority":{"kind":"team_controller","id":"engineering:customer.example","domain":"customer.example"},"human":{"id":"did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w","domain":"customer.example"},"generation":1}}`
	scope, err := savedScope(profile, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.BindingFor(scope); err != nil {
		t.Fatalf("saved scope is not the configured one: %v", err)
	}
	if _, err := savedScope(profile, []byte(`{"operation_id":"x"}`)); err == nil {
		t.Fatal("a body without a scope was accepted")
	}
}

// twoDomainProfile is the vector profile with the same authority and human
// ID also bound in a second configured human domain, in either row order.
func twoDomainProfile(t *testing.T, secondFirst bool) *handoff.Profile {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/vectors/protected-service-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	namespaces := doc["namespace_authorities"].([]any)
	other := map[string]any{"domain": "other.example", "controller_did": namespaces[0].(map[string]any)["controller_did"]}
	doc["namespace_authorities"] = append(namespaces, other)
	first := doc["bindings"].([]any)[0].(map[string]any)
	encoded, _ := json.Marshal(first)
	var second map[string]any
	_ = json.Unmarshal(encoded, &second)
	second["scope"].(map[string]any)["human"].(map[string]any)["domain"] = "other.example"
	if secondFirst {
		doc["bindings"] = []any{second, first}
	} else {
		doc["bindings"] = []any{first, second}
	}
	data, _ := json.Marshal(doc)
	profile, err := handoff.ParseProfile(data)
	if err != nil {
		t.Fatalf("the two-domain profile is valid: %v", err)
	}
	return profile
}

func TestAnApproverBoundInTwoHumanDomainsIsAmbiguousInEitherOrder(t *testing.T) {
	for _, secondFirst := range []bool{false, true} {
		profile := twoDomainProfile(t, secondFirst)
		if binding, err := protectedBinding(profile, "engineering:customer.example", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"); err == nil {
			t.Errorf("secondFirst=%v: chose %v", secondFirst, binding.Scope["human"])
		}
	}
}

func TestASavedBodyWithADuplicateScopeIsRefused(t *testing.T) {
	profile, _ := vectorProfile(t)
	scope := `{"v":1,"kind":"protected_key","service_id":"customer-signer","authority":{"kind":"team_controller","id":"engineering:customer.example","domain":"customer.example"},"human":{"id":"did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w","domain":"customer.example"},"generation":1}`
	body := `{"scope":{"v":1},"scope":` + scope + `}`
	if _, err := savedScope(profile, []byte(body)); err == nil {
		t.Fatal("a body with two scopes was read as its last")
	}
}
