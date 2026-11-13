package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
)

func TestTheProtectedProfileIsTheFlagThenTheEnvironmentThenTheIdentityHomeFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AWEB_PROTECTED_PROFILE", "")
	if _, err := protectedProfilePath("", home); err == nil ||
		!strings.Contains(err.Error(), "--protected-profile") ||
		!strings.Contains(err.Error(), "AWEB_PROTECTED_PROFILE") ||
		!strings.Contains(err.Error(), filepath.Join(home, "protected-profile.json")) {
		t.Fatalf("no profile anywhere: %v", err)
	}
	inHome := filepath.Join(home, "protected-profile.json")
	if err := os.WriteFile(inHome, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := protectedProfilePath("", home); err != nil || got != inHome {
		t.Fatalf("identity home default: %q %v", got, err)
	}
	t.Setenv("AWEB_PROTECTED_PROFILE", "/from/env.json")
	if got, err := protectedProfilePath("", home); err != nil || got != "/from/env.json" {
		t.Fatalf("environment: %q %v", got, err)
	}
	if got, err := protectedProfilePath(" /from/flag.json ", home); err != nil || got != "/from/flag.json" {
		t.Fatalf("flag: %q %v", got, err)
	}
}

func savePending(t *testing.T, profile *handoff.Profile, id string, body map[string]any) {
	t.Helper()
	members := map[string]any{"operation_id": id, "redirect_uri": "http://127.0.0.1:41234/callback"}
	for k, v := range body {
		members[k] = v
	}
	raw, _ := json.Marshal(members)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
		OperationID: id, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWithoutAnOperationIDAwResumesTheSavedOperationForTheSameRequest(t *testing.T) {
	_, profile, _ := admitTestSetup(t)
	intent := map[string]any{"operation": "team.agent.admit", "subject": map[string]any{"member_alias": "worker"}}
	other := map[string]any{"operation": "team.agent.admit", "subject": map[string]any{"member_alias": "other"}}

	fresh, resumed, err := protectedOperationID("", profile, intent)
	if err != nil || resumed || validOperationID(fresh) != nil {
		t.Fatalf("nothing saved: %q resumed=%v %v", fresh, resumed, err)
	}
	if again, _, _ := protectedOperationID("", profile, intent); again == fresh {
		t.Fatal("an unsaved request reused an id")
	}

	savePending(t, profile, admitTestOperation, intent)
	savePending(t, profile, "11111111-1111-4111-8111-111111111111", other)
	got, resumed, err := protectedOperationID("", profile, intent)
	if err != nil || !resumed || got != admitTestOperation {
		t.Fatalf("saved request: %q resumed=%v %v", got, resumed, err)
	}

	elsewhere := *profile
	elsewhere.RequestOrigin = "https://other.example"
	if got, resumed, _ := protectedOperationID("", &elsewhere, intent); resumed || got == admitTestOperation {
		t.Fatal("a request saved for another service was resumed")
	}

	if got, resumed, err := protectedOperationID(admitTestOperation, profile, other); err != nil || resumed || got != admitTestOperation {
		t.Fatalf("an explicit id is the caller's: %q %v", got, err)
	}
	if _, _, err := protectedOperationID("NOT-A-UUID", profile, intent); err == nil {
		t.Fatal("an invalid explicit id was accepted")
	}

	savePending(t, profile, "22222222-2222-4222-8222-222222222222", intent)
	if _, _, err := protectedOperationID("", profile, intent); err == nil ||
		!strings.Contains(err.Error(), admitTestOperation) || !strings.Contains(err.Error(), "22222222-2222-4222-8222-222222222222") {
		t.Fatalf("two saved operations for one request must be named, not guessed: %v", err)
	}
}

func TestAnAdmissionSavedBeforeSendingIsFoundAgainFromTheSameInputs(t *testing.T) {
	_, profile, _ := admitTestSetup(t)
	request := admitTestRequest(t)
	binding, err := admissionBinding(profile, request.Team)
	if err != nil {
		t.Fatal(err)
	}
	// The exact bytes aw saves before it sends anything.
	if _, err := operationBytes(profile, request.OperationID, admissionBody(profile, binding, request)); err != nil {
		t.Fatal(err)
	}
	again := request
	again.OperationID = ""
	got, resumed, err := protectedOperationID("", profile, admissionBody(profile, binding, again))
	if err != nil || !resumed || got != request.OperationID {
		t.Fatalf("rerun of the same admission: %q resumed=%v %v", got, resumed, err)
	}
	again.Alias = "someone-else"
	if got, resumed, _ := protectedOperationID("", profile, admissionBody(profile, binding, again)); resumed || got == request.OperationID {
		t.Fatal("a different admission resumed the saved one")
	}
}
