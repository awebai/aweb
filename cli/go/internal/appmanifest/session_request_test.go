package appmanifest

import (
	"encoding/json"
	"testing"
)

func secretsActions(t *testing.T) map[string]SessionAction {
	t.Helper()
	raw, _ := json.Marshal(secretsSessionActions(t))
	resolved, err := Load(ownerActCaseManifest(t, "https://secrets.example.com", raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]SessionAction{}
	for _, a := range resolved.OwnerActs.SessionActions {
		byName[a.Name] = a
	}
	return byName
}

func TestAReadIsAGetWithItsPathFilled(t *testing.T) {
	r, err := secretsActions(t)["change-set"].Request(map[string]any{"installation_id": "i-1", "change_id": "c-2"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "GET" || r.PathQuery != "/installations/i-1/change-sets/c-2" || r.Body != nil {
		t.Fatalf("request %+v", r)
	}
}

// Version 2 refuses a path value that is not one safe segment, and a session
// action keeps that rule.
func TestAPathValueThatIsNotOneSegmentIsRefused(t *testing.T) {
	if _, err := secretsActions(t)["change-set"].Request(map[string]any{"installation_id": "i-1", "change_id": "c/2"}); err == nil {
		t.Fatal("built a request with a multi-segment path value")
	}
}

func TestAJSONPostWithNoBodyMemberSendsAnEmptyObject(t *testing.T) {
	r, err := secretsActions(t)["confirm"].Request(map[string]any{"installation_id": "i-1", "change_id": "c-2"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.PathQuery != "/installations/i-1/change-sets/c-2/confirm" || string(r.Body) != "{}" {
		t.Fatalf("request %+v body %q", r, r.Body)
	}
}

func TestAStageCarriesItsBodyMembers(t *testing.T) {
	r, err := secretsActions(t)["onepassword-token"].Request(map[string]any{"installation_id": "i-1", "value": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if r.PathQuery != "/installations/i-1/backend-credentials/onepassword/versions" || string(r.Body) != `{"value":"v"}` {
		t.Fatalf("request %+v body %q", r, r.Body)
	}
}

func TestAMissingPathParamIsRefused(t *testing.T) {
	if _, err := secretsActions(t)["change-set"].Request(map[string]any{"installation_id": "i-1"}); err == nil {
		t.Fatal("built a request with no change_id")
	}
}
