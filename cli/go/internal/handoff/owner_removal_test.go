package handoff

import (
	"net/http"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestOwnerRemovalVerifierClosesClassificationAndRetainsExactRevoke(t *testing.T) {
	sent := map[string]any{"audience": "https://registry.example", "subject": map[string]any{
		"team_id": "engineering:customer.example", "certificate_id": "d511db2c-430c-41ab-a823-87fe43070cf3"}}
	body := []byte(`{"certificate_id":"d511db2c-430c-41ab-a823-87fe43070cf3"}`)
	raw, err := awid.ControllerRequestPayload("https://registry.example", http.MethodPost,
		"/v1/namespaces/customer.example/teams/engineering/certificates/revoke", body,
		"2026-11-13T12:00:00Z", "customer.example", "revoke_certificate",
		map[string]any{"team_name": "engineering", "certificate_id": "d511db2c-430c-41ab-a823-87fe43070cf3"})
	if err != nil {
		t.Fatal(err)
	}
	request, ok := decodeObject(raw)
	if !ok {
		t.Fatal("request is not an object")
	}
	artifact := map[string]any{"controller_did": "pinned by caller", "request": request}
	frozen := map[string]any{"requester_key": "authenticated requester", "target_kind": "agent"}
	for _, kind := range []string{"agent", "kind not verified"} {
		frozen["target_kind"] = kind
		if why := ownerRemovalArtifactDiffers(sent, frozen, artifact); why != "" {
			t.Fatal(why)
		}
	}
	for _, kind := range []any{"human", "service", "unknown", nil, true} {
		frozen["target_kind"] = kind
		if why := ownerRemovalArtifactDiffers(sent, frozen, artifact); why == "" {
			t.Fatalf("accepted kind %v", kind)
		}
	}
	frozen["target_kind"] = "agent"
	request["certificate_id"] = "another certificate"
	if why := ownerRemovalArtifactDiffers(sent, frozen, artifact); why == "" {
		t.Fatal("accepted changed certificate")
	}
}
