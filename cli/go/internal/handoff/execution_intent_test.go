package handoff

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// A stand-in service freezes the explicit consumer fields before time issuance.
func freezeTestArtifactIntent(artifact map[string]any, audience any, route string, issued []string, expiry string) map[string]any {
	template := clonedObject(artifact)
	absent := append([]string{}, issued...)
	if expiry != "" {
		absent = append(absent, expiry)
	}
	for _, path := range absent {
		parent, name, ok := objectPath(template, path)
		if ok {
			delete(parent, name)
		}
	}
	return map[string]any{"v": 1, "type": "aweb.protected-artifact-intent", "template": template,
		"delivery":        map[string]any{"audience": audience, "method": "POST", "path": route},
		"issuance_window": map[string]any{"not_before": "2026-11-13T12:00:00Z", "not_after": "2026-11-14T12:00:00Z"}}
}

func TestIssuedArtifactIsCheckedAgainstItsPinnedIntentAsHistory(t *testing.T) {
	sent := revokeIntent()
	artifact := map[string]any{"v": 1, "type": "aweb.owner-act", "act": sent["operation"],
		"team_id": "h:example.com", "team_key_did": "did:key:zteam", "aud": sent["audience"],
		"subject": sent["subject"], "nonce": "retained-nonce", "issued_at": "2026-11-13T14:00:00Z", "expires_at": "2026-11-13T14:10:00Z"}
	request := clonedObject(sent)
	request["artifact"] = freezeTestArtifactIntent(artifact, sent["audience"], "/.well-known/aweb-owner-act", []string{"/issued_at"}, "/expires_at")
	template, err := IntentTemplate(request)
	if err != nil || template["nonce"] != "retained-nonce" {
		t.Fatalf("template %v: %v", template, err)
	}
	// This operation is historical even if the reader's current clock is years later.
	if err := VerifyIssuedArtifact(request, artifact); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"nonce", "aud", "team_key_did", "issued_at", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			changed := clonedObject(artifact)
			changed[field] = "changed"
			if err := VerifyIssuedArtifact(request, changed); err == nil {
				t.Fatal("substituted issued artifact accepted")
			}
		})
	}
	late := clonedObject(artifact)
	late["issued_at"] = "2026-11-14T12:00:00Z"
	late["expires_at"] = "2026-11-14T12:10:00Z"
	if err := VerifyIssuedArtifact(request, late); err == nil {
		t.Fatal("renewed window accepted")
	}
}

func TestIntentDescriptorCannotInstallFieldsOrKeepPrepareTimeTimestamps(t *testing.T) {
	sent := revokeIntent()
	artifact := map[string]any{"v": 1, "type": "aweb.owner-act", "act": sent["operation"], "team_id": "h:example.com",
		"team_key_did": "did:key:zteam", "aud": sent["audience"], "subject": sent["subject"], "nonce": "retained-nonce"}
	for _, change := range []string{"time", "route", "window", "format", "extra"} {
		t.Run(change, func(t *testing.T) {
			request := clonedObject(sent)
			descriptor := freezeTestArtifactIntent(artifact, sent["audience"], "/.well-known/aweb-owner-act", []string{"/issued_at"}, "/expires_at")
			request["artifact"] = descriptor
			switch change {
			case "time":
				descriptor["template"].(map[string]any)["issued_at"] = "2026-11-13T12:00:00Z"
			case "route":
				descriptor["delivery"].(map[string]any)["path"] = "/other"
			case "window":
				descriptor["issuance_window"].(map[string]any)["not_after"] = "2026-11-15T12:00:00Z"
			case "format":
				delete(request, "approval_format")
			case "extra":
				descriptor["issued_fields"] = []any{"/subject"}
			}
			if _, err := IntentTemplate(request); err == nil {
				t.Fatal("invalid intent accepted")
			}
		})
	}
}

func TestOldSavedBodyNeverPreparesAgainOrSilentlyAcquiresTheNewFormat(t *testing.T) {
	old := revokeIntent()
	delete(old, "approval_format")
	old["operation_id"] = "11111111-1111-4111-8111-111111111111"
	sent := 0
	opts := GovernanceOptions{Notify: io.Discard, Sign: func(context.Context, string, *url.URL, []byte) (*http.Response, error) {
		sent++
		t.Fatal("old saved operation sent a request")
		return nil, nil
	}}
	_, err := Resume(context.Background(), opts, []byte(mustJSON(old)))
	if ErrorCode(err) != "upgrade_aw_required" || sent != 0 {
		t.Fatalf("err=%v sends=%d", err, sent)
	}
}
