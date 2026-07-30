package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// singlePageListingForTest returns the provisioned certificate on one complete
// page, so a test can drive the cleanup past the certificate stage and exercise
// what it reports afterwards.
func singlePageListingForTest() certificateListingFunc {
	return func(w http.ResponseWriter, r *http.Request, certificateID, teamID, memberDIDKey, alias string, revoked bool) {
		revokedAt := ""
		if revoked {
			revokedAt = "2026-07-29T01:00:00Z"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{{
				"certificate_id": certificateID, "team_id": teamID, "member_did_key": memberDIDKey,
				"alias": alias, "identity_scope": "global", "issued_at": "2026-07-29T00:00:00Z",
				"revoked_at": revokedAt,
			}},
			"has_more": false,
		})
	}
}

// The cleanup tuple is read back by the OAS attached-principal retire flow as its
// verification that a principal was fully cleaned - see
// oas/.agents/capabilities/owned/aweb-identity-attach/bin/aweb-identity-attach.mjs,
// parseLocalCleanupOutput. So a field that is printed without being observed is not
// an untidy log line: it is the evidence a retirement is declared complete on.
//
// The fixture's DELETE /v1/workspaces/... handler returns no identity_deleted field,
// which decodes to false. The server therefore reports that the bound identity was
// NOT deleted, and the cleanup must not say otherwise.
func TestCleanupLocalProvisionDoesNotClaimAnIdentityDeletionTheServerDidNotReport(t *testing.T) {
	fixture := setupProvisionedLocalMember(t, singlePageListingForTest())

	output, err := fixture.runCleanup(t)
	if err != nil {
		t.Fatalf("cleanup failed before it could report anything:\n%s", output)
	}
	var reported map[string]any
	if err := json.Unmarshal(output, &reported); err != nil {
		t.Fatalf("cleanup did not emit JSON: %v\n%s", err, output)
	}
	if reported["identity"] == "soft-deleted" {
		t.Fatalf(
			"the server reported identity_deleted=false and the cleanup tuple claims the identity was soft-deleted:\n%s",
			output,
		)
	}
}
