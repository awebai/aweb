package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// planSelfRetire decides whether `aw workspace delete` retires the caller.
// Getting this wrong in either direction is a real failure: too permissive and
// the command tries to revoke someone else's certificate; too restrictive and it
// silently goes back to reporting a retirement that leaks the alias.

func TestPlanSelfRetireRefusesAnotherWorkspace(t *testing.T) {
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
		Alias:         "mine",
	}
	plan := planSelfRetire(t.TempDir(), sel, "22222222-2222-4222-8222-222222222222")
	if plan.eligible {
		t.Fatal("self retirement must not be eligible for another workspace")
	}
	if plan.reason != aliasReleaseNotSelf {
		t.Fatalf("reason = %q, want %q", plan.reason, aliasReleaseNotSelf)
	}
}

func TestPlanSelfRetireRefusesNonHostedTeam(t *testing.T) {
	// Self-hosted and BYOT teams have no cloud-held controller to revoke through.
	for _, teamID := range []string{
		"default:acme.com",
		"default:evil-aweb.ai",
		"default:aweb.ai.example.com",
		"",
	} {
		sel := &awconfig.Selection{
			WorkspaceID:   "11111111-1111-4111-8111-111111111111",
			TeamID:        teamID,
			IdentityScope: "local",
			AwebURL:       "https://app.aweb.ai",
		}
		plan := planSelfRetire(t.TempDir(), sel, sel.WorkspaceID)
		if plan.eligible {
			t.Fatalf("team %q must not be treated as hosted", teamID)
		}
		if plan.reason != aliasReleaseNotHosted {
			t.Fatalf("team %q: reason = %q, want %q", teamID, plan.reason, aliasReleaseNotHosted)
		}
	}
}

func TestPlanSelfRetireRefusesGlobalAndUnknownScope(t *testing.T) {
	// Unknown scope must fail closed. Guessing "local" here would attempt to
	// revoke a global identity's certificate, which team-authorized removal owns.
	for _, scope := range []string{"global", "", "persistent", "ephemeral"} {
		sel := &awconfig.Selection{
			WorkspaceID:   "11111111-1111-4111-8111-111111111111",
			TeamID:        "default:acme.aweb.ai",
			IdentityScope: scope,
			AwebURL:       "https://app.aweb.ai",
		}
		plan := planSelfRetire(t.TempDir(), sel, sel.WorkspaceID)
		if plan.eligible {
			t.Fatalf("scope %q must not be eligible for self retirement", scope)
		}
		if plan.reason != aliasReleaseGlobalIdentity {
			t.Fatalf("scope %q: reason = %q, want %q", scope, plan.reason, aliasReleaseGlobalIdentity)
		}
	}
}

func TestPlanSelfRetireRefusesWithoutWorkspaceCredential(t *testing.T) {
	dir := t.TempDir()
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
	}
	plan := planSelfRetire(dir, sel, sel.WorkspaceID)
	if plan.eligible {
		t.Fatal("self retirement must not be eligible without a workspace-bound key")
	}
	if plan.reason != aliasReleaseNoCredential {
		t.Fatalf("reason = %q, want %q", plan.reason, aliasReleaseNoCredential)
	}
}

func TestPlanSelfRetireEligibleForOwnHostedLocalWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeSelfRetireWorkspaceConfig(t, dir, "aw_sk_selfretire", "https://app.aweb.ai")
	sel := &awconfig.Selection{
		WorkspaceID:   "11111111-1111-4111-8111-111111111111",
		TeamID:        "default:acme.aweb.ai",
		IdentityScope: "local",
		AwebURL:       "https://app.aweb.ai",
		Alias:         "oats-worker-1",
	}

	plan := planSelfRetire(dir, sel, sel.WorkspaceID)

	if !plan.eligible {
		t.Fatalf("own hosted local workspace must be eligible; reason = %q", plan.reason)
	}
	if plan.apiKey != "aw_sk_selfretire" {
		t.Fatalf("apiKey = %q, want the workspace-bound key", plan.apiKey)
	}
	if plan.teamID != "default:acme.aweb.ai" {
		t.Fatalf("teamID = %q", plan.teamID)
	}
	if plan.alias != "oats-worker-1" {
		t.Fatalf("alias = %q", plan.alias)
	}
}

func TestSelfRetireAPIPathMatchesRoute(t *testing.T) {
	got := hostedRemovalAPIPath("https://app.aweb.ai", "default:acme.aweb.ai", selfRetireSuffix)
	want := "/api/v1/teams/default%3Aacme.aweb.ai/agents/self-remove"
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	// A base URL already ending in /api must not produce /api/api/...
	got = hostedRemovalAPIPath("https://app.aweb.ai/api", "default:acme.aweb.ai", selfRetireSuffix)
	want = "/v1/teams/default%3Aacme.aweb.ai/agents/self-remove"
	if got != want {
		t.Fatalf("path with /api base = %q, want %q", got, want)
	}
}

func writeSelfRetireWorkspaceConfig(t *testing.T, dir, apiKey, awebURL string) {
	t.Helper()
	awDir := filepath.Join(dir, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := "aweb_url: " + awebURL + "\n" +
		"api_key: " + apiKey + "\n" +
		"memberships:\n" +
		"  - team_id: default:acme.aweb.ai\n" +
		"    alias: oats-worker-1\n" +
		"    workspace_id: 11111111-1111-4111-8111-111111111111\n" +
		"    cert_path: .aw/teams/default_acme.aweb.ai.json\n"
	if err := os.WriteFile(filepath.Join(awDir, "workspace.yaml"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
