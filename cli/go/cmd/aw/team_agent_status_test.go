package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
)

// agentStores stands in for the two stores the status command reads. Everything
// is served over real HTTP so the readings come from decoding real responses.
type agentStores struct {
	t *testing.T

	alias       string
	workspaceID string

	teamReadable      bool
	certificateActive bool
	workspacePresent  bool
	claimRefs         []string
	claimsTruncated   bool

	registry     *httptest.Server
	coordination *httptest.Server
}

func newAgentStores(t *testing.T) *agentStores {
	t.Helper()
	s := &agentStores{
		t:            t,
		alias:        "retiree",
		workspaceID:  "11111111-2222-3333-4444-555555555555",
		teamReadable: true,
	}

	s.registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/teams/backend":
			if !s.teamReadable {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Team not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "domain": "acme.com", "name": "backend"})
		case "/v1/namespaces/acme.com/teams/backend/members/" + s.alias:
			if !s.certificateActive {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Team member not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "certificate_id": "cert-retiree",
				"member_did_key": "did:key:z6MkRetiree", "member_address": "acme.com/" + s.alias,
				"alias": s.alias, "identity_scope": "local", "issued_at": "2026-07-29T00:00:00Z",
			})
		default:
			s.t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(s.registry.Close)

	s.coordination = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces":
			if !s.workspacePresent {
				_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []any{}, "has_more": false})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{{
				"workspace_id": s.workspaceID, "alias": s.alias,
			}}, "has_more": false})
		case "/v1/claims":
			claims := make([]map[string]any, 0, len(s.claimRefs))
			for _, ref := range s.claimRefs {
				claims = append(claims, map[string]any{
					"task_ref": ref, "workspace_id": s.workspaceID, "alias": s.alias,
					"claimed_at": "2026-07-29T00:00:00Z", "team_id": "backend:acme.com",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"claims": claims, "has_more": s.claimsTruncated})
		default:
			s.t.Fatalf("unexpected coordination request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(s.coordination.Close)

	return s
}

func (s *agentStores) read(t *testing.T) teamAgentStatusOutput {
	t.Helper()
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = s.registry.URL

	client, err := aweb.New(s.coordination.URL)
	if err != nil {
		t.Fatalf("aweb.New: %v", err)
	}

	out := teamAgentStatusOutput{TeamID: "backend:acme.com", Alias: s.alias}
	readAgentCertificateState(context.Background(), &out, "acme.com", "backend")
	readAgentCoordinationState(context.Background(), client, &out, s.alias)
	out.NameReusable = out.Certificate == agentCertificateNone && out.Workspace == agentWorkspaceAbsent
	return out
}

// This is the read that criterion 1 rests on: after a retirement, an independent
// command must show no active certificate, no claims, and the name free.
func TestAgentStatusShowsARetiredAgentAcrossBothStores(t *testing.T) {
	stores := newAgentStores(t)
	stores.certificateActive = false
	stores.workspacePresent = false

	out := stores.read(t)

	if out.Certificate != agentCertificateNone {
		t.Fatalf("certificate=%q, want %q", out.Certificate, agentCertificateNone)
	}
	if out.Workspace != agentWorkspaceAbsent {
		t.Fatalf("workspace=%q, want %q", out.Workspace, agentWorkspaceAbsent)
	}
	if out.ClaimsHeld != 0 {
		t.Fatalf("claims_held=%d, want 0", out.ClaimsHeld)
	}
	if !out.NameReusable {
		t.Fatalf("name_reusable=false; a fully retired name must be free")
	}
	if len(out.Unreadable) != 0 {
		t.Fatalf("unreadable=%v, want none", out.Unreadable)
	}
}

// An agent still holding claims must not read as retired, and the claims it
// holds have to be visible - a count alone was what let 36 board tasks sit under
// agents that no longer existed.
func TestAgentStatusShowsHeldClaimsForAnAgentStillPresent(t *testing.T) {
	stores := newAgentStores(t)
	stores.certificateActive = true
	stores.workspacePresent = true
	stores.claimRefs = []string{"backend-11", "backend-12"}

	out := stores.read(t)

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q", out.Certificate, agentCertificateActive)
	}
	if out.Workspace != agentWorkspacePresent {
		t.Fatalf("workspace=%q, want %q", out.Workspace, agentWorkspacePresent)
	}
	if out.ClaimsHeld != 2 {
		t.Fatalf("claims_held=%d, want 2", out.ClaimsHeld)
	}
	if strings.Join(out.ClaimedTasks, ",") != "backend-11,backend-12" {
		t.Fatalf("claimed_tasks=%v, want the refs themselves", out.ClaimedTasks)
	}
	if out.NameReusable {
		t.Fatalf("name_reusable=true while the agent still holds a certificate and a workspace")
	}
}

// A member lookup that 404s means nothing on its own: an unreachable or
// misaddressed registry answers identically. Without corroboration the reading
// is unknown, never "no active certificate".
func TestAgentStatusReportsUnknownRatherThanAbsentWhenTheRegistryCannotBeRead(t *testing.T) {
	stores := newAgentStores(t)
	stores.teamReadable = false
	stores.certificateActive = false
	stores.workspacePresent = false

	out := stores.read(t)

	if out.Certificate != agentCertificateUnknown {
		t.Fatalf("certificate=%q, want %q; an unreadable registry must not read as an absent member", out.Certificate, agentCertificateUnknown)
	}
	if out.NameReusable {
		t.Fatalf("name_reusable=true on an unreadable certificate store")
	}
	if len(out.Unreadable) == 0 {
		t.Fatalf("an unreadable store must say so")
	}
	if !strings.Contains(strings.Join(out.Unreadable, " "), "unreachable registry") {
		t.Fatalf("unreadable=%v, want it to name the ambiguity", out.Unreadable)
	}
}

// A truncated claim listing understates what is held, which is the failure this
// command exists to prevent, so it must be reported rather than presented as a
// complete count.
func TestAgentStatusSaysWhenTheClaimListingWasTruncated(t *testing.T) {
	stores := newAgentStores(t)
	stores.certificateActive = true
	stores.workspacePresent = true
	stores.claimRefs = []string{"backend-11"}
	stores.claimsTruncated = true

	out := stores.read(t)

	if out.ClaimsComplete {
		t.Fatalf("claims_complete=true on a truncated listing")
	}
	if !strings.Contains(formatTeamAgentStatus(out), "truncated") {
		t.Fatalf("human output does not disclose the truncation:\n%s", formatTeamAgentStatus(out))
	}
}
