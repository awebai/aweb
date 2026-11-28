package awconfig

import (
	"testing"

	"github.com/awebai/aw/awid"
)

func TestWorkspaceSelectionDecision(t *testing.T) {
	backend := WorktreeMembership{TeamID: "backend:acme.com", Alias: "alice", WorkspaceID: "ws-backend"}
	ops := WorktreeMembership{TeamID: "ops:acme.com", Alias: "alice-ops", WorkspaceID: "ws-ops"}
	workspace := func(awebURL string) *WorktreeWorkspace {
		return &WorktreeWorkspace{AwebURL: awebURL, Memberships: []WorktreeMembership{backend, ops}}
	}
	active := func(team string) *TeamState { return &TeamState{ActiveTeam: team} }
	for _, tc := range []struct {
		name       string
		facts      workspaceSelectionFacts
		membership string
		baseURL    string
		serverName string
		refusal    string
	}{
		{"active membership and the binding's server", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("backend:acme.com")}, "backend:acme.com", "https://app.aweb.ai", "app.aweb.ai", ""},
		{"active team matches case-insensitively", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active(" OPS:acme.com ")}, "ops:acme.com", "https://app.aweb.ai", "app.aweb.ai", ""},
		{"base URL override wins", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("backend:acme.com"), BaseURLOverride: "http://localhost:8000"}, "backend:acme.com", "http://localhost:8000", "localhost:8000", ""},
		{"base URL override fills a missing binding URL", workspaceSelectionFacts{Workspace: workspace(""), TeamState: active("backend:acme.com"), BaseURLOverride: "https://other.example"}, "backend:acme.com", "https://other.example", "other.example", ""},
		{"server name given is kept", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("backend:acme.com"), ServerName: "named"}, "backend:acme.com", "https://app.aweb.ai", "named", ""},
		{"team override selects another membership", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("backend:acme.com"), TeamIDOverride: " ops:acme.com "}, "ops:acme.com", "https://app.aweb.ai", "app.aweb.ai", ""},
		{"team override selects without an active team", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active(""), TeamIDOverride: "ops:acme.com"}, "ops:acme.com", "https://app.aweb.ai", "app.aweb.ai", ""},
		{"unknown team override names the memberships", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("backend:acme.com"), TeamIDOverride: "dev:acme.com"}, "", "", "", `team "dev:acme.com" is not present in workspace memberships; available: backend:acme.com, ops:acme.com`},
		{"unknown team override precedes a missing URL", workspaceSelectionFacts{Workspace: workspace(""), TeamState: active("backend:acme.com"), TeamIDOverride: "dev:acme.com"}, "", "", "", `team "dev:acme.com" is not present in workspace memberships; available: backend:acme.com, ops:acme.com`},
		{"missing URL", workspaceSelectionFacts{Workspace: workspace(""), TeamState: active("backend:acme.com")}, "", "", "", "worktree workspace binding is missing aweb_url"},
		{"missing URL precedes a missing membership", workspaceSelectionFacts{Workspace: workspace(" "), TeamState: active("")}, "", "", "", "worktree workspace binding is missing aweb_url"},
		{"active team outside the memberships", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active("dev:acme.com")}, "", "", "", `active team "dev:acme.com" is not in memberships; run aw id team switch <valid-team>`},
		{"no active team", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai"), TeamState: active(" ")}, "", "", "", "worktree workspace binding is missing active_team membership"},
		{"no team state", workspaceSelectionFacts{Workspace: workspace("https://app.aweb.ai")}, "", "", "", "worktree workspace binding is missing active_team membership"},
		{"membership without a team id", workspaceSelectionFacts{Workspace: &WorktreeWorkspace{AwebURL: "https://app.aweb.ai", Memberships: []WorktreeMembership{{TeamID: " "}}}, TeamState: active("backend:acme.com")}, "", "", "", `active team "backend:acme.com" is not in memberships; run aw id team switch <valid-team>`},
		{"base URL without a host", workspaceSelectionFacts{Workspace: workspace("app.aweb.ai"), TeamState: active("backend:acme.com")}, "", "", "", `invalid base URL: invalid base URL "app.aweb.ai"`},
		{"unparsable base URL", workspaceSelectionFacts{Workspace: workspace("http://[::1"), TeamState: active("backend:acme.com")}, "", "", "", `invalid base URL: parse "http://[::1": missing ']' in host`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideWorkspaceSelection(tc.facts)
			if tc.refusal != "" {
				if err == nil || err.Error() != tc.refusal {
					t.Fatalf("error=%v, want %q", err, tc.refusal)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Membership == nil || got.Membership.TeamID != tc.membership || got.BaseURL != tc.baseURL || got.ServerName != tc.serverName {
				t.Fatalf("verdict=%+v membership=%+v", got, got.Membership)
			}
		})
	}
}

func TestWorkspaceSelectionIdentityPrecedence(t *testing.T) {
	membership := &WorktreeMembership{TeamID: " backend:acme.com ", Alias: " alice ", WorkspaceID: " ws-1 "}
	workspace := &WorktreeWorkspace{AwebURL: " https://app.aweb.ai "}
	cert := &awid.TeamCertificate{MemberDIDKey: "did:key:z6MkCert", MemberDIDAW: "did:aw:cert", MemberAddress: "acme.com/cert", IdentityScope: awid.IdentityModeGlobal}
	identity := &WorktreeIdentity{DID: "did:key:z6MkFile", StableID: "did:aw:file", Address: "other.com/file", Custody: "self", IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://registry.example"}
	base := Selection{TeamID: "backend:acme.com", Domain: "acme.com", Alias: "alice", WorkspaceID: "ws-1", AwebURL: "https://app.aweb.ai"}
	with := func(edit func(*Selection)) Selection {
		s := base
		edit(&s)
		return s
	}
	for _, tc := range []struct {
		name       string
		membership *WorktreeMembership
		cert       *awid.TeamCertificate
		identity   *WorktreeIdentity
		want       Selection
	}{
		{"certificate identity wins over the identity file", membership, cert, identity, with(func(s *Selection) {
			s.DID, s.StableID, s.Address, s.IdentityScope = "did:key:z6MkCert", "did:aw:cert", "acme.com/cert", awid.IdentityModeGlobal
			s.Custody, s.RegistryURL = "self", "https://registry.example"
		})},
		{"certificate alone", membership, cert, nil, with(func(s *Selection) {
			s.DID, s.StableID, s.Address, s.IdentityScope = "did:key:z6MkCert", "did:aw:cert", "acme.com/cert", awid.IdentityModeGlobal
		})},
		{"identity file fills a missing certificate", membership, nil, identity, with(func(s *Selection) {
			s.DID, s.StableID, s.Address, s.IdentityScope = "did:key:z6MkFile", "did:aw:file", "other.com/file", awid.IdentityModeGlobal
			s.Custody, s.RegistryURL = "self", "https://registry.example"
		})},
		{"identity file fills certificate gaps", membership, &awid.TeamCertificate{IdentityScope: "team"}, identity, with(func(s *Selection) {
			s.DID, s.StableID, s.Address, s.IdentityScope = "did:key:z6MkFile", "did:aw:file", "other.com/file", awid.IdentityModeGlobal
			s.Custody, s.RegistryURL = "self", "https://registry.example"
		})},
		{"a local certificate never takes the file's stable id", membership, &awid.TeamCertificate{MemberDIDKey: "did:key:z6MkCert", IdentityScope: awid.IdentityModeLocal}, identity, with(func(s *Selection) {
			s.DID, s.Address, s.IdentityScope = "did:key:z6MkCert", "other.com/file", awid.IdentityModeLocal
			s.Custody, s.RegistryURL = "self", "https://registry.example"
		})},
		{"a local identity file has no stable id", membership, nil, &WorktreeIdentity{DID: "did:key:z6MkFile", StableID: "did:aw:file", IdentityScope: awid.IdentityModeLocal}, with(func(s *Selection) {
			s.DID, s.IdentityScope = "did:key:z6MkFile", awid.IdentityModeLocal
		})},
		{"no address anywhere", membership, &awid.TeamCertificate{MemberDIDKey: "did:key:z6MkCert"}, &WorktreeIdentity{DID: "did:key:z6MkFile"}, with(func(s *Selection) {
			s.DID = "did:key:z6MkCert"
		})},
		{"alias and domain come from the identity address when the membership lacks them", &WorktreeMembership{TeamID: "not-a-team-id"}, nil, &WorktreeIdentity{Address: "other.com/file"}, Selection{TeamID: "not-a-team-id", Alias: "file", Domain: "other.com", Address: "other.com/file", AwebURL: "https://app.aweb.ai"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := composeWorkspaceSelection(workspace, tc.membership, tc.cert, tc.identity); got != tc.want {
				t.Fatalf("selection=%+v\nwant      %+v", got, tc.want)
			}
		})
	}
}
