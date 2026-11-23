package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// settleCommand is the registration a refusal for an unconfirmed key names.
func settleCommand(domain, name string) string {
	return "aw id team create --namespace " + domain + " --name " + name
}

// setAsideTeamKeyForTest leaves domain/name as a team create leaves it after
// a failed read: no team key, and this machine's key set aside as unconfirmed.
func setAsideTeamKeyForTest(t *testing.T, domain, name string) {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.CreateTeamKey(domain, name, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SetAsideUnconfirmedTeamKey(domain, name, pub); err != nil {
		t.Fatal(err)
	}
}

func assertUnconfirmedRefusal(t *testing.T, what string, err error, domain, name string) {
	t.Helper()
	if code := errorCodeOf(err); code != codeTeamNameUnconfirmed {
		t.Fatalf("%s: code=%q err=%v, want %q", what, code, err, codeTeamNameUnconfirmed)
	}
	if !strings.Contains(err.Error(), settleCommand(domain, name)) {
		t.Fatalf("%s: refusal %q does not name %q", what, err, settleCommand(domain, name))
	}
}

// A team whose key is set aside as unconfirmed has a key on this machine
// that may be the registered one. Every command that reads the team key
// refuses for it, and none takes the team as keyless: none falls back to a
// hosted, cloud or unsigned path.
func TestTeamKeyReadersRefuseAnUnconfirmedKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	const domain, name = "acme.com", "ops"
	setAsideTeamKeyForTest(t, domain, name)

	t.Run("invite planning", func(t *testing.T) {
		_, err := planTeamInvite(teamInviteSource{
			WorkingDir: tmp, Domain: domain, Team: name, AwebURL: "https://app.aweb.ai/api",
		})
		assertUnconfirmedRefusal(t, "planTeamInvite", err, domain, name)
	})
	t.Run("controller invite", func(t *testing.T) {
		_, err := createControllerTeamInvite(teamInviteMintRequest{
			Plan:  teamInvitePlan{Source: teamInviteSource{Domain: domain, Team: name}, Kind: inviteAuthorityController},
			Scope: inviteMemberLocal,
		})
		assertUnconfirmedRefusal(t, "createControllerTeamInvite", err, domain, name)
	})
	t.Run("replace-key", func(t *testing.T) {
		_, err := loadLocalReplaceKeyController(domain, name)
		assertUnconfirmedRefusal(t, "loadLocalReplaceKeyController", err, domain, name)
	})
	t.Run("reissue-cert", func(t *testing.T) {
		_, err := loadReissueCertController(domain, name)
		assertUnconfirmedRefusal(t, "loadReissueCertController", err, domain, name)
	})
	t.Run("owner acts", func(t *testing.T) {
		_, err := loadOwnerTeamKey(awid.BuildTeamID(domain, name))
		assertUnconfirmedRefusal(t, "loadOwnerTeamKey", err, domain, name)
	})
	t.Run("team reads", func(t *testing.T) {
		_, err := teamReadSigners(tmp, domain, name)
		assertUnconfirmedRefusal(t, "teamReadSigners", err, domain, name)
	})
	t.Run("team server read", func(t *testing.T) {
		_, err := teamServerReadKey(domain, name)
		assertUnconfirmedRefusal(t, "teamServerReadKey", err, domain, name)
	})
}

// add-worktree with a parent API key mints the child through the cloud only
// for a team with no local key. A team whose key is set aside as unconfirmed
// is refused before any cloud call, and no worktree is made.
func TestAwWorkspaceAddWorktreeRefusesAnUnconfirmedTeamKey(t *testing.T) {
	t.Parallel()

	const origin = "https://github.com/acme/repo.git"
	const teamID = "backend:source"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cloudInit atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, teamID) {
			return
		}
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "name_prefix": "grace"})
		case "/api/v1/workspaces/init":
			cloudInit.Store(true)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	tmp := t.TempDir()
	canonicalTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(canonicalTmp, "aw")
	repo := filepath.Join(canonicalTmp, "repo")
	principalDir := filepath.Join(canonicalTmp, "principal")
	identityHome := filepath.Join(principalDir, ".aw")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	binding := workspaceBinding(server.URL, teamID, "alice", "source-1")
	binding.APIKey = "aw_sk_parent_key"
	writeWorkspaceBindingForTest(t, principalDir, binding)
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(identityHome, "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed principal context: %v", err)
	}
	keyPath := filepath.Join(tmp, ".awid", "team-keys", "source", "backend.key")
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.StoreSigningKeyFile(awid.SigningKeyFile{Path: keyPath + ".unconfirmed", Key: teamKey, PathPolicy: awid.OperatorManagedAuthorityPath}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a refusal, got success:\n%s", out)
	}
	if text := string(out); !strings.Contains(text, settleCommand("source", "backend")) {
		t.Fatalf("refusal does not name %q:\n%s", settleCommand("source", "backend"), text)
	}
	if cloudInit.Load() {
		t.Fatal("add-worktree fell back to the cloud mint")
	}
	if _, err := os.Stat(filepath.Join(canonicalTmp, "repo-grace")); !os.IsNotExist(err) {
		t.Fatalf("a child worktree was created: %v", err)
	}
	if _, err := os.Stat(keyPath + ".unconfirmed"); err != nil {
		t.Fatalf("the set-aside key was touched: %v", err)
	}
}
