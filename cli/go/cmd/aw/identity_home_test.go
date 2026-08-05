package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestExternalIdentityHomeWhoamiCannotRegisterInstanceWorkspace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	principalParent := filepath.Join(root, "principal")
	if err := os.MkdirAll(principalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	instanceHome := filepath.Join(root, "disposable-instance")
	if err := os.MkdirAll(instanceHome, 0o700); err != nil {
		t.Fatal(err)
	}

	type observedRequest struct {
		Method        string
		URL           string
		Body          string
		PathDisclosed bool
	}
	var requestMu sync.Mutex
	var requests []observedRequest
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		pathDisclosed := strings.Contains(r.URL.RequestURI(), instanceHome) || strings.Contains(string(body), instanceHome)
		for name, values := range r.Header {
			pathDisclosed = pathDisclosed || strings.Contains(name, instanceHome)
			for _, value := range values {
				pathDisclosed = pathDisclosed || strings.Contains(value, instanceHome)
			}
		}
		requestMu.Lock()
		requests = append(requests, observedRequest{
			Method: r.Method, URL: r.URL.RequestURI(), Body: string(body), PathDisclosed: pathDisclosed,
		})
		requestMu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agents/me/inbound-mode" {
			http.Error(w, "unexpected request", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(awid.AgentInboundModeResponse{
			AgentID: "agent-attached", TeamID: "backend:aweb.ai", Alias: "attached",
			IdentityScope: awid.IdentityModeGlobal, InboundMode: "open", Configurable: true,
		})
	}))

	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeSelectionFixtureForTest(t, principalParent, testSelectionFixture{
		AwebURL: server.URL, TeamID: "backend:aweb.ai", Alias: "attached",
		WorkspaceID: "workspace-attached", DID: awid.ComputeDIDKey(pub), StableID: awid.ComputeStableID(pub),
		Address: "aweb.ai/attached", Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, SigningKey: key,
	})
	identityHome := filepath.Join(principalParent, ".aw")
	cmd := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "whoami", "--json")
	cmd.Dir = instanceHome
	cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")), "AWEB_IDENTITY_HOME=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("attached whoami failed: %v\n%s", err, out)
	}
	requestMu.Lock()
	gotRequests := append([]observedRequest(nil), requests...)
	requestMu.Unlock()
	wantRequests := []observedRequest{{Method: http.MethodGet, URL: "/v1/agents/me/inbound-mode"}}
	if !reflect.DeepEqual(gotRequests, wantRequests) {
		t.Fatalf("attached whoami sent a request capable of registering its instance path: got %#v want %#v", gotRequests, wantRequests)
	}
	requestWire, err := json.Marshal(gotRequests)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(requestWire), instanceHome) {
		t.Fatalf("attached whoami disclosed its disposable instance path to the server: %s", requestWire)
	}
	if _, err := os.Lstat(filepath.Join(instanceHome, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("attached whoami created instance identity state: %v", err)
	}
}

func TestExternalIdentityHomeUsesPrincipalWithoutCopyingOrLinkingIdentityMaterial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	principalParent := filepath.Join(root, "principal")
	if err := os.MkdirAll(principalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_roles_id": "roles-1", "roles": map[string]any{"attached-role": map[string]any{"title": "Attached"}}})
		case "/v1/agents/me":
			_ = json.NewEncoder(w).Encode(map[string]any{"role_name": "attached-role"})
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	writeSelectionFixtureForTest(t, principalParent, testSelectionFixture{
		AwebURL: server.URL, TeamID: "backend:aweb.ai", Alias: "attached",
		WorkspaceID: "workspace-attached", DID: did, StableID: awid.ComputeStableID(pub),
		Address: "aweb.ai/attached", Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, SigningKey: key,
	})
	identityHome := filepath.Join(principalParent, ".aw")
	if err := os.WriteFile(filepath.Join(identityHome, "a2a-credentials.yaml"), []byte("credentials:\n  - host: gateway.example\n    api_key: static-principal-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	principalMaterial := principalMaterialForTest(t, identityHome)

	cases := []struct {
		name string
		args []string
		env  string
	}{
		{name: "flag", args: []string{"--identity-home", identityHome, "whoami", "--json"}},
		{name: "environment", args: []string{"whoami", "--json"}, env: "AWEB_IDENTITY_HOME=" + identityHome},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			instanceHome := filepath.Join(root, "instances", tc.name)
			if err := os.MkdirAll(instanceHome, 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, bin, tc.args...)
			cmd.Dir = instanceHome
			cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")), "AWEB_IDENTITY_HOME=")
			if tc.env != "" {
				cmd.Env = append(cmd.Env, tc.env)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("attached whoami failed: %v\n%s", err, string(out))
			}
			var identity struct {
				Address string `json:"address"`
			}
			if err := json.Unmarshal(extractJSON(t, out), &identity); err != nil || identity.Address != "aweb.ai/attached" {
				t.Fatalf("whoami did not use attached principal: address=%q err=%v\n%s", identity.Address, err, string(out))
			}

			mailArgs := []string{"mail", "inbox", "--json"}
			if tc.name == "flag" {
				mailArgs = append([]string{"--identity-home", identityHome}, mailArgs...)
			}
			mail := exec.CommandContext(ctx, bin, mailArgs...)
			mail.Dir = instanceHome
			mail.Env = cmd.Env
			if mailOut, mailErr := mail.CombinedOutput(); mailErr != nil {
				t.Fatalf("attached mail inbox failed: %v\n%s", mailErr, mailOut)
			}

			// Exercise a principal write through the real command path. The workspace
			// mutation must land in the identity home, never the empty instance.
			roleArgs := []string{"role-name", "set", "attached-role"}
			if tc.name == "flag" {
				roleArgs = append([]string{"--identity-home", identityHome}, roleArgs...)
			}
			role := exec.CommandContext(ctx, bin, roleArgs...)
			role.Dir = instanceHome
			role.Env = cmd.Env
			if roleOut, roleErr := role.CombinedOutput(); roleErr != nil {
				t.Fatalf("attached role-name write failed: %v\n%s", roleErr, roleOut)
			}
			workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(identityHome, "workspace.yaml"))
			if err != nil || workspace.Membership("backend:aweb.ai").RoleName != "attached-role" {
				t.Fatalf("principal workspace did not receive role mutation: err=%v workspace=%#v", err, workspace)
			}
			principalMaterial = principalMaterialForTest(t, identityHome)
			assertNoIdentityMaterialForTest(t, instanceHome, identityHome, principalMaterial)

			beforeReset := fileDigestsForTest(t, identityHome)
			resetArgs := []string{"reset"}
			if tc.name == "flag" {
				resetArgs = append([]string{"--identity-home", identityHome}, resetArgs...)
			}
			reset := exec.CommandContext(ctx, bin, resetArgs...)
			reset.Dir = instanceHome
			reset.Env = cmd.Env
			resetOut, resetErr := reset.CombinedOutput()
			if resetErr == nil || !strings.Contains(string(resetOut), "external identity home") {
				t.Fatalf("external reset must fail closed: err=%v\n%s", resetErr, string(resetOut))
			}
			if after := fileDigestsForTest(t, identityHome); !reflect.DeepEqual(after, beforeReset) {
				t.Fatal("external reset changed principal bytes")
			}

			beforeDeleteRequests := requests.Load()
			deleteArgs := []string{"workspace", "delete", "attached"}
			if tc.name == "flag" {
				deleteArgs = append([]string{"--identity-home", identityHome}, deleteArgs...)
			}
			remove := exec.CommandContext(ctx, bin, deleteArgs...)
			remove.Dir = instanceHome
			remove.Env = cmd.Env
			deleteOut, deleteErr := remove.CombinedOutput()
			if deleteErr == nil || !strings.Contains(string(deleteOut), "external identity home") {
				t.Fatalf("external workspace delete must fail closed: err=%v\n%s", deleteErr, string(deleteOut))
			}
			if got := requests.Load(); got != beforeDeleteRequests {
				t.Fatalf("workspace delete made HTTP requests before refusal: before=%d after=%d", beforeDeleteRequests, got)
			}
			assertNoIdentityMaterialForTest(t, instanceHome, identityHome, principalMaterial)
		})
	}

	workspacePath := filepath.Join(identityHome, "workspace.yaml")
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	membership := workspace.Membership("backend:aweb.ai")
	if membership == nil {
		t.Fatal("missing fixture membership")
	}
	originalCert := filepath.Join(identityHome, filepath.FromSlash(membership.CertPath))
	linkedCert := filepath.Join(identityHome, "team-certs", "linked.pem")
	if err := os.Symlink(originalCert, linkedCert); err != nil {
		t.Fatal(err)
	}
	membership.CertPath = "team-certs/linked.pem"
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		t.Fatal(err)
	}
	instanceHome := filepath.Join(root, "instances", "symlink-guard")
	if err := os.MkdirAll(instanceHome, 0o700); err != nil {
		t.Fatal(err)
	}
	guarded := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "whoami", "--json")
	guarded.Dir = instanceHome
	guarded.Env = testCommandEnv(filepath.Join(root, "user-home"))
	guardOut, guardErr := guarded.CombinedOutput()
	if guardErr == nil || !strings.Contains(string(guardOut), "symlink") {
		t.Fatalf("symlinked certificate must fail at use: err=%v\n%s", guardErr, string(guardOut))
	}
}

func TestExternalIdentityHomeRoutesMailAndRegistrySigningAuthority(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalParent := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	writeSelectionFixtureForTest(t, principalParent, testSelectionFixture{
		AwebURL: "https://team.example", TeamID: "backend:aweb.ai", Alias: "attached",
		WorkspaceID: "workspace-attached", DID: did, StableID: awid.ComputeStableID(pub),
		Address: "aweb.ai/attached", Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, SigningKey: key,
	})
	identityHome := filepath.Join(principalParent, ".aw")
	t.Setenv(awconfig.IdentityHomeEnv, identityHome)

	_, selection, err := resolveIdentityMessagingClientSelectionForDir(instance)
	if err != nil {
		t.Fatalf("mail identity resolution from empty instance failed: %v", err)
	}
	if selection.Address != "aweb.ai/attached" {
		t.Fatalf("mail selection address=%q", selection.Address)
	}
	authority, err := resolveRegistryReadAuthority(instance, "aweb.ai", "did")
	if err != nil {
		t.Fatalf("registry DID authority from empty instance failed: %v", err)
	}
	if authority.SubjectDID != did {
		t.Fatalf("registry authority DID=%q want %q", authority.SubjectDID, did)
	}
}

func TestRunBinaryUsesExternalPrincipalWorkspaceAndPropagatesIdentityHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell provider fixture is unix-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "events") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	principalParent := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	providerBin := filepath.Join(root, "provider-bin")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(providerBin, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeSelectionFixtureForTest(t, principalParent, testSelectionFixture{
		AwebURL: server.URL, TeamID: "backend:aweb.ai", Alias: "attached",
		WorkspaceID: "workspace-attached", DID: awid.ComputeDIDKey(pub), StableID: awid.ComputeStableID(pub),
		Address: "aweb.ai/attached", Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, SigningKey: key,
	})
	identityHome, err := filepath.EvalSymlinks(filepath.Join(principalParent, ".aw"))
	if err != nil {
		t.Fatal(err)
	}
	capturePath := filepath.Join(root, "provider-identity-home")
	provider := filepath.Join(providerBin, "claude")
	script := "#!/bin/sh\nprintf '%s' \"$AWEB_IDENTITY_HOME\" > \"$RUN_IDENTITY_CAPTURE\"\nprintf '%s\\n' '{\"type\":\"result\",\"duration_ms\":1,\"session_id\":\"attached-session\"}'\n"
	if err := os.WriteFile(provider, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "run", "claude", "--prompt", "done", "--max-runs", "1", "--wait", "0", "--idle-wait", "0")
	cmd.Dir = instance
	cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")),
		"PATH="+providerBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RUN_IDENTITY_CAPTURE="+capturePath,
		awconfig.IdentityHomeEnv+"=",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("attached run failed: %v\n%s", err, out)
	}
	captured, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("provider was not invoked: %v", err)
	}
	if got := strings.TrimSpace(string(captured)); got != identityHome {
		t.Fatalf("provider %s=%q want %q", awconfig.IdentityHomeEnv, got, identityHome)
	}
	if _, err := os.Lstat(filepath.Join(instance, ".aw", "workspace.yaml")); !os.IsNotExist(err) {
		t.Fatalf("run copied principal workspace into instance: %v", err)
	}
}

func TestRunPropagatesCanonicalExternalIdentityHomeToChildren(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(awconfig.IdentityHomeEnv, "")
	restore, err := propagateResolvedIdentityHomeForRun(awconfig.IdentityHome{Root: root, Source: awconfig.IdentityHomeFlag})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	child := exec.Command("/usr/bin/env")
	out, err := child.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), awconfig.IdentityHomeEnv+"="+root) {
		t.Fatalf("child environment missing canonical identity home:\n%s", string(out))
	}
}

type principalMaterialSnapshot struct {
	digests map[string]struct{}
	files   []fs.FileInfo
}

func principalMaterialForTest(t *testing.T, root string) principalMaterialSnapshot {
	t.Helper()
	material := principalMaterialSnapshot{digests: map[string]struct{}{}}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			material.digests[hex.EncodeToString(sum[:])] = struct{}{}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			material.files = append(material.files, info)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func TestIdentityMaterialScannerDetectsRenamedCopiesSymlinksAndHardlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principal := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(principal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	principalFile := filepath.Join(principal, "signing.key")
	secret := []byte("principal-secret-material")
	if err := os.WriteFile(principalFile, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instance, "renamed.bin"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(principalFile, filepath.Join(instance, "linked.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(principalFile, filepath.Join(instance, "hardlinked.bin")); err != nil {
		t.Fatal(err)
	}
	leaks, err := identityMaterialLeaksForTest(instance, principal, principalMaterialForTest(t, principal))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(leaks, "\n")
	for _, want := range []string{"byte-copy", "link into identity home", "hardlink"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scanner did not report %s:\n%s", want, joined)
		}
	}
}

func fileDigestsForTest(t *testing.T, root string) map[string]struct{} {
	return principalMaterialForTest(t, root).digests
}

func assertNoIdentityMaterialForTest(t *testing.T, instanceHome, identityHome string, principalMaterial principalMaterialSnapshot) {
	t.Helper()
	leaks, err := identityMaterialLeaksForTest(instanceHome, identityHome, principalMaterial)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range leaks {
		t.Error(leak)
	}
}

func identityMaterialLeaksForTest(instanceHome, identityHome string, principalMaterial principalMaterialSnapshot) ([]string, error) {
	leaks := []string{}
	sensitiveNames := map[string]struct{}{
		"identity.yaml": {}, "signing.key": {}, "encryption.yaml": {}, "team-certs": {},
	}
	err := filepath.WalkDir(instanceHome, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, readErr := filepath.EvalSymlinks(path)
			if readErr == nil {
				rel, relErr := filepath.Rel(identityHome, target)
				if relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					leaks = append(leaks, "instance contains link into identity home: "+path+" -> "+target)
				}
			}
			return nil
		}
		if _, sensitive := sensitiveNames[entry.Name()]; sensitive {
			leaks = append(leaks, "instance contains identity material by name: "+path)
		}
		if entry.Type().IsRegular() {
			info, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			for _, principalInfo := range principalMaterial.files {
				if os.SameFile(info, principalInfo) {
					leaks = append(leaks, "instance contains a hardlink to principal material: "+path)
				}
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			sum := sha256.Sum256(data)
			if _, copied := principalMaterial.digests[hex.EncodeToString(sum[:])]; copied {
				leaks = append(leaks, "instance contains a byte-copy of principal material: "+path)
			}
		}
		return nil
	})
	return leaks, err
}
