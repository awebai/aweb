//go:build e2e

// Real-stack end-to-end tests: they drive the actually-built `aw` binary via
// os/exec against the live awid + aweb + Library stack (docker-compose.e2e.yml).
// There are no httptest servers and no injected mocks here - that is the whole
// point of this suite. It exercises the same code paths a human's `aw` runs.
//
// Double-gated so it never runs in the default `go test ./...`:
//   - build tag `e2e` (this file is invisible without `-tags e2e`)
//   - runtime env `AW_E2E=1` (skips otherwise, so a stray `-tags e2e` is safe)
//
// Bring the stack up and run it with `make -C cli e2e`, which sets AW_E2E=1 and
// the stack URLs. See docs/e2e-library-stack.md.
package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envOr returns the environment value for key, or fallback if unset/empty.
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// Stack endpoints, defaulting to docker-compose.e2e.yml's published ports.
func awebURL() string    { return envOr("AWEB_URL", "http://127.0.0.1:18000") }
func awidURL() string    { return envOr("AWID_REGISTRY_URL", "http://127.0.0.1:18010") }
func libraryURL() string { return envOr("LIBRARY_E2E_LIBRARY_URL", "http://127.0.0.1:18765") }

const seededBlueprintRef = "aweb.team"

// awBinary resolves the built aw binary: AW_BIN if set, else cli/go/aw (one
// directory up from this package).
func awBinary(t *testing.T) string {
	t.Helper()
	if bin := strings.TrimSpace(os.Getenv("AW_BIN")); bin != "" {
		abs, err := filepath.Abs(bin)
		if err != nil {
			t.Fatalf("resolve AW_BIN %q: %v", bin, err)
		}
		return abs
	}
	abs, err := filepath.Abs(filepath.Join("..", "aw"))
	if err != nil {
		t.Fatalf("resolve default aw binary: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("aw binary not found at %s (build it or set AW_BIN): %v", abs, err)
	}
	return abs
}

// requireE2E skips unless AW_E2E=1, so the suite is inert outside the harness.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("AW_E2E") != "1" {
		t.Skip("set AW_E2E=1 and bring up the stack (make -C cli e2e) to run real-stack e2e")
	}
}

func randSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

// e2eTeam is a throwaway AWID identity + team, isolated in its own workspace and
// HOME, so each test is independent and never touches the shared cli team.
type e2eTeam struct {
	bin       string
	workspace string
	env       []string
	namespace string
	teamID    string
	alias     string
}

// exec runs the aw binary in the team's workspace, capturing stdout and stderr
// separately. aw prints results to stdout and diagnostics (including the
// `HTTP <code>` status line of `id request`) to stderr, so callers parse stdout
// only and use stderr for error context.
func (tm *e2eTeam) exec(args ...string) (stdout, stderr string, err error) {
	cmd := exec.Command(tm.bin, args...)
	cmd.Dir = tm.workspace
	cmd.Env = tm.env
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// run executes aw and returns stdout, failing the test on non-zero exit.
func (tm *e2eTeam) run(t *testing.T, args ...string) string {
	t.Helper()
	stdout, stderr, err := tm.exec(args...)
	if err != nil {
		t.Fatalf("aw %s failed: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), err, stdout, stderr)
	}
	return stdout
}

// runJSON runs `aw --json <args>` and decodes the stdout object.
func (tm *e2eTeam) runJSON(t *testing.T, args ...string) map[string]any {
	t.Helper()
	out := tm.run(t, append([]string{"--json"}, args...)...)
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("aw --json %s did not emit an object: %v\noutput:\n%s", strings.Join(args, " "), err, out)
	}
	return obj
}

// newThrowawayTeam provisions a fresh identity + team against the real awid and
// binds it into a fresh workspace so `aw id request --team-auth` produces a
// valid team certificate. Mirrors Library's own e2e provisioning flow.
func newThrowawayTeam(t *testing.T) *e2eTeam {
	t.Helper()
	bin := awBinary(t)
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	home := filepath.Join(root, "home")
	for _, dir := range []string{workspace, home} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	namespace := "cli-e2e-" + randSuffix(t) + ".test"
	team := "default"
	alias := "alice"
	address := namespace + "/" + alias

	env := append(os.Environ(),
		"HOME="+home,
		"AWEB_URL="+awebURL(),
		"AWID_REGISTRY_URL="+awidURL(),
		"AWID_SKIP_DNS_VERIFY=1",
		"NO_COLOR=1",
	)
	tm := &e2eTeam{bin: bin, workspace: workspace, env: env, namespace: namespace, teamID: team + ":" + namespace, alias: alias}

	tm.run(t, "id", "create", "--domain", namespace, "--name", alias, "--registry", awidURL(), "--skip-dns-verify")
	tm.run(t, "id", "team", "create", "--namespace", namespace, "--name", team, "--registry", awidURL())
	addMember := tm.runJSON(t, "id", "team", "add-member", "--namespace", namespace, "--team", team, "--member", address)
	certificateID, _ := addMember["certificate_id"].(string)
	if certificateID == "" {
		t.Fatalf("add-member returned no certificate_id: %v", addMember)
	}
	fetchCert := tm.runJSON(t, "id", "team", "fetch-cert", "--namespace", namespace, "--team", team, "--cert-id", certificateID, "--registry", awidURL())
	certPath, _ := fetchCert["cert_path"].(string)
	if certPath == "" {
		t.Fatalf("fetch-cert returned no cert_path: %v", fetchCert)
	}
	tm.run(t, "id", "team", "switch", tm.teamID)

	now := time.Now().UTC().Format(time.RFC3339)
	awDir := filepath.Join(workspace, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	binding := "aweb_url: http://127.0.0.1:1\n" +
		"memberships:\n" +
		"    - team_id: " + tm.teamID + "\n" +
		"      alias: " + alias + "\n" +
		"      workspace_id: " + randSuffix(t) + "\n" +
		"      cert_path: " + certPath + "\n" +
		"      joined_at: \"" + now + "\"\n" +
		"human_name: cli-e2e\n" +
		"agent_type: agent\n" +
		"workspace_path: " + workspace + "\n" +
		"updated_at: \"" + now + "\"\n"
	if err := os.WriteFile(filepath.Join(awDir, "workspace.yaml"), []byte(binding), 0o644); err != nil {
		t.Fatalf("write workspace.yaml: %v", err)
	}
	return tm
}

// idRequest drives `aw id request <method> <url> --team-auth --raw`, the real
// signed-request path the Library expects. There is no anonymous id request -
// even public reads are signed - so the suite always team-auths. Returns the
// response body from stdout (the `HTTP <code>` line goes to stderr).
func (tm *e2eTeam) idRequest(method, url string) (body, stderr string, err error) {
	return tm.exec("id", "request", method, url, "--team-auth", "--raw")
}

// TestRealStackTeamAuthReachesLibrary proves the built aw binary, a real AWID
// team certificate, and the real Library agree end to end: a team-scoped read
// authenticates and returns the empty proposals list for a fresh team.
func TestRealStackTeamAuthReachesLibrary(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)

	body, stderr, err := tm.idRequest("GET", libraryURL()+"/v1/proposals")
	if err != nil {
		t.Fatalf("authenticated GET /v1/proposals failed: %v\nstdout:\n%s\nstderr:\n%s", err, body, stderr)
	}
	if got := strings.TrimSpace(body); got != "[]" {
		t.Fatalf("fresh team proposals = %q, want []", got)
	}
}

// TestRealStackSeededBlueprintVisible proves the stack is seeded: the public
// catalog, fetched through the real binary, contains the seeded aweb.team
// blueprint.
func TestRealStackSeededBlueprintVisible(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)

	body, stderr, err := tm.idRequest("GET", libraryURL()+"/v1/blueprints")
	if err != nil {
		t.Fatalf("GET /v1/blueprints failed: %v\nstdout:\n%s\nstderr:\n%s", err, body, stderr)
	}
	var catalog []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &catalog); err != nil {
		t.Fatalf("GET /v1/blueprints did not return a JSON array: %v\noutput:\n%s", err, body)
	}
	found := false
	for _, bp := range catalog {
		if ref, _ := bp["blueprint_ref"].(string); ref == seededBlueprintRef {
			found = true
			// Assert it is versioned, not a specific version: the catalog source
			// evolves independently, so pinning a version here is brittle.
			if v, _ := bp["version"].(string); strings.TrimSpace(v) == "" {
				t.Errorf("%s has empty version", seededBlueprintRef)
			}
		}
	}
	if !found {
		t.Fatalf("%s not found in catalog; got %d blueprints", seededBlueprintRef, len(catalog))
	}
}
