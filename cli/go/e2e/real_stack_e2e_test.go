//go:build e2e

// Real-stack end-to-end tests: they drive the exact selected `aw` binary via
// os/exec against the live awid + aweb + Library stack (docker-compose.e2e.yml).
// The ordinary target builds it; release-skew cells supply staged/published bytes.
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

	"github.com/awebai/aw/awconfig"
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

// awBinary resolves the selected aw binary: AW_BIN if set, else cli/go/aw
// (one directory up from this package).
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

// requestedSkewDirection binds a release-driver cell to this invocation. The
// CLI/server journey is request/response shaped, so both matrix directions run
// the complete mutation + readback contract rather than silently deduplicating
// one direction.
func requestedSkewDirection(t *testing.T) string {
	t.Helper()
	direction := strings.TrimSpace(os.Getenv("AW_SKEW_DIRECTION"))
	switch direction {
	case "", "a-to-b", "b-to-a":
		return direction
	default:
		t.Fatalf("unsupported AW_SKEW_DIRECTION %q", direction)
		return ""
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

func TestRealStackWorkspacePresenceAndLocksUseDistinctIdentifiers(t *testing.T) {
	requireE2E(t)
	direction := requestedSkewDirection(t)
	if direction != "" {
		t.Logf("release skew cell direction: %s", direction)
	}
	tm := newThrowawayTeam(t)

	if err := os.Remove(filepath.Join(tm.workspace, ".aw", "workspace.yaml")); err != nil {
		t.Fatalf("remove library-only workspace binding: %v", err)
	}
	tm.run(t, "workspace", "connect", "--service", awebURL(), "--team", tm.teamID)
	tm.run(t, "heartbeat")

	resourceKey := "e2e-status-" + randSuffix(t)
	tm.run(t, "lock", "acquire", "--resource-key", resourceKey, "--ttl-seconds", "60")

	if direction == "" || direction == "b-to-a" {
		// Server -> CLI: the selected CLI must decode the server response into
		// distinct identities, attributed locks, and active presence.
		status := tm.runJSON(t, "workspace", "status")
		workspace, ok := status["workspace"].(map[string]any)
		if !ok {
			t.Fatalf("workspace status omitted its workspace object: %v", status)
		}
		workspaceID, _ := workspace["workspace_id"].(string)
		agentID, _ := workspace["agent_id"].(string)
		if workspaceID == "" || agentID == "" || workspaceID == agentID {
			t.Fatalf("workspace and agent identifiers were not distinct: workspace=%v", workspace)
		}
		if got, _ := workspace["status"].(string); got != "active" {
			t.Fatalf("workspace status = %q, want active: %v", got, workspace)
		}
		locks, _ := status["locks"].([]any)
		if len(locks) != 1 {
			t.Fatalf("workspace status locks = %v, want one lock", locks)
		}
		lock, ok := locks[0].(map[string]any)
		if !ok || lock["resource_key"] != resourceKey {
			t.Fatalf("workspace status lock = %v, want %q", locks[0], resourceKey)
		}
	}

	if direction == "" || direction == "a-to-b" {
		// CLI -> server: read the workspace identity from the local binding,
		// then inspect raw authenticated server state. This proves the selected
		// CLI's mutation reached the distinct agent principal rather than the
		// workspace UUID that server 1.26.31 incorrectly filtered against.
		binding, _, _, err := awconfig.LoadWorkspaceAndTeamState(tm.workspace)
		if err != nil {
			t.Fatalf("load connected workspace binding: %v", err)
		}
		membership := binding.Membership(tm.teamID)
		if membership == nil || membership.WorkspaceID == "" {
			t.Fatalf("connected workspace omitted %s membership: %v", tm.teamID, binding)
		}
		workspaceID := membership.WorkspaceID

		body, stderr, err := tm.idRequest("GET", awebURL()+"/v1/status?workspace_id="+workspaceID)
		if err != nil {
			t.Fatalf("GET /v1/status failed: %v\nstdout:\n%s\nstderr:\n%s", err, body, stderr)
		}
		var serverStatus map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &serverStatus); err != nil {
			t.Fatalf("GET /v1/status did not return an object: %v\noutput:\n%s", err, body)
		}
		serverLocks, _ := serverStatus["locks"].([]any)
		if len(serverLocks) != 1 {
			t.Fatalf("server status locks = %v, want one lock", serverLocks)
		}
		serverLock, ok := serverLocks[0].(map[string]any)
		if !ok || serverLock["resource_key"] != resourceKey {
			t.Fatalf("server status lock = %v, want %q", serverLocks[0], resourceKey)
		}
		holderAgentID, _ := serverLock["holder_agent_id"].(string)
		if holderAgentID == "" || holderAgentID == workspaceID {
			t.Fatalf("server lock holder %q is not distinct from workspace %q", holderAgentID, workspaceID)
		}

		body, stderr, err = tm.idRequest("GET", awebURL()+"/v1/agents")
		if err != nil {
			t.Fatalf("GET /v1/agents failed: %v\nstdout:\n%s\nstderr:\n%s", err, body, stderr)
		}
		var agents map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &agents); err != nil {
			t.Fatalf("GET /v1/agents did not return an object: %v\noutput:\n%s", err, body)
		}
		listed, _ := agents["agents"].([]any)
		if len(listed) != 1 {
			t.Fatalf("agent roster = %v, want one agent", listed)
		}
		listedAgent, ok := listed[0].(map[string]any)
		if !ok || listedAgent["online"] != true {
			t.Fatalf("agent roster did not report the connected workspace online: %v", listed[0])
		}
		if listedAgent["agent_id"] != holderAgentID {
			t.Fatalf("server lock holder %q != roster agent %v", holderAgentID, listedAgent["agent_id"])
		}
	}
}
