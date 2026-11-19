package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type commandStack struct {
	RegistryURL string `json:"registry_url"`
	ServerURL   string `json:"server_url"`
}

// sharedCommandStack is the package's one real aweb/AWID stack
// (scripts/test-egress/aweb_fixture.py). It starts on first use and
// stopSharedCommandStack ends it from TestMain after every test has run.
// Tests are isolated by data: each world publishes its own domain's DNS record
// and registers its own namespace and team.
var sharedCommandStack struct {
	once    sync.Once
	err     error
	stack   commandStack
	command *exec.Cmd
	input   io.WriteCloser
	replies *bufio.Scanner
	// mu holds one command and its acknowledgement together.
	mu     sync.Mutex
	nextID int
}

func packageCommandStack(t *testing.T) commandStack {
	t.Helper()
	sharedCommandStack.once.Do(startSharedCommandStack)
	if sharedCommandStack.err != nil {
		t.Fatal(sharedCommandStack.err)
	}
	return sharedCommandStack.stack
}

func startSharedCommandStack() {
	shared := &sharedCommandStack
	script, err := filepath.Abs("../../../../scripts/test-egress/aweb_fixture.py")
	if err != nil {
		shared.err = err
		return
	}
	project := filepath.Join(awTestBinary.sourceDir, "../../server")
	// No test's context: the stack outlives every test that uses it.
	command := exec.Command("uv", "run", "--offline", "--frozen", "--project", project, "python", "-P", script)
	command.Env = append([]string{}, awTestBinary.env...)
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		shared.err = err
		return
	}
	output, err := command.StdoutPipe()
	if err != nil {
		shared.err = err
		return
	}
	started := time.Now()
	if err := command.Start(); err != nil {
		shared.err = fmt.Errorf("start real command stack: %w", err)
		return
	}
	shared.command, shared.input, shared.replies = command, input, bufio.NewScanner(output)
	if !shared.replies.Scan() {
		shared.err = fmt.Errorf("real command stack exited before publishing readiness: %v", stopSharedCommandStack())
		return
	}
	if err := json.Unmarshal(shared.replies.Bytes(), &shared.stack); err != nil {
		shared.err = fmt.Errorf("real command stack readiness %q: %w", shared.replies.Text(), err)
		return
	}
	fmt.Fprintf(os.Stderr, "shared real command stack start: %s\n", time.Since(started).Round(time.Millisecond))
}

// publishCommandZone publishes domain's _awid TXT record naming controller in
// the stack's DNS zone. It writes nothing to the registry.
func publishCommandZone(domain, controllerDID string) error {
	shared := &sharedCommandStack
	shared.mu.Lock()
	defer shared.mu.Unlock()
	shared.nextID++
	id := shared.nextID
	line, err := json.Marshal(map[string]any{"id": id, "zone": map[string]string{"domain": domain, "controller": controllerDID}})
	if err != nil {
		return err
	}
	if _, err := shared.input.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("send zone command: %w", err)
	}
	if !shared.replies.Scan() {
		return fmt.Errorf("real command stack exited before acknowledging zone %s: %v", domain, shared.replies.Err())
	}
	var reply struct {
		ID    int    `json:"id"`
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(shared.replies.Bytes(), &reply); err != nil {
		return fmt.Errorf("zone acknowledgement %q: %w", shared.replies.Text(), err)
	}
	if reply.ID != id {
		return fmt.Errorf("zone acknowledgement %q does not answer command %d", shared.replies.Text(), id)
	}
	if !reply.OK {
		return fmt.Errorf("zone %s refused: %s", domain, reply.Error)
	}
	return nil
}

// stopSharedCommandStack closes the stack's input, which stops its services and
// drops its database, and waits for it to exit.
func stopSharedCommandStack() error {
	shared := &sharedCommandStack
	if shared.command == nil {
		return nil
	}
	closeErr := shared.input.Close()
	waitErr := shared.command.Wait()
	shared.command = nil
	if waitErr != nil {
		return fmt.Errorf("real command stack: %w", waitErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close real command stack input: %w", closeErr)
	}
	return nil
}

// realCommandWorld owns setup through the same writers installed clients use.
// R11c: docs/identity.md:97 and docs/identity-messaging-contract.md:434.
type realCommandWorld struct {
	Context      context.Context
	Binary       string
	Stack        commandStack
	Domain       string
	TeamID       string
	NamespaceKey ed25519.PrivateKey
	TeamKey      ed25519.PrivateKey
	Registry     *awid.RegistryClient
}

type commandMember struct {
	Home        string
	Certificate *awid.TeamCertificate
}

func newRealCommandWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	world := &realCommandWorld{
		Context: ctx, Binary: filepath.Join(t.TempDir(), "aw"),
		Domain: freshName(t, "commands-") + ".test", NamespaceKey: newKey(t), TeamKey: newKey(t),
	}
	buildAwBinary(t, ctx, world.Binary)
	world.Stack = packageCommandStack(t)
	if err := publishCommandZone(world.Domain, didOf(world.NamespaceKey)); err != nil {
		t.Fatal(err)
	}
	world.Registry = trustedClient(t, world.Stack.RegistryURL, nil)
	if _, err := world.Registry.RegisterNamespaceAt(ctx, world.Stack.RegistryURL, world.Domain, didOf(world.NamespaceKey), world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := world.Registry.CreateTeam(ctx, world.Stack.RegistryURL, world.Domain, "backend", "Command tests", didOf(world.TeamKey), world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	world.TeamID = awid.BuildTeamID(world.Domain, "backend")
	target, err := resolveTeamRegistrationEndpoint(world.Stack.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeTeamRegisterWithTarget(ctx, world.TeamKey, world.TeamID, target, false, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return world
}

// runInIdentityHome returns the command's stdout, where --json output goes.
// A failure's error carries the command's stderr.
func (world *realCommandWorld) runInIdentityHome(home string, args ...string) (string, error) {
	command := exec.CommandContext(world.Context, world.Binary, append([]string{"--identity-home", home, "--json"}, args...)...)
	command.Dir = filepath.Dir(home)
	command.Env = append(idCreateCommandEnv(filepath.Dir(home)), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		err = fmt.Errorf("%w\nstderr:\n%s", err, stderr.String())
	}
	return string(out), err
}

func (world *realCommandWorld) requireCommand(t *testing.T, home string, args ...string) string {
	t.Helper()
	out, err := world.runInIdentityHome(home, args...)
	if err != nil {
		t.Fatalf("aw %v: %v\n%s", args, err, out)
	}
	return out
}

func (world *realCommandWorld) addLocalMember(t *testing.T, alias string) commandMember {
	t.Helper()
	home := filepath.Join(t.TempDir(), ".aw")
	world.requireCommand(t, home, "id", "create", "--local")
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("loaded signing key did not produce an Ed25519 public key")
	}
	certificate, err := awid.SignTeamCertificate(world.TeamKey, awid.TeamCertificateFields{
		Team: world.TeamID, MemberDIDKey: awid.ComputeDIDKey(public), Alias: alias, IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.Registry.RegisterCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", certificate, world.TeamKey); err != nil {
		t.Fatal(err)
	}
	world.requireCommand(t, home, "id", "team", "install-cert", "--certificate", certificateFile(t, certificate), "--registry", world.Stack.RegistryURL)
	world.requireCommand(t, home, "service", "init", "--service", world.Stack.ServerURL, "--team", world.TeamID)
	return commandMember{Home: home, Certificate: certificate}
}

func TestRealServerWorldsShareOneStackAndKeepTeamsApart(t *testing.T) {
	first, second := newRealCommandWorld(t), newRealCommandWorld(t)
	if first.Stack != second.Stack {
		t.Fatalf("worlds started separate stacks: %+v and %+v", first.Stack, second.Stack)
	}
	if first.Domain == second.Domain || first.TeamID == second.TeamID {
		t.Fatalf("worlds share authority: %s/%s and %s/%s", first.Domain, first.TeamID, second.Domain, second.TeamID)
	}
	alice, bob := first.addLocalMember(t, "alice"), first.addLocalMember(t, "bob")
	otherBob := second.addLocalMember(t, "bob")
	first.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "same-team-only", "--body", "for the first team's bob")
	if inbox := first.requireCommand(t, bob.Home, "mail", "inbox"); !strings.Contains(inbox, "same-team-only") {
		t.Fatalf("first team's bob did not receive mail: %s", inbox)
	}
	if inbox := second.requireCommand(t, otherBob.Home, "mail", "inbox"); strings.Contains(inbox, "same-team-only") {
		t.Fatalf("mail crossed into the second team: %s", inbox)
	}
}

func TestRealServerZoneCommandPublishesOnlyValidNewRecords(t *testing.T) {
	world := newRealCommandWorld(t)
	controller := didOf(newKey(t))
	for _, refused := range []struct{ domain, controller, reason string }{
		{"Upper.test", controller, "zone domain is not a canonical DNS name"},
		{"two words.test", controller, "zone domain is not a canonical DNS name"},
		{freshName(t, "zone-") + ".test", "did:key:znot-a-key", "zone controller is not an Ed25519 did:key"},
		{world.Domain, controller, "zone domain is already published"},
	} {
		err := publishCommandZone(refused.domain, refused.controller)
		if err == nil || !strings.HasSuffix(err.Error(), "refused: "+refused.reason) {
			t.Fatalf("zone %q/%q: got %v, want refusal %q", refused.domain, refused.controller, err, refused.reason)
		}
	}
	// The world's own published namespace still resolves after the refusals.
	member := world.addLocalMember(t, "alice")
	world.requireCommand(t, member.Home, "mail", "send", "--to", "alice", "--subject", "after-refusals", "--body", "stack still serves")
}

func TestRealServerMailChatAndUnregisteredCertificate(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")
	world.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "real-server-mail", "--body", "mail from the real binary")
	if inbox := world.requireCommand(t, bob.Home, "mail", "inbox"); !strings.Contains(inbox, "real-server-mail") || !strings.Contains(inbox, "mail from the real binary") {
		t.Fatalf("real server did not deliver mail: %s", inbox)
	}
	world.requireCommand(t, alice.Home, "chat", "send-and-leave", "bob", "chat from the real binary", "--start-conversation")
	if pending := world.requireCommand(t, bob.Home, "chat", "pending"); !strings.Contains(pending, "chat from the real binary") {
		t.Fatalf("real server did not deliver chat: %s", pending)
	}
	// Same real key/team/alias, but no registry registration for this certificate.
	// This is an older client's unanchored credential, not forged registry state.
	unregistered, err := awid.SignTeamCertificate(world.TeamKey, awid.TeamCertificateFields{
		Team: world.TeamID, MemberDIDKey: alice.Certificate.MemberDIDKey, Alias: alice.Certificate.Alias, IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(alice.Home, world.TeamID, unregistered); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(alice.Home, "mail", "send", "--to", "bob", "--subject", "must-not-arrive", "--body", "unregistered")
	var refused cliErrorEnvelope
	if err == nil || json.Unmarshal([]byte(out), &refused) != nil || refused.Error.Code != "http_error" || refused.Error.HTTPStatus != 401 || refused.Error.Detail != "unregistered" {
		t.Fatalf("unregistered certificate did not get its own HTTP 401 refusal: %v\n%s", err, out)
	}
	if inbox := world.requireCommand(t, bob.Home, "mail", "inbox"); strings.Contains(inbox, "must-not-arrive") {
		t.Fatalf("unregistered sender delivered mail: %s", inbox)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(alice.Home, world.TeamID, alice.Certificate); err != nil {
		t.Fatal(err)
	}
	world.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "still-valid", "--body", "registered sender remains usable")
}
