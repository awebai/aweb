package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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

// sharedCommandStackDeadlines bound the package stack. A cold start took
// 12.8 s locally.
var sharedCommandStackDeadlines = commandStackDeadlines{Ready: 2 * time.Minute, Command: 30 * time.Second, Stop: time.Minute}

// sharedCommandStack is the package's one real aweb/AWID stack
// (scripts/test-egress/aweb_fixture.py). It starts on first use and
// stopSharedCommandStack ends it from TestMain after every test has run.
// Tests are isolated by data: each world publishes its own domain's DNS record
// and registers its own namespace and team.
var sharedCommandStack struct {
	once    sync.Once
	err     error
	stack   commandStack
	process *commandStackProcess
}

func packageCommandStack(t *testing.T) commandStack {
	t.Helper()
	sharedCommandStack.once.Do(func() { sharedCommandStack.err = startSharedCommandStack() })
	if sharedCommandStack.err != nil {
		t.Fatal(sharedCommandStack.err)
	}
	return sharedCommandStack.stack
}

func startSharedCommandStack() error {
	// From the package source, not the working directory: the test that
	// starts the stack may have changed directory.
	script := filepath.Join(awTestBinary.sourceDir, "../../scripts/test-egress/aweb_fixture.py")
	project := filepath.Join(awTestBinary.sourceDir, "../../server")
	// No test's context: the stack outlives every test that uses it.
	command := exec.Command("uv", "run", "--offline", "--frozen", "--project", project, "python", "-P", script)
	services, err := packageServicesEnv()
	if err != nil {
		return err
	}
	command.Env = append(append([]string{}, awTestBinary.env...), services...)
	command.Stderr = os.Stderr
	started := time.Now()
	process, line, err := startCommandStackProcess(command, sharedCommandStackDeadlines)
	if err != nil {
		return fmt.Errorf("real command stack: %w", err)
	}
	sharedCommandStack.process = process
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sharedCommandStack.stack); err != nil || sharedCommandStack.stack.RegistryURL == "" || sharedCommandStack.stack.ServerURL == "" {
		return process.fail(fmt.Errorf("real command stack readiness %q is not its two origins: %v", line, err))
	}
	fmt.Fprintf(os.Stderr, "shared real command stack start: %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

// commandZone is one domain's _awid record in the stack's DNS zone.
type commandZone struct {
	Domain     string `json:"domain"`
	Controller string `json:"controller"`
}

// publishCommandZone publishes zone's record. It writes nothing to the
// registry.
func publishCommandZone(zone commandZone) error {
	return sendStackCommand(stackZone, zone)
}

// sendStackCommand sends one command to the package stack and waits for its
// own acknowledgement.
func sendStackCommand(operation stackOperation, value any) error {
	if sharedCommandStack.process == nil {
		return fmt.Errorf("real command stack is not running: %v", sharedCommandStack.err)
	}
	return sharedCommandStack.process.send(operation, value)
}

// stopSharedCommandStack shuts the package stack down, which stops its
// services and drops its database, and kills anything it left running.
func stopSharedCommandStack() error {
	if sharedCommandStack.process == nil {
		return nil
	}
	return sharedCommandStack.process.stop()
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

// commandWorldAdmission serializes world setup on the shared stack. Each world
// resets the registry's rate-limit buckets as it starts, which gives it the
// fresh buckets its own stack would have had only while worlds run one after
// another; no world test runs in parallel, and admission never overlaps.
var commandWorldAdmission sync.Mutex

func newRealCommandWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	commandWorldAdmission.Lock()
	defer commandWorldAdmission.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	world := &realCommandWorld{
		Context: ctx, Binary: filepath.Join(t.TempDir(), "aw"),
		Domain: freshName(t, "commands-") + ".test", NamespaceKey: newKey(t), TeamKey: newKey(t),
	}
	buildAwBinary(t, ctx, world.Binary)
	world.Stack = packageCommandStack(t)
	// Fresh production rate-limit buckets: every test reaches the shared
	// registry from the same address (see commandWorldAdmission).
	if err := sendStackCommand(stackResetRateLimits, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := publishCommandZone(commandZone{Domain: world.Domain, Controller: didOf(world.NamespaceKey)}); err != nil {
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

// registerMemberCertificate signs fields' certificate with the team key and
// registers it at the registry, as the team controller does.
func (world *realCommandWorld) registerMemberCertificate(t *testing.T, fields awid.TeamCertificateFields) *awid.TeamCertificate {
	t.Helper()
	fields.Team = world.TeamID
	certificate, err := awid.SignTeamCertificate(world.TeamKey, fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.Registry.RegisterCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", certificate, world.TeamKey); err != nil {
		t.Fatal(err)
	}
	return certificate
}

// globalMember is a key with its registered did:aw and its address in the
// world's namespace.
type globalMember struct {
	Key     ed25519.PrivateKey
	DIDKey  string
	DIDAW   string
	Address string
}

func (world *realCommandWorld) registerGlobalMember(t *testing.T, name string) globalMember {
	t.Helper()
	key := newKey(t)
	member := globalMember{Key: key, DIDKey: didOf(key), DIDAW: awid.ComputeStableID(key.Public().(ed25519.PublicKey))}
	if _, err := world.Registry.RegisterIdentity(world.Context, world.Stack.RegistryURL, member.DIDKey, member.DIDAW, key); err != nil {
		t.Fatal(err)
	}
	if _, err := world.Registry.RegisterAddressAt(world.Context, world.Stack.RegistryURL, world.Domain, name, member.DIDAW, member.DIDKey, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	member.Address = world.Domain + "/" + name
	return member
}

// aliasCertificates is the registry's whole certificate history for alias,
// revoked certificates included.
func (world *realCommandWorld) aliasCertificates(t *testing.T, alias string) []awid.RegistryCertificate {
	t.Helper()
	all, err := world.Registry.ListCertificates(world.Context, world.Stack.RegistryURL, world.Domain, "backend", false, world.TeamKey)
	if err != nil {
		t.Fatal(err)
	}
	var out []awid.RegistryCertificate
	for _, certificate := range all {
		if certificate.Alias == alias {
			out = append(out, certificate)
		}
	}
	return out
}

// registryFault fronts the shared registry for answers the real registry
// cannot give on demand, such as a write that fails after its precondition
// held. Every request it does not answer reaches the real registry, and every
// answer it does not rewrite reaches the command as the registry gave it.
type registryFault struct {
	// Answer, when it returns true, has answered r in place of the registry.
	Answer func(w http.ResponseWriter, r *http.Request) bool
	// Rewrite edits a registry response before the command reads it.
	Rewrite func(response *http.Response) error
}

// frontRegistry returns the origin of a proxy that applies fault in front of
// the world's registry.
func (world *realCommandWorld) frontRegistry(t *testing.T, fault registryFault) string {
	t.Helper()
	target, err := url.Parse(world.Stack.RegistryURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	direct := proxy.Director
	proxy.Director = func(r *http.Request) {
		direct(r)
		r.Host = target.Host
	}
	proxy.ModifyResponse = fault.Rewrite
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fault.Answer != nil && fault.Answer(w, r) {
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	// Controller envelopes name the origin the client writes to, as they do
	// through a deployment's proxy.
	if err := sendStackCommand(stackPublicOrigin, server.URL); err != nil {
		t.Fatal(err)
	}
	return server.URL
}

// registryAnswer is one registry answer as a command met it: the did:key that
// signed the request ("" when unsigned) and the registry's status.
type registryAnswer struct {
	Signer string
	Status int
}

// registryRecording observes the real registry's answers to a command; it
// answers nothing itself.
type registryRecording struct {
	mu      sync.Mutex
	answers []registryAnswer
}

func (recording *registryRecording) Answers() []registryAnswer {
	recording.mu.Lock()
	defer recording.mu.Unlock()
	return append([]registryAnswer(nil), recording.answers...)
}

// recordRegistry returns the origin of a front that records every answer the
// world's registry gives through it.
func (world *realCommandWorld) recordRegistry(t *testing.T) (string, *registryRecording) {
	t.Helper()
	recording := &registryRecording{}
	origin := world.frontRegistry(t, registryFault{Rewrite: func(response *http.Response) error {
		signer := ""
		if parts := strings.Fields(response.Request.Header.Get("Authorization")); len(parts) == 3 && parts[0] == "DIDKey" {
			signer = parts[1]
		}
		recording.mu.Lock()
		defer recording.mu.Unlock()
		recording.answers = append(recording.answers, registryAnswer{Signer: signer, Status: response.StatusCode})
		return nil
	}})
	return origin, recording
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
	const notCanonical = "zone domain is not a canonical DNS name. Send lowercase ASCII labels with no trailing dot."
	for _, refused := range []struct {
		zone   commandZone
		reason string
	}{
		{zone: commandZone{Domain: "Upper.test", Controller: controller}, reason: notCanonical},
		{zone: commandZone{Domain: "two words.test", Controller: controller}, reason: notCanonical},
		{zone: commandZone{Domain: freshName(t, "zone-") + ".test", Controller: "did:key:znot-a-key"}, reason: "zone controller is not an Ed25519 did:key. Send the namespace controller's did:key."},
		{zone: commandZone{Domain: world.Domain, Controller: controller}, reason: "zone domain is already published. Use a fresh domain for each world."},
	} {
		err := publishCommandZone(refused.zone)
		if err == nil || err.Error() != "zone command refused: "+refused.reason {
			t.Fatalf("zone %+v: got %v, want refusal %q", refused.zone, err, refused.reason)
		}
	}
	// The world's own published namespace still resolves after the refusals.
	member := world.addLocalMember(t, "alice")
	world.requireCommand(t, member.Home, "mail", "send", "--to", "alice", "--subject", "after-refusals", "--body", "stack still serves")
}

func TestRealServerStackRefusesMalformedConfigurationCommands(t *testing.T) {
	newRealCommandWorld(t)
	const notLoopback = "public_origin is not a canonical http://127.0.0.1 origin. Send the front's origin as http://127.0.0.1:<port>."
	for _, refused := range []struct {
		operation stackOperation
		value     any
		reason    string
	}{
		{operation: stackPublicOrigin, value: "https://registry.example", reason: notLoopback},
		{operation: stackPublicOrigin, value: "http://127.0.0.1:8080/path", reason: notLoopback},
		{operation: stackResetRateLimits, value: map[string]any{"bucket": "all"}, reason: "reset_rate_limits takes an empty object. Send {'reset_rate_limits': {}}."},
		// An operation the fixture does not define, as an older or newer
		// harness could send.
		{operation: stackOperation("seed_certificate"), value: map[string]any{}, reason: "command names no single known operation. Send exactly one of zone, public_origin or reset_rate_limits."},
	} {
		err := sendStackCommand(refused.operation, refused.value)
		if err == nil || err.Error() != string(refused.operation)+" command refused: "+refused.reason {
			t.Fatalf("%s %v: got %v, want refusal %q", refused.operation, refused.value, err, refused.reason)
		}
	}
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
