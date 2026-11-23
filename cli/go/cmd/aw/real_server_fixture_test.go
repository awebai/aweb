package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type commandStack struct {
	RegistryURL string `json:"registry_url"`
	ServerURL   string `json:"server_url"`
}

type commandStackAuthority struct {
	Domain                  string
	ControllerDID           string
	CertificateDestination  string
	LoseCertificateResponse bool
}

func realCommandStack(t *testing.T, ctx context.Context, authority commandStackAuthority) commandStack {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/test-egress/aweb_fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(awTestBinary.sourceDir, "../../server")
	command := exec.CommandContext(ctx, "uv", "run", "--offline", "--frozen", "--project", project, "python", script)
	command.Env = append(append([]string{}, awTestBinary.env...), "AW_COMMAND_DOMAIN="+authority.Domain, "AW_COMMAND_CONTROLLER="+authority.ControllerDID)
	command.Env = append(command.Env, "AW_COMMAND_CERTIFICATE_DESTINATION="+authority.CertificateDestination,
		"AW_COMMAND_CERTIFICATE_RESPONSE_LOSS="+strconv.FormatBool(authority.LoseCertificateResponse))
	command.Stderr = os.Stderr
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := input.Close(); err != nil {
			t.Errorf("close command stack input: %v", err)
		}
		if err := command.Wait(); err != nil {
			t.Errorf("real command stack: %v", err)
		}
	})
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("real command stack exited before publishing readiness")
	}
	var stack commandStack
	if err := json.Unmarshal(scanner.Bytes(), &stack); err != nil {
		t.Fatalf("real command stack readiness: %v", err)
	}
	return stack
}

// realCommandWorld owns setup through the same writers installed clients use.
// R11c: docs/identity.md:97 and docs/identity-messaging-contract.md:434.
type realCommandWorld struct {
	Context      context.Context
	Binary       string
	UserHome     string
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
	return newRealCommandWorldWithRecipientFault(t, "", false)
}

func newRealCommandWorldWithCertificateObstruction(t *testing.T, recipientHome string) *realCommandWorld {
	t.Helper()
	return newRealCommandWorldWithRecipientFault(t, recipientHome, false)
}

func newRealCommandWorldWithRecipientFault(t *testing.T, recipientHome string, loseCertificateResponse bool) *realCommandWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	world := &realCommandWorld{
		Context: ctx, Binary: filepath.Join(t.TempDir(), "aw"),
		UserHome: t.TempDir(),
		Domain:   freshName(t, "commands-") + ".test", NamespaceKey: newKey(t), TeamKey: newKey(t),
	}
	buildAwBinary(t, ctx, world.Binary)
	world.TeamID = awid.BuildTeamID(world.Domain, "backend")
	authority := commandStackAuthority{Domain: world.Domain, ControllerDID: didOf(world.NamespaceKey), LoseCertificateResponse: loseCertificateResponse}
	if recipientHome != "" {
		var err error
		authority.CertificateDestination, err = awconfig.TeamCertificatePathFromIdentityHome(recipientHome, world.TeamID)
		if err != nil {
			t.Fatal(err)
		}
	}
	world.Stack = realCommandStack(t, ctx, authority)
	world.Registry = trustedClient(t, world.Stack.RegistryURL, nil)
	if _, err := world.Registry.RegisterNamespaceAt(ctx, world.Stack.RegistryURL, world.Domain, didOf(world.NamespaceKey), world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := world.Registry.CreateTeam(ctx, world.Stack.RegistryURL, world.Domain, "backend", "Command tests", didOf(world.TeamKey), world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	target, err := resolveTeamRegistrationEndpoint(world.Stack.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeTeamRegisterWithTarget(ctx, world.TeamKey, world.TeamID, target, false, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return world
}

func (world *realCommandWorld) runInIdentityHome(home string, args ...string) (string, error) {
	command := exec.CommandContext(world.Context, world.Binary, append([]string{"--identity-home", home, "--json"}, args...)...)
	command.Dir = filepath.Dir(home)
	command.Env = append(idCreateCommandEnv(world.UserHome), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
	// JSON is a stdout contract; stderr may carry ordinary recovery prose.
	// Keep that diagnostic on the error without mixing it into the envelope.
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	out, err := command.Output()
	if err != nil && diagnostic.Len() != 0 {
		err = fmt.Errorf("%w: %s", err, diagnostic.String())
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
