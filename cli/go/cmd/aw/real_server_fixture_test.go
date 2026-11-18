package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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

func realCommandStack(t *testing.T, ctx context.Context, domain, controller string) commandStack {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/test-egress/aweb_fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(awTestBinary.sourceDir, "../../server")
	command := exec.CommandContext(ctx, "uv", "run", "--offline", "--frozen", "--project", project, "python", script)
	command.Env = append(append([]string{}, awTestBinary.env...), "AW_COMMAND_DOMAIN="+domain, "AW_COMMAND_CONTROLLER="+controller)
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
		_ = input.Close()
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

func TestRealServerMailChatAndUnregisteredCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	domain, namespaceKey, teamKey := "commands.test", newKey(t), newKey(t)
	stack := realCommandStack(t, ctx, domain, didOf(namespaceKey))
	registry := trustedClient(t, stack.RegistryURL, nil)
	if _, err := registry.RegisterNamespaceAt(ctx, stack.RegistryURL, domain, didOf(namespaceKey), namespaceKey); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateTeam(ctx, stack.RegistryURL, domain, "backend", "Command tests", didOf(teamKey), namespaceKey); err != nil {
		t.Fatal(err)
	}
	teamID := awid.BuildTeamID(domain, "backend")
	target, err := resolveTeamRegistrationEndpoint(stack.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeTeamRegisterWithTarget(ctx, teamKey, teamID, target, false, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	run := func(home string, args ...string) (string, error) {
		t.Helper()
		command := exec.CommandContext(ctx, bin, append([]string{"--identity-home", home, "--json"}, args...)...)
		command.Dir = filepath.Dir(home)
		command.Env = append(idCreateCommandEnv(filepath.Dir(home)), "AWID_REGISTRY_URL="+stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
		out, err := command.CombinedOutput()
		return string(out), err
	}
	mustRun := func(home string, args ...string) string {
		t.Helper()
		out, err := run(home, args...)
		if err != nil {
			t.Fatalf("aw %v: %v\n%s", args, err, out)
		}
		return out
	}
	add := func(alias string) (string, *awid.TeamCertificate) {
		t.Helper()
		home := filepath.Join(t.TempDir(), ".aw")
		mustRun(home, "id", "create", "--local")
		key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
			Team: teamID, MemberDIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), Alias: alias, IdentityScope: "local",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.RegisterCertificate(ctx, stack.RegistryURL, domain, "backend", cert, teamKey); err != nil {
			t.Fatal(err)
		}
		mustRun(home, "id", "team", "install-cert", "--certificate", certificateFile(t, cert), "--registry", stack.RegistryURL)
		mustRun(home, "service", "init", "--service", stack.ServerURL, "--team", teamID)
		return home, cert
	}
	alice, certificate := add("alice")
	bob, _ := add("bob")
	mustRun(alice, "mail", "send", "--to", "bob", "--subject", "real-server-mail", "--body", "mail from the real binary")
	if inbox := mustRun(bob, "mail", "inbox"); !strings.Contains(inbox, "real-server-mail") || !strings.Contains(inbox, "mail from the real binary") {
		t.Fatalf("real server did not deliver mail: %s", inbox)
	}
	mustRun(alice, "chat", "send-and-leave", "bob", "chat from the real binary", "--start-conversation")
	if pending := mustRun(bob, "chat", "pending"); !strings.Contains(pending, "chat from the real binary") {
		t.Fatalf("real server did not deliver chat: %s", pending)
	}
	// Same real key/team/alias, but no registry registration for this certificate.
	// This is an older client's unanchored credential, not forged registry state.
	unregistered, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: teamID, MemberDIDKey: certificate.MemberDIDKey, Alias: certificate.Alias, IdentityScope: "local",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(alice, teamID, unregistered); err != nil {
		t.Fatal(err)
	}
	out, err := run(alice, "mail", "send", "--to", "bob", "--subject", "must-not-arrive", "--body", "unregistered")
	var refused cliErrorEnvelope
	if err == nil || json.Unmarshal([]byte(out), &refused) != nil || refused.Error.Code != "http_error" || refused.Error.HTTPStatus != 401 || refused.Error.Detail != "unregistered" {
		t.Fatalf("unregistered certificate did not get its own HTTP 401 refusal: %v\n%s", err, out)
	}
	if inbox := mustRun(bob, "mail", "inbox"); strings.Contains(inbox, "must-not-arrive") {
		t.Fatalf("unregistered sender delivered mail: %s", inbox)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(alice, teamID, certificate); err != nil {
		t.Fatal(err)
	}
	mustRun(alice, "mail", "send", "--to", "bob", "--subject", "still-valid", "--body", "registered sender remains usable")
}
