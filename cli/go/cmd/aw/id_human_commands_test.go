package main

import (
	"bytes"
	"context"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

// These subprocesses exercise the actual command selection and terminal guard.
// No keychain, issuer, registry or browser is substituted. Reaching any of those
// before refusing a missing human terminal would cross the custody boundary.
func TestHumanEnrollmentRegistrationAndProofRequireHumanCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	commands := map[string][]string{
		"parent request":      {"id", "parent", "request", "--root-parent", "--invitation-id", "no-file"},
		"child approve":       {"id", "child", "approve", "no-file"},
		"revoke":              {"id", "revoke", "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"},
		"create human parent": {"id", "create", "--name", "child", "--domain", "example.com", "--human-parent", "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"},
		"add":                 {"id", "human", "add", "--issuer", "https://issuer.example.invalid", "--person", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "--identity-key", "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"},
		"enroll":              {"id", "human", "enroll", "--issuer", "https://issuer.example.invalid"},
		"register":            {"id", "human", "register", "issued.json"},
		"proof":               {"id", "proof", "--message-file", "message.txt"},
	}
	for name, args := range commands {
		for _, terminal := range []bool{false, true} {
			label := "without terminal"
			want := "needs a human at an interactive terminal"
			if terminal {
				label = "agent at terminal"
				want = "refuses inside an agent runtime"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				home := t.TempDir()
				before := homeContents(t, home)
				argv := append([]string{"--human", "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj", "--human-domain", "example.com"}, args...)
				cmd := exec.CommandContext(ctx, bin, argv...)
				cmd.Dir, cmd.Env = home, testCommandEnv(home)
				var output bytes.Buffer
				var err error
				if terminal {
					cmd.Env = append(cmd.Env, "OATS_INSTANCE=human-custody-control")
					tty, startErr := pty.Start(cmd)
					if startErr != nil {
						t.Fatal(startErr)
					}
					done := make(chan struct{})
					go func() { _, _ = io.Copy(&output, tty); close(done) }()
					err = cmd.Wait()
					_ = tty.Close()
					<-done
				} else {
					configureHumanInitWithoutTerminal(cmd)
					cmd.Stdout, cmd.Stderr = &output, &output
					err = cmd.Run()
				}
				if err == nil || !strings.Contains(output.String(), want) {
					t.Fatalf("want %q; err=%v, output=%s", want, err, output.String())
				}
				if !maps.Equal(before, homeContents(t, home)) {
					t.Fatal("refusal changed the person's home")
				}
				if _, err := os.Stat(filepath.Join(home, ".aw", "signing.key")); !os.IsNotExist(err) {
					t.Fatal("human operation created an agent signing key")
				}
			})
		}
	}
}
