package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The verb table from docs/beads-mail-delegate.md §6. Stub verbs are declared
// implemented there and answer "not implemented yet" until their subtask
// lands; unsupported verbs answer their decided message. The production-binary
// run below is the identity-home allowlist evidence required by
// identity_home_policy.go: every beads-mail path must behave identically with
// an external principal and an empty instance, never falling back to instance
// state and never being refused as not identity-home-aware.
//
// This evidence is ROUTER-ONLY: stubs touch no identity or network state, so
// passing here does not show a verb consumes the selected principal. Each verb
// that gains real behavior must add dual-backend consumption evidence in its
// own subtask, per the TestExternalIdentityHomeTaskAndWorkCommandsUseSelected-
// Principal pattern in task_identity_home_test.go.
var beadsMailVerbExpectations = []struct {
	args     []string
	fragment string
}{
	{[]string{"send", "someone/", "-s", "hi"}, "not mapped to an aweb address"},
	{[]string{"send", "someone/"}, "subject"},
	{[]string{"send", "x/", "--from", "spoof"}, "cryptographic"},
	{[]string{"send", "x/", "--cc", "y/", "-s", "hi"}, "send to each recipient separately"},
	{[]string{"inbox", "other/"}, "one aweb identity"},
	{[]string{"read"}, "usage: bd mail read"},
	{[]string{"show"}, "usage: bd mail read"},
	{[]string{"thread"}, "usage: bd mail thread"},
	{[]string{"mark-read"}, "or --all"},
	{[]string{"reply"}, "usage: bd mail reply"},
	{[]string{"check", "other/"}, "one aweb identity"},
	{[]string{"ack"}, "or --all"},
	{[]string{"mark-unread", "msg-1"}, "no way to clear read state"},
	{[]string{"archive"}, "the durable record is your beads graph"},
	{[]string{"delete", "msg-1"}, "cannot be deleted from the aweb server"},
	{[]string{"clear"}, "cannot be deleted from the aweb server"},
	{[]string{"search", "query"}, "no mail search"},
	{[]string{"claim"}, "no claimable queues"},
	{[]string{"release", "msg-1"}, "no claimable queues"},
	{[]string{"announces"}, "no announce channels"},
	{[]string{"drain"}, "mark-read --all"},
}

func TestBeadsMailVerbRouterProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	// External principal home with deliberately unreadable state, plus an
	// empty instance directory: the frame must answer from its own routing
	// without touching either (identity_home_policy.go's evidence bar).
	principalHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(principalHome, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"identity.yaml":  "not: [valid identity yaml",
		"signing.key":    "not a signing key",
		"workspace.yaml": "not: [valid workspace yaml",
	} {
		if err := os.WriteFile(filepath.Join(principalHome, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyInstance := filepath.Join(root, "instance")
	if err := os.MkdirAll(emptyInstance, 0o700); err != nil {
		t.Fatal(err)
	}

	run := func(identityHome bool, args ...string) (string, error) {
		full := []string{}
		if identityHome {
			full = append(full, "--identity-home", principalHome)
		}
		full = append(full, "beads-mail")
		full = append(full, args...)
		cmd := exec.CommandContext(ctx, bin, full...)
		cmd.Dir = emptyInstance
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	for _, external := range []bool{false, true} {
		for _, tc := range beadsMailVerbExpectations {
			out, err := run(external, tc.args...)
			if err == nil {
				t.Errorf("external=%v %v: expected nonzero exit, got success:\n%s", external, tc.args, out)
				continue
			}
			if !strings.Contains(out, tc.fragment) {
				t.Errorf("external=%v %v: output missing %q:\n%s", external, tc.args, tc.fragment, out)
			}
			if strings.Contains(out, "identity-home-aware") {
				t.Errorf("external=%v %v: refused by identity-home policy instead of answering:\n%s", external, tc.args, out)
			}
		}
	}

	// Per-verb help must be reachable through the delegate: bd swallows
	// --help in 'bd mail <verb> --help', so 'bd mail help <verb>' (a plain
	// arg) is the documented path, and -h inside a verb's own args works
	// because flag parsing is disabled on the verbs.
	if out, err := run(false, "help", "send"); err != nil || !strings.Contains(out, "--subject") {
		t.Errorf("help send: err=%v output:\n%s", err, out)
	}
	if out, err := run(false, "send", "--help"); err != nil || !strings.Contains(out, "--subject") {
		t.Errorf("send --help: err=%v output:\n%s", err, out)
	}
	if out, err := run(false, "help", "no-such-verb"); err == nil || !strings.Contains(out, "unknown beads-mail verb") {
		t.Errorf("help no-such-verb: err=%v output:\n%s", err, out)
	}

	// Unknown verbs fail loudly (refuseUnknownSubcommands), and the bare
	// command shows help and exits 0, which is how 'bd mail' with a
	// configured delegate and no args presents us.
	if out, err := run(false, "frobnicate"); err == nil || !strings.Contains(out, "unknown command") {
		t.Errorf("unknown verb: err=%v output:\n%s", err, out)
	}
	if out, err := run(false); err != nil || !strings.Contains(out, "bd config set mail.delegate") {
		t.Errorf("bare beads-mail: err=%v output:\n%s", err, out)
	}
}

func TestBeadsMailPathsAllAllowlisted(t *testing.T) {
	for _, sub := range beadsMailCmd.Commands() {
		path := strings.TrimSpace(sub.CommandPath())
		if _, ok := identityHomeAwareCommandPaths[path]; !ok {
			t.Errorf("beads-mail verb %q is missing from identityHomeAwareCommandPaths", path)
		}
	}
}
