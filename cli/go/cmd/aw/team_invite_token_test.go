package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw team join takes its invite token from a file or stdin, so the token
// stays out of shell history and process arguments.
func TestTeamJoinTakesTheTokenFromAFileOrStdin(t *testing.T) {
	token, err := awconfig.EncodeInviteToken(&awconfig.TeamInvite{InviteID: "11111111-1111-4111-8111-111111111111", Domain: "acme.com", TeamName: "backend", Secret: "fixture-secret"})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "invite.token")
	if err := os.WriteFile(file, []byte("  "+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	join := func(stdin string, flags ...string) (*cobra.Command, []string, error) {
		cmd := &cobra.Command{}
		cmd.Flags().String("token-file", "", "")
		cmd.Flags().Bool("token-stdin", false, "")
		if err := cmd.Flags().Parse(flags); err != nil {
			t.Fatal(err)
		}
		cmd.SetIn(strings.NewReader(stdin))
		args, err := teamJoinTokenArgs(cmd, cmd.Flags().Args())
		return cmd, args, err
	}
	for _, flags := range [][]string{{"--token-file", file}, {"--token-stdin"}} {
		_, args, err := join(token+"\n", flags...)
		if err != nil || len(args) != 1 || args[0] != token {
			t.Fatalf("%v: args %q err %v", flags, args, err)
		}
	}
	_, args, err := join("", token)
	if err != nil || len(args) != 1 || args[0] != token {
		t.Fatalf("positional token: args %q err %v", args, err)
	}
	for _, flags := range [][]string{
		{"--token-file", file, "--token-stdin"},
		{"--token-file", file, token},
		{"--token-stdin", token},
	} {
		if _, _, err := join(token, flags...); exitCode(err) != 2 {
			t.Fatalf("%v: want a usage refusal, got %v", flags, err)
		}
	}
	missing := filepath.Join(t.TempDir(), "absent.token")
	if _, _, err := join("", "--token-file", missing); exitCode(err) != 2 || !strings.Contains(err.Error(), "--token-file") {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(file, []byte("not a token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := join("", "--token-file", file); exitCode(err) != 2 || strings.Contains(err.Error(), "not a token") {
		t.Fatalf("invalid file contents must refuse without echoing them: %v", err)
	}
}

// A printed invite token admits whoever holds it. The invite says so on
// stderr; stdout keeps its exact output.
func TestTeamInviteWarnsThatThePrintedTokenIsACredential(t *testing.T) {
	t.Parallel()
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)

	run := exec.CommandContext(ctx, bin, "id", "team", "invite", "--team", "backend", "--namespace", "acme.com", "--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout, run.Stderr = &stdout, &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("invite failed: %v\n%s", err, &stderr)
	}
	assertOneJSONDocument(t, stdout.Bytes())
	var out map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || out["token"] == "" {
		t.Fatalf("invite output %s: %v", &stdout, err)
	}
	token, _ := out["token"].(string)
	warning := stderr.String()
	for _, want := range []string{"credential", "--token-file", "--token-stdin"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("stderr %q does not say %q", warning, want)
		}
	}
	if strings.Contains(warning, token) {
		t.Fatal("the warning repeats the token")
	}
}

// The printed join command reads the token from a file, so following the
// invite keeps the token out of shell history; the token itself is printed
// once, on its own line.
func TestTeamInviteCommandReadsTheTokenFromAFile(t *testing.T) {
	for _, tc := range []struct {
		out  teamInviteOutput
		want string
	}{
		{teamInviteOutput{Token: "fixture-token", PorcelainJoin: true}, "Command:     aw team join --token-file <file> --name <name>\n"},
		{teamInviteOutput{Token: "fixture-token"}, "Command:     aw id team accept-invite --token-file <file> --name <name>\n"},
	} {
		got := formatTeamInvite(tc.out)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("missing %q in:\n%s", tc.want, got)
		}
		if strings.Count(got, "fixture-token") != 1 || !strings.Contains(got, "Token:       fixture-token\n") {
			t.Fatalf("the token must appear once, on the Token line:\n%s", got)
		}
	}
}

// The warning names only flags that the printed command has, and says when
// the invite expires when the invite carries an expiry.
func TestTeamInviteWarningFitsThePrintedCommand(t *testing.T) {
	warning := teamInviteTokenWarning("")
	for _, want := range []string{"credential", "--token-file", "--token-stdin", "command below"} {
		if !strings.Contains(warning, want) {
			t.Fatalf("warning %q does not say %q", warning, want)
		}
	}
	if strings.Contains(warning, "aw team join") {
		t.Fatalf("warning names a command the low-level invite does not print: %q", warning)
	}
	// A local invite records no expiry: it is valid until it is used.
	if !strings.Contains(warning, "can join the team until it is used.") || strings.Contains(warning, "expire") {
		t.Fatalf("local invite warning must say it is valid until used, with no expiry: %q", warning)
	}
	if got := teamInviteTokenWarning("2026-11-06T12:00:00Z"); !strings.Contains(got, "2026-11-06T12:00:00Z") {
		t.Fatalf("warning does not say when the invite expires: %q", got)
	}
}

// aw id team accept-invite reads its token from a file too: the flag its
// invite command prints.
func TestAcceptInviteTakesTheTokenFromAFile(t *testing.T) {
	if teamAcceptInviteCmd.Flags().Lookup("token-file") == nil {
		t.Fatal("aw id team accept-invite has no --token-file")
	}
	cmd := &cobra.Command{}
	cmd.Flags().String("token-file", "", "")
	cmd.Flags().Bool("token-stdin", false, "")
	if err := cmd.Flags().Parse([]string{"--token-file", "invite.token"}); err != nil {
		t.Fatal(err)
	}
	if err := teamAcceptInviteCmd.Args(cmd, nil); err != nil {
		t.Fatalf("--token-file without a positional token: %v", err)
	}
	if err := teamAcceptInviteCmd.Args(cmd, []string{"positional"}); exitCode(err) != 2 {
		t.Fatalf("--token-file with a positional token: want a usage refusal, got %v", err)
	}
}
