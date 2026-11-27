package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// aweb-aaun.7: a shipped binary reported a commit that resolves in no repository the
// reader has. The stamp is goreleaser's commit for the repository the release is built
// from - awebai/aw, a derived copy - while the source is developed in awebai/aweb. The
// hash is correct and unresolvable where anyone looks, so the version output has to name
// the repository it belongs to.

func withVersionVars(t *testing.T, v, c, repo, d string) {
	t.Helper()
	ov, oc, orepo, od := version, commit, commitRepo, date
	t.Cleanup(func() { version, commit, commitRepo, date = ov, oc, orepo, od })
	version, commit, commitRepo, date = v, c, repo, d
}

func TestVersionReportNamesTheRepositoryTheCommitResolvesIn(t *testing.T) {
	withVersionVars(t, "1.34.1",
		"ccb3001e3f36f0cc502b3f1d6ff20ff7512e8f97",
		"github.com/awebai/aw",
		"2026-07-29T06:38:41Z")

	got := versionReport()
	want := "commit: ccb3001e3f36f0cc502b3f1d6ff20ff7512e8f97 (github.com/awebai/aw)"
	if !strings.Contains(got, want) {
		t.Fatalf("version output does not say where the commit resolves, so a reader cannot\n"+
			"reach the source from the binary.\nwant line containing: %s\ngot:\n%s", want, got)
	}
}

// The other direction: a build that was not told its origin must not invent one. An
// unstamped local build prints the bare hash, which is honest, rather than claiming it
// came from the release repository.
func TestVersionReportClaimsNoOriginWhenItWasNotGivenOne(t *testing.T) {
	withVersionVars(t, "dev", "abc1234", "", "unknown")

	got := versionReport()
	if !strings.Contains(got, "commit: abc1234") {
		t.Fatalf("expected the bare commit line, got:\n%s", got)
	}
	if strings.Contains(got, "(") {
		t.Fatalf("version output named an origin it was never given:\n%s", got)
	}
}

// OATS resolves its CLI compatibility from the first aw version line.
func TestVersionReportStartsWithCLIVersion(t *testing.T) {
	withVersionVars(t, "1.36.50", "abc1234", "github.com/awebai/aw", "2026-10-27T00:00:00Z")
	first, _, ok := strings.Cut(versionReport(), "\n")
	if !ok || first != "aw 1.36.50" {
		t.Fatalf("first version line must identify the CLI: %q", first)
	}
}

// The framework reads aw's version before anything else, from the binary it will
// run, so the JSON answer has exactly these keys and states an unstamped value as
// an empty string.
func TestVersionAnswerKeys(t *testing.T) {
	for _, tc := range []struct {
		name             string
		v, c, repo, date string
		want             versionAnswer
	}{
		{"stamped release", "1.36.60", "ccb3001e3f36f0cc502b3f1d6ff20ff7512e8f97", "github.com/awebai/aw", "2026-11-26T00:00:00Z",
			versionAnswer{Version: "1.36.60", Commit: "ccb3001e3f36f0cc502b3f1d6ff20ff7512e8f97", CommitRepo: "github.com/awebai/aw", Built: "2026-11-26T00:00:00Z"}},
		{"unstamped build", "dev", "none", "", "unknown", versionAnswer{Version: "dev"}},
		{"commit without origin", "dev", "abc1234", "", "unknown", versionAnswer{Version: "dev", Commit: "abc1234"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withVersionVars(t, tc.v, tc.c, tc.repo, tc.date)
			if got := currentVersionAnswer(); got != tc.want {
				t.Fatalf("answer=%+v, want %+v", got, tc.want)
			}
		})
	}
}

// aw version --json answers with no identity selection, no update check and no
// network: here the selected identity home is a relative path, which every
// identity-preparing command refuses, text aw version included.
func TestVersionJSONNeedsNoIdentityProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	const unusable = "relative/.aw"
	for _, tc := range []struct {
		name string
		env  string
		args []string
	}{
		{"clean directory", "", []string{"version", "--json"}},
		{"unusable inherited home", unusable, []string{"version", "--json"}},
		{"json flag first", unusable, []string{"--json", "version"}},
		{"unusable selected home", "", []string{"--identity-home", unusable, "version", "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := exec.CommandContext(ctx, bin, tc.args...)
			run.Dir = t.TempDir()
			run.Env = append(testCommandEnv(tmp), "AWEB_IDENTITY_HOME="+tc.env, "AW_NO_UPDATE_CHECK=")
			var stdout, stderr bytes.Buffer
			run.Stdout, run.Stderr = &stdout, &stderr
			if err := run.Run(); err != nil {
				t.Fatalf("version --json failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("version --json wrote to stderr: %q", stderr.String())
			}
			var answer map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &answer); err != nil {
				t.Fatalf("version --json is not one JSON object: %v\n%s", err, stdout.String())
			}
			keys := make([]string, 0, len(answer))
			for key, value := range answer {
				if _, ok := value.(string); !ok {
					t.Fatalf("%s is %T, want string", key, value)
				}
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if got := strings.Join(keys, ","); got != "built,commit,commit_repo,version" {
				t.Fatalf("keys=%s", got)
			}
			if answer["version"] == "" {
				t.Fatalf("version is empty: %s", stdout.String())
			}
		})
	}
}
