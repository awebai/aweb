package main

import (
	"strings"
	"testing"
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
