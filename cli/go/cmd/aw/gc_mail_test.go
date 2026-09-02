package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestGCMailSubjectFallsBackToFirstBodyLine(t *testing.T) {
	if got := gcMailSubject("  Water levels  ", "body"); got != "Water levels" {
		t.Errorf("explicit subject = %q", got)
	}
	if got := gcMailSubject("", "the well is low\nsecond line"); got != "the well is low" {
		t.Errorf("derived subject = %q", got)
	}
	if got := gcMailSubject("", "   "); got != "(no subject)" {
		t.Errorf("empty body subject = %q", got)
	}
	long := strings.Repeat("x", 200)
	got := gcMailSubject("", long)
	if !strings.HasSuffix(got, "...") || len([]rune(got)) != 75 {
		t.Errorf("long subject = %q (%d runes)", got, len([]rune(got)))
	}
}

func TestGCMailNormalizeTimestampNeverBreaksTheMessage(t *testing.T) {
	// gc decodes created_at into a time.Time, so an unparseable value would
	// fail the WHOLE message decode. Dropping the field costs a timestamp.
	if got := gcMailNormalizeTimestamp("2026-09-02T11:43:10Z"); got != "2026-09-02T11:43:10Z" {
		t.Errorf("rfc3339 = %q", got)
	}
	if got := gcMailNormalizeTimestamp("2026-09-02T11:43:10.5"); got != "2026-09-02T11:43:10.5Z" {
		t.Errorf("naive = %q", got)
	}
	if got := gcMailNormalizeTimestamp("last tuesday"); got != "" {
		t.Errorf("garbage = %q, want dropped", got)
	}
	if got := gcMailNormalizeTimestamp(""); got != "" {
		t.Errorf("empty = %q", got)
	}
}

func TestGCMailWireSanitizesAndRoundTripsIdentities(t *testing.T) {
	msg := &awid.InboxMessage{
		MessageID:      "m-1",
		ConversationID: "c-1",
		FromAddress:    "acme.aweb.ai/mayor",
		FromAlias:      "mayor",
		ToAddress:      "beta.aweb.ai/deacon",
		Subject:        "hi\x1b[31m",
		Body:           "line one\nline\ttwo\x1b]0;title\x07",
		CreatedAt:      "2026-09-02T11:43:10Z",
	}
	wire := gcMailWire(msg)
	if wire.From != "acme.aweb.ai/mayor" || wire.To != "beta.aweb.ai/deacon" {
		t.Errorf("identities = %q -> %q; the verified address must win over the alias so the label re-resolves as a recipient", wire.From, wire.To)
	}
	if strings.Contains(wire.Subject, "\x1b") || strings.Contains(wire.Body, "\x1b") {
		t.Errorf("escape survived sanitization: subject=%q body=%q", wire.Subject, wire.Body)
	}
	if !strings.Contains(wire.Body, "line one\nline\ttwo") {
		t.Errorf("newline/tab did not survive: %q", wire.Body)
	}
	if wire.Read {
		t.Error("ReadAt nil must render read=false")
	}
	if wire.ThreadID != "c-1" {
		t.Errorf("thread_id = %q, want the aweb conversation id", wire.ThreadID)
	}
	// Every label this provider emits must resolve back through the §4 order.
	if _, err := resolveDelegateMailRecipient(delegateMailAddressMap{entries: map[string]string{}, spec: gcMailMapSpec}, wire.From); err != nil {
		t.Errorf("emitted from %q does not resolve as a recipient: %v", wire.From, err)
	}
}

func TestGCMailWireIsGCsMessageShape(t *testing.T) {
	// The field names are gc's mail.Message JSON tags; a rename on either side
	// silently drops data, so pin them.
	encoded, err := json.Marshal(gcMailWire(&awid.InboxMessage{MessageID: "m-1", FromAddress: "a.aweb.ai/x", ToAddress: "b.aweb.ai/y", Subject: "s", Body: "b", CreatedAt: "2026-09-02T11:43:10Z", ConversationID: "c-1"}))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "from", "to", "subject", "body", "created_at", "read", "thread_id"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("wire message is missing %q: %s", key, encoded)
		}
	}
	for _, key := range []string{"reply_to", "priority", "cc", "rig"} {
		if _, ok := decoded[key]; ok {
			t.Errorf("wire message emits %q, which aweb cannot honestly fill", key)
		}
	}
}

func TestGCMailErrorsNeverExitTwo(t *testing.T) {
	// gc's exec provider converts exit code 2 into SUCCESS WITH EMPTY OUTPUT
	// ("unknown operation"). A known operation that fails with exit 2 would be
	// reported to the user as having worked.
	if code := exitCode(gcMailError("boom")); code != 1 {
		t.Errorf("gcMailError exit code = %d, want 1", code)
	}
	if code := exitCode(gcMailNotFound("m-1")); code != 1 {
		t.Errorf("gcMailNotFound exit code = %d, want 1", code)
	}
	if code := exitCode(gcMailForceExitCode(usageError("shared helper usage error"))); code != 1 {
		t.Errorf("gcMailForceExitCode(usageError) = %d, want 1", code)
	}
	if got := gcMailForceExitCode(nil); got != nil {
		t.Errorf("gcMailForceExitCode(nil) = %v", got)
	}
	if code := exitCode(gcMailForceExitCode(&cliError{code: 3, msg: "x"})); code != 3 {
		t.Errorf("non-2 codes must pass through, got %d", code)
	}
}

func TestGCMailNotFoundCarriesGCsProtocolMarker(t *testing.T) {
	// exec.go's normalizeMessageError greps stderr for this exact token to
	// produce mail.ErrNotFound instead of a generic backend failure.
	if !strings.Contains(gcMailNotFound("m-1").Error(), "gc-mail-error:not-found") {
		t.Errorf("not-found error lost the marker: %v", gcMailNotFound("m-1"))
	}
}

func TestGCMailRefusalsAvoidGCsAlreadyArchivedMarker(t *testing.T) {
	// exec.go maps any archive/delete error containing "already archived" onto
	// mail.ErrAlreadyArchived, which gc reports as "Already archived <id>" —
	// a success line. Our refusals must not trip it.
	for _, sub := range gcMailCmd.Commands() {
		name := strings.Fields(sub.Use)[0]
		if name != "archive" && name != "delete" {
			continue
		}
		err := sub.RunE(sub, []string{"m-1"})
		if err == nil {
			t.Fatalf("%s must refuse, not succeed", name)
		}
		if strings.Contains(err.Error(), "already archived") {
			t.Errorf("%s refusal contains gc's already-archived marker: %v", name, err)
		}
		if exitCode(err) != 1 {
			t.Errorf("%s refusal exit code = %d, want 1 (2 would read as success)", name, exitCode(err))
		}
	}
}

func TestGCMailReservedNamesRequireAnExplicitMapping(t *testing.T) {
	empty := delegateMailAddressMap{entries: map[string]string{}, spec: gcMailMapSpec}
	for _, name := range []string{"human", "controller", "Human"} {
		if _, err := resolveGCMailRecipient(empty, name); err == nil {
			t.Errorf("%q resolved without a mapping; gc's reserved names must never fall through to a same-team alias lookup", name)
		} else if !strings.Contains(err.Error(), ".gc/aweb-mail.toml") {
			t.Errorf("%q error does not name the map file: %v", name, err)
		}
	}
	mapped := delegateMailAddressMap{entries: map[string]string{"human": "acme.aweb.ai/juan"}, spec: gcMailMapSpec}
	target, err := resolveGCMailRecipient(mapped, "human")
	if err != nil || target.Value != "acme.aweb.ai/juan" || !target.Mapped {
		t.Errorf("mapped human = %+v, err=%v", target, err)
	}
}

func TestGCMailResolutionReusesTheBeadsOrder(t *testing.T) {
	m := delegateMailAddressMap{entries: map[string]string{"myrig/witness": "acme.aweb.ai/witness"}, spec: gcMailMapSpec, path: ".gc/aweb-mail.toml"}
	cases := []struct{ in, kind, value string }{
		{"myrig/witness", "address", "acme.aweb.ai/witness"},
		{"acme.aweb.ai/reviewer", "address", "acme.aweb.ai/reviewer"},
		{"@handle/agent", "address", "handle.aweb.ai/agent"},
		{"did:aw:abc", "did", "did:aw:abc"},
		{"reviewer", "alias", "reviewer"},
	}
	for _, tc := range cases {
		got, err := resolveGCMailRecipient(m, tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got.Kind != tc.kind || got.Value != tc.value {
			t.Errorf("%q = %s/%s, want %s/%s", tc.in, got.Kind, got.Value, tc.kind, tc.value)
		}
	}
	// A rig-style name gc accepts but the map does not know is the one error a
	// gc user meets before reading any documentation.
	_, err := resolveGCMailRecipient(m, "otherrig/deacon")
	if err == nil || !strings.Contains(err.Error(), ".gc/aweb-mail.toml") || !strings.Contains(err.Error(), "[addresses]") {
		t.Errorf("unmapped rig name error = %v; it must quote the file and the line to add", err)
	}
}

func TestGCMailAddressMapLivesUnderTheCityMarker(t *testing.T) {
	root := t.TempDir()
	city := filepath.Join(root, "city")
	if err := os.MkdirAll(filepath.Join(city, ".gc"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := "[addresses]\n\"myrig/witness\" = \"acme.aweb.ai/witness\"\n"
	if err := os.WriteFile(filepath.Join(city, ".gc", "aweb-mail.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// GC_CITY names the city ROOT, not the .gc directory inside it — the
	// opposite of BEADS_DIR, which is why the spec carries envNamesMarkerDir.
	t.Setenv("GC_CITY", city)
	m, err := loadDelegateMailAddressMap(root, gcMailMapSpec)
	if err != nil {
		t.Fatal(err)
	}
	if m.entries["myrig/witness"] != "acme.aweb.ai/witness" {
		t.Errorf("GC_CITY lookup found %v", m.entries)
	}

	// Unset, the marker directory is found by walking up, so a provider
	// invoked from a session subdirectory still sees the city's map.
	t.Setenv("GC_CITY", "")
	nested := filepath.Join(city, "rigs", "myrig")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	m, err = loadDelegateMailAddressMap(nested, gcMailMapSpec)
	if err != nil {
		t.Fatal(err)
	}
	if m.entries["myrig/witness"] != "acme.aweb.ai/witness" {
		t.Errorf("walk-up lookup found %v", m.entries)
	}
	if !strings.HasSuffix(m.path, filepath.Join(".gc", "aweb-mail.toml")) {
		t.Errorf("map path = %q", m.path)
	}
}

func TestGCMailReadInputRejectsWhatItCannotUse(t *testing.T) {
	got, err := gcMailReadInput(strings.NewReader(`{"from":"mayor","subject":"s","body":"b"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.From != "mayor" || got.Subject != "s" || got.Body != "b" {
		t.Errorf("decoded = %+v", got)
	}
	if _, err := gcMailReadInput(strings.NewReader("")); err == nil {
		t.Error("empty stdin must fail; gc always writes the JSON object for send and reply")
	} else if exitCode(err) != 1 {
		t.Errorf("empty stdin exit code = %d, want 1", exitCode(err))
	}
	if _, err := gcMailReadInput(strings.NewReader("not json")); err == nil {
		t.Error("non-JSON stdin must fail")
	}
}

func TestGCMailPathsAllAllowlisted(t *testing.T) {
	for _, sub := range gcMailCmd.Commands() {
		path := strings.TrimSpace(sub.CommandPath())
		if _, ok := identityHomeAwareCommandPaths[path]; !ok {
			t.Errorf("gc-mail operation %q is missing from identityHomeAwareCommandPaths", path)
		}
	}
}

func TestGCMailCoversTheWholeExecProtocol(t *testing.T) {
	// Every operation gascity's exec provider can invoke, from
	// internal/mail/exec/exec.go @ c96e54a3ab890ca984755b7fc5b5290cba5122d5.
	// A gap here means gc calls an operation cobra does not know, which
	// refuseUnknownSubcommands answers with exit 2 — silently "success".
	required := []string{
		"ensure-running", "send", "inbox", "get", "read", "mark-read",
		"mark-unread", "archive", "delete", "all", "check", "reply",
		"thread", "count",
	}
	have := map[string]bool{}
	for _, sub := range gcMailCmd.Commands() {
		have[strings.Fields(sub.Use)[0]] = true
	}
	for _, op := range required {
		if !have[op] {
			t.Errorf("exec protocol operation %q has no gc-mail subcommand", op)
		}
	}
}

// gcMailVerbExpectations is the identity-home allowlist evidence required by
// identity_home_policy.go: every gc-mail path must answer from its own routing
// with an external principal and an empty instance directory — never falling
// back to instance state, and never being refused as not identity-home-aware.
//
// The paths listed here answer before any network or identity use; the
// consumption evidence for the paths that DO reach the server is
// TestGCMailExecProviderContract, which drives the production binary through
// gc's own exec protocol against a workspace identity in cwd.
var gcMailVerbExpectations = []struct {
	args     []string
	stdin    string
	fragment string
}{
	{[]string{"send"}, "", "usage: aw gc-mail send"},
	{[]string{"send", "otherrig/deacon"}, `{"from":"mayor","subject":"s","body":"b"}`, "is not mapped to an aweb address"},
	{[]string{"send", "human"}, `{"from":"mayor","subject":"s","body":"b"}`, "is not mapped to an aweb address"},
	{[]string{"send", "someone", "extra"}, "", "usage: aw gc-mail send"},
	{[]string{"reply"}, "", "usage: aw gc-mail reply"},
	{[]string{"get"}, "", "usage: aw gc-mail get"},
	{[]string{"read"}, "", "usage: aw gc-mail read"},
	{[]string{"mark-read"}, "", "usage: aw gc-mail mark-read"},
	{[]string{"thread"}, "", "usage: aw gc-mail thread"},
	{[]string{"inbox", "a", "b"}, "", "usage: aw gc-mail inbox"},
	{[]string{"count", "a", "b"}, "", "usage: aw gc-mail count"},
	{[]string{"mark-unread", "m-1"}, "", "no way to clear read state"},
	{[]string{"archive", "m-1"}, "", "cannot be removed on request"},
	{[]string{"delete", "m-1"}, "", "cannot be removed on request"},
	{[]string{"resolve", "otherrig/deacon"}, "", "is not mapped to an aweb address"},
}

func TestGCMailVerbRouterProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

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

	run := func(identityHome bool, stdin string, args ...string) (string, int, error) {
		full := []string{}
		if identityHome {
			full = append(full, "--identity-home", principalHome)
		}
		full = append(full, "gc-mail")
		full = append(full, args...)
		cmd := exec.CommandContext(ctx, bin, full...)
		cmd.Dir = emptyInstance
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Env = append(os.Environ(), "AW_NO_UPDATE_CHECK=1", "HOME="+root, "GC_CITY=")
		out, err := cmd.CombinedOutput()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
		return string(out), code, err
	}

	for _, external := range []bool{false, true} {
		for _, tc := range gcMailVerbExpectations {
			out, code, err := run(external, tc.stdin, tc.args...)
			if err == nil {
				t.Errorf("external=%v %v: expected nonzero exit, got success:\n%s", external, tc.args, out)
				continue
			}
			if code == 2 {
				t.Errorf("external=%v %v: exited 2, which gc reads as \"unknown operation, succeeded\":\n%s", external, tc.args, out)
			}
			if !strings.Contains(out, tc.fragment) {
				t.Errorf("external=%v %v: output missing %q:\n%s", external, tc.args, tc.fragment, out)
			}
			if strings.Contains(out, "identity-home-aware") {
				t.Errorf("external=%v %v: refused by identity-home policy instead of answering:\n%s", external, tc.args, out)
			}
		}
		// ensure-running succeeds silently under both homes: gc calls it once
		// once per provider instance and discards the result.
		if out, _, err := run(external, "", "ensure-running"); err != nil || strings.TrimSpace(out) != "" {
			t.Errorf("external=%v ensure-running: err=%v output:\n%s", external, err, out)
		}
	}

	// An operation this provider does not implement is gc's forward-
	// compatibility case, and exit 2 is the right answer there — the one
	// place where it means what gc thinks it means.
	if out, code, err := run(false, "", "teleport"); err == nil || code != 2 {
		t.Errorf("unknown operation: code=%d err=%v output:\n%s", code, err, out)
	}
}
