package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const localLogTestTeamID = "acme:example.com"

type localLogFixture struct {
	sel      *awconfig.Selection
	teamKey  ed25519.PrivateKey
	ownerKey *ecdh.PrivateKey
	logsDir  string
}

// newLocalLogFixture is an agent workspace whose team certificate names a
// real team key, with HOME isolated so log-key records install under it.
func newLocalLogFixture(t *testing.T) *localLogFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, "agent")
	pub, teamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &awid.TeamCertificate{
		Version: 1, CertificateID: "cert-1", Team: localLogTestTeamID,
		TeamDIDKey: awid.ComputeDIDKey(pub), MemberDIDKey: "did:key:z6MkMember",
		Alias: "agent", IdentityScope: awid.IdentityModeLocal,
		IssuedAt: "2026-11-13T00:00:00Z", Signature: "sig",
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(root, localLogTestTeamID, cert); err != nil {
		t.Fatal(err)
	}
	return &localLogFixture{
		sel:     &awconfig.Selection{WorkingDir: root, TeamID: localLogTestTeamID, Alias: "agent"},
		teamKey: teamKey,
		logsDir: filepath.Join(home, ".config", "aw", "logs"),
	}
}

// installOwnerKey installs a log-key record signed by signer and keeps the
// owner's private half for the test to read the log back.
func (f *localLogFixture) installOwnerKey(t *testing.T, signer ed25519.PrivateKey) *awid.LogKeyRecord {
	t.Helper()
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(localLogTestTeamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, signer); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveLogKeyRecord(rec); err != nil {
		t.Fatal(err)
	}
	f.ownerKey = pair.Private
	return rec
}

func (f *localLogFixture) commLogPath() string {
	return commLogPath(f.logsDir, commLogNameForSelection(f.sel))
}

func readRawLines(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			lines = append(lines, scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// openAllLines opens every line of path with the owner's key, failing on
// any line that is not sealed.
func openAllLines(t *testing.T, path string, owner *ecdh.PrivateKey) []string {
	t.Helper()
	var out []string
	for _, raw := range readRawLines(t, path) {
		var line awid.SealedLogLine
		if err := json.Unmarshal([]byte(raw), &line); err != nil || line.Sealed == "" {
			t.Fatalf("line is not sealed: %s", raw)
		}
		plaintext, err := awid.OpenLogLine(&line, owner)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(plaintext))
	}
	return out
}

func TestCommLogStaysPlaintextWithoutAnOwnerKey(t *testing.T) {
	f := newLocalLogFixture(t)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "hello"})

	entries, err := readCommLog(f.commLogPath(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Body != "hello" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestCommLogSealsToTheOwnerKey(t *testing.T) {
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", From: "alice", Body: "the secret"})

	raw, err := os.ReadFile(f.commLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "the secret") || strings.Contains(string(raw), "alice") {
		t.Fatalf("log holds plaintext: %s", raw)
	}
	opened := openAllLines(t, f.commLogPath(), f.ownerKey)
	if len(opened) != 1 {
		t.Fatalf("opened %d lines", len(opened))
	}
	var entry CommLogEntry
	if err := json.Unmarshal([]byte(opened[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Body != "the secret" || entry.From != "alice" {
		t.Fatalf("opened entry = %+v", entry)
	}

	entries, err := readCommLog(f.commLogPath(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the agent must not read sealed lines back: %+v", entries)
	}
}

func TestCommLogWritesNothingUnderAnUnverifiedOwnerKey(t *testing.T) {
	f := newLocalLogFixture(t)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.installOwnerKey(t, stranger)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "the secret"})

	if _, err := os.Stat(f.commLogPath()); !os.IsNotExist(err) {
		t.Fatalf("a record not signed by the team key must stop logging, not fall back to plaintext: %v", err)
	}
}

func TestFirstSealedWriteSealsExistingPlaintextInPlace(t *testing.T) {
	f := newLocalLogFixture(t)
	name := commLogNameForSelection(f.sel)
	appendCommLog(f.logsDir, name, localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "first"})
	appendCommLog(f.logsDir, name, localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "send", Channel: "chat", Body: "second"})

	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, name, localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "third"})

	raw, err := os.ReadFile(f.commLogPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"first", "second", "third"} {
		if strings.Contains(string(raw), body) {
			t.Fatalf("plaintext %q survived: %s", body, raw)
		}
	}
	info, err := os.Stat(f.commLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v", info.Mode().Perm())
	}
	var bodies []string
	for _, line := range openAllLines(t, f.commLogPath(), f.ownerKey) {
		var entry CommLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, entry.Body)
	}
	if strings.Join(bodies, ",") != "first,second,third" {
		t.Fatalf("owner reads %v", bodies)
	}
}

func TestSealedInteractionLogDedupsAndGivesNoRecap(t *testing.T) {
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	key := localLogKeyForSelection(f.sel)
	root := f.sel.WorkingDir
	for i := 0; i < 2; i++ {
		appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-1", From: "alice", Text: "the secret"})
	}
	appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailOut, MessageID: "m-1", To: "alice", Text: "reply"})

	path := interactionLogPath(root)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "the secret") || strings.Contains(string(raw), "alice") {
		t.Fatalf("interaction log holds plaintext: %s", raw)
	}
	if opened := openAllLines(t, path, f.ownerKey); len(opened) != 2 {
		t.Fatalf("want one line per kind and message, got %d", len(opened))
	}
	if recap := loadRunContinueRecap(root, &strings.Builder{}); recap != "" {
		t.Fatalf("a sealed log gives the agent no recap, got %q", recap)
	}
}

func TestInteractionLogSealsExistingPlaintextKeepingDedup(t *testing.T) {
	f := newLocalLogFixture(t)
	root := f.sel.WorkingDir
	appendInteractionLogForDir(root, localLogKeyForSelection(f.sel), &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-1", Text: "before"})

	f.installOwnerKey(t, f.teamKey)
	key := localLogKeyForSelection(f.sel)
	appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-1", Text: "before"})
	appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-2", Text: "after"})

	opened := openAllLines(t, interactionLogPath(root), f.ownerKey)
	if len(opened) != 2 || !strings.Contains(opened[0], "before") || !strings.Contains(opened[1], "after") {
		t.Fatalf("owner reads %v", opened)
	}
}
