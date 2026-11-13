package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

const testLogPassphrase = "correct horse battery"

// scriptedPassphrases answers prompts in order and counts them.
type scriptedPassphrases struct {
	answers []string
	asked   int
}

func (s *scriptedPassphrases) prompt(string) ([]byte, error) {
	if s.asked >= len(s.answers) {
		return nil, errors.New("unexpected passphrase prompt")
	}
	s.asked++
	return []byte(s.answers[s.asked-1]), nil
}

// ownerWithTeamKey makes this machine the owner of the fixture's team: its
// controller key is in AWID state under the isolated HOME.
func ownerWithTeamKey(t *testing.T, f *localLogFixture) {
	t.Helper()
	domain, name, err := awid.ParseTeamID(localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(domain, name, f.teamKey); err != nil {
		t.Fatal(err)
	}
}

func TestLogKeyCreateSignsARecordAndKeepsTheKeyInTheKeychain(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}

	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awconfig.LoadTeamCertificateForTeam(f.sel.WorkingDir, localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.VerifyLogKeyRecord(rec, localLogTestTeamID, cert.TeamDIDKey); err != nil {
		t.Fatalf("created record must verify under the team key: %v", err)
	}
	blob, err := awconfig.LogKeychain{}.LoadLogKey(rec.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := awid.ImportLogKeyBackup(blob, []byte(testLogPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	line, err := awid.SealLogLine(rec, "", []byte("hello owner"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := awid.OpenLogLine(line, priv); err != nil || string(opened) != "hello owner" {
		t.Fatalf("keychain key does not open the record's lines: %q %v", opened, err)
	}
}

func TestLogKeyCreateRefusesWithoutTheTeamControllerKey(t *testing.T) {
	keyring.MockInit()
	newLocalLogFixture(t)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	_, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "only the owner of team") {
		t.Fatalf("err = %v", err)
	}
	if prompt.asked != 0 {
		t.Fatal("a non-owner must not be asked for a passphrase")
	}
}

func TestLogKeyCreateRefusesBadPassphrases(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	for name, answers := range map[string][]string{
		"mismatch": {testLogPassphrase, testLogPassphrase + "x"},
		"short":    {"short", "short"},
	} {
		prompt := &scriptedPassphrases{answers: answers}
		if _, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()}); err == nil {
			t.Fatalf("%s: passphrase accepted", name)
		}
	}
}

func TestLogKeyInstallAcceptsOnlyTheTeamsOwnerKey(t *testing.T) {
	f := newLocalLogFixture(t)
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(localLogTestTeamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, stranger); err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err == nil {
		t.Fatal("a record signed by another key must not install")
	}
	if _, err := awconfig.LoadLogKeyRecord(localLogTestTeamID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused record was installed: %v", err)
	}

	if err := awid.SignLogKeyRecord(rec, f.teamKey); err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	if key := localLogKeyForSelection(f.sel); key.record == nil || key.record.KeyID != rec.KeyID {
		t.Fatalf("installed key not in use: %+v", key)
	}
}

func TestLogReadOpensEveryRotatedKeyAndPlaintextLines(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	name := commLogNameForSelection(f.sel)
	keychain := awconfig.LogKeychain{}

	appendCommLog(f.logsDir, name, localLogKeyForSelection(f.sel), &CommLogEntry{Timestamp: "2026-11-13T09:00:00Z", Dir: "recv", Channel: "mail", From: "alice", Body: "plain before any key"})
	for i, body := range []string{"sealed under the first key", "sealed under the second key"} {
		prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
		rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: keychain, Prompt: prompt.prompt, Now: time.Now()})
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		if err := installLogKeyRecord(f.sel, rec); err != nil {
			t.Fatal(err)
		}
		appendCommLog(f.logsDir, name, localLogKeyForSelection(f.sel), &CommLogEntry{Timestamp: "2026-11-13T09:00:00Z", Dir: "recv", Channel: "mail", From: "alice", Body: body})
	}

	var out bytes.Buffer
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	if err := readOwnerLogs(logReadOptions{Files: []string{f.commLogPath()}, Keychain: keychain, Prompt: prompt.prompt, Out: &out}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"plain before any key", "sealed under the first key", "sealed under the second key"} {
		if !strings.Contains(out.String(), body) {
			t.Fatalf("owner output lacks %q:\n%s", body, out.String())
		}
	}
	if prompt.asked != 2 {
		t.Fatalf("want one passphrase prompt per key, got %d", prompt.asked)
	}
}

func TestLogReadPrintsInteractionEntriesAndJSON(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	appendInteractionLogForDir(f.sel.WorkingDir, localLogKeyForSelection(f.sel), &InteractionEntry{Kind: interactionKindChatIn, MessageID: "c-1", From: "bob", Text: "chat body"})
	path := interactionLogPath(f.sel.WorkingDir)

	var text bytes.Buffer
	if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &text}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "bob") || !strings.Contains(text.String(), "chat body") {
		t.Fatalf("text output:\n%s", text.String())
	}

	var js bytes.Buffer
	if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &js, JSON: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js.String(), `"kind":"chat_in"`) || !strings.Contains(js.String(), `"text":"chat body"`) {
		t.Fatalf("json output:\n%s", js.String())
	}
}

func TestLogReadRefusesAWrongPassphrase(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "secret"})

	var out bytes.Buffer
	err = readOwnerLogs(logReadOptions{Files: []string{f.commLogPath()}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{"not the passphrase"}}).prompt, Out: &out})
	if err == nil || strings.Contains(out.String(), "secret") {
		t.Fatalf("err = %v, out = %q", err, out.String())
	}
}

func TestLogReadNamesAKeyTheKeychainDoesNotHold(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogKeyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "secret"})

	err := readOwnerLogs(logReadOptions{Files: []string{filepath.Clean(f.commLogPath())}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{}).prompt, Out: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "not in this machine's keychain") {
		t.Fatalf("err = %v", err)
	}
}

// Anyone who can write the log can seal a line to the owner's public key, so
// what aw log read prints is untrusted: no terminal control reaches the owner.
func TestLogReadNeutralizesTerminalControlInForgedLines(t *testing.T) {
	keyring.MockInit()
	f := newLocalLogFixture(t)
	ownerWithTeamKey(t, f)
	prompt := &scriptedPassphrases{answers: []string{testLogPassphrase, testLogPassphrase}}
	rec, err := createLogKey(logKeyCreateOptions{TeamID: localLogTestTeamID, Keychain: awconfig.LogKeychain{}, Prompt: prompt.prompt, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := installLogKeyRecord(f.sel, rec); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "forged.jsonl")
	forged := []string{
		"not json \x1b]0;owned\x07 \x1b[2J",
		"{\"kind\":\"chat_in\",\"from\":\"\x1b[31mmallory\",\"text\":\"hi\"}",
		`{"ts":"\u001b[2J","dir":"recv","ch":"\u001b]0;owned\u0007","from":"eve","body":"hi"}`,
	}
	for _, plaintext := range forged {
		if err := appendLocalLogLine(path, localLogKey{record: rec}, []byte(plaintext), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := appendLocalLogLine(path, localLogKey{record: rec}, []byte(`{"kind":"chat_in","from":"bob","text":"esc \u001b[2J inside a valid string"}`), nil); err != nil {
		t.Fatal(err)
	}
	for _, asJSON := range []bool{false, true} {
		var out bytes.Buffer
		if err := readOwnerLogs(logReadOptions{Files: []string{path}, Keychain: awconfig.LogKeychain{}, Prompt: (&scriptedPassphrases{answers: []string{testLogPassphrase}}).prompt, Out: &out, JSON: asJSON}); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(out.String(), "\x1b\x07") {
			t.Fatalf("json=%v: terminal control reached the owner: %q", asJSON, out.String())
		}
		if strings.Count(out.String(), "\n") != 4 {
			t.Fatalf("json=%v: want one output line per log line: %q", asJSON, out.String())
		}
	}
}
