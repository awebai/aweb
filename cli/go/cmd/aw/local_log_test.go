package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
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
	certPath, err := awconfig.SaveTeamCertificateForTeam(root, localLogTestTeamID, cert)
	if err != nil {
		t.Fatal(err)
	}
	workspacePath := awconfig.WorktreeWorkspacePath(root)
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, &awconfig.WorktreeWorkspace{
		AwebURL:     "https://app.aweb.example",
		Memberships: []awconfig.WorktreeMembership{{TeamID: localLogTestTeamID, Alias: "agent", CertPath: certPath}},
	}); err != nil {
		t.Fatal(err)
	}
	return &localLogFixture{
		sel:     &awconfig.Selection{WorkingDir: root, WorkspacePath: workspacePath, TeamID: localLogTestTeamID, Alias: "agent"},
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
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "hello"})

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
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", From: "alice", Body: "the secret"})

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
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "the secret"})

	if _, err := os.Stat(f.commLogPath()); !os.IsNotExist(err) {
		t.Fatalf("a record not signed by the team key must stop logging, not fall back to plaintext: %v", err)
	}
}

// moveCertificateToStoredPath moves the team certificate to a non-canonical
// stored cert_path and puts a certificate naming decoyKey as the team key at
// the canonical path. It returns decoyKey.
func (f *localLogFixture) moveCertificateToStoredPath(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	canonical := awconfig.TeamCertificatePath(f.sel.WorkingDir, localLogTestTeamID)
	cert, err := awid.LoadTeamCertificate(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(canonical, filepath.Join(f.sel.WorkingDir, ".aw", "certificate.json")); err != nil {
		t.Fatal(err)
	}
	decoyPub, decoyKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decoy := *cert
	decoy.TeamDIDKey = awid.ComputeDIDKey(decoyPub)
	if err := awid.SaveTeamCertificate(canonical, &decoy); err != nil {
		t.Fatal(err)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(f.sel.WorkspacePath)
	if err != nil {
		t.Fatal(err)
	}
	for i := range workspace.Memberships {
		workspace.Memberships[i].CertPath = "certificate.json"
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(f.sel.WorkspacePath, workspace); err != nil {
		t.Fatal(err)
	}
	return decoyKey
}

// The log key is verified against the team key of the certificate the
// selected membership stores, wherever its cert_path points, exactly as
// certificate authentication loads it.
func TestCommLogVerifiesTheOwnerKeyAgainstTheStoredCertPath(t *testing.T) {
	f := newLocalLogFixture(t)
	f.moveCertificateToStoredPath(t)
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "the secret"})

	if opened := openAllLines(t, f.commLogPath(), f.ownerKey); len(opened) != 1 {
		t.Fatalf("opened %d lines", len(opened))
	}
}

// A certificate left at the canonical path does not vouch for the record
// when the selected membership stores its certificate elsewhere.
func TestCommLogIgnoresACanonicalCertificateTheMembershipDoesNotStore(t *testing.T) {
	f := newLocalLogFixture(t)
	decoyKey := f.moveCertificateToStoredPath(t)
	f.installOwnerKey(t, decoyKey)
	appendCommLog(f.logsDir, commLogNameForSelection(f.sel), localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "the secret"})

	if _, err := os.Stat(f.commLogPath()); !os.IsNotExist(err) {
		t.Fatalf("a record signed by the canonical decoy's key must stop logging: %v", err)
	}
}

// Plaintext lines already in a log carry no team: they may have been written
// for another team of the same principal or before any key. A sealed write
// never seals them to its own team's owner; it leaves them exactly as they are.
func TestSealedWritesLeaveExistingPlaintextLinesAlone(t *testing.T) {
	f := newLocalLogFixture(t)
	name := commLogNameForSelection(f.sel)
	appendCommLog(f.logsDir, name, localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "first"})
	appendCommLog(f.logsDir, name, localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "send", Channel: "chat", Body: "second"})
	before := readRawLines(t, f.commLogPath())

	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, name, localLogPolicyForSelection(f.sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "third"})

	after := readRawLines(t, f.commLogPath())
	if len(after) != 3 || after[0] != before[0] || after[1] != before[1] {
		t.Fatalf("existing plaintext lines changed:\nbefore %q\nafter  %q", before, after)
	}
	if isSealedLogLine([]byte(after[0])) || isSealedLogLine([]byte(after[1])) {
		t.Fatal("existing plaintext lines were sealed")
	}
	var sealed awid.SealedLogLine
	if err := json.Unmarshal([]byte(after[2]), &sealed); err != nil || sealed.Sealed == "" {
		t.Fatalf("the new line is not sealed: %s", after[2])
	}
	opened, err := awid.OpenLogLine(&sealed, f.ownerKey)
	if err != nil || !strings.Contains(string(opened), `"body":"third"`) {
		t.Fatalf("owner opens %q, %v", opened, err)
	}
}

func TestSealedInteractionLogDedupsAndGivesNoRecap(t *testing.T) {
	f := newLocalLogFixture(t)
	f.installOwnerKey(t, f.teamKey)
	key := localLogPolicyForSelection(f.sel)
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

func TestInteractionLogKeepsPlaintextLinesAndDedupsAcrossThem(t *testing.T) {
	f := newLocalLogFixture(t)
	root := f.sel.WorkingDir
	appendInteractionLogForDir(root, localLogPolicyForSelection(f.sel), &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-1", Text: "before"})

	f.installOwnerKey(t, f.teamKey)
	key := localLogPolicyForSelection(f.sel)
	appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-1", Text: "before"})
	appendInteractionLogForDir(root, key, &InteractionEntry{Kind: interactionKindMailIn, MessageID: "m-2", Text: "after"})

	lines := readRawLines(t, interactionLogPath(root))
	if len(lines) != 2 || isSealedLogLine([]byte(lines[0])) || !strings.Contains(lines[0], `"text":"before"`) {
		t.Fatalf("lines = %q", lines)
	}
	var sealed awid.SealedLogLine
	if err := json.Unmarshal([]byte(lines[1]), &sealed); err != nil {
		t.Fatal(err)
	}
	opened, err := awid.OpenLogLine(&sealed, f.ownerKey)
	if err != nil || !strings.Contains(string(opened), `"text":"after"`) {
		t.Fatalf("owner opens %q, %v", opened, err)
	}
}

// Installing a key and writing are serialized on the team's policy lock, and
// a write resolves the policy only once it holds that lock: a write that was
// waiting while a key was installed is sealed to it.
func TestWriteWaitingOnTheTeamPolicyLockSealsToAKeyInstalledMeanwhile(t *testing.T) {
	f := newLocalLogFixture(t)
	policy := localLogPolicyForSelection(f.sel)
	lock, err := awconfig.LockLogKeyPolicy(localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		appendCommLog(f.logsDir, commLogNameForSelection(f.sel), policy, &CommLogEntry{Dir: "recv", Channel: "mail", Body: "racing-secret"})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the write did not wait for the policy lock")
	case <-time.After(200 * time.Millisecond):
	}
	f.installOwnerKey(t, f.teamKey)
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	<-done
	raw, err := os.ReadFile(f.commLogPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "racing-secret") {
		t.Fatalf("a write decided before the install appended plaintext: %s", raw)
	}
	if opened := openAllLines(t, f.commLogPath(), f.ownerKey); len(opened) != 1 {
		t.Fatalf("owner opens %d lines", len(opened))
	}
}

func TestInstallWaitsOnTheTeamPolicyLock(t *testing.T) {
	f := newLocalLogFixture(t)
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(localLogTestTeamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, f.teamKey); err != nil {
		t.Fatal(err)
	}
	lock, err := awconfig.LockLogKeyPolicy(localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- installLogKeyRecord(f.sel, rec) }()
	select {
	case err := <-done:
		t.Fatalf("install did not wait for the policy lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A long-lived policy follows the installed record: a replaced key is used
// from the next write, and a record that stops verifying stops logging.
func TestLongLivedPolicyFollowsReplacementAndCorruption(t *testing.T) {
	f := newLocalLogFixture(t)
	policy := localLogPolicyForSelection(f.sel)
	name := commLogNameForSelection(f.sel)
	f.installOwnerKey(t, f.teamKey)
	first := f.ownerKey
	appendCommLog(f.logsDir, name, policy, &CommLogEntry{Dir: "recv", Channel: "mail", Body: "one"})
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, name, policy, &CommLogEntry{Dir: "recv", Channel: "mail", Body: "two"})

	lines := readRawLines(t, f.commLogPath())
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	var second awid.SealedLogLine
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if _, err := awid.OpenLogLine(&second, first); err == nil {
		t.Fatal("the write after replacement still used the replaced key")
	}
	if opened, err := awid.OpenLogLine(&second, f.ownerKey); err != nil || !strings.Contains(string(opened), `"body":"two"`) {
		t.Fatalf("the replacing key does not open the next line: %q %v", opened, err)
	}

	path, err := awconfig.LogKeyRecordPath(localLogTestTeamID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	appendCommLog(f.logsDir, name, policy, &CommLogEntry{Dir: "recv", Channel: "mail", Body: "three-secret"})
	if got := readRawLines(t, f.commLogPath()); len(got) != 2 {
		t.Fatalf("a corrupted record must stop logging, got %d lines", len(got))
	}
}

// resignTeamCertificateForTest replaces the workspace's team certificate with
// the same membership signed by a team key the test holds.
func resignTeamCertificateForTest(t *testing.T, workingDir, teamID string) ed25519.PrivateKey {
	t.Helper()
	old, err := awconfig.LoadTeamCertificateForTeam(workingDir, teamID)
	if err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: old.Team, MemberDIDKey: old.MemberDIDKey, MemberDIDAW: old.MemberDIDAW,
		MemberAddress: old.MemberAddress, Alias: old.Alias, IdentityScope: old.IdentityScope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert); err != nil {
		t.Fatal(err)
	}
	return teamKey
}

func TestAwMailSendSealsTheCommLogAfterLogKeyInstall(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{Agents: []awid.AgentView{}})
		case "/v1/messages":
			var posted awid.SendMessageRequest
			_ = json.NewDecoder(r.Body).Decode(&posted)
			_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "msg-sealed-1", "conversation_id": posted.ConversationID, "status": "delivered", "delivered_at": "2026-11-13T12:00:00Z"})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)
	const teamID = "backend:demo"
	teamKey := resignTeamCertificateForTest(t, tmp, teamID)

	awCmd := func(args ...string) ([]byte, error) {
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL=http://127.0.0.1:1")
		run.Dir = tmp
		return run.CombinedOutput()
	}
	records := 0
	writeRecord := func(signer ed25519.PrivateKey) (string, *awid.LogKeyPair) {
		pair, err := awid.GenerateLogKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		rec, err := awid.NewLogKeyRecord(teamID, pair.Public, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := awid.SignLogKeyRecord(rec, signer); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		records++
		path := filepath.Join(tmp, fmt.Sprintf("log-key-%d.json", records))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path, pair
	}

	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := writeRecord(stranger)
	if out, err := awCmd("team", "admin", "log-key", "install", foreign); err == nil || !strings.Contains(string(out), "not signed by this team's key") {
		t.Fatalf("a record not signed by the team key must be refused for that reason: %v\n%s", err, out)
	}

	recordPath, pair := writeRecord(teamKey)
	if out, err := awCmd("team", "admin", "log-key", "install", recordPath); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	if out, err := awCmd("mail", "send", "--plaintext", "--to", "eve", "--subject", "sealed subject", "--body", "sealed body"); err != nil {
		t.Fatalf("mail send: %v\n%s", err, out)
	}

	logs, err := filepath.Glob(filepath.Join(tmp, ".config", "aw", "logs", "*.jsonl"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("logs = %v, %v", logs, err)
	}
	raw, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sealed body") || strings.Contains(string(raw), "sealed subject") {
		t.Fatalf("comm log holds plaintext: %s", raw)
	}
	opened := openAllLines(t, logs[0], pair.Private)
	if len(opened) != 1 || !strings.Contains(opened[0], `"body":"sealed body"`) || !strings.Contains(opened[0], `"msg_id":"msg-sealed-1"`) {
		t.Fatalf("owner reads %v", opened)
	}

	out, err := awCmd("log")
	if err == nil || !strings.Contains(string(out), "aw log read") {
		t.Fatalf("agent-side aw log must refuse while sealing is on: %v\n%s", err, out)
	}
}

// installRecordFileForTest writes a log-key record signed by signer straight
// into the agent host's installed records under home.
func installRecordFileForTest(t *testing.T, home, teamID string, signer ed25519.PrivateKey) {
	t.Helper()
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(teamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, signer); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".config", "aw", "log-keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, awconfig.EncodeTeamIDForCertificatePath(teamID)+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAwDoctorLocalReportsTheOwnerLogKey(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorGlobalFixture(t, tmp, "https://app.example.com/api")
	teamID := resolvedTeamIDForTest("backend:example.com")
	doctor := func() doctorOutput {
		out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
		if err != nil && !strings.Contains(string(out), `"checks"`) {
			t.Fatalf("doctor: %v\n%s", err, out)
		}
		return decodeDoctorOutput(t, out)
	}

	// No installed key is the normal default: logs stay plaintext until an
	// owner installs one. It is reported, and it does not degrade the verdict.
	check := requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogKey, doctorStatusInfo)
	if !strings.Contains(check.Message, "plaintext") {
		t.Fatalf("missing key message: %q", check.Message)
	}
	if got := aggregateDoctorStatus([]doctorCheck{check}); got != doctorStatusOK {
		t.Fatalf("a team with no owner log key degrades the verdict to %q", got)
	}

	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installRecordFileForTest(t, tmp, teamID, stranger)
	requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogKey, doctorStatusFail)

	teamKey := resignTeamCertificateForTest(t, tmp, teamID)
	installRecordFileForTest(t, tmp, teamID, teamKey)
	requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogKey, doctorStatusOK)
	requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogPlaintext, doctorStatusOK)

	// A plaintext line left in a log while sealing is on is named, not sealed.
	interactionLog := interactionLogPath(tmp)
	if err := os.MkdirAll(filepath.Dir(interactionLog), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(interactionLog, []byte(`{"ts":"2026-11-13T09:00:00Z","kind":"mail_in","text":"legacy"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext := requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogPlaintext, doctorStatusWarn)
	resolvedLog, err := filepath.EvalSymlinks(interactionLog)
	if err != nil {
		t.Fatal(err)
	}
	if detail := fmt.Sprint(plaintext.Detail); !strings.Contains(detail, interactionLog) && !strings.Contains(detail, resolvedLog) {
		t.Fatalf("the check must name the log holding plaintext: %#v", plaintext.Detail)
	}
}

// The owner's split as an operator runs it: an unsigned record, its exact
// signing bytes, a signature made elsewhere attached with `sign`, then
// `install`. `sign` without a route refuses.
func TestAwLogKeySignAttachesASignatureMadeElsewhere(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "https://app.aweb.ai")
	const teamID = "backend:demo"
	teamKey := resignTeamCertificateForTest(t, tmp, teamID)
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))

	awCmd := func(args ...string) ([]byte, error) {
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL=http://127.0.0.1:1")
		run.Dir = tmp
		return run.Output()
	}

	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := awid.NewLogKeyRecord(teamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	unsignedPath := filepath.Join(tmp, "unsigned.json")
	if err := os.WriteFile(unsignedPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	signing, err := awCmd("team", "admin", "log-key", "signing-bytes", "--record", unsignedPath, "--team-key-did", teamDID)
	if err != nil {
		t.Fatalf("signing-bytes: %v", err)
	}
	withKey := *unsigned
	withKey.TeamKeyDID = teamDID
	want, err := awid.LogKeyRecordSigningBytes(&withKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(signing) != string(want) {
		t.Fatalf("signing-bytes printed %q, want %q", signing, want)
	}

	if out, err := awCmd("team", "admin", "log-key", "sign", "--record", unsignedPath); err == nil {
		t.Fatalf("sign without a route must refuse: %s", out)
	}

	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, signing))
	signedPath := filepath.Join(tmp, "signed.json")
	if _, err := awCmd("team", "admin", "log-key", "sign", "--record", unsignedPath, "--team-key-did", teamDID, "--signature", signature, "--out", signedPath); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := awCmd("team", "admin", "log-key", "install", signedPath); err != nil {
		t.Fatalf("install of the attached record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".config", "aw", "log-keys", awconfig.EncodeTeamIDForCertificatePath(teamID)+".json")); err != nil {
		t.Fatalf("record not installed: %v", err)
	}
}

// newGrantLogFixture is a grant seat of the fixture's team: a grant home with
// no team certificate, whose grant.yaml records teamDIDKey (empty for a grant
// minted before the field existed).
func newGrantLogFixture(t *testing.T, f *localLogFixture, teamDIDKey string) *awconfig.Selection {
	t.Helper()
	grantHome := filepath.Join(filepath.Dir(f.sel.WorkingDir), "grant-home")
	if err := os.MkdirAll(grantHome, 0o700); err != nil {
		t.Fatal(err)
	}
	_, sessionKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKeyExclusive(awconfig.GrantHomeSigningKeyPath(grantHome), sessionKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(grantHome), &awconfig.GrantHome{
		Version: awconfig.GrantHomeSchemaVersion, GrantID: "grant-1", TeamID: localLogTestTeamID,
		Subject: awconfig.GrantSubject{DIDAW: "did:aw:agent", DIDKey: "did:key:zAgent", Alias: "agent"},
		Scopes:  []string{"mail.read"}, ExpiresAt: "2099-01-01T00:00:00Z", AwebURL: "https://app.aweb.ai",
		TeamDIDKey: teamDIDKey,
	}); err != nil {
		t.Fatal(err)
	}
	return &awconfig.Selection{WorkingDir: filepath.Join(filepath.Dir(f.sel.WorkingDir), "grant-work"), IdentityHome: grantHome, ExternalIdentityHome: true, TeamID: localLogTestTeamID, Alias: "agent"}
}

func TestGrantSeatSealsToTheRecordItsGrantNamesTheTeamKeyFor(t *testing.T) {
	f := newLocalLogFixture(t)
	sel := newGrantLogFixture(t, f, awid.ComputeDIDKey(f.teamKey.Public().(ed25519.PublicKey)))
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(sel), localLogPolicyForSelection(sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "grant-secret"})

	path := commLogPath(f.logsDir, commLogNameForSelection(sel))
	opened := openAllLines(t, path, f.ownerKey)
	if len(opened) != 1 || !strings.Contains(opened[0], "grant-secret") {
		t.Fatalf("owner reads %v", opened)
	}
}

// A grant minted before grants recorded the team key cannot verify the
// record: it stops logging rather than write plaintext.
func TestGrantSeatWithoutARecordedTeamKeyWritesNothing(t *testing.T) {
	f := newLocalLogFixture(t)
	sel := newGrantLogFixture(t, f, "")
	f.installOwnerKey(t, f.teamKey)
	appendCommLog(f.logsDir, commLogNameForSelection(sel), localLogPolicyForSelection(sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "grant-secret"})

	if _, err := os.Stat(commLogPath(f.logsDir, commLogNameForSelection(sel))); !os.IsNotExist(err) {
		t.Fatalf("an old grant must stop logging, not write: %v", err)
	}
	key := localLogPolicyForSelection(sel).resolve()
	if key.err == nil || !strings.Contains(key.err.Error(), "aw id grant mint") {
		t.Fatalf("the refusal must say to re-mint the grant: %v", key.err)
	}
}

func TestGrantSeatRefusesARecordSignedByAnotherTeamKey(t *testing.T) {
	f := newLocalLogFixture(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sel := newGrantLogFixture(t, f, awid.ComputeDIDKey(f.teamKey.Public().(ed25519.PublicKey)))
	f.installOwnerKey(t, other)
	appendCommLog(f.logsDir, commLogNameForSelection(sel), localLogPolicyForSelection(sel), &CommLogEntry{Dir: "recv", Channel: "mail", Body: "grant-secret"})
	if _, err := os.Stat(commLogPath(f.logsDir, commLogNameForSelection(sel))); !os.IsNotExist(err) {
		t.Fatalf("a record not signed by the grant's team key must stop logging: %v", err)
	}
}

// A grant whose grant.yaml names another team than the selection is not
// evidence for the selection's team.
func TestGrantSeatOfAnotherTeamDoesNotVouchForTheRecord(t *testing.T) {
	f := newLocalLogFixture(t)
	sel := newGrantLogFixture(t, f, awid.ComputeDIDKey(f.teamKey.Public().(ed25519.PublicKey)))
	f.installOwnerKey(t, f.teamKey)
	grant, err := awconfig.LoadGrantHome(sel.IdentityHome)
	if err != nil {
		t.Fatal(err)
	}
	grant.TeamID = "other:example.com"
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(sel.IdentityHome), grant); err != nil {
		t.Fatal(err)
	}
	if key := localLogPolicyForSelection(sel).resolve(); key.err == nil {
		t.Fatal("a grant of another team verified the record")
	}
}

// Doctor run as a grant seat reports the owner log key from the grant's
// recorded team key, and names re-minting for a grant that records none.
func TestAwDoctorLocalReportsTheOwnerLogKeyForAGrantSeat(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	_, teamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	const teamID = "backend:acme.com"
	grantHome := filepath.Join(tmp, "grant-home")
	_, grant := writeGrantHomeForTest(t, grantHome, "https://app.aweb.ai")
	if grant.TeamID != teamID {
		t.Fatalf("fixture team %q", grant.TeamID)
	}
	installRecordFileForTest(t, tmp, teamID, teamKey)
	doctor := func() doctorOutput {
		out, err := runDoctorCLI(t, bin, tmp, "--identity-home", grantHome, "doctor", "local", "--json")
		if err != nil && !strings.Contains(string(out), `"checks"`) {
			t.Fatalf("doctor: %v\n%s", err, out)
		}
		return decodeDoctorOutput(t, out)
	}

	check := requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogKey, doctorStatusFail)
	if !strings.Contains(check.NextStep+check.Message, "aw id grant mint") {
		t.Fatalf("an old grant must be told to re-mint: %#v", check)
	}

	grant.TeamDIDKey = teamDID
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(grantHome), grant); err != nil {
		t.Fatal(err)
	}
	requireDoctorCheckStatus(t, doctor(), doctorCheckLocalLogKey, doctorStatusOK)
}

// Under registry pinning a registry named only in identity.yaml is reached at
// public addresses; doctor names AWID_REGISTRY_URL as the fix when the stored
// registry is plainly private, and is satisfied once the variable names it.
func TestAwDoctorNamesAWIDRegistryURLForAPrivateStoredRegistry(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorGlobalFixture(t, tmp, "https://app.example.com/api")
	identityPath := filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	doctor := func(env ...string) doctorOutput {
		run := exec.Command(bin, "doctor", "identity", "--offline", "--json")
		run.Dir = tmp
		run.Env = append(testCommandEnv(tmp), env...)
		out, err := run.CombinedOutput()
		if err != nil && !strings.Contains(string(out), `"checks"`) {
			t.Fatalf("doctor: %v\n%s", err, out)
		}
		return decodeDoctorOutput(t, out)
	}

	requireDoctorCheckStatus(t, doctor(), doctorCheckIdentityLocalRegistryPinned, doctorStatusInfo)

	identity.RegistryURL = "https://10.1.2.3:8443"
	if err := awconfig.SaveWorktreeIdentityTo(identityPath, identity); err != nil {
		t.Fatal(err)
	}
	check := requireDoctorCheckStatus(t, doctor(), doctorCheckIdentityLocalRegistryPinned, doctorStatusWarn)
	if !strings.Contains(check.Message+check.NextStep, "AWID_REGISTRY_URL") {
		t.Fatalf("the check must name AWID_REGISTRY_URL: %#v", check)
	}
	requireDoctorCheckStatus(t, doctor("AWID_REGISTRY_URL=https://10.1.2.3:8443"), doctorCheckIdentityLocalRegistryPinned, doctorStatusOK)
}
