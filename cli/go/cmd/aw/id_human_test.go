package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/creack/pty"
	"github.com/zalando/go-keyring"
)

const humanInitDomain = "humans.example.invalid"

// runHumanInitBinary runs the real aw binary with a fresh HOME. With
// terminal it runs under a pty that becomes its controlling terminal;
// without, it runs in a new session with no controlling terminal at all.
func runHumanInitBinary(t *testing.T, terminal bool, env []string, args ...string) (string, error, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	home := t.TempDir()
	cmd := exec.CommandContext(ctx, bin, append([]string{"id", "human", "init"}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), append([]string{"HOME=" + home, "AW_NO_UPDATE_CHECK=1", "OATS_INSTANCE_HOME=", "OATS_INSTANCE="}, env...)...)
	var output bytes.Buffer
	var err error
	if terminal {
		var tty *os.File
		tty, err = pty.Start(cmd)
		if err != nil {
			t.Fatal(err)
		}
		defer tty.Close()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(&output, tty); close(done) }()
		err = cmd.Wait()
		<-done
	} else {
		cmd.Stdin = nil
		cmd.Stdout = &output
		cmd.Stderr = &output
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		err = cmd.Run()
	}
	return output.String(), err, home
}

func assertNoHumanCreated(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(home, ".awid", "humans")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("human records were written: %v", err)
	}
}

func TestHumanInitRefusesWithoutAControllingTerminal(t *testing.T) {
	out, err, home := runHumanInitBinary(t, false, nil, "--domain", humanInitDomain, "--as-root")
	if err == nil || !strings.Contains(out, "needs a human at an interactive terminal") {
		t.Fatalf("err=%v output:\n%s", err, out)
	}
	assertNoHumanCreated(t, home)
}

func TestHumanInitRefusesInsideAnAgentRuntimeEvenAtATerminal(t *testing.T) {
	for _, marker := range agentRuntimeMarkers {
		t.Run(marker, func(t *testing.T) {
			out, err, home := runHumanInitBinary(t, true, []string{marker + "=/somewhere"}, "--domain", humanInitDomain, "--as-root")
			if err == nil || !strings.Contains(out, "refuses inside an agent runtime") {
				t.Fatalf("err=%v output:\n%s", err, out)
			}
			assertNoHumanCreated(t, home)
		})
	}
}

func TestHumanInitHasNoFlagThatApproves(t *testing.T) {
	for _, flag := range []string{"--yes", "--confirm", "--passphrase=correct horse battery", "--non-interactive"} {
		out, err, home := runHumanInitBinary(t, true, nil, "--domain", humanInitDomain, "--as-root", flag)
		if err == nil || !strings.Contains(out, "unknown flag") {
			t.Fatalf("%s: err=%v output:\n%s", flag, err, out)
		}
		assertNoHumanCreated(t, home)
	}
}

func TestHumanInitRequiresAsRoot(t *testing.T) {
	out, err, home := runHumanInitBinary(t, true, nil, "--domain", humanInitDomain)
	if err == nil || !strings.Contains(out, "--as-root is required") {
		t.Fatalf("err=%v output:\n%s", err, out)
	}
	assertNoHumanCreated(t, home)
}

// humanInitHarness runs the command in-process against the real AWID
// fixture, with the human's passphrase typed by answers. The keychain is
// go-keyring's in-memory store; the shared journey uses a real one.
type humanInitHarness struct {
	t             *testing.T
	home          string
	registryURL   string
	controllerKey ed25519.PrivateKey
	resolver      staticTXTResolver
	answers       []string
	prompts       []string
}

func newHumanInitHarness(t *testing.T) *humanInitHarness {
	t.Helper()
	keyring.MockInit()
	h := &humanInitHarness{t: t, home: t.TempDir(), registryURL: realAWIDFixture(t)}
	t.Setenv("HOME", h.home)
	t.Setenv("AW_CONFIG_PATH", "")
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey(humanInitDomain, key); err != nil {
		t.Fatal(err)
	}
	h.controllerKey = key
	h.resolver = staticTXTResolver{"_awid." + humanInitDomain: {idCreateDNSRecordValue(awid.ComputeDIDKey(pub), "")}}
	return h
}

func (h *humanInitHarness) run(answers ...string) (idHumanInitOutput, error) {
	h.answers = append(h.answers, answers...)
	return executeIDHumanInit(context.Background(), idHumanInitOptions{
		Domain:          humanInitDomain,
		AsRoot:          true,
		RegistryURL:     h.registryURL,
		HumanAtTerminal: func() error { return nil },
		Keychain:        awconfig.HumanKeychain{},
		Prompt: func(prompt string) ([]byte, error) {
			h.prompts = append(h.prompts, prompt)
			if len(h.answers) == 0 {
				return nil, errors.New("no answer left for " + prompt)
			}
			answer := h.answers[0]
			h.answers = h.answers[1:]
			return []byte(answer), nil
		},
		TXTResolver: h.resolver,
		Now:         time.Now,
	})
}

func (h *humanInitHarness) records() []*awconfig.HumanRecord {
	h.t.Helper()
	records, err := awconfig.HumanRecords(humanInitDomain)
	if err != nil {
		h.t.Fatal(err)
	}
	return records
}

const humanPassphrase = "correct horse battery"

func TestHumanInitRefusesADNSControllerOtherThanThisMachines(t *testing.T) {
	h := newHumanInitHarness(t)
	_, other, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	h.resolver["_awid."+humanInitDomain] = []string{idCreateDNSRecordValue(awid.ComputeDIDKey(other.Public().(ed25519.PublicKey)), "")}
	if _, err := h.run(humanPassphrase, humanPassphrase); err == nil || !strings.Contains(err.Error(), "does not match this machine's controller") {
		t.Fatalf("err=%v", err)
	}
	if len(h.records()) != 0 || len(h.prompts) != 0 {
		t.Fatalf("records=%d prompts=%d", len(h.records()), len(h.prompts))
	}
}

func TestHumanInitMismatchedPassphrasesCreateNothing(t *testing.T) {
	h := newHumanInitHarness(t)
	if _, err := h.run(humanPassphrase, humanPassphrase+"!"); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("err=%v", err)
	}
	if len(h.records()) != 0 {
		t.Fatal("a record was written")
	}
}

// Against the real AWID fixture the human's did:aw registers, then the
// namespace step stops: the fixture's domain has no _awid record AWID can
// resolve, so AWID admits no namespace and no certificate is issued. The
// retry resumes the same human and never mints again. The namespace-rooted
// registration itself runs in the shared CoreDNS journey.
func TestHumanInitRegistersTheDIDThenResumesTheSameHuman(t *testing.T) {
	h := newHumanInitHarness(t)
	_, err := h.run(humanPassphrase, humanPassphrase, humanPassphrase)
	if err == nil || !strings.Contains(err.Error(), "register namespace "+humanInitDomain) {
		t.Fatalf("err=%v", err)
	}
	records := h.records()
	if len(records) != 1 || records[0].State != awconfig.HumanDIDRegistered || records[0].CertificateID != "" {
		t.Fatalf("records %+v", records)
	}
	human := records[0]
	blob, err := awconfig.HumanKeychain{}.LoadHumanKey(human.StableID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := awid.ImportHumanKeyBackup(blob, []byte(humanPassphrase))
	if err != nil || awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != human.DIDKey {
		t.Fatalf("keychain key: %v", err)
	}
	registry := awid.NewAWIDRegistryClient(nil, nil)
	resolved, err := registry.ResolveKeyAt(context.Background(), h.registryURL, human.StableID)
	if err != nil || resolved.CurrentDIDKey != human.DIDKey {
		t.Fatalf("AWID resolves %+v (%v)", resolved, err)
	}
	dir, err := awconfig.ControllerIssuanceDir(humanInitDomain)
	if err != nil {
		t.Fatal(err)
	}
	if entry, err := (awconfig.IDIssuanceFileStore{Dir: dir}).EntryForSubject(human.StableID); err != nil || entry != nil {
		t.Fatalf("a certificate was issued without evidence: %v %v", entry, err)
	}

	prompts := len(h.prompts)
	if _, err := h.run(); err == nil || !strings.Contains(err.Error(), "register namespace "+humanInitDomain) {
		t.Fatalf("retry err=%v", err)
	}
	if after := h.records(); len(after) != 1 || *after[0] != *human {
		t.Fatalf("the retry changed the human: %+v", after)
	}
	if len(h.prompts) != prompts {
		t.Fatalf("the retry asked %d more times", len(h.prompts)-prompts)
	}
}

// A second human in a domain is a deliberate act: rerunning init after it
// succeeded does not quietly mint another.
func TestHumanInitDoesNotQuietlyCreateASecondHuman(t *testing.T) {
	h := newHumanInitHarness(t)
	done := &awconfig.HumanRecord{StableID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", DIDKey: "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX", Domain: humanInitDomain, RegistryURL: h.registryURL, State: awconfig.HumanRegistered}
	if err := awconfig.SaveHumanRecord(done); err != nil {
		t.Fatal(err)
	}
	if _, err := h.run(humanPassphrase, humanPassphrase); err == nil || !strings.Contains(err.Error(), "--another") {
		t.Fatalf("err=%v", err)
	}
	if records := h.records(); len(records) != 1 || len(h.prompts) != 0 {
		t.Fatalf("records=%d prompts=%d", len(records), len(h.prompts))
	}
}
