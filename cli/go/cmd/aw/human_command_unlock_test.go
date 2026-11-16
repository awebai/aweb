package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A real encrypted backup on the private fixture filesystem. OS-keychain and
// controlling-terminal integration is exercised by the product journey.
type humanBackupFile struct{ id, path string }

func (f humanBackupFile) LoadHumanKey(id string) ([]byte, error) {
	if id != f.id {
		return nil, awid.ErrHumanKeyNotFound
	}
	return os.ReadFile(f.path)
}
func (f humanBackupFile) SaveHumanKey(id string, blob []byte) error {
	if id != f.id {
		return fmt.Errorf("wrong fixture identity")
	}
	return os.WriteFile(f.path, blob, 0600)
}
func commandUnlockFixture(t *testing.T, passphrase string) (*humanParticipation, *[]string, *[]byte) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(awconfig.IdentityHomeEnv, "")
	old := identityHomeFlag
	identityHomeFlag = ""
	t.Cleanup(func() { identityHomeFlag = old })
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	t.Cleanup(func() { clear(key) })
	rec := &awconfig.HumanRecord{StableID: awid.ComputeStableID(key.Public().(ed25519.PublicKey)), DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), Domain: "example.test", State: awconfig.HumanPrepared}
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	store := humanBackupFile{rec.StableID, filepath.Join(home, "backup.pbes2")}
	if err := awid.InstallHumanKey(store, rec.StableID, key, []byte(humanPassphrase)); err != nil {
		t.Fatal(err)
	}
	prompts := []string{}
	var supplied []byte
	h, err := loadHumanParticipationState(rec.StableID, rec.Domain, store, func(text string) ([]byte, error) {
		prompts = append(prompts, text)
		supplied = []byte(passphrase)
		return supplied, nil
	}, func() error { return nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.close)
	return h, &prompts, &supplied
}

func TestHumanCommandWipesKeyOnSuccessAndError(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			h, prompts, _ := commandUnlockFixture(t, humanPassphrase)
			old := activeHuman
			activeHuman = h
			t.Cleanup(func() { activeHuman = old })
			h.operation = "one person command"
			var descriptions bytes.Buffer
			h.output = &descriptions
			var keyBytes []byte
			failure := errors.New("command failed after signing")
			cmd := &cobra.Command{Use: "person-command", SilenceErrors: true, SilenceUsage: true, RunE: func(*cobra.Command, []string) error {
				for _, text := range []string{"first act", "second act"} {
					if _, _, err := h.sign([]byte(text), text); err != nil {
						return err
					}
				}
				keyBytes = h.unlockedKey
				if fail {
					return failure
				}
				return nil
			}}
			cmd.SetArgs([]string{})
			err := cmd.Execute()
			if (err != nil) != fail {
				t.Fatalf("command result %v", err)
			}
			if len(keyBytes) != ed25519.PrivateKeySize || !bytes.Equal(keyBytes, make([]byte, len(keyBytes))) {
				t.Fatal("command exit retained private key bytes")
			}
			if len(h.unlockedKey) != 0 || len(*prompts) != 1 {
				t.Fatal("key/prompt lifetime crossed command exit")
			}
			if _, _, err := h.sign([]byte("later"), "after exit"); err == nil {
				t.Fatal("closed command signed")
			}
			for _, text := range []string{"signature 1:", "signature 2:", "first act", "second act"} {
				if !strings.Contains(descriptions.String(), text) {
					t.Fatal("signature description missing")
				}
			}
		})
	}
}

func TestHumanCommandSecondCommandUnlocksAgain(t *testing.T) {
	h, first, _ := commandUnlockFixture(t, humanPassphrase)
	if _, _, err := h.sign([]byte("first"), "first command"); err != nil {
		t.Fatal(err)
	}
	h.close()
	count := 0
	next, err := loadHumanParticipationState(h.record.StableID, h.record.Domain, humanBackupFile{h.record.StableID, filepath.Join(os.Getenv("HOME"), "backup.pbes2")}, func(string) ([]byte, error) { count++; return []byte(humanPassphrase), nil }, func() error { return nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	defer next.close()
	if _, _, err = next.sign([]byte("second"), "second command"); err != nil {
		t.Fatal(err)
	}
	if len(*first) != 1 || count != 1 {
		t.Fatal("second command reused the first unlock")
	}
}

func TestHumanCommandCloseDuringPromptCannotSignOrHang(t *testing.T) {
	previous, _, _ := commandUnlockFixture(t, humanPassphrase)
	entered, resume := make(chan struct{}), make(chan struct{})
	var supplied []byte
	h, err := loadHumanParticipationState(previous.record.StableID, previous.record.Domain, humanBackupFile{previous.record.StableID, filepath.Join(os.Getenv("HOME"), "backup.pbes2")}, func(string) ([]byte, error) {
		close(entered)
		<-resume
		supplied = []byte(humanPassphrase)
		return supplied, nil
	}, func() error { return nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	finished := make(chan error, 1)
	go func() {
		_, sig, e := h.sign([]byte("act"), "blocked prompt")
		if len(sig) != 0 {
			e = fmt.Errorf("closed prompt signed")
		}
		finished <- e
	}()
	<-entered
	h.close()
	close(resume)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed command resumed signing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup blocked on terminal prompt")
	}
	if !bytes.Equal(supplied, make([]byte, len(supplied))) {
		t.Fatal("cancelled prompt retained passphrase")
	}
}

func TestHumanCommandInterruptExits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signal os.Signal
		code   int
	}{{"interrupt", os.Interrupt, 130}, {"terminate", syscall.SIGTERM, 143}, {"hangup", syscall.SIGHUP, 129}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHumanCommandInterruptWorker$")
			cmd.Env = append(os.Environ(), "AW_TEST_HUMAN_INTERRUPT=1", "TMPDIR="+t.TempDir())
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			cmd.Stderr = &diagnostics
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewScanner(out)
			if !reader.Scan() || reader.Text() != "human unlocked" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("worker did not unlock: %s", diagnostics.String())
			}
			if err = cmd.Process.Signal(tc.signal); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != tc.code {
				t.Fatalf("signal result %v, want exit %d: %s", err, tc.code, diagnostics.String())
			}
		})
	}
}

func TestHumanCommandInterruptWorker(t *testing.T) {
	if os.Getenv("AW_TEST_HUMAN_INTERRUPT") != "1" {
		return
	}
	h, _, _ := commandUnlockFixture(t, humanPassphrase)
	h.watchSignals()
	if _, _, err := h.sign([]byte("act"), "interrupt fixture"); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "human unlocked")
	select {}
}
func TestHumanCommandUnlocksOnceForMultipleSignatures(t *testing.T) {
	h, prompts, supplied := commandUnlockFixture(t, humanPassphrase)
	h.operation = "enroll your approval key"
	for _, description := range []string{"start", "material", "confirm", "finish", "activate"} {
		payload := []byte(description)
		did, signature, err := h.sign(payload, description)
		if err != nil {
			t.Fatal(err)
		}
		public, err := awid.ExtractPublicKey(did)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(public, payload, signature) {
			t.Fatal("signature invalid")
		}
	}
	if len(*prompts) != 1 {
		t.Fatalf("passphrase prompts=%d, want one for the command", len(*prompts))
	}
	if !strings.Contains((*prompts)[0], h.record.StableID) || !strings.Contains((*prompts)[0], h.operation) {
		t.Fatal("unlock prompt does not name selected human and operation")
	}
	if !bytes.Equal(*supplied, make([]byte, len(*supplied))) {
		t.Fatal("passphrase bytes retained")
	}
}
func TestHumanCommandWrongPassphraseDoesNotRetryOrSign(t *testing.T) {
	h, prompts, supplied := commandUnlockFixture(t, "a wrong passphrase")
	for i := 0; i < 2; i++ {
		did, signature, err := h.sign([]byte("act"), "attempt")
		if err == nil || did != "" || len(signature) != 0 {
			t.Fatal("wrong passphrase signed an act")
		}
	}
	if len(*prompts) != 1 {
		t.Fatalf("failed command retried its passphrase %d times", len(*prompts))
	}
	if !bytes.Equal(*supplied, make([]byte, len(*supplied))) {
		t.Fatal("failed passphrase not wiped")
	}
}
