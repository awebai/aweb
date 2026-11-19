package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestHookConfirmationProcess(t *testing.T) {
	root := os.Getenv("AW_TEST_HOOK_CONFIRMATION_ROOT")
	if root == "" {
		return
	}
	result := SetupClaudeHooks(root, requireHookConfirmation)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
}

func TestHookInstallationPreservesSettingsEditedDuringConfirmation(t *testing.T) {
	root := t.TempDir()
	path := writeNotifySettings(t, root, `{"user":"before","hooks":{"PostToolUse":[]}}`)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHookConfirmationProcess$")
	child.Env = append(os.Environ(), "AW_TEST_HOOK_CONFIRMATION_ROOT="+root)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := child.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	child.Stdout = &output
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if child.ProcessState == nil {
			if err := child.Wait(); err != nil {
				var exited *exec.ExitError
				if !errors.As(err, &exited) {
					t.Errorf("waiting for hook confirmation: %v", err)
				}
			}
		}
	})
	reader := bufio.NewReader(prompt)
	var shown strings.Builder
	for !strings.HasSuffix(shown.String(), "[n]: ") {
		value, err := reader.ReadByte()
		if err != nil {
			t.Fatalf("confirmation was not presented: %v (%s)", err, shown.String())
		}
		shown.WriteByte(value)
	}
	const edited = `{"user":"edited while the prompt was open","large":12345678901234567890,"hooks":{"PostToolUse":[]}}`
	if err := os.WriteFile(path, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(input, "y\n"); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(&output, reader); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatalf("hook installation failed: %v (%s)", err, output.String())
	}
	if result := CleanupClaudeNotifyHook(root); result.Error != nil {
		t.Fatal(result.Error)
	}
	if got := readInstallFile(t, path); string(got) != edited {
		t.Fatalf("concurrent user edit was lost: %s", got)
	}
}

func TestHookSettingsLockExcludesAnotherWriterAndReleasesAfterFailure(t *testing.T) {
	root := t.TempDir()
	path := writeNotifySettings(t, root, `{"hooks":{}}`)
	lockPath := hookSettingsLockPath(path)
	failure := errors.New("editor refused the replacement")
	err := withHookSettingsLock(path, func() error {
		other, err := awconfig.TryLockExclusive(lockPath)
		if other != nil {
			if closeErr := other.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if !errors.Is(err, awconfig.ErrLockUnavailable) {
			t.Fatalf("a second writer entered the transaction: %v", err)
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatalf("lost editor failure: %v", err)
	}
	other, err := awconfig.TryLockExclusive(lockPath)
	if err != nil {
		t.Fatalf("failed transaction left its lock held: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHookSettingsLockRefusalNamesSettingsAndRecovery(t *testing.T) {
	root := t.TempDir()
	const original = `{"hooks":{}}`
	path := writeNotifySettings(t, root, original)
	if err := os.Mkdir(hookSettingsLockPath(path), 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	err := withHookSettingsLock(path, func() error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "retry the command") {
		t.Fatalf("missing settings path or recovery instruction: %v", err)
	}
	if called || string(readInstallFile(t, path)) != original {
		t.Fatal("refused lock still allowed the settings editor to run")
	}
}
