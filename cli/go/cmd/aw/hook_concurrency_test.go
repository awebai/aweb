package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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
			if err := child.Wait(); err != nil && ctx.Err() == nil {
				t.Errorf("waiting for hook confirmation: %v", err)
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
