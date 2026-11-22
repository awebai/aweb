package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitInvitePrivateInputsRefuseBeforeWritingAHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name, input, want string
		args              []string
	}{
		{name: "stdin empty", args: []string{"--token-stdin"}, want: "empty"},
		{name: "stdin invalid", args: []string{"--token-stdin"}, input: "aw_inv_v1_sensitive_invalid_envelope", want: "invalid invite token"},
		{name: "two sources", args: []string{"--token-stdin", "--token-file", "not-read"}, want: "cannot be used together"},
		{name: "raw and stdin", args: []string{"--invite", "aw_inv_secret_raw", "--token-stdin"}, want: "not both"},
		{name: "different outcome", args: []string{"--join-from", "not-read", "--token-stdin"}, want: "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			run := exec.CommandContext(ctx, bin, append([]string{"init", "--json"}, tc.args...)...)
			run.Dir = home
			run.Env = testCommandEnv(home)
			run.Stdin = strings.NewReader(tc.input)
			out, err := run.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("err=%v output=%s", err, out)
			}
			if strings.Contains(string(out), "aw_inv_secret_raw") || strings.Contains(string(out), "sensitive_invalid_envelope") {
				t.Fatal("credential in diagnostic")
			}
			if _, err := os.Stat(filepath.Join(home, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("invalid input wrote identity: %v", err)
			}
		})
	}
}
