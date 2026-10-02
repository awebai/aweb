package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcceptInviteTokenStdinRefusals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	var calls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unexpected request", 500) }))
	for _, tc := range []struct {
		name, input, want string
		args              []string
		openPipe          bool
	}{
		{name: "conflict_before_read", input: "", args: []string{"aw_inv_secret_positional"}, want: "cannot be combined", openPipe: true},
		{name: "empty", want: "empty"},
		{name: "whitespace", input: " \n\t", want: "empty"},
		{name: "invalid", input: "secret-invalid-token", want: "invalid invite token"},
		{name: "malformed_envelope", input: "aw_inv_v1_secret_invalid_envelope", want: "invalid invite token"},
		{name: "multiline", input: "aw_inv_secret_first\naw_inv_secret_second\n", want: "one token line"},
		{name: "oversize", input: strings.Repeat("s", 65537), want: "65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			caseCtx, caseCancel := context.WithTimeout(ctx, 5*time.Second)
			defer caseCancel()
			args := append([]string{"id", "team", "accept-invite", "--token-stdin"}, tc.args...)
			run := exec.CommandContext(caseCtx, bin, args...)
			run.Dir = home
			run.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AW_TRACE=1")
			run.Stdin = strings.NewReader(tc.input)
			if tc.openPipe {
				r, w, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				defer w.Close()
				run.Stdin = r
			}
			out, err := run.CombinedOutput()
			if caseCtx.Err() != nil {
				t.Fatal("refusal waited for stdin")
			}
			if err == nil || !strings.Contains(string(out), tc.want) {
				t.Fatalf("error=%v output=%s; want %s", err, out, tc.want)
			}
			for _, secret := range []string{"secret-invalid-token", "aw_inv_secret", "secret_invalid_envelope", strings.Repeat("s", 100)} {
				if strings.Contains(string(out), secret) {
					t.Fatal("refusal leaked token bytes")
				}
			}
			if _, err := os.Stat(filepath.Join(home, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("invalid input changed identity state: %v", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid inputs made %d HTTP calls", calls.Load())
	}
}
