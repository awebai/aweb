package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNormalizeStateCoversTheImplementedVocabulary(t *testing.T) {
	// Every string docs/terminal-wake-broker.md §4 and §5 names as occurring,
	// plus the shell state from the OATS lead's samples, plus strings nothing
	// has ever reported. The mapping is total by construction: there is no
	// input without an answer, which is what keeps a vocabulary extension from
	// crashing the broker.
	cases := map[string]State{
		"idle":          StateIdle,
		"done":          StateIdle,
		"IDLE":          StateIdle,
		"  done  ":      StateIdle,
		"working":       StateBusy,
		"blocked":       StateBlocked,
		"unknown":       StateUnknown,
		"stopped":       StateStopped,
		"not-launched":  StateStopped,
		"shell":         StateShell,
		"generic shell": StateShell,
		"generic-shell": StateShell,

		// Unrecognised strings degrade to unknown, the conservative path.
		"":                   StateUnknown,
		"paused":             StateUnknown,
		"thinking-real-hard": StateUnknown,
		"idle-ish":           StateUnknown,
		" ":                  StateUnknown,
	}
	for raw, want := range cases {
		if got := NormalizeState(raw); got != want {
			t.Errorf("NormalizeState(%q)=%q want %q", raw, got, want)
		}
	}
}

// fakeOats writes a script that answers with the given stdout and exit code, so
// the exec path itself is under test rather than mocked away.
func fakeOats(t *testing.T, stdout string, exit int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake oats script is POSIX shell")
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.json")
	if err := os.WriteFile(payload, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "oats")
	script := fmt.Sprintf("#!/bin/sh\ncat >/dev/null\ncat %s\nexit %d\n", payload, exit)
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

type sample struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

func loadSamples(t *testing.T) map[string]sample {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "broker-inspect-samples.json"))
	if err != nil {
		t.Fatal(err)
	}
	var samples map[string]sample
	if err := json.Unmarshal(data, &samples); err != nil {
		t.Fatal(err)
	}
	return samples
}

// TestRealOatsSamples runs the adapter against output captured from a real
// `oats session inspect`, so the envelope contract is asserted against what the
// tool actually prints rather than against what this package assumed.
func TestRealOatsSamples(t *testing.T) {
	samples := loadSamples(t)

	t.Run("pending", func(t *testing.T) {
		s := samples["pending"]
		client := &ExecClient{Bin: fakeOats(t, s.Stdout, s.Exit)}
		_, err := client.Inspect(context.Background(), "/private/tmp/oats-broker-samples-I8aAxP/pending")
		if err == nil {
			t.Fatal("a pending home must surface its typed error, not a present:false verdict")
		}
		if !IsRuntimeEndpointUnknown(err) {
			t.Fatalf("err=%v want %s", err, CodeRuntimeEndpointUnknown)
		}
		if ErrorCode(err) != CodeRuntimeEndpointUnknown {
			t.Fatalf("ErrorCode=%q", ErrorCode(err))
		}
	})

	for _, name := range []string{"tmux", "herdr"} {
		t.Run(name, func(t *testing.T) {
			s := samples[name]
			client := &ExecClient{Bin: fakeOats(t, s.Stdout, s.Exit)}
			got, err := client.Inspect(context.Background(), "/does/not/matter")
			if err != nil {
				// The real samples carry backend-specific extras (paneId,
				// terminalId). Failing on an unnamed field would make every
				// OATS addition a broker outage.
				t.Fatalf("unexpected error on a real %s envelope: %v", name, err)
			}
			if got.Backend != name {
				t.Errorf("backend=%q want %q", got.Backend, name)
			}
			if !got.Present {
				t.Error("present=false on a real live envelope")
			}
			if got.State != StateUnknown || got.RawState != "unknown" {
				t.Errorf("state=%q raw=%q", got.State, got.RawState)
			}
		})
	}
}

func TestInputRequiresSubmittedTrue(t *testing.T) {
	ok := `{"schemaVersion":1,"ok":true,"result":{"home":"/h","backend":"tmux","submitted":true}}`
	if err := (&ExecClient{Bin: fakeOats(t, ok, 0)}).Input(context.Background(), "/h", "hello"); err != nil {
		t.Fatalf("submitted:true rejected: %v", err)
	}

	// submitted:false is not delivery. Treating it as one would clear a hint
	// from the pending set without anything reaching the terminal.
	notSubmitted := `{"schemaVersion":1,"ok":true,"result":{"home":"/h","backend":"tmux","submitted":false}}`
	err := (&ExecClient{Bin: fakeOats(t, notSubmitted, 0)}).Input(context.Background(), "/h", "hello")
	if err == nil {
		t.Fatal("submitted:false accepted as delivery")
	}
	if ErrorCode(err) != "E_NOT_SUBMITTED" {
		t.Fatalf("code=%q", ErrorCode(err))
	}
}

func TestRefusedInputIsATypedError(t *testing.T) {
	refusal := `{"schemaVersion":1,"ok":false,"error":{"code":"E_TARGET_REPLACED","message":"tmux window identity changed"}}`
	err := (&ExecClient{Bin: fakeOats(t, refusal, 1)}).Input(context.Background(), "/h", "hello")
	if err == nil {
		t.Fatal("a refusal was reported as success")
	}
	if ErrorCode(err) != "E_TARGET_REPLACED" {
		t.Fatalf("code=%q err=%v", ErrorCode(err), err)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.ExitCode == 0 {
		t.Fatalf("expected a typed error carrying the non-zero exit, got %#v", err)
	}
}

func TestUnreachableBackendIsAnErrorNotAVerdict(t *testing.T) {
	// No envelope at all: the tool is missing, or crashed. §6 requires this be
	// retried and reported, never read as an absent instance.
	client := &ExecClient{Bin: filepath.Join(t.TempDir(), "definitely-not-here")}
	_, err := client.Inspect(context.Background(), "/h")
	if err == nil {
		t.Fatal("a missing oats reported success")
	}
	if ErrorCode(err) != "E_OATS_UNREACHABLE" {
		t.Fatalf("code=%q err=%v", ErrorCode(err), err)
	}
	if IsRuntimeEndpointUnknown(err) {
		t.Fatal("a transport failure must not masquerade as a pending home")
	}
}

func TestUnsupportedSchemaVersionIsRejected(t *testing.T) {
	future := `{"schemaVersion":2,"ok":true,"result":{"state":"idle","present":true}}`
	_, err := (&ExecClient{Bin: fakeOats(t, future, 0)}).Inspect(context.Background(), "/h")
	if err == nil {
		t.Fatal("schemaVersion 2 was decoded as if it were version 1")
	}
}

func TestResolveBinPrefersFlagThenEnv(t *testing.T) {
	t.Setenv(OatsBinEnv, "/env/oats")
	if got := (&ExecClient{Bin: "/flag/oats"}).ResolveBin(); got != "/flag/oats" {
		t.Errorf("flag lost to env: %q", got)
	}
	if got := (&ExecClient{}).ResolveBin(); got != "/env/oats" {
		t.Errorf("env ignored: %q", got)
	}
	t.Setenv(OatsBinEnv, "")
	if got := (&ExecClient{}).ResolveBin(); got != DefaultOatsBin {
		t.Errorf("default=%q want %q", got, DefaultOatsBin)
	}
}
