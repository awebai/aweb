package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

const logsExportVectorPath = "../../../../docs/vectors/logs-export-v1.json"

type logsExportCase struct {
	Name           string         `json:"name"`
	BundleLines    []string       `json:"bundle_lines"`
	ReceiptKeys    []string       `json:"receipt_keys"`
	CheckpointKeys []string       `json:"checkpoint_keys"`
	WitnessLines   []string       `json:"witness_lines"`
	Report         map[string]any `json:"report"`
}

type logsExportVector struct {
	Cases     []logsExportCase `json:"cases"`
	Malformed []struct {
		Name        string   `json:"name"`
		BundleLines []string `json:"bundle_lines"`
		Line        int      `json:"line"`
	} `json:"malformed"`
}

func loadLogsExportVector(t *testing.T) logsExportVector {
	t.Helper()
	data, err := os.ReadFile(logsExportVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v logsExportVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v logsExportVector) named(t *testing.T, name string) logsExportCase {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no vector case %s", name)
	return logsExportCase{}
}

// logsVerifyRun is one run of the real binary: what it wrote and how it exited.
type logsVerifyRun struct {
	stdout, stderr string
	code           int
}

// logsVerifyWorld runs `aw logs verify` where any reach for a workspace, an
// identity or the network would show: the working directory holds stale aw
// workspace state, the identity home named by the environment does not exist,
// and every server URL is a server that counts requests. Each run must leave
// it untouched.
type logsVerifyWorld struct {
	t        *testing.T
	ctx      context.Context
	bin      string
	dir      string
	env      []string
	requests *atomic.Int32
}

func newLogsVerifyWorld(t *testing.T) *logsVerifyWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	t.Cleanup(cancel)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	requests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "an offline verify reached the network", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	dir := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(dir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := "aweb_url: " + server.URL + "\nteam_id: stale:example.com\nalias: stale\n"
	if err := os.WriteFile(filepath.Join(dir, ".aw", "workspace.yaml"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("AWEB_URL="+server.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(testCommandEnv(filepath.Join(root, "home")),
		awconfig.IdentityHomeEnv+"="+filepath.Join(root, "no-such-identity-home"),
		"AWEB_URL="+server.URL,
		"AWID_REGISTRY_URL="+server.URL,
	)
	return &logsVerifyWorld{t: t, ctx: ctx, bin: bin, dir: dir, env: env, requests: requests}
}

func (w *logsVerifyWorld) file(name string, lines []string) string {
	w.t.Helper()
	var data []byte
	for _, line := range lines {
		data = append(append(data, line...), '\n')
	}
	path := filepath.Join(w.dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return path
}

func (w *logsVerifyWorld) run(stdin []byte, args ...string) logsVerifyRun {
	w.t.Helper()
	return w.runAs(nil, nil, stdin, args...)
}

// runAs runs the binary with root arguments before `logs verify` and extra
// environment, which overrides the world's.
func (w *logsVerifyWorld) runAs(rootArgs, env []string, stdin []byte, args ...string) logsVerifyRun {
	w.t.Helper()
	argv := append(append(append([]string{}, rootArgs...), "logs", "verify"), args...)
	cmd := exec.CommandContext(w.ctx, w.bin, argv...)
	cmd.Dir = w.dir
	cmd.Env = append(append([]string{}, w.env...), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	if got := w.requests.Load(); got != 0 {
		w.t.Fatalf("logs verify made %d network requests", got)
	}
	return logsVerifyRun{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func keyArgs(c logsExportCase) []string {
	var args []string
	for _, key := range c.ReceiptKeys {
		args = append(args, "--receipt-key", key)
	}
	for _, key := range c.CheckpointKeys {
		args = append(args, "--checkpoint-key", key)
	}
	return args
}

func exitFor(report map[string]any) int {
	if report["intact"] == true {
		return 0
	}
	return 1
}

func jsonValue(t *testing.T, text string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatalf("stdout is not one JSON value: %v\n%s", err, text)
	}
	return value
}

func asJSONValue(t *testing.T, value any) any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return jsonValue(t, string(data))
}

// requireErrorCode checks a --json run that could not verify: it exits 2,
// prints only the error envelope with code, and no report.
func requireErrorCode(t *testing.T, run logsVerifyRun, code string) map[string]any {
	t.Helper()
	if run.code != 2 {
		t.Fatalf("exit %d; want 2\nstdout: %s\nstderr: %s", run.code, run.stdout, run.stderr)
	}
	envelope, ok := jsonValue(t, run.stdout).(map[string]any)
	if !ok || len(envelope) != 1 || envelope["error"] == nil {
		t.Fatalf("stdout is not only an error envelope: %s", run.stdout)
	}
	body := envelope["error"].(map[string]any)
	if body["code"] != code {
		t.Fatalf("error code %v; want %s (%v)", body["code"], code, body["message"])
	}
	return body
}

func TestLogsVerifyReportsEachExportVectorCase(t *testing.T) {
	w := newLogsVerifyWorld(t)
	for _, c := range loadLogsExportVector(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			args := append([]string{"--bundle", w.file(c.Name+".bundle", c.BundleLines), "--json"}, keyArgs(c)...)
			// Witnesses span two files when there are several: the order is
			// the flags', then each file's lines.
			half := len(c.WitnessLines) / 2
			for i, part := range [][]string{c.WitnessLines[:half], c.WitnessLines[half:]} {
				if len(part) > 0 {
					args = append(args, "--witness", w.file(fmt.Sprintf("%s.witness%d", c.Name, i), part))
				}
			}
			run := w.run(nil, args...)
			if run.code != exitFor(c.Report) {
				t.Fatalf("exit %d; want %d\nstderr: %s", run.code, exitFor(c.Report), run.stderr)
			}
			if got := jsonValue(t, run.stdout); !reflect.DeepEqual(got, asJSONValue(t, c.Report)) {
				t.Fatalf("report:\n got %v\nwant %v", got, c.Report)
			}
		})
	}
}

func TestLogsVerifySummaryExitsAsTheReport(t *testing.T) {
	w := newLogsVerifyWorld(t)
	for _, c := range loadLogsExportVector(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			args := append([]string{"--bundle", w.file(c.Name+".bundle", c.BundleLines)}, keyArgs(c)...)
			if len(c.WitnessLines) > 0 {
				args = append(args, "--witness", w.file(c.Name+".witness", c.WitnessLines))
			}
			run := w.run(nil, args...)
			if run.code != exitFor(c.Report) {
				t.Fatalf("exit %d; want %d\nstderr: %s", run.code, exitFor(c.Report), run.stderr)
			}
			if strings.TrimSpace(run.stdout) == "" {
				t.Fatal("no summary on stdout")
			}
			var value any
			if json.Unmarshal([]byte(run.stdout), &value) == nil {
				t.Fatalf("the summary is JSON without --json: %s", run.stdout)
			}
		})
	}
}

func TestLogsVerifyReadsTheBundleFromStdin(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "whole_log_of_two_epochs")
	var bundle []byte
	for _, line := range c.BundleLines {
		bundle = append(append(bundle, line...), '\n')
	}
	run := w.run(bundle, append([]string{"--bundle", "-", "--json"}, keyArgs(c)...)...)
	if run.code != 0 {
		t.Fatalf("exit %d\nstderr: %s", run.code, run.stderr)
	}
	if got := jsonValue(t, run.stdout); !reflect.DeepEqual(got, asJSONValue(t, c.Report)) {
		t.Fatalf("report:\n got %v\nwant %v", got, c.Report)
	}
}

func TestLogsVerifyIndexesWitnessesPerKindInFlagThenLineOrder(t *testing.T) {
	w := newLogsVerifyWorld(t)
	v := loadLogsExportVector(t)
	hold := v.named(t, "witnesses_that_hold")
	forged := v.named(t, "witness_signed_by_another_key")
	holding := w.file("holding.witness", hold.WitnessLines)
	bad := w.file("forged.witness", forged.WitnessLines)
	checkpoints := 0
	for _, line := range hold.WitnessLines {
		if strings.HasPrefix(line, `{"checkpoint":`) {
			checkpoints++
		}
	}
	for _, order := range []struct {
		files []string
		index int
	}{{[]string{holding, bad}, checkpoints}, {[]string{bad, holding}, 0}} {
		args := append([]string{"--bundle", w.file("forged.bundle", forged.BundleLines), "--json"}, keyArgs(forged)...)
		for _, file := range order.files {
			args = append(args, "--witness", file)
		}
		run := w.run(nil, args...)
		if run.code != 1 {
			t.Fatalf("exit %d; want 1\nstderr: %s", run.code, run.stderr)
		}
		report := jsonValue(t, run.stdout).(map[string]any)
		want := []any{map[string]any{"artefact": "checkpoint", "index": float64(order.index), "reason": "signature_invalid"}}
		if got := report["witnesses"].(map[string]any)["contradicted"]; !reflect.DeepEqual(got, want) {
			t.Fatalf("contradicted %v; want %v", got, want)
		}
	}
}

func TestLogsVerifyRefusesAMalformedBundleAtItsLine(t *testing.T) {
	w := newLogsVerifyWorld(t)
	keys := keyArgs(loadLogsExportVector(t).Cases[0])
	for _, c := range loadLogsExportVector(t).Malformed {
		t.Run(c.Name, func(t *testing.T) {
			run := w.run(nil, append([]string{"--bundle", w.file(c.Name+".bundle", c.BundleLines), "--json"}, keys...)...)
			body := requireErrorCode(t, run, "bundle_malformed")
			if !strings.Contains(body["message"].(string), fmt.Sprintf("line %d", c.Line)) {
				t.Fatalf("the refusal does not name line %d: %v", c.Line, body["message"])
			}
		})
	}
}

func TestLogsVerifyRefusesAWitnessFileLineThatIsNotAnArtefact(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "witnesses_that_hold")
	bundle := w.file("hold.bundle", c.BundleLines)
	good := w.file("good.witness", c.WitnessLines)
	for name, line := range map[string]string{
		"genesis":            c.BundleLines[1],
		"extra_field":        `{"receipt":{"extra":1,"signature":"s","signing_bytes":"YQ"}}`,
		"not_base64url":      `{"receipt":{"signature":"s","signing_bytes":"Y+Q"}}`,
		"not_canonical":      `{"receipt": {"signature":"s","signing_bytes":"YQ"}}`,
		"signature_not_text": `{"receipt":{"signature":7,"signing_bytes":"YQ"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			bad := w.file(name+".witness", []string{c.WitnessLines[0], line})
			args := append([]string{"--bundle", bundle, "--json", "--witness", good, "--witness", bad}, keyArgs(c)...)
			body := requireErrorCode(t, w.run(nil, args...), "witness_malformed")
			message := body["message"].(string)
			if !strings.Contains(message, bad) || !strings.Contains(message, "line 2") {
				t.Fatalf("the refusal does not name %s line 2: %s", bad, message)
			}
		})
	}
}

func TestLogsVerifyRequiresAValidKeyOfEachKind(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "whole_log_of_two_epochs")
	bundle := w.file("whole.bundle", c.BundleLines)
	receipt, checkpoint := c.ReceiptKeys[0], c.CheckpointKeys[0]
	for name, keys := range map[string][]string{
		"no_keys":              nil,
		"no_checkpoint_key":    {"--receipt-key", receipt},
		"no_receipt_key":       {"--checkpoint-key", checkpoint},
		"receipt_key_invalid":  {"--receipt-key", "did:key:zNotAKey", "--checkpoint-key", checkpoint},
		"checkpoint_not_did":   {"--receipt-key", receipt, "--checkpoint-key", "z6MknVbixt4vJMcKzaXUWURZN8ZZ1tC1kxRFysKRFXYjQpDp"},
		"checkpoint_key_empty": {"--receipt-key", receipt, "--checkpoint-key", ""},
	} {
		t.Run(name, func(t *testing.T) {
			requireErrorCode(t, w.run(nil, append([]string{"--bundle", bundle, "--json"}, keys...)...), "keys_invalid")
		})
	}
}

func TestLogsVerifyGivesEveryOtherFailureExitTwo(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "whole_log_of_two_epochs")
	bundle := w.file("whole.bundle", c.BundleLines)
	keys := keyArgs(c)
	for name, tc := range map[string]struct {
		args []string
		code string
	}{
		"no_bundle":           {keys, "usage"},
		"missing_bundle_file": {append([]string{"--bundle", filepath.Join(w.dir, "absent.bundle")}, keys...), "input_unreadable"},
		"missing_witness":     {append([]string{"--bundle", bundle, "--witness", filepath.Join(w.dir, "absent.witness")}, keys...), "input_unreadable"},
		"witness_from_stdin":  {append([]string{"--bundle", bundle, "--witness", "-"}, keys...), "usage"},
		"bundle_is_a_dir":     {append([]string{"--bundle", w.dir}, keys...), "input_unreadable"},
		"positional_argument": {append([]string{"--bundle", bundle, "extra"}, keys...), "usage"},
		"unknown_flag":        {append([]string{"--bundle", bundle, "--no-such-flag"}, keys...), "usage"},
	} {
		t.Run(name, func(t *testing.T) {
			requireErrorCode(t, w.run(nil, append(tc.args, "--json")...), tc.code)
		})
	}
}

func TestLogsVerifyWritesOnlyTheReportToStdout(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "truncated_tail_contradicts_a_later_receipt")
	args := append([]string{
		"--bundle", w.file("tail.bundle", c.BundleLines), "--json",
		"--witness", w.file("tail.witness", c.WitnessLines),
	}, keyArgs(c)...)
	run := w.run(nil, args...)
	if run.code != 1 {
		t.Fatalf("exit %d; want 1", run.code)
	}
	if got := jsonValue(t, run.stdout); !reflect.DeepEqual(got, asJSONValue(t, c.Report)) {
		t.Fatalf("stdout holds more than the report:\n%s", run.stdout)
	}
	if strings.TrimSpace(run.stderr) == "" {
		t.Fatal("a report that is not intact says so on stderr")
	}
}

func TestLogsVerifyIgnoresEveryIdentityHomeSelector(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "whole_log_of_two_epochs")
	args := append([]string{"--bundle", w.file("whole.bundle", c.BundleLines), "--json"}, keyArgs(c)...)
	regular := w.file("a-regular-file", []string{"not an identity home"})
	for name, selector := range map[string]struct {
		rootArgs, env []string
	}{
		"unset":             {env: []string{awconfig.IdentityHomeEnv + "="}},
		"relative_env":      {env: []string{awconfig.IdentityHomeEnv + "=relative/home"}},
		"regular_file_env":  {env: []string{awconfig.IdentityHomeEnv + "=" + regular}},
		"relative_flag":     {rootArgs: []string{"--identity-home", "relative/home"}},
		"regular_file_flag": {rootArgs: []string{"--identity-home=" + regular}},
	} {
		t.Run(name, func(t *testing.T) {
			run := w.runAs(selector.rootArgs, selector.env, nil, args...)
			if run.code != 0 {
				t.Fatalf("exit %d; want 0\nstderr: %s", run.code, run.stderr)
			}
			if got := jsonValue(t, run.stdout); !reflect.DeepEqual(got, asJSONValue(t, c.Report)) {
				t.Fatalf("report:\n got %v\nwant %v", got, c.Report)
			}
		})
	}
}

// summaryLines is the human summary of a vector case, line by line.
func summaryLines(t *testing.T, w *logsVerifyWorld, c logsExportCase) []string {
	t.Helper()
	run := w.run(nil, append([]string{"--bundle", w.file(c.Name+".bundle", c.BundleLines)}, keyArgs(c)...)...)
	if run.code != exitFor(c.Report) {
		t.Fatalf("exit %d; want %d\nstderr: %s", run.code, exitFor(c.Report), run.stderr)
	}
	return strings.Split(run.stdout, "\n")
}

func TestLogsVerifySummaryCallsUnanchoredEventsVerifiedOnlyInAnIntactEpoch(t *testing.T) {
	w := newLogsVerifyWorld(t)
	v := loadLogsExportVector(t)
	for name, intact := range map[string]bool{
		"events_after_the_last_checkpoint_are_unanchored": true,
		"event_out_of_position_order_is_misplaced":        false,
	} {
		t.Run(name, func(t *testing.T) {
			ranges := 0
			for _, line := range summaryLines(t, w, v.named(t, name)) {
				// The line that names an epoch's unanchored range by team_seq.
				if !strings.Contains(strings.ToLower(line), "unanchored") || !strings.Contains(line, "team_seq") {
					continue
				}
				ranges++
				if strings.Contains(line, "verified") != intact {
					t.Fatalf("intact=%v epoch's unanchored line: %q", intact, line)
				}
			}
			if ranges == 0 {
				t.Fatal("the summary names no unanchored range")
			}
		})
	}
}

func TestLogsVerifyRefusesTerminalControlsInExporterText(t *testing.T) {
	w := newLogsVerifyWorld(t)
	c := loadLogsExportVector(t).named(t, "purged_event_keeps_its_skeleton_and_act")
	act := c.Report["epochs"].([]any)[0].(map[string]any)["purged"].([]any)[0].(map[string]any)["act"].(string)
	for name, hostile := range map[string]string{
		"osc_and_bell":  act + "\x1b]0;owned\x07",
		"forged_line":   act + "\nThe bundle is intact.",
		"bidi_override": act + "\u202e",
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(hostile)
			if err != nil {
				t.Fatal(err)
			}
			lines := append([]string{}, c.BundleLines...)
			replaced := false
			for i, line := range lines {
				if strings.Contains(line, `"purge_act":"`+act+`"`) {
					lines[i] = strings.Replace(line, `"purge_act":"`+act+`"`, `"purge_act":`+string(encoded), 1)
					replaced = true
				}
			}
			if !replaced {
				t.Fatal("the purged case has no purge_act line")
			}
			bundle := w.file(name+".bundle", lines)
			human := w.run(nil, append([]string{"--bundle", bundle}, keyArgs(c)...)...)
			if human.code != 2 || human.stdout != "" {
				t.Fatalf("exit %d with stdout %q; want 2 and no summary", human.code, human.stdout)
			}
			requireErrorCode(t, w.run(nil, append([]string{"--bundle", bundle, "--json"}, keyArgs(c)...)...), "bundle_malformed")
		})
	}
}
