package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/wake"
)

// TestWakeCommandsProductionBinary is the identity-home regression every entry
// in identityHomeAwareCommandPaths owes.
//
// The wake commands hold no principal state: the state directory is per host
// and each registration names its identity home explicitly, so an attached
// external principal must change nothing about what they do. This runs each of
// them against an unusable principal home from an empty instance directory and
// asserts three things: the command answers, it does not fall back to the
// instance directory, and it does not touch the principal.
//
// Note on --identity-home: `aw wake register` defines its own --identity-home
// flag, naming the *instance's* identity home, which shadows the root's
// persistent flag of the same name for that one command. The command surface
// was fixed with OATS before this was written and the flag means something
// different there, so the external-principal case for register is exercised
// through AWEB_IDENTITY_HOME, which is not shadowed. TestWakeRegisterFlagShadowsTheRootIdentityHome
// pins that behaviour so it is a decision rather than a surprise.
func TestWakeCommandsProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	principalHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(principalHome, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"identity.yaml":  "not: [valid identity yaml",
		"signing.key":    "not a signing key",
		"workspace.yaml": "not: [valid workspace yaml",
	} {
		if err := os.WriteFile(filepath.Join(principalHome, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := fileDigestsForTest(t, principalHome)

	instanceHome := filepath.Join(root, "agent-home")
	if err := os.MkdirAll(filepath.Join(instanceHome, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, principal := range []string{"none", "environment", "flag"} {
		t.Run(principal, func(t *testing.T) {
			cwd := filepath.Join(root, "cwd", principal)
			stateDir := filepath.Join(root, "state", principal)
			if err := os.MkdirAll(cwd, 0o700); err != nil {
				t.Fatal(err)
			}

			run := func(args ...string) (string, int, error) {
				full := append([]string{}, args...)
				env := append(testCommandEnv(filepath.Join(root, "user-home")), "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")
				switch principal {
				case "environment":
					env = append(env, awconfig.IdentityHomeEnv+"="+principalHome)
				case "flag":
					full = append([]string{"--identity-home", principalHome}, full...)
				}
				cmd := exec.CommandContext(ctx, bin, full...)
				cmd.Dir = cwd
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				code := 0
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					code = exitErr.ExitCode()
				}
				return string(out), code, err
			}

			// The exact call the oats.aweb hook makes, plus --state-dir so the
			// test does not touch the host's real broker state.
			registerArgs := []string{"wake", "register", "--home", instanceHome,
				"--identity-home", filepath.Join(instanceHome, ".aw"),
				"--delivery", "session", "--backend", "tmux", "--state-dir", stateDir}

			steps := [][]string{
				registerArgs,
				{"wake", "status", "--state-dir", stateDir},
				{"wake", "status", "--json", "--state-dir", stateDir},
				{"wake", "pause", "--home", instanceHome, "--state-dir", stateDir},
				{"wake", "resume", "--home", instanceHome, "--state-dir", stateDir},
				{"wake", "deregister", "--home", instanceHome, "--state-dir", stateDir},
			}
			for _, args := range steps {
				out, code, err := run(args...)
				if err != nil {
					t.Fatalf("%v failed (exit %d):\n%s", args, code, out)
				}
				if strings.Contains(out, "identity-home-aware") {
					t.Fatalf("%v was refused by the identity-home policy:\n%s", args, out)
				}
			}

			// It answered from the host state directory, not from the instance.
			if _, err := os.Lstat(filepath.Join(cwd, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("a wake command created instance identity state: %v", err)
			}
			if after := fileDigestsForTest(t, principalHome); !reflect.DeepEqual(after, before) {
				t.Fatal("a wake command changed principal identity state")
			}
			if _, err := os.Stat(filepath.Join(stateDir, "registry.d")); err != nil {
				t.Fatalf("the state directory was not used: %v", err)
			}

			// The exclusivity check, from the production binary.
			out, code, err := run("wake", "register", "--home", instanceHome,
				"--identity-home", filepath.Join(instanceHome, ".aw"), "--state-dir", stateDir)
			if err == nil {
				t.Fatalf("a registration without --delivery session succeeded:\n%s", out)
			}
			if code != 2 {
				t.Errorf("refusal exit=%d want 2:\n%s", code, out)
			}
			if !strings.Contains(out, "delivery") || !strings.Contains(out, "doubles every wake") {
				t.Errorf("the refusal does not name the conflict:\n%s", out)
			}

			// The rest of the refusal set the hook contract names.
			for _, bad := range [][]string{
				{"wake", "register", "--home", "relative/home", "--identity-home", filepath.Join(instanceHome, ".aw"), "--delivery", "session", "--state-dir", stateDir},
				{"wake", "register", "--home", instanceHome, "--identity-home", filepath.Join(instanceHome, "not-a-home"), "--delivery", "session", "--state-dir", stateDir},
			} {
				out, code, err := run(bad...)
				if err == nil {
					t.Errorf("%v succeeded:\n%s", bad, out)
				}
				if code == 0 {
					t.Errorf("%v exited 0 while refusing:\n%s", bad, out)
				}
			}

			// A retire hook that runs twice, or after an expiry already dropped
			// the registration, must not fail the retirement.
			out, code, err = run("wake", "deregister", "--home", instanceHome, "--state-dir", stateDir)
			if err != nil {
				t.Fatalf("deregistering an unknown home exited %d:\n%s", code, out)
			}
			if !strings.Contains(out, "nothing to deregister") {
				t.Fatalf("deregistering an unknown home did not say so:\n%s", out)
			}
		})
	}
}

// TestWakeRegisterFlagShadowsTheRootIdentityHome pins the collision described
// above, so a reader finds a decision here rather than a surprise in the field.
func TestWakeRegisterFlagShadowsTheRootIdentityHome(t *testing.T) {
	local := wakeRegisterCmd.Flags().Lookup("identity-home")
	if local == nil {
		t.Fatal("aw wake register lost its --identity-home flag; the surface was fixed with OATS")
	}
	if strings.Contains(local.Usage, "principal") {
		t.Fatal("the register flag documents itself as the principal selector; it names the instance's identity home")
	}
	if rootCmd.PersistentFlags().Lookup("identity-home") == nil {
		t.Fatal("the root persistent --identity-home disappeared")
	}
	// Only `register` shadows it. Every other wake command leaves the root flag
	// reachable, which is what the production-binary regression exercises.
	for _, cmd := range []string{"run", "status", "pause", "resume", "deregister"} {
		found, _, err := rootCmd.Find([]string{"wake", cmd})
		if err != nil {
			t.Fatalf("aw wake %s: %v", cmd, err)
		}
		if found.Flags().Lookup("identity-home") != nil {
			t.Errorf("aw wake %s shadows the root --identity-home", cmd)
		}
	}
}

// TestWakeRunIsIdempotentAndServesItsSocket: one daemon per host, a second
// start exits 0 saying so, and the state directory holds the lock and socket
// the note describes.
func TestWakeRunIsIdempotentAndServesItsSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake oats stand-in is POSIX shell")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	// A unix socket path is bounded by sun_path, and t.TempDir() embeds the
	// test name; the daemon says so itself, but the test needs a short one.
	stateRoot, err := os.MkdirTemp("", "awwk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stateRoot)
	stateDir := filepath.Join(stateRoot, "w")

	env := append(testCommandEnv(filepath.Join(root, "user-home")), "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")
	daemonCtx, stopDaemon := context.WithCancel(ctx)
	defer stopDaemon()
	daemon := exec.CommandContext(daemonCtx, bin, "wake", "run", "--state-dir", stateDir)
	daemon.Dir = root
	daemon.Env = env
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopDaemon()
		_ = daemon.Wait()
	}()

	socket := filepath.Join(stateDir, "control.sock")
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never created its control socket")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, alive := wake.LockOwner(filepath.Join(stateDir, "lock")); !alive {
		t.Fatal("the daemon did not take the host lock")
	}

	second := exec.CommandContext(ctx, bin, "wake", "run", "--state-dir", stateDir)
	second.Dir = root
	second.Env = env
	out, err := second.CombinedOutput()
	if err != nil {
		t.Fatalf("a second start must exit 0: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "already running") {
		t.Fatalf("a second start did not report the running daemon:\n%s", out)
	}

	// The running daemon answers status over the socket.
	statusCmd := exec.CommandContext(ctx, bin, "wake", "status", "--json", "--state-dir", stateDir)
	statusCmd.Dir = root
	statusCmd.Env = env
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status against a running daemon: %v\n%s", err, statusOut)
	}
	var status wake.Status
	if err := json.Unmarshal(statusOut, &status); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, statusOut)
	}
	if !status.DaemonRunning || status.DaemonPID == 0 {
		t.Fatalf("status did not reach the running daemon: %+v", status)
	}
	if status.MaxStreams != wake.DefaultMaxStreams {
		t.Fatalf("max_streams=%d want %d", status.MaxStreams, wake.DefaultMaxStreams)
	}
}

// TestWakeCommandsFallBackToFilesWhenTheDaemonIsDown: an OATS hook must not
// fail because the broker happens to be restarting.
func TestWakeCommandsFallBackToFilesWhenTheDaemonIsDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	stateDir := filepath.Join(root, "state")
	instanceHome := filepath.Join(root, "agent-home")
	if err := os.MkdirAll(filepath.Join(instanceHome, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := append(testCommandEnv(filepath.Join(root, "user-home")), "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")

	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return string(out)
	}

	run("wake", "register", "--home", instanceHome, "--identity-home", filepath.Join(instanceHome, ".aw"),
		"--delivery", "session", "--state-dir", stateDir)
	run("wake", "pause", "--home", instanceHome, "--state-dir", stateDir)

	// No daemon ever ran: the state is on disk, where the daemon reconciles it.
	if _, err := os.Stat(filepath.Join(stateDir, "control.sock")); !os.IsNotExist(err) {
		t.Fatalf("the fallback path created a socket: %v", err)
	}
	store, err := wake.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	reg, ok, err := store.LoadRegistration(instanceHome)
	if err != nil || !ok {
		t.Fatalf("the registration was not written by the fallback path: ok=%t err=%v", ok, err)
	}
	if reg.Delivery != wake.DeliverySession {
		t.Fatalf("registration=%+v", reg)
	}
	state, err := store.LoadInstance(instanceHome)
	if err != nil || !state.Paused {
		t.Fatalf("durable pause was not written by the fallback path: %+v err=%v", state, err)
	}

	out := run("wake", "status", "--state-dir", stateDir)
	if !strings.Contains(out, "not running") || !strings.Contains(out, instanceHome) {
		t.Fatalf("status with the daemon down did not read the files:\n%s", out)
	}

	run("wake", "deregister", "--home", instanceHome, "--state-dir", stateDir)
	if _, ok, _ := store.LoadRegistration(instanceHome); ok {
		t.Fatal("deregister via the fallback path left the registration behind")
	}
}

// TestWakeRegisterAcceptsAHomeUnderASymlinkedParent is the regression for the
// collision the reviewer found in the ACK of 6efe8c49.
//
// `aw` reads the root --identity-home out of argv textually, before cobra, so
// that a plugin runs under the attached principal. That scan used to run to the
// end of argv, which meant `aw wake register --identity-home <the instance's
// own identity home>` had the *instance's* path put through the principal path
// preflight — and that preflight refuses a home reached through a symlinked
// parent. The process exited non-zero before register ran at all, and the OATS
// spawn hook reads a non-zero exit as a failed spawn.
//
// A symlinked ancestor is not exotic: on macOS /tmp is one.
func TestWakeRegisterAcceptsAHomeUnderASymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not the same contract on windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "agent", ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// The home the hook would pass: its parent component is a symlink.
	instanceHome := filepath.Join(root, "link", "agent")
	stateDir := filepath.Join(root, "state")

	cmd := exec.CommandContext(ctx, bin, "wake", "register",
		"--home", instanceHome,
		"--identity-home", filepath.Join(instanceHome, ".aw"),
		"--delivery", "session", "--state-dir", stateDir)
	cmd.Dir = root
	cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")), "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("registering a home under a symlinked parent failed the spawn: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "must not be a symlink") {
		t.Fatalf("the instance identity home was put through the principal preflight:\n%s", out)
	}

	store, err := wake.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.LoadRegistration(instanceHome); err != nil || !ok {
		t.Fatalf("the registration was not written: ok=%t err=%v", ok, err)
	}
}

// TestIdentityHomePreScanStopsAtABuiltinCommand pins the scan itself, including
// the two shapes that must keep working: the root flag before a built-in, and a
// plugin's own trailing flag.
func TestIdentityHomePreScanStopsAtABuiltinCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"root flag before a builtin", []string{"--identity-home", "/principal", "wake", "register", "--home", "/h"}, "/principal"},
		{"builtin subcommand flag is not the principal", []string{"wake", "register", "--home", "/h", "--identity-home", "/h/.aw"}, ""},
		{"builtin subcommand flag does not override the root one", []string{"--identity-home", "/principal", "wake", "register", "--identity-home", "/h/.aw"}, "/principal"},
		{"equals form before a builtin", []string{"--identity-home=/principal", "mail", "inbox"}, "/principal"},
		{"a plugin keeps its trailing flag", []string{"folio", "present", "--identity-home", "/principal"}, "/principal"},
		{"root flag before a plugin", []string{"--identity-home", "/principal", "folio", "present"}, "/principal"},
		{"a server named after a command is not a command", []string{"--server-name", "run", "folio", "--identity-home", "/principal"}, "/principal"},
		{"no flag at all", []string{"wake", "status"}, ""},
		// help and completion are added by cobra inside ExecuteC, after this
		// scan runs, so they reach the built-in set only because
		// reservedRootCommandNames adds them itself. Sharing that set with
		// plugin dispatch is what makes this true rather than accidental.
		{"help is a builtin at scan time", []string{"help", "--identity-home", "/principal"}, ""},
		{"completion is a builtin at scan time", []string{"completion", "bash", "--identity-home", "/principal"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := identityHomeForPluginDispatch(tc.args); got != tc.want {
				t.Errorf("identityHomeForPluginDispatch(%v)=%q want %q", tc.args, got, tc.want)
			}
		})
	}
}
