package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake"
	"github.com/awebai/aw/wake/session"
	"github.com/spf13/cobra"
)

// The terminal wake broker: one reconnecting event stream per authorized
// identity on a host, coalescing hints and typing them into each instance's
// original terminal through the OATS input operation.
//
// docs/terminal-wake-broker.md is the design; this file is only the command
// surface. The broker never fetches, decrypts or types a sender's content, and
// it never acknowledges anything on any path.

// StateDirEnv overrides the default state directory. It exists so a test or a
// second host profile can point the broker somewhere else without a flag on
// every hook invocation.
const wakeStateDirEnv = "AW_WAKE_STATE_DIR"

var (
	wakeStateDirFlag     string
	wakeMaxStreams       int
	wakeCoalesceMS       int
	wakeRateLimitMS      int
	wakeOatsBin          string
	wakeRegisterHome     string
	wakeRegisterIDHome   string
	wakeRegisterDelivery string
	wakeRegisterBackend  string
	wakeDeregisterHome   string
	wakePauseHome        string
	wakeResumeHome       string
)

var wakeCmd = &cobra.Command{
	Use:   "wake",
	Short: "Terminal wake broker: stream events and type wake hints into instance terminals",
	Long: "Terminal wake broker.\n\n" +
		"One daemon per host holds a reconnecting event stream per registered identity,\n" +
		"coalesces the resulting hints per instance, and types a short fetch instruction\n" +
		"plus a hint summary into each instance's original terminal through OATS.\n\n" +
		"It never fetches, decrypts or types a sender's message, and it never\n" +
		"acknowledges anything: the instance's own `aw` does all of that.",
}

var wakeRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the host wake broker in the foreground",
	Long: "Run the host wake broker in the foreground.\n\n" +
		"One daemon per host. All state is on disk and there is no cursor, so the\n" +
		"daemon is safe to restart at any time: it re-reads its registrations and\n" +
		"pending hints, and the reconnect snapshot re-raises anything still unread.\n" +
		"A second start exits 0 reporting the running daemon.",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := wakeStore()
		if err != nil {
			return err
		}

		lock, err := wake.AcquireLock(store.LockDir())
		if err != nil {
			var running *wake.ErrDaemonAlreadyRunning
			if errors.As(err, &running) {
				fmt.Fprintf(cmd.OutOrStdout(), "wake broker is already running (pid %d); nothing to do\n", running.PID)
				return nil
			}
			return err
		}
		defer func() { _ = lock.Release() }()

		broker, err := wake.NewBroker(wake.Config{
			Store:      store,
			Session:    &session.ExecClient{Bin: strings.TrimSpace(wakeOatsBin)},
			OpenStream: wakeStreamOpener,
			MaxStreams: wakeMaxStreams,
			Coalesce:   millis(wakeCoalesceMS),
			RateLimit:  millis(wakeRateLimitMS),
			Log:        wakeLogger(),
		})
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		controlErr := make(chan error, 1)
		go func() { controlErr <- wake.ServeControl(ctx, broker) }()

		fmt.Fprintf(cmd.OutOrStdout(), "wake broker listening: state_dir=%s socket=%s max_streams=%d\n",
			store.Dir(), store.SocketPath(), broker.MaxStreams())

		runErr := broker.Run(ctx)
		if err := <-controlErr; err != nil && runErr == nil {
			runErr = err
		}
		return runErr
	},
}

var wakeRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an instance home with the wake broker",
	Long: "Register an instance home with the wake broker.\n\n" +
		"Called by the OATS spawn hook. --delivery must be session: the broker and a\n" +
		"live native channel are two presentation surfaces on one identity, and running\n" +
		"both doubles every wake. A registration stays pending until an inspect reports\n" +
		"the instance present; pending errors are tolerated until the 30-minute expiry.\n\n" +
		"Exit 0 means the registration was written durably: over the daemon's socket\n" +
		"when it is up, and straight to the state directory when it is not, so a hook\n" +
		"never fails because the broker is restarting. A non-zero exit means refused —\n" +
		"a missing --delivery session, a relative path, or an unreadable identity home.\n\n" +
		"--identity-home here names the instance's own identity home, and shadows the\n" +
		"root flag of the same name for this command. Give the principal's home before\n" +
		"the subcommand (aw --identity-home <principal> wake register ...) when you need\n" +
		"both.",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg := wake.Registration{
			Home:         strings.TrimSpace(wakeRegisterHome),
			IdentityHome: strings.TrimSpace(wakeRegisterIDHome),
			Delivery:     strings.TrimSpace(wakeRegisterDelivery),
			Backend:      strings.TrimSpace(wakeRegisterBackend),
			RegisteredAt: time.Now().UTC(),
		}
		if err := reg.Validate(); err != nil {
			return usageError("%s", err.Error())
		}
		store, err := wakeStore()
		if err != nil {
			return err
		}
		_, err = wakeCallOrFallback(store, wake.ControlRequest{Op: wake.OpRegister, Registration: &reg}, func() error {
			if existing, ok, loadErr := store.LoadRegistration(reg.Home); loadErr == nil && ok {
				reg.RegisteredAt = existing.RegisteredAt
			}
			return store.SaveRegistration(reg)
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "registered %s (identity home %s)\n", reg.Home, reg.IdentityHome)
		return nil
	},
}

var wakeDeregisterCmd = &cobra.Command{
	Use:   "deregister",
	Short: "Remove an instance home from the wake broker",
	Long: "Remove an instance home from the wake broker.\n\n" +
		"Called by the OATS retire hook after quiescence. The broker never stops an\n" +
		"instance and never removes a registration on its own; an instance it observed\n" +
		"stopped is marked inactive and waits here.\n\n" +
		"An unknown or already-retired home exits 0 with a note: the hook may run twice,\n" +
		"or after the pending expiry already dropped the registration, and neither is a\n" +
		"failed retirement.",
	RunE: func(cmd *cobra.Command, args []string) error {
		home := strings.TrimSpace(wakeDeregisterHome)
		if home == "" || !filepath.IsAbs(home) {
			return usageError("--home must be an absolute instance home path")
		}
		store, err := wakeStore()
		if err != nil {
			return err
		}
		existed := false
		resp, err := wakeCallOrFallback(store, wake.ControlRequest{Op: wake.OpDeregister, Home: home}, func() error {
			had, delErr := store.DeleteRegistration(home)
			existed = had
			return delErr
		})
		if err != nil {
			return err
		}
		if resp.Existed {
			existed = true
		}
		// An unknown or already-retired home is not an error. The retire hook
		// can run twice, or after an expiry already dropped the registration,
		// and a non-zero exit there would fail a retirement that is complete.
		if !existed {
			fmt.Fprintf(cmd.OutOrStdout(), "no registration for %s; nothing to deregister\n", home)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "deregistered %s\n", home)
		return nil
	},
}

var wakePauseCmd = &cobra.Command{
	Use:   "pause",
	Short: "Stop the broker typing into one instance, durably",
	Long: "Stop the broker typing into one instance.\n\n" +
		"Pause is durable broker state and survives a restart. It suppresses typing;\n" +
		"it does not stop the stream, drop hints, or acknowledge anything.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return wakeSetPaused(cmd, wakePauseHome, true)
	},
}

var wakeResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Let the broker type into one instance again",
	RunE: func(cmd *cobra.Command, args []string) error {
		return wakeSetPaused(cmd, wakeResumeHome, false)
	},
}

var wakeStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report per-home broker state, last attempt, and pending hints",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := wakeStore()
		if err != nil {
			return err
		}
		var status wake.Status
		resp, callErr := wake.Call(store.SocketPath(), wake.ControlRequest{Op: wake.OpStatus})
		switch {
		case callErr == nil && resp.Status != nil:
			status = *resp.Status
		case callErr != nil && errors.Is(callErr, wake.ErrDaemonDown):
			status, err = wake.StatusFromStore(store, wakeMaxStreams)
			if err != nil {
				return err
			}
		case callErr != nil:
			return callErr
		}
		printOutput(status, formatWakeStatus)
		return nil
	},
}

func wakeSetPaused(cmd *cobra.Command, home string, paused bool) error {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return usageError("--home must be an absolute instance home path")
	}
	store, err := wakeStore()
	if err != nil {
		return err
	}
	op := wake.OpResume
	if paused {
		op = wake.OpPause
	}
	if _, err := wakeCallOrFallback(store, wake.ControlRequest{Op: op, Home: home}, func() error {
		return wake.SetPausedInStore(store, home, paused)
	}); err != nil {
		return err
	}
	verb := "resumed"
	if paused {
		verb = "paused"
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", verb, home)
	return nil
}

// wakeCallOrFallback sends a control request to the running daemon, and writes
// the state files directly when nothing is listening.
//
// The fallback is what keeps an OATS hook from failing because the broker
// happens to be restarting: the daemon reconciles registry.d on start and on a
// timer, so a file written here is picked up either way. It is not a bypass of
// the exclusivity check — Registration.Validate runs on the command side, and
// the daemon re-validates every file it reconciles.
func wakeCallOrFallback(store *wake.Store, req wake.ControlRequest, fallback func() error) (wake.ControlResponse, error) {
	resp, err := wake.Call(store.SocketPath(), req)
	if err == nil {
		return resp, nil
	}
	if !errors.Is(err, wake.ErrDaemonDown) {
		return resp, err
	}
	return wake.ControlResponse{OK: true}, fallback()
}

// wakeStore resolves the state directory: the flag, then AW_WAKE_STATE_DIR,
// then ~/.config/aw/wake.
func wakeStore() (*wake.Store, error) {
	dir := strings.TrimSpace(wakeStateDirFlag)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(wakeStateDirEnv))
	}
	if dir == "" {
		resolved, err := awconfig.PathInUserState("wake")
		if err != nil {
			return nil, err
		}
		dir = resolved
	}
	if !filepath.IsAbs(dir) {
		return nil, usageError("--state-dir must be an absolute path, got %q", dir)
	}
	return wake.NewStore(dir)
}

// wakeStreamOpener builds one identity's event stream source.
//
// Credentials stay explicit per client and authentication is never
// re-implemented: this resolves the identity home through the same selection
// path every other identity-home-aware command uses. The broker needs
// stream-read authority and nothing else — it never opens a message, so it
// never needs decryption material for any identity.
func wakeStreamOpener(identityHome string) (run.EventStreamOpener, error) {
	identityHome = strings.TrimSpace(identityHome)
	if identityHome == "" || !filepath.IsAbs(identityHome) {
		return nil, fmt.Errorf("identity home must be an absolute path, got %q", identityHome)
	}
	home := awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	workingDir := awconfig.WorktreeRootFromIdentityPath(filepath.Join(identityHome, "identity.yaml"))
	if strings.TrimSpace(workingDir) == "" {
		workingDir = filepath.Dir(identityHome)
	}
	client, _, err := resolveClientSelectionAtIdentityHome(workingDir, home)
	if err != nil {
		return nil, err
	}
	return run.NewEventStreamOpener(client.Client), nil
}

func wakeLogger() func(string, ...any) {
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "%s wake: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
}

func millis(v int) time.Duration {
	if v <= 0 {
		return 0
	}
	return time.Duration(v) * time.Millisecond
}

func formatWakeStatus(v any) string {
	status, ok := v.(wake.Status)
	if !ok {
		return ""
	}
	var b strings.Builder
	daemon := "not running"
	if status.DaemonRunning {
		daemon = fmt.Sprintf("running (pid %d)", status.DaemonPID)
	}
	fmt.Fprintf(&b, "wake broker: %s\n", daemon)
	fmt.Fprintf(&b, "  state dir:   %s\n", status.StateDir)
	fmt.Fprintf(&b, "  max streams: %d\n", status.MaxStreams)

	if len(status.Streams) == 0 {
		b.WriteString("\nStreams: none\n")
	} else {
		b.WriteString("\nStreams:\n")
		for _, stream := range status.Streams {
			line := fmt.Sprintf("  %s  %s", stream.Phase, stream.IdentityHome)
			if !stream.Admitted {
				line += "  [over the stream bound; registration kept]"
			}
			if stream.UnreadCount > 0 {
				line += fmt.Sprintf("  unread=%d", stream.UnreadCount)
			}
			if strings.TrimSpace(stream.LastError) != "" {
				line += "  error=" + stream.LastError
			}
			b.WriteString(line + "\n")
		}
	}

	if len(status.Instances) == 0 {
		b.WriteString("\nInstances: none registered\n")
		return b.String()
	}
	b.WriteString("\nInstances:\n")
	for _, inst := range status.Instances {
		fmt.Fprintf(&b, "  %s\n", inst.Home)
		fmt.Fprintf(&b, "    phase=%s pending_hints=%d evicted=%d paused=%t\n", inst.Phase, inst.PendingHints, inst.Evicted, inst.Paused)
		fmt.Fprintf(&b, "    identity_home=%s backend=%s\n", inst.IdentityHome, dashIfEmpty(inst.Backend))
		fmt.Fprintf(&b, "    last_state=%s last_inspect=%s last_attempt=%s last_submit=%s\n",
			dashIfEmpty(inst.LastState), stampOrDash(inst.LastInspectAt), stampOrDash(inst.LastAttemptAt), stampOrDash(inst.LastSubmitAt))
		if inst.UnreadCount > 0 {
			fmt.Fprintf(&b, "    unread=%d\n", inst.UnreadCount)
		}
		if strings.TrimSpace(inst.LastError) != "" {
			fmt.Fprintf(&b, "    last_error=%s\n", inst.LastError)
		}
	}
	return b.String()
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func stampOrDash(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func init() {
	wakeCmd.GroupID = groupNetwork

	for _, cmd := range []*cobra.Command{wakeRunCmd, wakeRegisterCmd, wakeDeregisterCmd, wakeStatusCmd, wakePauseCmd, wakeResumeCmd} {
		cmd.Flags().StringVar(&wakeStateDirFlag, "state-dir", "", "Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)")
	}

	wakeRunCmd.Flags().IntVar(&wakeMaxStreams, "max-streams", wake.DefaultMaxStreams, "Maximum concurrent identity event streams")
	wakeRunCmd.Flags().IntVar(&wakeCoalesceMS, "coalesce", int(wake.DefaultCoalesce/time.Millisecond), "Coalescing window in milliseconds")
	wakeRunCmd.Flags().IntVar(&wakeRateLimitMS, "rate-limit", int(wake.DefaultRateLimit/time.Millisecond), "Minimum milliseconds between submission attempts per instance")
	wakeRunCmd.Flags().StringVar(&wakeOatsBin, "oats-bin", "", "OATS executable to run (default $"+session.OatsBinEnv+", else `oats` from PATH)")

	wakeRegisterCmd.Flags().StringVar(&wakeRegisterHome, "home", "", "Absolute instance home path")
	wakeRegisterCmd.Flags().StringVar(&wakeRegisterIDHome, "identity-home", "", "Absolute identity home the instance streams under")
	wakeRegisterCmd.Flags().StringVar(&wakeRegisterDelivery, "delivery", "", "Delivery mode recorded by the spawn hook; must be session")
	wakeRegisterCmd.Flags().StringVar(&wakeRegisterBackend, "backend", "", "Terminal backend hint: tmux or herdr")

	wakeDeregisterCmd.Flags().StringVar(&wakeDeregisterHome, "home", "", "Absolute instance home path")
	wakePauseCmd.Flags().StringVar(&wakePauseHome, "home", "", "Absolute instance home path")
	wakeResumeCmd.Flags().StringVar(&wakeResumeHome, "home", "", "Absolute instance home path")
	wakeStatusCmd.Flags().IntVar(&wakeMaxStreams, "max-streams", wake.DefaultMaxStreams, "Stream bound reported when the daemon is down")

	wakeCmd.AddCommand(wakeRunCmd, wakeRegisterCmd, wakeDeregisterCmd, wakeStatusCmd, wakePauseCmd, wakeResumeCmd)
	rootCmd.AddCommand(wakeCmd)
}
