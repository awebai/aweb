package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

var (
	agentHomeFlag     string
	agentRuntimeFlag  string
	agentCommandFlag  string
	agentFollowLogs   bool
	agentRestartForce bool
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start and inspect local materialized agents",
	Long:  "Start, stop, restart, inspect, and read logs for local materialized agent homes under agents/instances/<name>.",
}

var agentStartCmd = &cobra.Command{
	Use:   "start <name>",
	Short: "Start a local agent runtime from its materialized profile",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentStart,
}

var agentStatusCmd = &cobra.Command{
	Use:   "status <name>",
	Short: "Show local agent runtime status",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentStatus,
}

var agentStopCmd = &cobra.Command{
	Use:   "stop <name>",
	Short: "Stop a local agent runtime",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentStop,
}

var agentRestartCmd = &cobra.Command{
	Use:   "restart <name>",
	Short: "Restart a local agent runtime",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentRestart,
}

var agentLogsCmd = &cobra.Command{
	Use:   "logs <name>",
	Short: "Print local agent runtime logs",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentLogs,
}

func init() {
	for _, cmd := range []*cobra.Command{agentStartCmd, agentStatusCmd, agentStopCmd, agentRestartCmd, agentLogsCmd} {
		cmd.Flags().StringVar(&agentHomeFlag, "home", "", "Agent home directory override (default: agents/instances/<name>)")
	}
	agentStartCmd.Flags().StringVar(&agentRuntimeFlag, "runtime", "", "Runtime to start explicitly (claude-code|codex|pi|local-shell)")
	agentStartCmd.Flags().StringVar(&agentCommandFlag, "command", "", "Advanced: explicit shell command to run instead of a named runtime")
	agentRestartCmd.Flags().StringVar(&agentRuntimeFlag, "runtime", "", "Runtime to start explicitly (claude-code|codex|pi|local-shell)")
	agentRestartCmd.Flags().StringVar(&agentCommandFlag, "command", "", "Advanced: explicit shell command to run instead of a named runtime")
	agentRestartCmd.Flags().BoolVar(&agentRestartForce, "force", false, "Restart even when the recorded process is not running")
	agentLogsCmd.Flags().BoolVar(&agentFollowLogs, "follow", false, "Follow logs until interrupted")
	agentCmd.AddCommand(agentStartCmd, agentStatusCmd, agentStopCmd, agentRestartCmd, agentLogsCmd)
	rootCmd.AddCommand(agentCmd)
}

type agentRuntimeState struct {
	Name      string    `json:"name"`
	HomeDir   string    `json:"home_dir"`
	Runtime   string    `json:"runtime"`
	Command   []string  `json:"command"`
	PID       int       `json:"pid"`
	LogPath   string    `json:"log_path"`
	StartedAt time.Time `json:"started_at"`
}

type agentStatusOutput struct {
	Name      string   `json:"name"`
	HomeDir   string   `json:"home_dir"`
	Runtime   string   `json:"runtime,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Status    string   `json:"status"`
	LogPath   string   `json:"log_path,omitempty"`
	Command   []string `json:"command,omitempty"`
	StartedAt string   `json:"started_at,omitempty"`
	Detail    string   `json:"detail,omitempty"`
}

func runAgentStart(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	state, err := startAgentRuntime(name, home, strings.TrimSpace(agentRuntimeFlag), strings.TrimSpace(agentCommandFlag))
	if err != nil {
		return err
	}
	printOutput(agentStatusFromState(state, "running", ""), formatAgentStatus)
	return nil
}

func runAgentStatus(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	out, err := loadAgentStatus(name, home)
	if err != nil {
		return err
	}
	printOutput(out, formatAgentStatus)
	return nil
}

func runAgentStop(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	state, err := loadAgentRuntimeState(home)
	if err != nil {
		return err
	}
	if state.PID <= 0 {
		return fmt.Errorf("agent %s has invalid runtime pid", name)
	}
	if processAlive(state.PID) {
		proc, err := os.FindProcess(state.PID)
		if err != nil {
			return err
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil && processAlive(state.PID) {
			return fmt.Errorf("stop agent %s pid %d: %w", name, state.PID, err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && processAlive(state.PID) {
			time.Sleep(50 * time.Millisecond)
		}
		if processAlive(state.PID) {
			_ = proc.Kill()
		}
	}
	out := agentStatusFromState(state, "stopped", "")
	printOutput(out, formatAgentStatus)
	return nil
}

func runAgentRestart(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	if state, err := loadAgentRuntimeState(home); err == nil && processAlive(state.PID) {
		proc, _ := os.FindProcess(state.PID)
		_ = proc.Signal(syscall.SIGTERM)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && processAlive(state.PID) {
			time.Sleep(50 * time.Millisecond)
		}
	} else if err != nil && !agentRestartForce && !os.IsNotExist(err) {
		return err
	}
	state, err := startAgentRuntime(name, home, strings.TrimSpace(agentRuntimeFlag), strings.TrimSpace(agentCommandFlag))
	if err != nil {
		return err
	}
	printOutput(agentStatusFromState(state, "running", ""), formatAgentStatus)
	return nil
}

func runAgentLogs(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(args[0])
	home, err := resolveAgentHome(name)
	if err != nil {
		return err
	}
	state, err := loadAgentRuntimeState(home)
	if err != nil {
		return err
	}
	if strings.TrimSpace(state.LogPath) == "" {
		return fmt.Errorf("agent %s has no log path", name)
	}
	return printAgentLog(cmd.OutOrStdout(), state.LogPath, agentFollowLogs)
}

func resolveAgentHome(name string) (string, error) {
	if name == "" {
		return "", usageError("agent name is required")
	}
	if strings.TrimSpace(agentHomeFlag) != "" {
		return filepath.Abs(agentHomeFlag)
	}
	if !isValidWorkspaceAlias(name) {
		return "", usageError("invalid agent name %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars); use --home for an explicit path", name)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(resolveRepoRoot(wd), "agents", "instances", name), nil
}

func startAgentRuntime(name, home, runtimeOverride, commandOverride string) (*agentRuntimeState, error) {
	if err := validateAgentHomeForStart(home); err != nil {
		return nil, err
	}
	if existing, err := loadAgentRuntimeState(home); err == nil && processAlive(existing.PID) {
		return nil, usageError("agent %s is already running with pid %d", name, existing.PID)
	}
	runtime, argv, err := selectAgentRuntime(runtimeOverride, commandOverride)
	if err != nil {
		return nil, err
	}
	runtimeDir := agentRuntimeDir(home)
	if err := preflightAgentRuntimeDir(runtimeDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(runtimeDir, "agent.log")
	statePath := agentRuntimeStatePath(home)
	if err := preflightAgentRuntimeFile(logPath); err != nil {
		return nil, err
	}
	if err := preflightAgentRuntimeFile(statePath); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = home
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "AW_AGENT_HOME="+home, "AW_AGENT_RUNTIME="+runtime)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s runtime %q in %s: %w", name, runtime, home, err)
	}
	go func() { _ = cmd.Wait() }()
	state := &agentRuntimeState{Name: name, HomeDir: home, Runtime: runtime, Command: argv, PID: cmd.Process.Pid, LogPath: logPath, StartedAt: time.Now().UTC()}
	if err := saveAgentRuntimeState(home, state); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	return state, nil
}

func validateAgentHomeForStart(home string) error {
	if err := pathpreflight.PreflightDir(home, "agent home", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("agent home %s not found (missing worktree or agents/instances entry)", home)
		}
		return err
	}
	if _, err := os.Lstat(home); os.IsNotExist(err) {
		return fmt.Errorf("agent home %s not found (missing worktree or agents/instances entry)", home)
	} else if err != nil {
		return err
	}
	profilePath := filepath.Join(home, ".aw", "profile", "profile.yaml")
	if _, err := os.Lstat(profilePath); os.IsNotExist(err) {
		return fmt.Errorf("profile materialization missing for %s: expected %s", home, profilePath)
	} else if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(home, awconfig.DefaultWorktreeWorkspaceRelativePath())); err == nil {
		if _, err := resolveSelectionForDir(home); err != nil {
			return fmt.Errorf("bad team config or certificate for %s: %w", home, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func preflightAgentRuntimeDir(runtimeDir string) error {
	return pathpreflight.PreflightDir(runtimeDir, "agent runtime directory", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

const supportedAgentRuntimes = "claude-code|codex|pi|local-shell"

func selectAgentRuntime(runtimeOverride, commandOverride string) (string, []string, error) {
	if commandOverride != "" {
		runtime := strings.ToLower(strings.TrimSpace(runtimeOverride))
		if runtime == "" {
			runtime = "custom"
		}
		return runtime, []string{"sh", "-c", commandOverride}, nil
	}
	chosen := strings.ToLower(strings.TrimSpace(runtimeOverride))
	if chosen == "" {
		return "", nil, fmt.Errorf("runtime is required; pass --runtime (%s) or --command. Runtime hints and runtime_assumptions are advisory metadata only; inspect them with `aw blueprint inspect` or `aw library get-profile` before choosing", supportedAgentRuntimes)
	}
	switch chosen {
	case "claude-code":
		path, err := exec.LookPath("claude")
		if err != nil {
			return "", nil, fmt.Errorf("missing provider for runtime claude-code: claude executable not found")
		}
		return chosen, []string{path}, nil
	case "codex":
		path, err := exec.LookPath("codex")
		if err != nil {
			return "", nil, fmt.Errorf("missing provider for runtime codex: codex executable not found")
		}
		return chosen, []string{path}, nil
	case "pi":
		path, err := exec.LookPath("pi")
		if err != nil {
			return "", nil, fmt.Errorf("missing provider for runtime pi: pi executable not found")
		}
		return chosen, []string{path}, nil
	case "local-shell", "local shell":
		path, err := exec.LookPath("sh")
		if err != nil {
			return "", nil, fmt.Errorf("missing provider for runtime local-shell: sh executable not found")
		}
		return "local-shell", []string{path, "-c", "while :; do sleep 3600; done"}, nil
	default:
		return "", nil, fmt.Errorf("runtime %q is not supported by aw agent start; supported runtimes: %s", chosen, supportedAgentRuntimes)
	}
}

func agentRuntimeDir(home string) string { return filepath.Join(home, ".aw", "runtime") }
func agentRuntimeStatePath(home string) string {
	return filepath.Join(agentRuntimeDir(home), "agent.json")
}

func preflightAgentRuntimeFile(path string) error {
	return pathpreflight.PreflightFile(path, "agent runtime file", pathpreflight.AllowTempAmbientSymlinkPrefix())
}
func saveAgentRuntimeState(home string, state *agentRuntimeState) error {
	if err := preflightAgentRuntimeFile(agentRuntimeStatePath(home)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(agentRuntimeStatePath(home), data, 0o600)
}

func loadAgentRuntimeState(home string) (*agentRuntimeState, error) {
	data, err := os.ReadFile(agentRuntimeStatePath(home))
	if err != nil {
		return nil, err
	}
	var state agentRuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse runtime state: %w", err)
	}
	return &state, nil
}

func loadAgentStatus(name, home string) (agentStatusOutput, error) {
	state, err := loadAgentRuntimeState(home)
	if os.IsNotExist(err) {
		return agentStatusOutput{Name: name, HomeDir: home, Status: "not_started", Detail: "no local runtime state"}, nil
	}
	if err != nil {
		return agentStatusOutput{}, err
	}
	status := "exited"
	if processAlive(state.PID) {
		status = "running"
	}
	return agentStatusFromState(state, status, ""), nil
}

func agentStatusFromState(state *agentRuntimeState, status, detail string) agentStatusOutput {
	started := ""
	if !state.StartedAt.IsZero() {
		started = state.StartedAt.Format(time.RFC3339Nano)
	}
	return agentStatusOutput{Name: state.Name, HomeDir: state.HomeDir, Runtime: state.Runtime, PID: state.PID, Status: status, LogPath: state.LogPath, Command: state.Command, StartedAt: started, Detail: detail}
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func printAgentLog(w io.Writer, path string, follow bool) error {
	if !follow {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(w, file); err != nil {
		return err
	}
	for {
		buf := make([]byte, 4096)
		n, err := file.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil && err != io.EOF {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func formatAgentStatus(v any) string {
	out := v.(agentStatusOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s", out.Name, out.Status)
	if out.Runtime != "" {
		fmt.Fprintf(&b, " runtime=%s", out.Runtime)
	}
	if out.PID != 0 {
		fmt.Fprintf(&b, " pid=%d", out.PID)
	}
	if out.Detail != "" {
		fmt.Fprintf(&b, " (%s)", out.Detail)
	}
	b.WriteString("\n")
	if out.LogPath != "" {
		fmt.Fprintf(&b, "logs: %s\n", out.LogPath)
	}
	return b.String()
}
