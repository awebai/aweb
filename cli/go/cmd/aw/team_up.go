package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	teamUpSession  string
	teamUpDryRun   bool
	teamUpAttach   bool
	teamUpNoAttach bool
	teamUpRecreate bool
	teamUpForce    bool
)

var teamHumanUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Launch local team agents in tmux",
	Long: "Launch local team agents in tmux. This is a local runtime convenience: " +
		"it reads materialized agents/instances/<name> homes and starts one tmux " +
		"window per supported interactive harness. Team definitions and profile " +
		"provenance remain in aweb state and .aw/profile/ref.json.",
	Args: cobra.NoArgs,
	RunE: runTeamHumanUp,
}

type teamUpPlan struct {
	Session string            `json:"session"`
	Agents  []teamUpAgentPlan `json:"agents"`
}

type teamUpAgentPlan struct {
	Name        string   `json:"name"`
	HomeDir     string   `json:"home_dir"`
	RuntimeKind string   `json:"runtime_kind"`
	Command     []string `json:"command"`
	Action      string   `json:"action"`
	Reason      string   `json:"reason,omitempty"`
	RunningPID  int      `json:"running_pid,omitempty"`
	RunningCmd  string   `json:"running_command,omitempty"`
}

const (
	teamUpActionStart = "start"
	teamUpActionSkip  = "skip"
)

type teamUpRunningProcess struct {
	PID     int
	Command string
	CWD     string
}

var teamUpDetectActiveHomes = detectTeamUpActiveHomes

func init() {
	teamUpAttach = true
	teamHumanUpCmd.Flags().StringVar(&teamUpSession, "session", "", "tmux session name (default: active team name or aw-team)")
	teamHumanUpCmd.Flags().BoolVar(&teamUpDryRun, "dry-run", false, "Print the tmux launch plan without running it")
	teamHumanUpCmd.Flags().BoolVar(&teamUpAttach, "attach", true, "Attach or switch to the tmux session after launch")
	teamHumanUpCmd.Flags().BoolVar(&teamUpNoAttach, "no-attach", false, "Do not attach or switch to the tmux session after launch")
	teamHumanUpCmd.Flags().BoolVar(&teamUpRecreate, "recreate", false, "Kill and recreate an existing tmux session")
	teamHumanUpCmd.Flags().BoolVar(&teamUpForce, "force", false, "Start even when another process already has an agent home as its cwd")
	teamHumanCmd.AddCommand(teamHumanUpCmd)
}

func runTeamHumanUp(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	repoRoot := resolveRepoRoot(wd)
	session := strings.TrimSpace(teamUpSession)
	if session == "" {
		session = defaultTeamUpSessionName(repoRoot)
	}
	plan, err := buildTeamUpPlan(repoRoot, session, teamUpForce, teamUpRecreate)
	if err != nil {
		return err
	}
	if teamUpDryRun {
		return printTeamUpPlan(cmd.OutOrStdout(), plan)
	}
	if err := preflightTeamUpCommands(plan); err != nil {
		return err
	}
	attach := teamUpAttach && !teamUpNoAttach
	if err := executeTeamUpPlan(cmd, plan, teamUpRecreate, attach); err != nil {
		return err
	}
	return nil
}

func defaultTeamUpSessionName(repoRoot string) string {
	workspace, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(repoRoot)
	if err == nil && teamState != nil {
		teamID := strings.TrimSpace(teamState.ActiveTeam)
		if teamID != "" {
			return safeTmuxName(teamID)
		}
	}
	if err == nil && workspace != nil && len(workspace.Memberships) == 1 {
		teamID := strings.TrimSpace(workspace.Memberships[0].TeamID)
		if teamID != "" {
			return safeTmuxName(teamID)
		}
	}
	return "aw-team"
}

func buildTeamUpPlan(repoRoot, session string, force bool, recreate bool) (teamUpPlan, error) {
	agentsDir := filepath.Join(repoRoot, "agents", "instances")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return teamUpPlan{}, fmt.Errorf("no agents/instances directory found; add materialized agents first with `aw team add NAME@BLUEPRINT/PROFILE=<runtime>`")
		}
		return teamUpPlan{}, err
	}
	plan := teamUpPlan{Session: safeTmuxName(firstNonEmptyLibraryValue(session, "aw-team"))}
	activeHomes := map[string]teamUpRunningProcess{}
	if !(force || recreate) {
		activeHomes, err = teamUpDetectActiveHomes(agentsDir)
		if err != nil {
			return teamUpPlan{}, err
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		home := filepath.Join(agentsDir, name)
		if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return teamUpPlan{}, err
		}
		runtimeKind, err := readTeamUpRuntimeKind(home)
		if err != nil {
			return teamUpPlan{}, fmt.Errorf("%s: %w", name, err)
		}
		command, err := teamUpCommandForRuntime(runtimeKind)
		if err != nil {
			return teamUpPlan{}, fmt.Errorf("%s: %w", name, err)
		}
		agent := teamUpAgentPlan{Name: name, HomeDir: home, RuntimeKind: runtimeKind, Command: command, Action: teamUpActionStart}
		if proc, ok := activeHomes[canonicalTeamUpPath(home)]; ok {
			agent.Action = teamUpActionSkip
			agent.Reason = "process already has agent home as cwd"
			agent.RunningPID = proc.PID
			agent.RunningCmd = proc.Command
		}
		plan.Agents = append(plan.Agents, agent)
	}
	sort.Slice(plan.Agents, func(i, j int) bool { return plan.Agents[i].Name < plan.Agents[j].Name })
	if len(plan.Agents) == 0 {
		return teamUpPlan{}, fmt.Errorf("no materialized agents found under agents/instances (expected .aw/profile/profile.yaml)")
	}
	return plan, nil
}

func readTeamUpRuntimeKind(home string) (string, error) {
	refPath := filepath.Join(home, ".aw", "profile", "ref.json")
	data, err := os.ReadFile(refPath)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultMaterializeRuntimeKind, nil
		}
		return "", fmt.Errorf("read %s: %w", refPath, err)
	}
	var ref recordedProfileRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return "", fmt.Errorf("parse %s: %w", refPath, err)
	}
	runtimeKind := strings.TrimSpace(ref.RuntimeKind)
	if runtimeKind == "" {
		return defaultMaterializeRuntimeKind, nil
	}
	return normalizeMaterializeRuntimeKind(runtimeKind)
}

func teamUpCommandForRuntime(runtimeKind string) ([]string, error) {
	switch strings.TrimSpace(runtimeKind) {
	case "claude-code":
		return []string{"claude", "--dangerously-skip-permissions", "--dangerously-load-development-channels", "server:aweb"}, nil
	case "pi":
		return []string{"pi"}, nil
	case "codex", "local-shell":
		return nil, fmt.Errorf("runtime %q is not supported by this exploratory aw team up; only claude-code and pi are supported", runtimeKind)
	default:
		return nil, fmt.Errorf("runtime %q is not supported by aw team up", runtimeKind)
	}
}

func preflightTeamUpCommands(plan teamUpPlan) error {
	if _, err := exec.LookPath("tmux"); err != nil {
		return fmt.Errorf("tmux is required for `aw team up`; install tmux and try again")
	}
	needsClaude := false
	needsPi := false
	for _, agent := range plan.Agents {
		if agent.Action != teamUpActionStart {
			continue
		}
		switch agent.RuntimeKind {
		case "claude-code":
			needsClaude = true
		case "pi":
			needsPi = true
		}
	}
	if needsClaude {
		if _, err := exec.LookPath("claude"); err != nil {
			return fmt.Errorf("claude is required for one or more claude-code agents; install Claude Code and try again")
		}
	}
	if needsPi {
		if _, err := exec.LookPath("pi"); err != nil {
			return fmt.Errorf("pi is required for one or more agents; install it with `pi install npm:@awebai/pi@latest` and try again")
		}
	}
	return nil
}

func executeTeamUpPlan(cmd *cobra.Command, plan teamUpPlan, recreate, attach bool) error {
	starts := teamUpAgentsToStart(plan)
	exists := tmuxSessionExists(plan.Session)
	if exists && recreate {
		if err := runTmux(cmd, "kill-session", "-t", plan.Session); err != nil {
			return err
		}
		exists = false
	}
	if len(starts) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "aw team up: no missing agents to start in session %q\n", plan.Session)
		if attach && exists {
			return attachTeamUpSession(cmd, plan.Session)
		}
		return nil
	}
	for i, agent := range starts {
		shellCmd := teamUpShellCommand(agent)
		if !exists && i == 0 {
			if err := runTmux(cmd, "new-session", "-d", "-s", plan.Session, "-n", safeTmuxName(agent.Name), shellCmd); err != nil {
				return err
			}
			exists = true
			continue
		}
		if err := runTmux(cmd, "new-window", "-t", plan.Session, "-n", safeTmuxName(agent.Name), shellCmd); err != nil {
			return err
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "aw team up: started %d missing agent(s) in tmux session %q\n", len(starts), plan.Session)
	if attach {
		return attachTeamUpSession(cmd, plan.Session)
	}
	return nil
}

func teamUpAgentsToStart(plan teamUpPlan) []teamUpAgentPlan {
	var starts []teamUpAgentPlan
	for _, agent := range plan.Agents {
		if agent.Action == teamUpActionStart {
			starts = append(starts, agent)
		}
	}
	return starts
}

func tmuxSessionExists(session string) bool {
	return exec.Command("tmux", "has-session", "-t", session).Run() == nil
}

func detectTeamUpActiveHomes(agentsDir string) (map[string]teamUpRunningProcess, error) {
	switch runtime.GOOS {
	case "linux":
		return detectTeamUpActiveHomesProc(agentsDir)
	default:
		return detectTeamUpActiveHomesLsof(agentsDir)
	}
}

func detectTeamUpActiveHomesLsof(agentsDir string) (map[string]teamUpRunningProcess, error) {
	out := map[string]teamUpRunningProcess{}
	cmd := exec.Command("lsof", "-nP", "-a", "-d", "cwd", "+D", agentsDir)
	data, err := cmd.Output()
	if err != nil && len(data) == 0 {
		if _, lookErr := exec.LookPath("lsof"); lookErr != nil {
			return out, nil
		}
		return out, nil
	}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(fields[1])
		cwd := fields[len(fields)-1]
		if home := teamUpHomeForCWD(agentsDir, cwd); home != "" {
			out[home] = teamUpRunningProcess{PID: pid, Command: fields[0], CWD: cwd}
		}
	}
	return out, nil
}

func detectTeamUpActiveHomesProc(agentsDir string) (map[string]teamUpRunningProcess, error) {
	out := map[string]teamUpRunningProcess{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out, nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
		if err != nil {
			continue
		}
		home := teamUpHomeForCWD(agentsDir, cwd)
		if home == "" {
			continue
		}
		command := ""
		if data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm")); err == nil {
			command = strings.TrimSpace(string(data))
		}
		out[home] = teamUpRunningProcess{PID: pid, Command: command, CWD: cwd}
	}
	return out, nil
}

func teamUpHomeForCWD(agentsDir, cwd string) string {
	agentsDir = canonicalTeamUpPath(agentsDir)
	cwd = canonicalTeamUpPath(cwd)
	rel, err := filepath.Rel(agentsDir, cwd)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return ""
	}
	return filepath.Join(agentsDir, parts[0])
}

func canonicalTeamUpPath(path string) string {
	clean := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return filepath.Clean(resolved)
	}
	return clean
}

func attachTeamUpSession(cmd *cobra.Command, session string) error {
	if strings.TrimSpace(os.Getenv("TMUX")) != "" {
		return runTmux(cmd, "switch-client", "-t", session)
	}
	return runTmux(cmd, "attach-session", "-t", session)
}

func runTmux(cmd *cobra.Command, args ...string) error {
	c := exec.Command("tmux", args...)
	c.Stdin = cmd.InOrStdin()
	c.Stdout = cmd.OutOrStdout()
	c.Stderr = cmd.ErrOrStderr()
	if err := c.Run(); err != nil {
		return fmt.Errorf("tmux %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func printTeamUpPlan(out interface{ Write([]byte) (int, error) }, plan teamUpPlan) error {
	if jsonFlag {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}
	starts := 0
	skips := 0
	for _, agent := range plan.Agents {
		if agent.Action == teamUpActionStart {
			starts++
		} else {
			skips++
		}
	}
	fmt.Fprintf(out, "tmux session: %s\n", plan.Session)
	fmt.Fprintf(out, "reconcile: %d to start, %d already up\n", starts, skips)
	for _, agent := range plan.Agents {
		fmt.Fprintf(out, "- %s (%s): %s\n", agent.Name, agent.RuntimeKind, agent.Action)
		fmt.Fprintf(out, "  home: %s\n", agent.HomeDir)
		if agent.Action == teamUpActionStart {
			fmt.Fprintf(out, "  command: %s\n", strings.Join(agent.Command, " "))
			continue
		}
		fmt.Fprintf(out, "  reason: %s\n", agent.Reason)
		if agent.RunningPID > 0 {
			fmt.Fprintf(out, "  process: %d %s\n", agent.RunningPID, agent.RunningCmd)
		}
	}
	return nil
}

func teamUpShellCommand(agent teamUpAgentPlan) string {
	return "cd " + teamUpShellQuote(agent.HomeDir) + " && exec " + teamUpShellJoin(agent.Command)
}

func teamUpShellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, teamUpShellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func teamUpShellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func safeTmuxName(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "aw-team"
	}
	var b strings.Builder
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "aw-team"
	}
	return out
}
