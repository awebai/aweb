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
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	teamUpSession   string
	teamUpDryRun    bool
	teamUpAttach    bool
	teamUpNoAttach  bool
	teamUpRecreate  bool
	teamUpForce     bool
	teamUpForceKill bool
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

var (
	teamUpDetectActiveHomes       = detectTeamUpActiveHomes
	teamUpSessionExists           = tmuxSessionExists
	teamUpRunTmux                 = runTmux
	teamUpRunTmuxOutput           = runTmuxOutput
	teamUpConfirmClaudePromptWait = 45 * time.Second
)

func init() {
	teamUpAttach = true
	teamHumanUpCmd.Flags().StringVar(&teamUpSession, "session", "", "tmux session name (default: active team name or aw-team)")
	teamHumanUpCmd.Flags().BoolVar(&teamUpDryRun, "dry-run", false, "Print the tmux launch plan without running it")
	teamHumanUpCmd.Flags().BoolVar(&teamUpAttach, "attach", true, "Attach or switch to the tmux session after launch")
	teamHumanUpCmd.Flags().BoolVar(&teamUpNoAttach, "no-attach", false, "Do not attach or switch to the tmux session after launch")
	teamHumanUpCmd.Flags().BoolVar(&teamUpRecreate, "recreate", false, "Kill and recreate an existing tmux session")
	teamHumanUpCmd.Flags().BoolVar(&teamUpForceKill, "force-kill", false, "Allow --recreate to kill a tmux session that contains running agent windows")
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
	started, err := executeTeamUpPlan(cmd, plan, teamUpRecreate, teamUpForceKill, false)
	if err != nil {
		return err
	}
	if err := confirmStartedClaudeChannelPrompts(plan.Session, started); err != nil {
		return err
	}
	if attach && tmuxSessionExists(plan.Session) {
		return attachTeamUpSession(cmd, plan.Session)
	}
	return nil
}

func defaultTeamUpSessionName(repoRoot string) string {
	workspace, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(repoRoot)
	if err == nil && teamState != nil {
		teamID := strings.TrimSpace(teamState.ActiveTeam)
		if teamID != "" {
			return teamUpTmuxName(teamID)
		}
	}
	if err == nil && workspace != nil && len(workspace.Memberships) == 1 {
		teamID := strings.TrimSpace(workspace.Memberships[0].TeamID)
		if teamID != "" {
			return teamUpTmuxName(teamID)
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
	plan := teamUpPlan{Session: teamUpTmuxName(firstNonEmptyLibraryValue(session, "aw-team"))}
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
		return []string{"claude", "--dangerously-skip-permissions", "--dangerously-load-development-channels", claudeChannelSpec}, nil
	case "pi":
		return []string{"pi", "--approve"}, nil
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
		if result := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: true}); result != nil && result.Error != nil {
			return result.Error
		}
	}
	if needsPi {
		if result := EnsurePiChannelExtension(); result != nil && result.Error != nil {
			return result.Error
		}
	}
	return nil
}

func executeTeamUpPlan(cmd *cobra.Command, plan teamUpPlan, recreate, forceKill, attach bool) ([]teamUpAgentPlan, error) {
	starts := teamUpAgentsToStart(plan)
	exists := teamUpSessionExists(plan.Session)
	if exists && recreate {
		if !forceKill {
			if err := guardTeamUpRecreate(plan); err != nil {
				return nil, err
			}
		}
		if err := teamUpRunTmux(cmd, "kill-session", "-t", plan.Session); err != nil {
			return nil, err
		}
		exists = false
	}
	if len(starts) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "aw team up: no missing agents to start in session %q\n", plan.Session)
		if attach && exists {
			return nil, attachTeamUpSession(cmd, plan.Session)
		}
		return nil, nil
	}
	for _, agent := range starts {
		if err := launchAgentWindow(cmd, plan.Session, agent); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "aw team up: started %d missing agent(s) in tmux session %q\n", len(starts), plan.Session)
	if attach {
		return starts, attachTeamUpSession(cmd, plan.Session)
	}
	return starts, nil
}

func guardTeamUpRecreate(plan teamUpPlan) error {
	live, err := liveTeamUpAgentsInSession(plan)
	if err != nil {
		return err
	}
	if len(live) == 0 {
		return nil
	}
	return fmt.Errorf("refusing aw team up --recreate for tmux session %q because it contains running agent window(s): %s. Use a throwaway --session for dogfood, or pass --force-kill to intentionally kill this session", plan.Session, strings.Join(live, ", "))
}

func liveTeamUpAgentsInSession(plan teamUpPlan) ([]string, error) {
	if len(plan.Agents) == 0 {
		return nil, nil
	}
	windows, err := teamUpSessionWindowNames(plan.Session)
	if err != nil {
		return nil, fmt.Errorf("inspect tmux session %q before --recreate: %w", plan.Session, err)
	}
	if len(windows) == 0 {
		return nil, nil
	}
	agentsDir := filepath.Dir(plan.Agents[0].HomeDir)
	activeHomes, err := teamUpDetectActiveHomes(agentsDir)
	if err != nil {
		return nil, err
	}
	var live []string
	for _, agent := range plan.Agents {
		if !windows[teamUpWindowName(agent.Name)] {
			continue
		}
		proc, ok := activeHomes[canonicalTeamUpPath(agent.HomeDir)]
		if !ok {
			continue
		}
		label := agent.Name
		if proc.PID > 0 {
			label = fmt.Sprintf("%s(pid %d)", agent.Name, proc.PID)
		}
		live = append(live, label)
	}
	sort.Strings(live)
	return live, nil
}

func teamUpSessionWindowNames(session string) (map[string]bool, error) {
	out, err := teamUpRunTmuxOutput("list-windows", "-t", session, "-F", "#W")
	if err != nil {
		return nil, err
	}
	windows := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			windows[name] = true
		}
	}
	return windows, nil
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

func launchAgentWindow(cmd *cobra.Command, session string, agent teamUpAgentPlan) error {
	shellCmd := teamUpShellCommand(agent)
	windowName := teamUpWindowName(agent.Name)
	if !teamUpSessionExists(session) {
		return teamUpRunTmux(cmd, "new-session", "-d", "-s", session, "-n", windowName, shellCmd)
	}
	return teamUpRunTmux(cmd, "new-window", "-t", session, "-n", windowName, shellCmd)
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
		return teamUpRunTmux(cmd, "switch-client", "-t", session)
	}
	return teamUpRunTmux(cmd, "attach-session", "-t", session)
}

func runTmux(cmd *cobra.Command, args ...string) error {
	c := exec.Command("tmux", args...)
	if cmd != nil {
		c.Stdin = cmd.InOrStdin()
		c.Stdout = cmd.OutOrStdout()
		c.Stderr = cmd.ErrOrStderr()
	}
	if err := c.Run(); err != nil {
		return fmt.Errorf("tmux %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func runTmuxOutput(args ...string) (string, error) {
	data, err := exec.Command("tmux", args...).CombinedOutput()
	if err != nil {
		return string(data), fmt.Errorf("tmux %s: %w", strings.Join(args, " "), err)
	}
	return string(data), nil
}

func confirmStartedClaudeChannelPrompts(session string, started []teamUpAgentPlan) error {
	deadline := time.Now().Add(teamUpConfirmClaudePromptWait)
	for _, agent := range started {
		if agent.RuntimeKind != "claude-code" {
			continue
		}
		if err := confirmClaudeChannelPrompt(session, agent, deadline); err != nil {
			return err
		}
	}
	return nil
}

func confirmClaudeChannelPrompt(session string, agent teamUpAgentPlan, deadline time.Time) error {
	target := teamUpWindowTarget(session, agent.Name)
	var last string
	answeredPrompt := ""
	for time.Now().Before(deadline) {
		pane, err := teamUpRunTmuxOutput("capture-pane", "-t", target, "-p")
		if err == nil {
			last = pane
			if claudeChannelPromptComplete(pane) {
				return nil
			}
			prompt := claudeBlockingPromptKind(pane)
			if prompt == "" {
				answeredPrompt = ""
			} else if prompt != answeredPrompt {
				if err := teamUpRunTmux(nil, "send-keys", "-t", target, "Enter"); err != nil {
					return err
				}
				answeredPrompt = prompt
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for Claude Code to load the aweb channel in tmux window %q within %s; no known prompt (trust-folder / dev-channel) reached completion. Claude's prompt wording may have changed; update the prompt signatures in team_up.go (claudeChannelPromptVisible / claudeTrustFolderPromptVisible). Last pane output:\n%s", target, teamUpConfirmClaudePromptWait, last)
}

func teamUpWindowTarget(session, agentName string) string {
	return teamUpTmuxName(session) + ":" + teamUpWindowName(agentName)
}

func teamUpWindowName(agentName string) string {
	return teamUpTmuxName(agentName)
}

func teamUpTmuxName(name string) string {
	// safeTmuxName historically allows '.', but tmux normalizes dots to
	// underscores in session names and treats dots as pane separators in targets.
	// Normalize dots consistently everywhere aw creates or targets tmux names.
	return strings.ReplaceAll(safeTmuxName(name), ".", "_")
}

func claudeBlockingPromptKind(pane string) string {
	lower := strings.ToLower(pane)
	trustIdx := claudeTrustFolderPromptIndex(lower)
	channelIdx := claudeChannelPromptIndex(lower)
	switch {
	case trustIdx < 0 && channelIdx < 0:
		return ""
	case channelIdx > trustIdx:
		return "dev-channel"
	default:
		return "trust-folder"
	}
}

func claudeTrustFolderPromptVisible(pane string) bool {
	return claudeTrustFolderPromptIndex(strings.ToLower(pane)) >= 0
}

func claudeTrustFolderPromptIndex(lower string) int {
	return maxStringIndex(lower, "trust this folder", "is this a project you created or one you trust")
}

func claudeChannelPromptVisible(pane string) bool {
	return claudeChannelPromptIndex(strings.ToLower(pane)) >= 0
}

func claudeChannelPromptIndex(lower string) int {
	idx := strings.LastIndex(lower, "i am using this for local development")
	if idx < 0 || !strings.Contains(lower[idx:], "exit") {
		return -1
	}
	return idx
}

func maxStringIndex(s string, needles ...string) int {
	maxIdx := -1
	for _, needle := range needles {
		if idx := strings.LastIndex(s, needle); idx > maxIdx {
			maxIdx = idx
		}
	}
	return maxIdx
}

func claudeChannelPromptComplete(pane string) bool {
	lower := strings.ToLower(pane)
	completeIdx := claudeChannelCompleteIndex(lower)
	if completeIdx < 0 {
		return false
	}
	lastPromptIdx := maxStringIndexAtLeast(claudeTrustFolderPromptIndex(lower), claudeChannelPromptIndex(lower))
	return completeIdx > lastPromptIdx
}

func claudeChannelCompleteIndex(lower string) int {
	return maxStringIndex(lower, "messages from plugin:aweb-channel", "bypass permissions on")
}

func maxStringIndexAtLeast(indexes ...int) int {
	maxIdx := -1
	for _, idx := range indexes {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	return maxIdx
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
