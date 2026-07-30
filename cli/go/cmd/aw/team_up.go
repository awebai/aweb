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
	Session     string            `json:"session"`
	Agents      []teamUpAgentPlan `json:"agents"`
	TmuxContext teamUpTmuxContext `json:"-"`
}

type teamUpTmuxContext uint8

const (
	teamUpConfiguredTmuxContext teamUpTmuxContext = iota
	teamUpCallerTmuxContext
)

type teamUpSessionSelection struct {
	Session     string
	TmuxContext teamUpTmuxContext
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
	teamUpActionStart         = "start"
	teamUpActionSkip          = "skip"
	teamUpActionRefuse        = "refuse"
	teamUpTmuxTmpdirEnv       = "AWEB_TMUX_TMPDIR"
	teamUpTmuxKillOverrideEnv = "AWEB_TMUX_KILL_OK"
	tmuxTmpdirEnv             = "TMUX_TMPDIR"
	tmuxEnv                   = "TMUX"
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
	teamUpGuardedAgentPath        = ensureTeamUpGuardedAgentPath
	teamUpConfirmClaudePromptWait = 45 * time.Second
)

func init() {
	teamUpAttach = true
	teamHumanUpCmd.Flags().StringVar(&teamUpSession, "session", "", "tmux session name (default: caller's session inside tmux, otherwise active team name or aw-team)")
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
	selection, err := resolveTeamUpSession(repoRoot, teamUpSession)
	if err != nil {
		return err
	}
	plan, err := buildTeamUpPlanForSession(repoRoot, selection, teamUpForce, teamUpRecreate)
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
	if err := confirmStartedClaudeChannelPromptsInContext(plan.TmuxContext, plan.Session, started); err != nil {
		return err
	}
	if attach && teamUpSessionExistsInContext(plan.TmuxContext, plan.Session) {
		return attachTeamUpSession(cmd, plan.TmuxContext, plan.Session)
	}
	return nil
}

func resolveTeamUpSession(repoRoot, explicitSession string) (teamUpSessionSelection, error) {
	if session := strings.TrimSpace(explicitSession); session != "" {
		return teamUpSessionSelection{Session: session, TmuxContext: teamUpConfiguredTmuxContext}, nil
	}
	if strings.TrimSpace(os.Getenv(tmuxEnv)) == "" {
		return teamUpSessionSelection{Session: defaultTeamUpSessionName(repoRoot), TmuxContext: teamUpConfiguredTmuxContext}, nil
	}
	cmd := exec.Command("tmux", "display-message", "-p", "#S")
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return teamUpSessionSelection{}, fmt.Errorf("resolve caller tmux session before launch: %w: %s", err, detail)
		}
		return teamUpSessionSelection{}, fmt.Errorf("resolve caller tmux session before launch: %w", err)
	}
	session := strings.TrimRight(string(output), "\r\n")
	if strings.TrimSpace(session) == "" {
		return teamUpSessionSelection{}, fmt.Errorf("resolve caller tmux session before launch: tmux returned an empty session name")
	}
	return teamUpSessionSelection{Session: session, TmuxContext: teamUpCallerTmuxContext}, nil
}

func selectedTeamUpSessionName(selection teamUpSessionSelection) string {
	session := firstNonEmptyLibraryValue(selection.Session, "aw-team")
	if selection.TmuxContext == teamUpCallerTmuxContext {
		return session
	}
	return teamUpTmuxName(session)
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
	return buildTeamUpPlanForSession(repoRoot, teamUpSessionSelection{Session: session, TmuxContext: teamUpConfiguredTmuxContext}, force, recreate)
}

func buildTeamUpPlanForSession(repoRoot string, selection teamUpSessionSelection, force bool, recreate bool) (teamUpPlan, error) {
	agentsDir := filepath.Join(repoRoot, "agents", "instances")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return teamUpPlan{}, fmt.Errorf("no agents/instances directory found; add materialized agents first with `aw team add NAME@BLUEPRINT/PROFILE=<runtime>`")
		}
		return teamUpPlan{}, err
	}
	plan := teamUpPlan{Session: selectedTeamUpSessionName(selection), TmuxContext: selection.TmuxContext}
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
		if reason, ok := teamUpHomeAccountsForItself(home); !ok {
			plan.Agents = append(plan.Agents, teamUpAgentPlan{Name: name, HomeDir: home, Action: teamUpActionRefuse, Reason: reason})
			continue
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

// teamUpHomeAccountsForItself reports whether a directory is a current agent home
// rather than merely shaped like one. It returns the refusal reason when it is not.
//
// aweb-aawn: the launcher used to accept any directory containing
// .aw/profile/profile.yaml, and never read the file - so a COPY of a home was an
// executable artifact that started a second process holding the original's
// credentials, and so was a directory containing nothing but that one empty file.
//
// The check is positive rather than a denylist of backup-looking names: a home must
// carry a workspace identity AND that identity must name the place the home actually
// is. Every other identity check in the tree compares copied artifacts to each other -
// .aw/context against .aw/workspace.yaml, the signing key against the certificate - and
// those agree in any faithful copy. This compares a copied thing against something that
// cannot be copied: where the directory sits. A copy names where it was copied FROM,
// wherever it is put, so it fails wherever someone puts it.
//
// The cost is that a legitimately moved or renamed home stops launching until `aw init`
// is re-run there. That is the intended reading: a home that does not know where it is
// should not start holding credentials.
func teamUpHomeAccountsForItself(home string) (string, bool) {
	workspacePath := filepath.Join(home, ".aw", "workspace.yaml")
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "no .aw/workspace.yaml, so this directory has no agent identity of its own", false
		}
		return fmt.Sprintf("unusable .aw/workspace.yaml: %v", err), false
	}
	recorded := strings.TrimSpace(workspace.WorkspacePath)
	if recorded == "" {
		return "no workspace_path in .aw/workspace.yaml, so it does not say where it belongs", false
	}
	if canonicalTeamUpPath(recorded) != canonicalTeamUpPath(home) {
		return fmt.Sprintf("workspace_path says %s but this home is at %s, so it is a copy of another home and would run as that agent", recorded, home), false
	}
	return "", true
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
		return fmt.Errorf("%s", formatTeamUpNoTmuxGuidance(plan))
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
	exists := teamUpSessionExistsInContext(plan.TmuxContext, plan.Session)
	if exists && recreate {
		if !forceKill {
			if err := guardTeamUpRecreate(plan); err != nil {
				return nil, err
			}
		}
		if err := teamUpRunTmuxInContext(plan.TmuxContext, cmd, "kill-session", "-t", plan.Session); err != nil {
			return nil, err
		}
		exists = false
	}
	if len(starts) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "aw team up: no missing agents to start in session %q\n", plan.Session)
		if attach && exists {
			return nil, attachTeamUpSession(cmd, plan.TmuxContext, plan.Session)
		}
		return nil, nil
	}
	for _, agent := range starts {
		if err := launchAgentWindow(cmd, plan.TmuxContext, plan.Session, agent); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "aw team up: started %d missing agent(s) in tmux session %q\n", len(starts), plan.Session)
	if attach {
		return starts, attachTeamUpSession(cmd, plan.TmuxContext, plan.Session)
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
	windows, err := teamUpSessionWindowNames(plan.TmuxContext, plan.Session)
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

func teamUpSessionWindowNames(tmuxContext teamUpTmuxContext, session string) (map[string]bool, error) {
	out, err := teamUpRunTmuxOutputInContext(tmuxContext, "list-windows", "-t", session+":", "-F", "#W")
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

func launchAgentWindow(cmd *cobra.Command, tmuxContext teamUpTmuxContext, session string, agent teamUpAgentPlan) error {
	guardedPath, err := teamUpGuardedAgentPath()
	if err != nil {
		return fmt.Errorf("prepare tmux guard for agent %q: %w", agent.Name, err)
	}
	shellCmd := teamUpShellCommand(agent, guardedPath)
	windowName := teamUpWindowName(agent.Name)
	if !teamUpSessionExistsInContext(tmuxContext, session) {
		return teamUpRunTmuxInContext(tmuxContext, cmd, "new-session", "-d", "-s", session, "-n", windowName, shellCmd)
	}
	return teamUpRunTmuxInContext(tmuxContext, cmd, "new-window", "-t", session+":", "-n", windowName, shellCmd)
}

func tmuxSessionExists(session string) bool {
	return tmuxSessionExistsInContext(teamUpConfiguredTmuxContext, session)
}

func tmuxSessionExistsInContext(tmuxContext teamUpTmuxContext, session string) bool {
	return teamUpTmuxCommand(tmuxContext, "has-session", "-t", session+":").Run() == nil
}

func teamUpSessionExistsInContext(tmuxContext teamUpTmuxContext, session string) bool {
	if tmuxContext == teamUpConfiguredTmuxContext {
		return teamUpSessionExists(session)
	}
	return tmuxSessionExistsInContext(tmuxContext, session)
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

func attachTeamUpSession(cmd *cobra.Command, tmuxContext teamUpTmuxContext, session string) error {
	if tmuxContext == teamUpCallerTmuxContext || (strings.TrimSpace(os.Getenv(tmuxEnv)) != "" && resolveTeamUpTmuxTmpdir() == "") {
		return teamUpRunTmuxInContext(tmuxContext, cmd, "switch-client", "-t", session+":")
	}
	return teamUpRunTmuxInContext(tmuxContext, cmd, "attach-session", "-t", session+":")
}

func runTmux(cmd *cobra.Command, args ...string) error {
	return runTmuxInContext(teamUpConfiguredTmuxContext, cmd, args...)
}

func runTmuxInContext(tmuxContext teamUpTmuxContext, cmd *cobra.Command, args ...string) error {
	c := teamUpTmuxCommand(tmuxContext, args...)
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
	return runTmuxOutputInContext(teamUpConfiguredTmuxContext, args...)
}

func runTmuxOutputInContext(tmuxContext teamUpTmuxContext, args ...string) (string, error) {
	data, err := teamUpTmuxCommand(tmuxContext, args...).CombinedOutput()
	if err != nil {
		return string(data), fmt.Errorf("tmux %s: %w", strings.Join(args, " "), err)
	}
	return string(data), nil
}

func teamUpRunTmuxInContext(tmuxContext teamUpTmuxContext, cmd *cobra.Command, args ...string) error {
	if tmuxContext == teamUpConfiguredTmuxContext {
		return teamUpRunTmux(cmd, args...)
	}
	return runTmuxInContext(tmuxContext, cmd, args...)
}

func teamUpRunTmuxOutputInContext(tmuxContext teamUpTmuxContext, args ...string) (string, error) {
	if tmuxContext == teamUpConfiguredTmuxContext {
		return teamUpRunTmuxOutput(args...)
	}
	return runTmuxOutputInContext(tmuxContext, args...)
}

func teamUpTmuxCommand(tmuxContext teamUpTmuxContext, args ...string) *exec.Cmd {
	cmd := exec.Command("tmux", args...)
	if tmuxContext != teamUpCallerTmuxContext {
		if tmpdir := resolveTeamUpTmuxTmpdir(); tmpdir != "" {
			cmd.Env = envWithValueAndUnset(os.Environ(), tmuxTmpdirEnv, tmpdir, tmuxEnv)
		}
	}
	return cmd
}

func resolveTeamUpTmuxTmpdir() string {
	if tmpdir := strings.TrimSpace(os.Getenv(teamUpTmuxTmpdirEnv)); tmpdir != "" {
		return tmpdir
	}
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	root := resolveRepoRoot(wd)
	workspace, workspacePath, err := awconfig.LoadWorktreeWorkspaceFromDir(root)
	if err != nil || workspace == nil {
		return ""
	}
	return resolveWorkspaceTmuxTmpdir(workspacePath, workspace.AwebTmuxTmpdir)
}

func resolveWorkspaceTmuxTmpdir(workspacePath, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	root := awconfig.WorktreeRootFromWorkspacePath(workspacePath)
	if strings.TrimSpace(root) == "" {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(root, value))
}

func envWithValueAndUnset(env []string, key, value string, unsetKeys ...string) []string {
	prefix := key + "="
	drop := map[string]bool{}
	for _, unsetKey := range unsetKeys {
		unsetKey = strings.TrimSpace(unsetKey)
		if unsetKey != "" && unsetKey != key {
			drop[unsetKey+"="] = true
		}
	}
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			if !replaced {
				out = append(out, prefix+value)
				replaced = true
			}
			continue
		}
		dropped := false
		for dropPrefix := range drop {
			if strings.HasPrefix(item, dropPrefix) {
				dropped = true
				break
			}
		}
		if dropped {
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, prefix+value)
	}
	return out
}

func confirmStartedClaudeChannelPrompts(session string, started []teamUpAgentPlan) error {
	return confirmStartedClaudeChannelPromptsInContext(teamUpConfiguredTmuxContext, session, started)
}

func confirmStartedClaudeChannelPromptsInContext(tmuxContext teamUpTmuxContext, session string, started []teamUpAgentPlan) error {
	deadline := time.Now().Add(teamUpConfirmClaudePromptWait)
	for _, agent := range started {
		if agent.RuntimeKind != "claude-code" {
			continue
		}
		if err := confirmClaudeChannelPrompt(tmuxContext, session, agent, deadline); err != nil {
			return err
		}
	}
	return nil
}

func confirmClaudeChannelPrompt(tmuxContext teamUpTmuxContext, session string, agent teamUpAgentPlan, deadline time.Time) error {
	target := teamUpWindowTarget(tmuxContext, session, agent.Name)
	var last string
	answeredPrompt := ""
	for time.Now().Before(deadline) {
		pane, err := teamUpRunTmuxOutputInContext(tmuxContext, "capture-pane", "-t", target, "-p")
		if err == nil {
			last = pane
			if claudeChannelPromptComplete(pane) {
				return nil
			}
			prompt := claudeBlockingPromptKind(pane)
			if prompt == "" {
				answeredPrompt = ""
			} else if prompt != answeredPrompt {
				if err := teamUpRunTmuxInContext(tmuxContext, nil, "send-keys", "-t", target, "Enter"); err != nil {
					return err
				}
				answeredPrompt = prompt
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for Claude Code to load the aweb channel in tmux window %q within %s; no known prompt (trust-folder / dev-channel) reached completion. Claude's prompt wording may have changed; update the prompt signatures in team_up.go (claudeChannelPromptVisible / claudeTrustFolderPromptVisible). Last pane output:\n%s", target, teamUpConfirmClaudePromptWait, last)
}

func teamUpWindowTarget(tmuxContext teamUpTmuxContext, session, agentName string) string {
	if tmuxContext != teamUpCallerTmuxContext {
		session = teamUpTmuxName(session)
	}
	return session + ":" + teamUpWindowName(agentName)
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
	refusals := 0
	for _, agent := range plan.Agents {
		switch agent.Action {
		case teamUpActionStart:
			starts++
		case teamUpActionRefuse:
			refusals++
		default:
			skips++
		}
	}
	fmt.Fprintf(out, "tmux session: %s\n", plan.Session)
	// Refusals are counted apart from skips: a directory this command declined to run
	// is not an agent that is already up, and reporting it as one would hide exactly
	// what the refusal exists to surface.
	summary := fmt.Sprintf("reconcile: %d to start, %d already up", starts, skips)
	if refusals > 0 {
		summary += fmt.Sprintf(", %d refused", refusals)
	}
	fmt.Fprintf(out, "%s\n", summary)
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

func teamUpShellCommand(agent teamUpAgentPlan, guardedPath string) string {
	return "unset " + teamUpTmuxKillOverrideEnv + " && export PATH=" + teamUpShellQuote(guardedPath) + " && cd " + teamUpShellQuote(agent.HomeDir) + " && exec " + teamUpShellJoin(agent.Command)
}

func formatTeamUpNoTmuxGuidance(plan teamUpPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "tmux is recommended for `aw team up`. Install tmux, then re-run `aw team up`.\n")
	fmt.Fprintf(&b, "With tmux installed, `aw team up` automatically starts and wires every agent for you (channel plugin, trust/dev-channel prompts, pi --approve).\n")
	starts := teamUpAgentsToStart(plan)
	if len(starts) == 0 {
		fmt.Fprintf(&b, "No missing agents need a manual launch right now.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	fmt.Fprintf(&b, "\nManual fallback commands for this plan:\n")
	for _, agent := range starts {
		fmt.Fprintf(&b, "- %s (%s)\n", agent.Name, agent.RuntimeKind)
		fmt.Fprintf(&b, "  home: %s\n", agent.HomeDir)
		fmt.Fprintf(&b, "  command: %s\n", teamUpManualLaunchCommand(agent))
	}
	return strings.TrimRight(b.String(), "\n")
}

func teamUpManualLaunchCommand(agent teamUpAgentPlan) string {
	return "cd " + teamUpShellQuote(agent.HomeDir) + " && " + teamUpManualShellJoin(agent.Command)
}

func teamUpManualShellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, teamUpShellQuoteIfNeeded(arg))
	}
	return strings.Join(quoted, " ")
}

func teamUpShellQuoteIfNeeded(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_@%+=:,./-", r) {
			continue
		}
		return teamUpShellQuote(s)
	}
	return s
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
