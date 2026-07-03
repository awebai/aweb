package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var teamHumanExtendCmd = &cobra.Command{
	Use:   "extend <agent-spec>...",
	Short: "Add agents to an existing team by discovering membership authority",
	Long:  "Add agents to an existing team by discovering membership authority. Specs use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global] for empty-profile homes. Explicit --api-key/AWEB_API_KEY wins; otherwise the current workspace or an invite-capable agents/instances home is used.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTeamHumanExtend,
}

type teamExtendAuthority struct {
	Tier       string
	AnchorDir  string
	AgentsRoot string
	APIKey     string
	TeamID     string
	Checked    int
}

type teamExtendCandidate struct {
	HomeDir     string
	TeamID      string
	TeamName    string
	Domain      string
	RegistryURL string
	AwebURL     string
}

func runTeamHumanExtend(cmd *cobra.Command, args []string) error {
	if teamHumanAddLayoutOnly || strings.TrimSpace(teamHumanAddHome) != "" {
		return usageError("aw team extend does not support --home or --layout-only; use aw team add from a team workspace for primitive-only placement")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	authority, err := resolveTeamExtendAuthority(wd)
	if err != nil {
		return err
	}
	return runTeamHumanAddWithOptions(cmd, args, teamHumanAddRunOptions{
		CWD:                 wd,
		InviteAnchorDir:     authority.AnchorDir,
		AgentsRoot:          authority.AgentsRoot,
		WorktreeAnchorDir:   wd,
		APIKey:              authority.APIKey,
		ForceAPIKey:         strings.TrimSpace(authority.APIKey) != "",
		ExpectedTeamID:      expectedTeamIDForExtend(authority),
		OutputStatus:        "extended",
		OutputAuthorityTier: authority.Tier,
	})
}

func expectedTeamIDForExtend(authority teamExtendAuthority) string {
	if strings.TrimSpace(authority.APIKey) == "" {
		return ""
	}
	return strings.TrimSpace(teamHumanExtendTeamID)
}

func resolveTeamExtendAuthority(wd string) (teamExtendAuthority, error) {
	agentsRoot, err := resolveTeamExtendAgentsRoot(wd)
	if err != nil {
		return teamExtendAuthority{}, err
	}
	apiKey := strings.TrimSpace(teamHumanExtendAPIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv(initAPIKeyEnvVar))
	}
	teamID := strings.TrimSpace(teamHumanExtendTeamID)
	if apiKey != "" {
		return teamExtendAuthority{Tier: "api-key", AnchorDir: wd, AgentsRoot: agentsRoot, APIKey: apiKey, TeamID: teamID}, nil
	}
	if candidate, ok, err := resolveTeamExtendCandidate(wd, teamID); err != nil {
		return teamExtendAuthority{}, err
	} else if ok {
		return teamExtendAuthority{Tier: "current-workspace", AnchorDir: candidate.HomeDir, AgentsRoot: agentsRoot, TeamID: candidate.TeamID}, nil
	}
	candidates, checked, err := scanTeamExtendCandidates(agentsRoot, teamID)
	if err != nil {
		return teamExtendAuthority{}, err
	}
	if len(candidates) == 0 {
		if teamID != "" {
			return teamExtendAuthority{}, usageError("no membership authority found for --team-id %s: no --api-key/%s, and no matching invite-capable agent workspace under %s (checked %d candidate homes); run aw team extend inside a team directory, pass --api-key, or create a new team with aw team create <name>", teamID, initAPIKeyEnvVar, agentsRoot, checked)
		}
		return teamExtendAuthority{}, usageError("no membership authority found: no --api-key/%s, and no invite-capable agent workspace under %s (checked %d candidate homes); run aw team extend inside a team directory, pass --api-key, or create a new team with aw team create <name>", initAPIKeyEnvVar, agentsRoot, checked)
	}
	teams := map[string]bool{}
	for _, candidate := range candidates {
		teams[candidate.TeamID] = true
	}
	if teamID == "" && len(teams) > 1 {
		teamIDs := make([]string, 0, len(teams))
		for id := range teams {
			teamIDs = append(teamIDs, id)
		}
		sort.Strings(teamIDs)
		return teamExtendAuthority{}, usageError("multiple teams found under %s: %s; pass --team-id to choose one", agentsRoot, strings.Join(teamIDs, ", "))
	}
	winner := candidates[0]
	return teamExtendAuthority{Tier: "discovered-agent", AnchorDir: winner.HomeDir, AgentsRoot: agentsRoot, TeamID: winner.TeamID, Checked: checked}, nil
}

func resolveTeamExtendAgentsRoot(wd string) (string, error) {
	wd = strings.TrimSpace(wd)
	if wd == "" {
		var err error
		wd, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	wd, err := filepath.Abs(wd)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(filepath.Join(wd, "agents", "instances")); err == nil && info.IsDir() {
		return filepath.Join(wd, "agents", "instances"), nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	for probe := wd; ; probe = filepath.Dir(probe) {
		if filepath.Base(probe) == "instances" && filepath.Base(filepath.Dir(probe)) == "agents" {
			return probe, nil
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
	}
	if repoRoot := resolveRepoRoot(wd); strings.TrimSpace(repoRoot) != "" {
		candidate := filepath.Join(repoRoot, "agents", "instances")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		} else if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return filepath.Join(wd, "agents", "instances"), nil
}

func scanTeamExtendCandidates(agentsRoot, teamID string) ([]teamExtendCandidate, int, error) {
	entries, err := os.ReadDir(agentsRoot)
	if os.IsNotExist(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var candidates []teamExtendCandidate
	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		checked++
		home := filepath.Join(agentsRoot, entry.Name())
		candidate, ok, err := resolveTeamExtendCandidate(home, teamID)
		if err != nil {
			return nil, checked, err
		}
		if ok {
			candidates = append(candidates, candidate)
		}
	}
	return candidates, checked, nil
}

func resolveTeamExtendCandidate(homeDir, filterTeamID string) (teamExtendCandidate, bool, error) {
	team, domain, registryURL, awebURL, err := resolveTeamInviteTargetWithoutFlagOverrides(homeDir)
	if err != nil {
		var usageErr *cliError
		if errors.As(err, &usageErr) {
			return teamExtendCandidate{}, false, nil
		}
		if os.IsNotExist(err) {
			return teamExtendCandidate{}, false, nil
		}
		return teamExtendCandidate{}, false, err
	}
	teamID := awid.BuildTeamID(domain, team)
	if filter := strings.TrimSpace(filterTeamID); filter != "" && !strings.EqualFold(teamID, filter) {
		return teamExtendCandidate{}, false, nil
	}
	return teamExtendCandidate{HomeDir: homeDir, TeamID: teamID, TeamName: team, Domain: domain, RegistryURL: registryURL, AwebURL: awebURL}, true, nil
}

func resolveTeamInviteTargetWithoutFlagOverrides(workingDir string) (team, domain, registryURL, awebURL string, err error) {
	oldTeam := teamInviteTeam
	oldNamespace := teamInviteNamespace
	teamInviteTeam = ""
	teamInviteNamespace = ""
	defer func() {
		teamInviteTeam = oldTeam
		teamInviteNamespace = oldNamespace
	}()
	return resolveTeamInviteTarget(workingDir)
}

func printTeamCreateExtendNotice(wd string) {
	if teamHumanCreateBYOT || jsonFlag {
		return
	}
	_, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(wd)
	if err != nil || teamState == nil || strings.TrimSpace(teamState.ActiveTeam) == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "Notice: current workspace is already a member of team %s; use `aw team extend` to add members to that existing team. `aw team create` will create a new team.\n", strings.TrimSpace(teamState.ActiveTeam))
}
