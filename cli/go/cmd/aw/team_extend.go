package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const (
	teamExtendAuthorityTierAPIKey                  = "api-key"
	teamExtendAuthorityTierAPIKeyWorkspaceAsserted = "api-key-workspace-asserted"
	teamExtendAuthorityTierCurrentWorkspace        = "current-workspace"
	teamExtendAuthorityTierDiscoveredAgent         = "discovered-agent"
)

var teamHumanExtendCmd = &cobra.Command{
	Use:   "extend <agent-spec>...",
	Short: "Add agents to an existing team by discovering membership authority",
	Long:  "Add agents to an existing team by discovering membership authority. Specs use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global] for empty-profile homes. A person's setup key (explicit --api-key or AWEB_API_KEY) takes the API path; a workspace key selects signed creation instead. With no current creator, exactly one discovered agent workspace is selected and named; several candidates require choosing a workspace or its --identity-home.\n\n" + creationAuthorityHelp,
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTeamHumanExtend,
}

type teamExtendAuthority struct {
	Creation              *creationAuthority
	Tier                  string
	AnchorDir             string
	AgentsRoot            string
	APIKey                string
	TeamID                string
	TeamIDAssertionSource teamIDAssertionSource
	Checked               int
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
		return usageError("aw team admin extend does not support --home or --layout-only; use aw team admin add from a team workspace for primitive-only placement")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	authority, err := resolveTeamExtendAuthority(wd)
	if err != nil {
		return err
	}
	authority, err = selectTeamExtendCreation(wd, authority)
	if err != nil {
		return err
	}
	expectedTeamID, assertionSource := expectedTeamIDForExtend(authority)
	return runTeamHumanAddWithOptions(cmd, args, teamHumanAddRunOptions{
		CWD:                   wd,
		InviteAnchorDir:       authority.AnchorDir,
		AgentsRoot:            authority.AgentsRoot,
		WorktreeAnchorDir:     wd,
		APIKey:                authority.APIKey,
		ExpectedTeamID:        expectedTeamID,
		TeamIDAssertionSource: assertionSource,
		OutputStatus:          "extended",
		OutputAuthorityTier:   authority.Tier,
		AuthorityTeamID:       authority.TeamID,
		CommandName:           "aw team admin extend",
		Creation:              authority.Creation,
	})
}

func expectedTeamIDForExtend(authority teamExtendAuthority) (string, teamIDAssertionSource) {
	if strings.TrimSpace(authority.APIKey) == "" {
		return "", teamIDAssertionSourceNone
	}
	return strings.TrimSpace(authority.TeamID), authority.TeamIDAssertionSource
}

func resolveTeamExtendAuthority(wd string) (teamExtendAuthority, error) {
	agentsRoot, err := resolveTeamExtendAgentsRoot(wd)
	if err != nil {
		return teamExtendAuthority{}, err
	}
	explicitAPIKey := strings.TrimSpace(teamHumanExtendAPIKey)
	apiKey := explicitAPIKey
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv(initAPIKeyEnvVar))
	}
	teamID := strings.TrimSpace(teamHumanExtendTeamID)

	if apiKey != "" {
		if teamID != "" {
			return teamExtendAuthority{Tier: teamExtendAuthorityTierAPIKey, AnchorDir: wd, AgentsRoot: agentsRoot, APIKey: apiKey, TeamID: teamID, TeamIDAssertionSource: teamIDAssertionSourceExplicitFlag}, nil
		}
		if explicitAPIKey == "" {
			activeTeamID, found, err := activeTeamIDForExtend(wd)
			if err != nil {
				return teamExtendAuthority{}, err
			}
			if found {
				return teamExtendAuthority{Tier: teamExtendAuthorityTierAPIKeyWorkspaceAsserted, AnchorDir: wd, AgentsRoot: agentsRoot, APIKey: apiKey, TeamID: activeTeamID, TeamIDAssertionSource: teamIDAssertionSourceWorkspaceActiveTeam}, nil
			}
		}
		return teamExtendAuthority{Tier: teamExtendAuthorityTierAPIKey, AnchorDir: wd, AgentsRoot: agentsRoot, APIKey: apiKey}, nil
	}
	facts := teamExtendCreatorFacts{CreatorRequired: true, TeamFilter: teamID, AgentsRoot: agentsRoot}
	if err := readTeamExtendCreatorFacts(wd, teamID, &facts); err != nil {
		return teamExtendAuthority{}, err
	}
	creator, err := decideTeamExtendCreator(facts)
	if err != nil {
		return teamExtendAuthority{}, err
	}
	authority := teamExtendAuthority{Tier: creator.Tier, AnchorDir: creator.Candidate.HomeDir, AgentsRoot: agentsRoot, TeamID: creator.Candidate.TeamID}
	if creator.Tier == teamExtendAuthorityTierDiscoveredAgent {
		printDiscoveredCreator(*creator.Candidate)
		authority.Checked = facts.Checked
	}
	return authority, nil
}

// teamExtendCreatorFacts holds what extend has found about candidate creators.
// A creator is required when no API key supplies authority; with a workspace
// key, finding none leaves creation to the working directory.
type teamExtendCreatorFacts struct {
	CreatorRequired bool
	TeamFilter      string
	AgentsRoot      string
	Current         *teamExtendCandidate
	ExternalHome    string
	Discovered      []teamExtendCandidate
	Checked         int
}

type teamExtendCreator struct {
	Tier      string
	Candidate *teamExtendCandidate
}

// decideTeamExtendCreator chooses the workspace that creates extend's members:
// the working directory's own membership, else the one discovered agent
// workspace, never one of several by directory order.
func decideTeamExtendCreator(facts teamExtendCreatorFacts) (teamExtendCreator, error) {
	if facts.Current != nil {
		return teamExtendCreator{Tier: teamExtendAuthorityTierCurrentWorkspace, Candidate: facts.Current}, nil
	}
	if facts.CreatorRequired && facts.ExternalHome != "" {
		return teamExtendCreator{}, usageError("selected identity home %s has no invite authority for the requested team", facts.ExternalHome)
	}
	if len(facts.Discovered) == 0 {
		if !facts.CreatorRequired {
			return teamExtendCreator{Tier: teamExtendAuthorityTierCurrentWorkspace}, nil
		}
		if facts.TeamFilter != "" {
			return teamExtendCreator{}, usageError("no membership authority found for --team-id %s: no --api-key/%s, and no matching invite-capable agent workspace under %s (checked %d candidate homes); run aw team admin extend inside a team directory, pass --api-key, or create a new team with aw team admin create <name>", facts.TeamFilter, initAPIKeyEnvVar, facts.AgentsRoot, facts.Checked)
		}
		return teamExtendCreator{}, usageError("no membership authority found: no --api-key/%s, and no invite-capable agent workspace under %s (checked %d candidate homes); run aw team admin extend inside a team directory, pass --api-key, or create a new team with aw team admin create <name>", initAPIKeyEnvVar, facts.AgentsRoot, facts.Checked)
	}
	if facts.CreatorRequired && facts.TeamFilter == "" {
		teams := map[string]bool{}
		for _, candidate := range facts.Discovered {
			teams[candidate.TeamID] = true
		}
		if len(teams) > 1 {
			teamIDs := make([]string, 0, len(teams))
			for id := range teams {
				teamIDs = append(teamIDs, id)
			}
			sort.Strings(teamIDs)
			return teamExtendCreator{}, usageError("multiple teams found under %s: %s; pass --team-id to choose one", facts.AgentsRoot, strings.Join(teamIDs, ", "))
		}
	}
	if len(facts.Discovered) > 1 {
		return teamExtendCreator{}, creationCandidatesError(facts.Discovered)
	}
	return teamExtendCreator{Tier: teamExtendAuthorityTierDiscoveredAgent, Candidate: &facts.Discovered[0]}, nil
}

// readTeamExtendCreatorFacts reads candidates in the order the decision uses
// them and stops at the first fact that decides it: the working directory's
// membership of currentTeamFilter's team (any team when empty), then, without
// one, the identity home and the agent workspaces of the facts' team filter.
func readTeamExtendCreatorFacts(wd, currentTeamFilter string, facts *teamExtendCreatorFacts) error {
	current, ok, err := resolveTeamExtendCandidate(wd, currentTeamFilter)
	if err != nil {
		return err
	}
	if ok {
		facts.Current = &current
		return nil
	}
	if facts.CreatorRequired {
		home, err := identityHomeForDir(wd)
		if err != nil {
			return err
		}
		if home.External() {
			facts.ExternalHome = home.Root
			return nil
		}
	}
	facts.Discovered, facts.Checked, err = scanTeamExtendCandidates(facts.AgentsRoot, facts.TeamFilter)
	return err
}

func activeTeamIDForExtend(wd string) (string, bool, error) {
	teamState, _, err := loadTeamStateForInvite(wd)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	activeTeamID := strings.TrimSpace(teamState.ActiveTeam)
	if activeTeamID == "" {
		return "", false, usageError("workspace team state exists but has no active team; run `aw team switch <team_id>` or remove the invalid team state before using %s", initAPIKeyEnvVar)
	}
	domain, team, err := awid.ParseTeamID(activeTeamID)
	if err != nil {
		return "", false, fmt.Errorf("invalid active team %q: %w", activeTeamID, err)
	}
	return awid.BuildTeamID(domain, team), true, nil
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
		if errors.Is(err, errTeamInviteTargetHasNoActiveTeam) || os.IsNotExist(err) {
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
	home, err := identityHomeForDir(wd)
	if err != nil {
		return
	}
	_, teamState, _, err := loadCurrentWorkspaceAndTeamState(wd, externalIdentityHomeRoot(home))
	if err != nil || teamState == nil || strings.TrimSpace(teamState.ActiveTeam) == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "Notice: current workspace is already a member of team %s; use `aw team admin extend` to add members to that existing team. `aw team admin create` will create a new team.\n", strings.TrimSpace(teamState.ActiveTeam))
}

func selectTeamExtendCreation(wd string, authority teamExtendAuthority) (teamExtendAuthority, error) {
	if authority.APIKey != "" {
		apiKey := authority.APIKey
		agentsRoot := authority.AgentsRoot
		base, err := resolveAPIKeyInitAwebURL()
		if err != nil {
			return teamExtendAuthority{}, err
		}
		ctx, cancel := commandAPIContext(nil)
		selected, err := readAPIKeyCreationTeam(ctx, base, apiKey)
		cancel()
		if err != nil {
			return teamExtendAuthority{}, err
		}
		expected, assertionSource := expectedTeamIDForExtend(authority)
		if expected != "" && !strings.EqualFold(expected, selected.CanonicalTeamID) {
			return teamExtendAuthority{}, teamIDAssertionMismatchError(expected, selected.CanonicalTeamID, assertionSource)
		}
		if selected.APIKeyKind == creationKeyKindWorkspace {
			requested := selected.CanonicalTeamID
			// Discover a native issuer using the same current/discovered selection as
			// no-key extend. resolveAgentCreation below still checks its team.
			facts := teamExtendCreatorFacts{TeamFilter: requested, AgentsRoot: agentsRoot}
			if err := readTeamExtendCreatorFacts(wd, "", &facts); err != nil {
				return teamExtendAuthority{}, err
			}
			creator, err := decideTeamExtendCreator(facts)
			if err != nil {
				return teamExtendAuthority{}, err
			}
			anchor := wd
			if creator.Candidate != nil {
				anchor = creator.Candidate.HomeDir
			}
			if creator.Tier == teamExtendAuthorityTierDiscoveredAgent {
				printDiscoveredCreator(*creator.Candidate)
			}
			tier := creator.Tier
			creation, err := resolveAgentCreation(agentCreationRequest{WorkingDir: anchor, APIKey: apiKey, AwebURL: base, RequestedTeam: requested, SelectedTeam: selected})
			if err != nil {
				return teamExtendAuthority{}, err
			}
			return teamExtendAuthority{Tier: tier, AnchorDir: anchor, AgentsRoot: agentsRoot, TeamID: creation.SourceTeam, APIKey: apiKey, Creation: &creation}, nil
		}
		creation, err := decideCreationAuthority(creationAuthorityInput{SuppliedKey: true, KeyKind: selected.APIKeyKind})
		if err != nil {
			return teamExtendAuthority{}, err
		}
		creation.SelectedTeam = selected
		authority.Creation = &creation
	}
	return authority, nil
}

func creationCandidatesError(candidates []teamExtendCandidate) error {
	names := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		names = append(names, candidate.HomeDir+" ("+candidate.TeamID+")")
	}
	sort.Strings(names)
	return usageError("choose the creating workspace: run aw team admin extend from it, or select --identity-home <home>; candidates: %s", strings.Join(names, ", "))
}

func printDiscoveredCreator(candidate teamExtendCandidate) {
	fmt.Fprintf(os.Stderr, "Using agent workspace %s as the creator.\n", candidate.HomeDir)
}
