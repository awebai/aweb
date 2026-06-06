package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/awebai/aw/awconfig"
)

const (
	agentsIdentityScopeLocal  = "local"
	agentsIdentityScopeGlobal = "global"

	agentsWorkRepoRoot    = "repo_root"
	agentsWorkGitWorktree = "git_worktree"

	agentsSequenceClassic = "classic-name"
	agentsSequenceStar    = "star-name"
)

var (
	agentsSlugPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	agentsFieldPattern = regexp.MustCompile(`\{([a-z0-9-]+)\}`)
)

var agentsClassicNames = []string{
	"alice",
	"bob",
	"charlie",
	"dave",
	"eve",
	"frank",
	"grace",
	"henry",
	"ivy",
	"jack",
	"kate",
	"leo",
	"mia",
	"noah",
	"olivia",
	"peter",
	"quinn",
	"rose",
	"sam",
	"tara",
	"uma",
	"victor",
	"wendy",
	"xavier",
	"yara",
	"zoe",
}

var agentsStarNames = []string{
	"sirius",
	"vega",
	"altair",
	"deneb",
	"rigel",
	"polaris",
	"arcturus",
	"capella",
	"antares",
	"spica",
	"aldebaran",
	"procyon",
	"regulus",
	"bellatrix",
	"castor",
	"pollux",
	"mira",
	"achernar",
	"hadar",
	"shaula",
	"avior",
	"alnair",
	"mintaka",
	"merak",
	"dubhe",
	"algol",
}

type agentsNamingPolicy struct {
	LocalAliasSequence  string
	LocalAliasPattern   string
	GlobalAliasSequence string
	GlobalAliasPattern  string
	GlobalNameSequence  string
	GlobalNamePattern   string
	WorktreePattern     string
}

type agentsNamingInput struct {
	AgentsDir string
	Namespace string
	User      string
	Agents    []agentsNamingAgentInput
	Policy    agentsNamingPolicy

	ExistingAliases     map[string]bool
	ExistingGlobalNames map[string]bool
	ExistingHomeNames   map[string]bool
	ExistingWorktrees   map[string]bool
	ExistingBranches    map[string]bool
}

type agentsNamingAgentInput struct {
	Responsibility string
	IdentityScope  string
	WorkBinding    string
}

type agentsNamingPlan struct {
	Agents []agentsNamingAgentPlan
}

type agentsNamingAgentPlan struct {
	Responsibility string `json:"responsibility"`
	IdentityScope  string `json:"identity_scope"`
	TeamAlias      string `json:"team_alias"`
	GlobalName     string `json:"global_name,omitempty"`
	GlobalAddress  string `json:"global_address,omitempty"`
	HomeName       string `json:"home_name"`
	HomePath       string `json:"home_path"`
	WorkBinding    string `json:"work_binding"`
	WorkPath       string `json:"work_path"`
	WorktreeName   string `json:"worktree_name,omitempty"`
	WorktreePath   string `json:"worktree_path,omitempty"`
	BranchName     string `json:"branch_name,omitempty"`
	CollisionState string `json:"collision_state"`
}

func defaultAgentsNamingPolicy() agentsNamingPolicy {
	return agentsNamingPolicy{
		LocalAliasSequence:  agentsSequenceClassic,
		LocalAliasPattern:   "{classic-name}",
		GlobalAliasSequence: agentsSequenceClassic,
		GlobalAliasPattern:  "{user}-{classic-name}",
		GlobalNamePattern:   "{user}-{responsibility}",
		WorktreePattern:     "{responsibility}",
	}
}

func buildAgentsNamingPlan(input agentsNamingInput) (agentsNamingPlan, error) {
	policy := mergeAgentsNamingPolicy(input.Policy)
	agentsDir, err := normalizeAgentsNamingField("agents-dir", firstNonEmpty(input.AgentsDir, "agents"))
	if err != nil {
		return agentsNamingPlan{}, err
	}
	namespace := awconfig.NormalizeDomain(input.Namespace)
	user := strings.TrimSpace(input.User)
	if needsAgentsNamingUser(policy) {
		var userErr error
		user, userErr = normalizeAgentsNamingField("user", user)
		if userErr != nil {
			return agentsNamingPlan{}, userErr
		}
	}

	existingAliases := normalizeAgentsNameSet(input.ExistingAliases)
	existingGlobalNames := normalizeAgentsNameSet(input.ExistingGlobalNames)
	existingHomeNames := normalizeAgentsNameSet(input.ExistingHomeNames)
	existingWorktrees := normalizeAgentsNameSet(input.ExistingWorktrees)
	existingBranches := normalizeAgentsNameSet(input.ExistingBranches)

	usedAliases := map[string]bool{}
	usedGlobalNames := map[string]bool{}
	usedHomeNames := map[string]bool{}
	usedWorktrees := map[string]bool{}
	usedBranches := map[string]bool{}
	sequenceOffsets := map[string]int{}

	plans := make([]agentsNamingAgentPlan, 0, len(input.Agents))
	for _, agent := range input.Agents {
		responsibility, err := normalizeAgentsNamingField("responsibility", agent.Responsibility)
		if err != nil {
			return agentsNamingPlan{}, err
		}
		scope := strings.TrimSpace(agent.IdentityScope)
		if scope == "" {
			scope = agentsIdentityScopeLocal
		}
		if scope != agentsIdentityScopeLocal && scope != agentsIdentityScopeGlobal {
			return agentsNamingPlan{}, usageError("agent %q has unsupported identity_scope %q", responsibility, scope)
		}
		workBinding := strings.TrimSpace(agent.WorkBinding)
		if workBinding == "" {
			workBinding = agentsWorkRepoRoot
		}
		if workBinding != agentsWorkRepoRoot && workBinding != agentsWorkGitWorktree {
			return agentsNamingPlan{}, usageError("agent %q has unsupported work %q", responsibility, workBinding)
		}
		if existingHomeNames[responsibility] || usedHomeNames[responsibility] {
			return agentsNamingPlan{}, usageError("agent home %q is already planned or exists", responsibility)
		}
		usedHomeNames[responsibility] = true

		fields := map[string]string{
			"user":           user,
			"responsibility": responsibility,
		}
		aliasPattern := policy.LocalAliasPattern
		aliasSequence := policy.LocalAliasSequence
		if scope == agentsIdentityScopeGlobal {
			aliasPattern = policy.GlobalAliasPattern
			aliasSequence = policy.GlobalAliasSequence
		}
		alias, err := nextAvailableAgentsName(agentsNameRequest{
			Field:        "team alias",
			Pattern:      aliasPattern,
			SequenceName: aliasSequence,
			Fields:       fields,
			Existing:     existingAliases,
			Used:         usedAliases,
			Offsets:      sequenceOffsets,
		})
		if err != nil {
			return agentsNamingPlan{}, fmt.Errorf("agent %q: %w", responsibility, err)
		}
		usedAliases[alias] = true

		globalName := ""
		if scope == agentsIdentityScopeGlobal {
			globalName, err = nextAvailableAgentsName(agentsNameRequest{
				Field:        "global name",
				Pattern:      policy.GlobalNamePattern,
				SequenceName: policy.GlobalNameSequence,
				Fields:       fields,
				Existing:     existingGlobalNames,
				Used:         usedGlobalNames,
				Offsets:      sequenceOffsets,
			})
			if err != nil {
				return agentsNamingPlan{}, fmt.Errorf("agent %q: %w", responsibility, err)
			}
			usedGlobalNames[globalName] = true
		}

		plan := agentsNamingAgentPlan{
			Responsibility: responsibility,
			IdentityScope:  scope,
			TeamAlias:      alias,
			GlobalName:     globalName,
			HomeName:       responsibility,
			HomePath:       filepath.ToSlash(filepath.Join(agentsDir, "home", responsibility)),
			WorkBinding:    workBinding,
			WorkPath:       ".",
			CollisionState: "available",
		}
		if globalName != "" && namespace != "" {
			plan.GlobalAddress = namespace + "/" + globalName
		}
		if workBinding == agentsWorkGitWorktree {
			worktreeName, err := nextAvailableAgentsName(agentsNameRequest{
				Field:   "worktree name",
				Pattern: policy.WorktreePattern,
				Fields:  fields,
				Existing: mergeAgentsNameSets(
					existingWorktrees,
					existingBranches,
				),
				Used: mergeAgentsNameSets(
					usedWorktrees,
					usedBranches,
				),
				Offsets: sequenceOffsets,
			})
			if err != nil {
				return agentsNamingPlan{}, fmt.Errorf("agent %q: %w", responsibility, err)
			}
			usedWorktrees[worktreeName] = true
			usedBranches[worktreeName] = true
			plan.WorktreeName = worktreeName
			plan.BranchName = worktreeName
			plan.WorktreePath = filepath.ToSlash(filepath.Join(agentsDir, "worktrees", worktreeName))
			plan.WorkPath = plan.WorktreePath
		}
		plans = append(plans, plan)
	}
	sort.SliceStable(plans, func(i, j int) bool {
		return plans[i].Responsibility < plans[j].Responsibility
	})
	return agentsNamingPlan{Agents: plans}, nil
}

func renderAgentsNamingPlanHuman(plan agentsNamingPlan) string {
	var out strings.Builder
	for _, agent := range plan.Agents {
		fmt.Fprintf(&out, "%s\n", agent.Responsibility)
		fmt.Fprintf(&out, "  Scope:      %s\n", agent.IdentityScope)
		fmt.Fprintf(&out, "  Alias:      %s\n", agent.TeamAlias)
		if agent.GlobalAddress != "" {
			fmt.Fprintf(&out, "  Address:    %s\n", agent.GlobalAddress)
		}
		fmt.Fprintf(&out, "  Home:       %s\n", agent.HomePath)
		fmt.Fprintf(&out, "  Work:       %s\n", agent.WorkPath)
		fmt.Fprintf(&out, "  Collision:  %s\n", agent.CollisionState)
	}
	return strings.TrimRight(out.String(), "\n")
}

type agentsNameRequest struct {
	Field        string
	Pattern      string
	SequenceName string
	Fields       map[string]string
	Existing     map[string]bool
	Used         map[string]bool
	Offsets      map[string]int
}

func nextAvailableAgentsName(req agentsNameRequest) (string, error) {
	pattern := strings.TrimSpace(req.Pattern)
	if pattern == "" {
		return "", usageError("%s pattern must not be empty", req.Field)
	}
	if err := validateAgentsPattern(req.Field, pattern); err != nil {
		return "", err
	}
	sequenceName := strings.TrimSpace(req.SequenceName)
	if !agentsPatternNeedsSequence(pattern) {
		name, err := expandAgentsNamingPattern(req.Field, pattern, req.Fields)
		if err != nil {
			return "", err
		}
		if req.Existing[name] || req.Used[name] {
			return "", usageError("%s %q is already in use", req.Field, name)
		}
		return name, nil
	}
	if sequenceName == "" {
		return "", usageError("%s pattern %q requires a naming sequence", req.Field, pattern)
	}
	if err := validateAgentsSequence(sequenceName); err != nil {
		return "", err
	}
	offset := req.Offsets[req.Field+"|"+sequenceName]
	limit := agentsSequenceLimit(sequenceName)
	for i := offset; i < limit; i++ {
		candidate, err := agentsSequenceCandidate(sequenceName, i)
		if err != nil {
			return "", err
		}
		fields := copyAgentsFields(req.Fields)
		fields[sequenceName] = candidate
		name, err := expandAgentsNamingPattern(req.Field, pattern, fields)
		if err != nil {
			return "", err
		}
		req.Offsets[req.Field+"|"+sequenceName] = i + 1
		if req.Existing[name] || req.Used[name] {
			continue
		}
		return name, nil
	}
	return "", usageError("%s candidates exhausted for sequence %s", req.Field, sequenceName)
}

func mergeAgentsNamingPolicy(policy agentsNamingPolicy) agentsNamingPolicy {
	defaults := defaultAgentsNamingPolicy()
	if strings.TrimSpace(policy.LocalAliasSequence) == "" {
		policy.LocalAliasSequence = defaults.LocalAliasSequence
	}
	if strings.TrimSpace(policy.LocalAliasPattern) == "" {
		policy.LocalAliasPattern = defaults.LocalAliasPattern
	}
	if strings.TrimSpace(policy.GlobalAliasSequence) == "" {
		policy.GlobalAliasSequence = defaults.GlobalAliasSequence
	}
	if strings.TrimSpace(policy.GlobalAliasPattern) == "" {
		policy.GlobalAliasPattern = defaults.GlobalAliasPattern
	}
	if strings.TrimSpace(policy.GlobalNamePattern) == "" {
		policy.GlobalNamePattern = defaults.GlobalNamePattern
	}
	if strings.TrimSpace(policy.WorktreePattern) == "" {
		policy.WorktreePattern = defaults.WorktreePattern
	}
	return policy
}

func needsAgentsNamingUser(policy agentsNamingPolicy) bool {
	for _, pattern := range []string{
		policy.LocalAliasPattern,
		policy.GlobalAliasPattern,
		policy.GlobalNamePattern,
		policy.WorktreePattern,
	} {
		if strings.Contains(pattern, "{user}") {
			return true
		}
	}
	return false
}

func expandAgentsNamingPattern(field, pattern string, fields map[string]string) (string, error) {
	if err := validateAgentsPattern(field, pattern); err != nil {
		return "", err
	}
	missing := ""
	expanded := agentsFieldPattern.ReplaceAllStringFunc(pattern, func(match string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "{"), "}")
		value, ok := fields[key]
		if !ok || strings.TrimSpace(value) == "" {
			missing = key
			return ""
		}
		return value
	})
	if missing != "" {
		return "", usageError("%s pattern %q references unavailable field {%s}", field, pattern, missing)
	}
	if strings.Contains(expanded, "{") || strings.Contains(expanded, "}") {
		return "", usageError("%s pattern %q contains invalid field syntax", field, pattern)
	}
	return normalizeAgentsNamingField(field, expanded)
}

func validateAgentsPattern(field, pattern string) error {
	if strings.Contains(pattern, "/") || strings.Contains(pattern, "\\") || strings.Contains(pattern, "..") {
		return usageError("%s pattern %q must not contain path separators or path traversal", field, pattern)
	}
	for _, match := range agentsFieldPattern.FindAllStringSubmatch(pattern, -1) {
		key := match[1]
		switch key {
		case "user", "responsibility", agentsSequenceClassic, agentsSequenceStar:
		default:
			return usageError("%s pattern %q references unsupported field {%s}", field, pattern, key)
		}
	}
	return nil
}

func agentsPatternNeedsSequence(pattern string) bool {
	return strings.Contains(pattern, "{"+agentsSequenceClassic+"}") ||
		strings.Contains(pattern, "{"+agentsSequenceStar+"}")
}

func normalizeAgentsNamingField(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", usageError("%s must not be empty", field)
	}
	if strings.Contains(value, "/") || strings.Contains(value, "\\") || strings.Contains(value, "..") {
		return "", usageError("%s %q must not contain path separators or path traversal", field, value)
	}
	if !agentsSlugPattern.MatchString(value) {
		return "", usageError("%s %q must be a slug containing only lowercase letters, numbers, and dashes", field, value)
	}
	return value, nil
}

func validateAgentsSequence(sequence string) error {
	switch sequence {
	case agentsSequenceClassic, agentsSequenceStar:
		return nil
	default:
		return usageError("unsupported naming sequence %q", sequence)
	}
}

func agentsSequenceCandidate(sequence string, index int) (string, error) {
	var names []string
	switch sequence {
	case agentsSequenceClassic:
		names = agentsClassicNames
	case agentsSequenceStar:
		names = agentsStarNames
	default:
		return "", usageError("unsupported naming sequence %q", sequence)
	}
	if index < 0 {
		return "", usageError("invalid sequence index %d", index)
	}
	if index < len(names) {
		return normalizeAgentsNamingField(sequence, names[index])
	}
	repeat := ((index - len(names)) / len(names)) + 1
	base := names[(index-len(names))%len(names)]
	return normalizeAgentsNamingField(sequence, fmt.Sprintf("%s-%02d", base, repeat))
}

func agentsSequenceLimit(sequence string) int {
	switch sequence {
	case agentsSequenceClassic:
		return len(agentsClassicNames) * 100
	case agentsSequenceStar:
		return len(agentsStarNames) * 100
	default:
		return 0
	}
}

func normalizeAgentsNameSet(values map[string]bool) map[string]bool {
	out := map[string]bool{}
	for value, ok := range values {
		if !ok {
			continue
		}
		normalized, err := normalizeAgentsNamingField("existing name", value)
		if err != nil {
			continue
		}
		out[normalized] = true
	}
	return out
}

func mergeAgentsNameSets(sets ...map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, set := range sets {
		for value, ok := range set {
			if ok {
				out[value] = true
			}
		}
	}
	return out
}

func copyAgentsFields(fields map[string]string) map[string]string {
	out := make(map[string]string, len(fields))
	for key, value := range fields {
		out[key] = value
	}
	return out
}
