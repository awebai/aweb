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
	agentsLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
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
	WorktreeSequence    string
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
	Responsibility string                          `json:"responsibility"`
	IdentityScope  string                          `json:"identity_scope"`
	TeamAlias      string                          `json:"team_alias"`
	GlobalName     string                          `json:"global_name,omitempty"`
	GlobalAddress  string                          `json:"global_address,omitempty"`
	HomeName       string                          `json:"home_name"`
	HomePath       string                          `json:"home_path"`
	WorkBinding    string                          `json:"work_binding"`
	WorkPath       string                          `json:"work_path"`
	WorktreeName   string                          `json:"worktree_name,omitempty"`
	WorktreePath   string                          `json:"worktree_path,omitempty"`
	BranchName     string                          `json:"branch_name,omitempty"`
	Availability   []agentsNamingAvailabilityCheck `json:"availability"`
}

type agentsNamingAvailabilityCheck struct {
	Field  string `json:"field"`
	Value  string `json:"value"`
	Status string `json:"status"`
	Source string `json:"source"`
}

func defaultAgentsNamingPolicy() agentsNamingPolicy {
	return agentsNamingPolicy{
		LocalAliasSequence:  agentsSequenceClassic,
		LocalAliasPattern:   "{classic-name}",
		GlobalAliasSequence: agentsSequenceClassic,
		GlobalAliasPattern:  "{user}-{classic-name}",
		GlobalNamePattern:   "{user}-{responsibility}",
		WorktreeSequence:    agentsSequenceClassic,
		WorktreePattern:     "{responsibility}",
	}
}

func buildAgentsNamingPlan(input agentsNamingInput) (agentsNamingPlan, error) {
	policy := mergeAgentsNamingPolicy(input.Policy)
	agentsDir, err := normalizeAgentsNamingField("agents-dir", firstNonEmpty(input.AgentsDir, "agents"))
	if err != nil {
		return agentsNamingPlan{}, err
	}
	namespace, err := normalizeAgentsNamespace(input.Namespace)
	if err != nil {
		return agentsNamingPlan{}, err
	}
	user := strings.TrimSpace(input.User)
	if agentsNamingInputNeedsUser(policy, input.Agents) {
		if user == "" {
			return agentsNamingPlan{}, usageError("identity prefix is required for this agents layout because at least one naming pattern uses {user}; pass --identity-prefix or set AWEB_IDENTITY_PREFIX, AWEB_HUMAN, or USER")
		}
		var userErr error
		user, userErr = normalizeAgentsNamingField("user", user)
		if userErr != nil {
			return agentsNamingPlan{}, userErr
		}
	}

	existingAliases, err := normalizeAgentsNameSet("existing team alias", input.ExistingAliases)
	if err != nil {
		return agentsNamingPlan{}, err
	}
	existingGlobalNames, err := normalizeAgentsNameSet("existing global name", input.ExistingGlobalNames)
	if err != nil {
		return agentsNamingPlan{}, err
	}
	existingHomeNames, err := normalizeAgentsNameSet("existing home name", input.ExistingHomeNames)
	if err != nil {
		return agentsNamingPlan{}, err
	}
	existingWorktrees, err := normalizeAgentsNameSet("existing worktree name", input.ExistingWorktrees)
	if err != nil {
		return agentsNamingPlan{}, err
	}
	existingBranches, err := normalizeAgentsNameSet("existing branch name", input.ExistingBranches)
	if err != nil {
		return agentsNamingPlan{}, err
	}

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
			Availability: []agentsNamingAvailabilityCheck{
				agentsAvailableCheck("team_alias", alias, "existing team aliases and current plan"),
				agentsAvailableCheck("home", responsibility, "existing home paths and current plan"),
			},
		}
		if globalName != "" && namespace != "" {
			plan.GlobalAddress = namespace + "/" + globalName
		}
		if globalName != "" {
			plan.Availability = append(plan.Availability,
				agentsAvailableCheck("global_name", globalName, "existing namespace addresses and current plan"),
			)
		}
		if workBinding == agentsWorkGitWorktree {
			worktreeName, err := nextAvailableAgentsWorktreeName(agentsNameRequest{
				Field:        "worktree name",
				Pattern:      policy.WorktreePattern,
				SequenceName: policy.WorktreeSequence,
				Fields:       fields,
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
			plan.Availability = append(plan.Availability,
				agentsAvailableCheck("worktree", worktreeName, "existing worktrees and current plan"),
				agentsAvailableCheck("branch", worktreeName, "existing branches and current plan"),
			)
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
		fmt.Fprintf(&out, "  Availability:\n")
		for _, check := range agent.Availability {
			fmt.Fprintf(&out, "    %s: %s (%s: %s)\n", check.Field, check.Status, check.Source, check.Value)
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

func agentsAvailableCheck(field, value, source string) agentsNamingAvailabilityCheck {
	return agentsNamingAvailabilityCheck{
		Field:  field,
		Value:  value,
		Status: "available",
		Source: source,
	}
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

func nextAvailableAgentsWorktreeName(req agentsNameRequest) (string, error) {
	if agentsPatternNeedsSequence(req.Pattern) {
		return nextAvailableAgentsName(req)
	}
	base, err := nextAvailableAgentsName(req)
	if err == nil {
		return base, nil
	}
	if !strings.Contains(err.Error(), "already in use") {
		return "", err
	}
	expanded, expandErr := expandAgentsNamingPattern(req.Field, req.Pattern, req.Fields)
	if expandErr != nil {
		return "", expandErr
	}
	for suffix := 2; suffix <= 1000; suffix++ {
		candidate := fmt.Sprintf("%s-%d", expanded, suffix)
		candidate, err = normalizeAgentsNamingField(req.Field, candidate)
		if err != nil {
			return "", err
		}
		if req.Existing[candidate] || req.Used[candidate] {
			continue
		}
		return candidate, nil
	}
	return "", usageError("%s candidates exhausted for base %q", req.Field, expanded)
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
	if strings.TrimSpace(policy.WorktreeSequence) == "" {
		policy.WorktreeSequence = defaults.WorktreeSequence
	}
	return policy
}

func agentsNamingInputNeedsUser(policy agentsNamingPolicy, agents []agentsNamingAgentInput) bool {
	for _, agent := range agents {
		scope := strings.TrimSpace(agent.IdentityScope)
		if scope == "" {
			scope = agentsIdentityScopeLocal
		}
		patterns := []string{policy.WorktreePattern}
		if scope == agentsIdentityScopeGlobal {
			patterns = append(patterns, policy.GlobalAliasPattern, policy.GlobalNamePattern)
		} else {
			patterns = append(patterns, policy.LocalAliasPattern)
		}
		for _, pattern := range patterns {
			if strings.Contains(pattern, "{user}") {
				return true
			}
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

func normalizeAgentsNamespace(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	normalized := awconfig.NormalizeDomain(trimmed)
	if normalized == "" {
		return "", usageError("namespace must not be empty")
	}
	if strings.Contains(normalized, "/") || strings.Contains(normalized, "\\") || strings.Contains(normalized, "..") {
		return "", usageError("namespace %q must not contain path separators or path traversal", value)
	}
	if strings.HasPrefix(normalized, ".") || strings.HasSuffix(normalized, ".") {
		return "", usageError("namespace %q must not start or end with a dot", value)
	}
	for _, label := range strings.Split(normalized, ".") {
		if !agentsLabelPattern.MatchString(label) {
			return "", usageError("namespace %q must contain valid DNS labels", value)
		}
	}
	return normalized, nil
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

func normalizeAgentsNameSet(field string, values map[string]bool) (map[string]bool, error) {
	out := map[string]bool{}
	for value, ok := range values {
		if !ok {
			continue
		}
		normalized, err := normalizeAgentsNamingField(field, value)
		if err != nil {
			return nil, err
		}
		out[normalized] = true
	}
	return out, nil
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
