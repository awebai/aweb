package teamblueprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Source struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Ref     string `json:"ref"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
}

type Blueprint struct {
	SchemaVersion   int                 `json:"schema_version" yaml:"schema_version"`
	ID              string              `json:"id" yaml:"id"`
	Name            string              `json:"name" yaml:"name"`
	Version         string              `json:"version" yaml:"version"`
	Summary         string              `json:"summary" yaml:"summary"`
	Profiles        []BlueprintProfile  `json:"profiles" yaml:"profiles"`
	RecommendedApps []string            `json:"recommended_apps,omitempty" yaml:"recommended_apps"`
	ApprovalPolicy  ApprovalPolicy      `json:"approval_policy,omitempty" yaml:"approval_policy"`
	RuntimeOptions  map[string][]string `json:"runtime_options,omitempty" yaml:"runtime_options"`
	Source          Source              `json:"source" yaml:"-"`
	LoadedProfiles  []Profile           `json:"loaded_profiles" yaml:"-"`
}

type BlueprintProfile struct {
	ID               string              `json:"id" yaml:"id"`
	Path             string              `json:"path" yaml:"path"`
	DefaultAgentName string              `json:"default_agent_name,omitempty" yaml:"default_agent_name"`
	Role             string              `json:"role,omitempty" yaml:"role"`
	Purpose          string              `json:"purpose,omitempty" yaml:"purpose"`
	Required         *bool               `json:"required,omitempty" yaml:"required"`
	DefaultCount     int                 `json:"default_count,omitempty" yaml:"default_count"`
	Min              int                 `json:"min,omitempty" yaml:"min"`
	Max              int                 `json:"max,omitempty" yaml:"max"`
	RuntimeOptions   []string            `json:"runtime_options,omitempty" yaml:"runtime_options"`
	RequiredApps     map[string]AppGrant `json:"required_apps,omitempty" yaml:"required_apps"`
	Subscriptions    []Subscription      `json:"subscriptions,omitempty" yaml:"subscriptions"`
	ApprovalRequired []string            `json:"approval_required,omitempty" yaml:"approval_required"`
	Artifacts        []Artifact          `json:"artifacts,omitempty" yaml:"artifacts"`
}

type Profile struct {
	SchemaVersion    int                 `json:"schema_version" yaml:"schema_version"`
	ID               string              `json:"id" yaml:"id"`
	Name             string              `json:"name" yaml:"name"`
	Version          string              `json:"version" yaml:"version"`
	Summary          string              `json:"summary" yaml:"summary"`
	RuntimeHints     RuntimeHints        `json:"runtime_hints,omitempty" yaml:"runtime_hints"`
	AcceptsWork      []string            `json:"accepts_work,omitempty" yaml:"accepts_work"`
	RequiredApps     map[string]AppGrant `json:"required_apps,omitempty" yaml:"required_apps"`
	Subscriptions    []Subscription      `json:"subscriptions,omitempty" yaml:"subscriptions"`
	ApprovalRequired []string            `json:"approval_required,omitempty" yaml:"approval_required"`
	Artifacts        []Artifact          `json:"artifacts,omitempty" yaml:"artifacts"`
	InstructionsPath string              `json:"instructions_path" yaml:"-"`
	Path             string              `json:"path" yaml:"-"`
	Digest           string              `json:"digest" yaml:"-"`
}

type RuntimeHints struct {
	Preferred []string `json:"preferred,omitempty" yaml:"preferred"`
}

type AppGrant struct {
	Scopes []string `json:"scopes,omitempty" yaml:"scopes"`
}

type Subscription struct {
	App         string         `json:"app,omitempty" yaml:"app"`
	Event       string         `json:"event" yaml:"event"`
	Type        string         `json:"type,omitempty" yaml:"type"`
	ResourceRef string         `json:"resource_ref,omitempty" yaml:"resource_ref"`
	Filter      map[string]any `json:"filter,omitempty" yaml:"filter"`
}

type Artifact struct {
	Path string `json:"path" yaml:"path"`
	Kind string `json:"kind" yaml:"kind"`
}

type ApprovalPolicy struct {
	RequireHumanApproval []string `json:"require_human_approval,omitempty" yaml:"require_human_approval"`
}

type Plan struct {
	Source                 Source           `json:"source"`
	Blueprint              BlueprintSummary `json:"blueprint"`
	Agents                 []AgentPlan      `json:"agents"`
	RuntimeHints           []string         `json:"runtime_hints,omitempty"`
	RequestedApps          []AppRequest     `json:"requested_apps,omitempty"`
	EventSubscriptions     []Subscription   `json:"event_subscriptions,omitempty"`
	ApprovalPolicy         ApprovalPolicy   `json:"approval_policy,omitempty"`
	CodeArtifacts          []Artifact       `json:"code_artifacts,omitempty"`
	FilesWouldWrite        []string         `json:"files_would_write"`
	CommandsWouldRun       []string         `json:"commands_would_run"`
	RequiredHumanDecisions []string         `json:"required_human_decisions"`
}

type BlueprintSummary struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Summary string `json:"summary"`
}

type AgentPlan struct {
	Role             string   `json:"role"`
	ProfileID        string   `json:"profile_id"`
	ProfileVersion   string   `json:"profile_version"`
	DefaultAgentName string   `json:"default_agent_name"`
	DefaultCount     int      `json:"default_count"`
	Min              int      `json:"min"`
	Max              int      `json:"max"`
	RuntimeHints     []string `json:"runtime_hints,omitempty"`
	Purpose          string   `json:"purpose,omitempty"`
}

type AppRequest struct {
	App    string   `json:"app"`
	Scopes []string `json:"scopes,omitempty"`
}

func LoadLocalDir(dir string) (*Blueprint, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("blueprint source %s is not a directory", dir)
	}
	if err := scanUnsafeSource(abs); err != nil {
		return nil, err
	}
	blueprintPath := filepath.Join(abs, "blueprint.yaml")
	raw, err := os.ReadFile(blueprintPath)
	if err != nil {
		return nil, fmt.Errorf("blueprint.yaml: %w", err)
	}
	var bp Blueprint
	if err := yaml.Unmarshal(raw, &bp); err != nil {
		return nil, fmt.Errorf("blueprint.yaml: parse: %w", err)
	}
	if err := validateBlueprint(abs, &bp); err != nil {
		return nil, err
	}
	profiles := make([]Profile, 0, len(bp.Profiles))
	for _, slot := range bp.Profiles {
		profile, err := loadProfile(abs, slot)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, *profile)
	}
	bp.LoadedProfiles = profiles
	digest, err := digestDir(abs)
	if err != nil {
		return nil, err
	}
	bp.Source = Source{ID: bp.ID, Kind: "local_dir", Ref: abs, Version: bp.Version, Digest: digest}
	return &bp, nil
}

func InspectPlan(bp *Blueprint) Plan {
	appScopes := map[string]map[string]bool{}
	subscriptions := []Subscription{}
	artifacts := []Artifact{}
	agents := make([]AgentPlan, 0, len(bp.Profiles))
	profileByID := map[string]Profile{}
	for _, p := range bp.LoadedProfiles {
		profileByID[p.ID] = p
		mergeApps(appScopes, p.RequiredApps)
		subscriptions = append(subscriptions, p.Subscriptions...)
		artifacts = append(artifacts, p.Artifacts...)
	}
	for _, slot := range bp.Profiles {
		p := profileByID[slot.ID]
		mergeApps(appScopes, slot.RequiredApps)
		subscriptions = append(subscriptions, slot.Subscriptions...)
		artifacts = append(artifacts, slot.Artifacts...)
		count := slot.DefaultCount
		if count <= 0 {
			count = 1
		}
		min := slot.Min
		if min <= 0 {
			min = 1
		}
		max := slot.Max
		if max <= 0 {
			max = count
		}
		runtimeHints := append([]string(nil), slot.RuntimeOptions...)
		if len(runtimeHints) == 0 {
			runtimeHints = append(runtimeHints, p.RuntimeHints.Preferred...)
		}
		agents = append(agents, AgentPlan{
			Role:             firstNonEmpty(slot.Role, slot.ID),
			ProfileID:        p.ID,
			ProfileVersion:   p.Version,
			DefaultAgentName: firstNonEmpty(slot.DefaultAgentName, slot.ID),
			DefaultCount:     count,
			Min:              min,
			Max:              max,
			RuntimeHints:     runtimeHints,
			Purpose:          firstNonEmpty(slot.Purpose, p.Summary),
		})
	}
	for _, app := range bp.RecommendedApps {
		if strings.TrimSpace(app) == "" {
			continue
		}
		if _, ok := appScopes[app]; !ok {
			appScopes[app] = map[string]bool{}
		}
	}
	files := []string{"blueprint.yaml"}
	for _, p := range bp.LoadedProfiles {
		files = append(files, filepath.ToSlash(filepath.Join(p.Path, "profile.yaml")), filepath.ToSlash(filepath.Join(p.Path, "instructions.md")))
	}
	return Plan{
		Source:             bp.Source,
		Blueprint:          BlueprintSummary{ID: bp.ID, Name: bp.Name, Version: bp.Version, Summary: bp.Summary},
		Agents:             agents,
		RuntimeHints:       flattenRuntimeHints(bp.RuntimeOptions),
		RequestedApps:      appRequests(appScopes),
		EventSubscriptions: dedupeSubscriptions(subscriptions),
		ApprovalPolicy:     bp.ApprovalPolicy,
		CodeArtifacts:      dedupeArtifacts(artifacts),
		FilesWouldWrite:    sortedUnique(files),
		CommandsWouldRun:   []string{},
		RequiredHumanDecisions: []string{
			"review requested app grants and scopes",
			"approve or deny event subscriptions",
			"choose runtime bindings for planned agents",
		},
	}
}

func (p Plan) JSON() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

func validateBlueprint(root string, bp *Blueprint) error {
	if bp.SchemaVersion != 1 {
		return fmt.Errorf("blueprint.yaml:schema_version: expected 1")
	}
	for field, value := range map[string]string{"id": bp.ID, "name": bp.Name, "version": bp.Version, "summary": bp.Summary} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("blueprint.yaml:%s: required", field)
		}
	}
	if len(bp.Profiles) == 0 {
		return fmt.Errorf("blueprint.yaml:profiles: at least one profile is required")
	}
	seen := map[string]bool{}
	for idx, slot := range bp.Profiles {
		prefix := fmt.Sprintf("blueprint.yaml:profiles[%d]", idx)
		if strings.TrimSpace(slot.ID) == "" {
			return fmt.Errorf("%s.id: required", prefix)
		}
		if seen[slot.ID] {
			return fmt.Errorf("%s.id: duplicate %q", prefix, slot.ID)
		}
		seen[slot.ID] = true
		if err := validateRelativePath(prefix+".path", slot.Path); err != nil {
			return err
		}
		full := filepath.Join(root, filepath.FromSlash(slot.Path))
		if !isWithin(root, full) {
			return fmt.Errorf("%s.path: escapes blueprint root", prefix)
		}
	}
	return nil
}

func loadProfile(root string, slot BlueprintProfile) (*Profile, error) {
	profileDir := filepath.Join(root, filepath.FromSlash(slot.Path))
	profilePath := filepath.Join(profileDir, "profile.yaml")
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: %w", slot.Path, err)
	}
	var p Profile
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: parse: %w", slot.Path, err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s/profile.yaml:schema_version: expected 1", slot.Path)
	}
	for field, value := range map[string]string{"id": p.ID, "name": p.Name, "version": p.Version, "summary": p.Summary} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s/profile.yaml:%s: required", slot.Path, field)
		}
	}
	if p.ID != slot.ID {
		return nil, fmt.Errorf("%s/profile.yaml:id: got %q, want slot id %q", slot.Path, p.ID, slot.ID)
	}
	instructions := filepath.Join(profileDir, "instructions.md")
	if _, err := os.Stat(instructions); err != nil {
		return nil, fmt.Errorf("%s/instructions.md: required", slot.Path)
	}
	for i, artifact := range p.Artifacts {
		if err := validateRelativePath(fmt.Sprintf("%s/profile.yaml:artifacts[%d].path", slot.Path, i), artifact.Path); err != nil {
			return nil, err
		}
	}
	digest, err := digestDir(profileDir)
	if err != nil {
		return nil, err
	}
	p.Path = filepath.ToSlash(slot.Path)
	p.InstructionsPath = filepath.ToSlash(filepath.Join(slot.Path, "instructions.md"))
	p.Digest = digest
	return &p, nil
}

func validateRelativePath(field string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	if filepath.IsAbs(value) || strings.HasPrefix(value, "/") {
		return fmt.Errorf("%s: absolute paths are not allowed", field)
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || strings.Contains(value, "@") && strings.Contains(value, ":") {
		return fmt.Errorf("%s: host or scheme paths are not allowed", field)
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s: path traversal is not allowed", field)
	}
	return nil
}

func scanUnsafeSource(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, segment := range strings.Split(relSlash, "/") {
			if segment == ".aw" {
				return fmt.Errorf("%s: .aw runtime state is not allowed in blueprints", relSlash)
			}
		}
		base := strings.ToLower(d.Name())
		if unsafeFileName(base) {
			return fmt.Errorf("%s: identity material, credentials, tokens, secrets, or generated runtime state are not allowed", relSlash)
		}
		if d.IsDir() {
			if base == "worktrees" || base == "worktree" || base == "generated-worktrees" || (base == "work" && strings.Contains(relSlash, "instances/")) {
				return fmt.Errorf("%s: generated worktrees are not allowed in blueprints", relSlash)
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if unsafeContent(string(data)) {
			return fmt.Errorf("%s: unexpected identity material, credentials, tokens, or secrets", relSlash)
		}
		return nil
	})
}

func unsafeFileName(base string) bool {
	blocked := []string{".env", "identity.yaml", "workspace.yaml", "certificate", "cert", "private", "secret", "token", "credential", "apikey", "api_key", "id_rsa", "id_ed25519", "known_hosts"}
	for _, item := range blocked {
		if base == item || strings.Contains(base, item) {
			return true
		}
	}
	return strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".crt") || strings.HasSuffix(base, ".p12")
}

func unsafeContent(s string) bool {
	lower := strings.ToLower(s)
	patterns := []string{"-----begin ", "private key", "did:key:", "did:aw:", "awid", "team_certificate", "x-awid-team-certificate", "api_key", "apikey", "access_token", "refresh_token", "secret_key", "password="}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func digestDir(root string) (string, error) {
	h := sha256.New()
	paths := []string{}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(paths)
	for _, path := range paths {
		rel, _ := filepath.Rel(root, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func mergeApps(dst map[string]map[string]bool, apps map[string]AppGrant) {
	for app, grant := range apps {
		app = strings.TrimSpace(app)
		if app == "" {
			continue
		}
		if _, ok := dst[app]; !ok {
			dst[app] = map[string]bool{}
		}
		for _, scope := range grant.Scopes {
			if strings.TrimSpace(scope) != "" {
				dst[app][strings.TrimSpace(scope)] = true
			}
		}
	}
}

func appRequests(appScopes map[string]map[string]bool) []AppRequest {
	apps := make([]string, 0, len(appScopes))
	for app := range appScopes {
		apps = append(apps, app)
	}
	sort.Strings(apps)
	out := make([]AppRequest, 0, len(apps))
	for _, app := range apps {
		scopes := make([]string, 0, len(appScopes[app]))
		for scope := range appScopes[app] {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		out = append(out, AppRequest{App: app, Scopes: scopes})
	}
	return out
}

func flattenRuntimeHints(options map[string][]string) []string {
	items := []string{}
	for key, values := range options {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				items = append(items, key+":"+strings.TrimSpace(value))
			}
		}
	}
	return sortedUnique(items)
}

func dedupeSubscriptions(in []Subscription) []Subscription {
	seen := map[string]Subscription{}
	keys := []string{}
	for _, sub := range in {
		keyBytes, _ := json.Marshal(sub)
		key := string(keyBytes)
		if _, ok := seen[key]; !ok {
			seen[key] = sub
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := make([]Subscription, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func dedupeArtifacts(in []Artifact) []Artifact {
	seen := map[string]Artifact{}
	keys := []string{}
	for _, artifact := range in {
		key := artifact.Path + "\x00" + artifact.Kind
		if _, ok := seen[key]; !ok {
			seen[key] = artifact
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := make([]Artifact, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
