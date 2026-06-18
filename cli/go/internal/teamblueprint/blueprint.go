package teamblueprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

type Source struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Ref     string `json:"ref"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"digest"`
}

type Display struct {
	Name    string `json:"name,omitempty" yaml:"name"`
	Summary string `json:"summary,omitempty" yaml:"summary"`
	Icon    string `json:"icon,omitempty" yaml:"icon"`
}

type Ref struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
}

type Blueprint struct {
	SchemaVersion   int                 `json:"schema_version" yaml:"schema_version"`
	ID              string              `json:"id" yaml:"id"`
	Version         string              `json:"version" yaml:"version"`
	Display         Display             `json:"display,omitempty" yaml:"display"`
	Name            string              `json:"name,omitempty" yaml:"name"`
	Summary         string              `json:"summary,omitempty" yaml:"summary"`
	Slots           []SlotSpec          `json:"slots" yaml:"slots"`
	RecommendedApps []string            `json:"recommended_apps,omitempty" yaml:"recommended_apps"`
	ApprovalPolicy  ApprovalPolicy      `json:"approval_policy,omitempty" yaml:"approval_policy"`
	RuntimeOptions  map[string][]string `json:"runtime_options,omitempty" yaml:"runtime_options"`
	AppRequests     map[string]AppGrant `json:"app_requests,omitempty" yaml:"app_requests"`
	Source          Source              `json:"source" yaml:"-"`
	LoadedProfiles  []Profile           `json:"loaded_profiles" yaml:"-"`
}

type SlotSpec struct {
	Role             string   `json:"role" yaml:"role"`
	Display          Display  `json:"display,omitempty" yaml:"display"`
	Required         *bool    `json:"required,omitempty" yaml:"required"`
	ProfileRef       Ref      `json:"profile_ref" yaml:"profile_ref"`
	DefaultAgentName string   `json:"default_agent_name,omitempty" yaml:"default_agent_name"`
	DefaultCount     int      `json:"default_count,omitempty" yaml:"default_count"`
	Min              int      `json:"min,omitempty" yaml:"min"`
	Max              int      `json:"max,omitempty" yaml:"max"`
	RuntimeOptions   []string `json:"runtime_options,omitempty" yaml:"runtime_options"`
	AppRequestRefs   []string `json:"app_request_refs,omitempty" yaml:"app_request_refs"`
}

type Profile struct {
	SchemaVersion    int                 `json:"schema_version" yaml:"schema_version"`
	ID               string              `json:"id" yaml:"id"`
	Version          string              `json:"version" yaml:"version"`
	Display          Display             `json:"display,omitempty" yaml:"display"`
	Name             string              `json:"name,omitempty" yaml:"name"`
	Summary          string              `json:"summary,omitempty" yaml:"summary"`
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
	Path      string `json:"path" yaml:"path"`
	Kind      string `json:"kind" yaml:"kind"`
	ProfileID string `json:"profile_id,omitempty" yaml:"-"`
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
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Version string  `json:"version"`
	Summary string  `json:"summary"`
	Display Display `json:"display,omitempty"`
}

type AgentPlan struct {
	Role             string   `json:"role"`
	Display          Display  `json:"display,omitempty"`
	ProfileRef       Ref      `json:"profile_ref"`
	ProfileID        string   `json:"profile_id"`
	ProfileVersion   string   `json:"profile_version"`
	DefaultAgentName string   `json:"default_agent_name"`
	DefaultCount     int      `json:"default_count"`
	Min              int      `json:"min"`
	Max              int      `json:"max"`
	RuntimeHints     []string `json:"runtime_options,omitempty"`
	AppRequestRefs   []string `json:"app_request_refs,omitempty"`
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
	if err := decodeKnownYAML(raw, &bp); err != nil {
		return nil, fmt.Errorf("blueprint.yaml: parse: %w", err)
	}
	if err := validateBlueprint(abs, &bp); err != nil {
		return nil, err
	}
	profiles := make([]Profile, 0, len(bp.Slots))
	for _, slot := range bp.Slots {
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
	agents := make([]AgentPlan, 0, len(bp.Slots))
	profileByID := map[string]Profile{}
	for _, p := range bp.LoadedProfiles {
		profileByID[p.ID] = p
		mergeApps(appScopes, p.RequiredApps)
		subscriptions = append(subscriptions, p.Subscriptions...)
		artifacts = append(artifacts, p.Artifacts...)
	}
	for _, slot := range bp.Slots {
		p := profileByID[slot.ProfileRef.ID]
		for _, ref := range slot.AppRequestRefs {
			mergeApps(appScopes, map[string]AppGrant{appRequestAppName(ref): bp.AppRequests[ref]})
		}
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
			Role:             slot.Role,
			Display:          slot.Display,
			ProfileRef:       slot.ProfileRef,
			ProfileID:        p.ID,
			ProfileVersion:   p.Version,
			DefaultAgentName: firstNonEmpty(slot.DefaultAgentName, slot.Role, slot.ProfileRef.ID),
			DefaultCount:     count,
			Min:              min,
			Max:              max,
			RuntimeHints:     runtimeHints,
			AppRequestRefs:   append([]string(nil), slot.AppRequestRefs...),
			Purpose:          firstNonEmpty(slot.Display.Summary, p.Display.Summary, p.Summary),
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
		Source:                 bp.Source,
		Blueprint:              BlueprintSummary{ID: bp.ID, Name: blueprintName(bp), Version: bp.Version, Summary: blueprintSummary(bp), Display: bp.Display},
		Agents:                 agents,
		RuntimeHints:           flattenRuntimeHints(bp.RuntimeOptions),
		RequestedApps:          appRequests(appScopes),
		EventSubscriptions:     dedupeSubscriptions(subscriptions),
		ApprovalPolicy:         bp.ApprovalPolicy,
		CodeArtifacts:          dedupeArtifacts(artifacts),
		FilesWouldWrite:        sortedUnique(files),
		CommandsWouldRun:       []string{},
		RequiredHumanDecisions: []string{"review requested app grants and scopes", "approve or deny event subscriptions", "choose runtime bindings for planned agents"},
	}
}

func (p Plan) JSON() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

func decodeKnownYAML(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode(out)
}

func validateBlueprint(root string, bp *Blueprint) error {
	if bp.SchemaVersion != 1 {
		return fmt.Errorf("blueprint.yaml:schema_version: expected 1")
	}
	for field, value := range map[string]string{"id": bp.ID, "version": bp.Version} {
		if err := validateRequiredString("blueprint.yaml:"+field, value); err != nil {
			return err
		}
	}
	if strings.TrimSpace(blueprintName(bp)) == "" {
		return fmt.Errorf("blueprint.yaml:display.name: required")
	}
	if strings.TrimSpace(blueprintSummary(bp)) == "" {
		return fmt.Errorf("blueprint.yaml:display.summary: required")
	}
	if len(bp.Slots) == 0 {
		return fmt.Errorf("blueprint.yaml:slots: at least one slot is required")
	}
	for i, app := range bp.RecommendedApps {
		if err := validateRefString(fmt.Sprintf("blueprint.yaml:recommended_apps[%d]", i), app); err != nil {
			return err
		}
	}
	for i, approval := range bp.ApprovalPolicy.RequireHumanApproval {
		if err := validateRequiredString(fmt.Sprintf("blueprint.yaml:approval_policy.require_human_approval[%d]", i), approval); err != nil {
			return err
		}
	}
	seenRoles := map[string]bool{}
	for idx, slot := range bp.Slots {
		prefix := fmt.Sprintf("blueprint.yaml:slots[%d]", idx)
		if err := validateRequiredString(prefix+".role", slot.Role); err != nil {
			return err
		}
		if seenRoles[slot.Role] {
			return fmt.Errorf("%s.role: duplicate %q", prefix, slot.Role)
		}
		seenRoles[slot.Role] = true
		if err := validateProfileRefID(prefix+".profile_ref.id", slot.ProfileRef.ID); err != nil {
			return err
		}
		if err := validateRequiredString(prefix+".profile_ref.version", slot.ProfileRef.Version); err != nil {
			return err
		}
		if slot.DefaultCount < 0 || slot.Min < 0 || slot.Max < 0 {
			return fmt.Errorf("%s: counts and ranges must be non-negative", prefix)
		}
		count := slot.DefaultCount
		if count == 0 {
			count = 1
		}
		min := slot.Min
		if min == 0 {
			min = 1
		}
		max := slot.Max
		if max == 0 {
			max = count
		}
		if min > count || count > max {
			return fmt.Errorf("%s: require min <= default_count <= max", prefix)
		}
		for i, runtime := range slot.RuntimeOptions {
			if err := validateRequiredString(fmt.Sprintf("%s.runtime_options[%d]", prefix, i), runtime); err != nil {
				return err
			}
		}
		for i, ref := range slot.AppRequestRefs {
			if err := validateRefString(fmt.Sprintf("%s.app_request_refs[%d]", prefix, i), ref); err != nil {
				return err
			}
			if _, ok := bp.AppRequests[ref]; !ok {
				return fmt.Errorf("%s.app_request_refs[%d]: unresolved app request ref %q", prefix, i, ref)
			}
		}
	}
	for ref, grant := range bp.AppRequests {
		if err := validateRefString("blueprint.yaml:app_requests ref", ref); err != nil {
			return err
		}
		if appRequestAppName(ref) == "" {
			return fmt.Errorf("blueprint.yaml:app_requests.%s: app name is required", ref)
		}
		for i, scope := range grant.Scopes {
			if err := validateRequiredString(fmt.Sprintf("blueprint.yaml:app_requests.%s.scopes[%d]", ref, i), scope); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadProfile(root string, slot SlotSpec) (*Profile, error) {
	profileRel := filepath.ToSlash(filepath.Join("profiles", slot.ProfileRef.ID))
	profileDir := filepath.Join(root, filepath.FromSlash(profileRel))
	if !isWithin(root, profileDir) {
		return nil, fmt.Errorf("blueprint.yaml:slots.profile_ref.id: resolves outside blueprint root")
	}
	profilePath := filepath.Join(profileDir, "profile.yaml")
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: %w", profileRel, err)
	}
	var p Profile
	if err := decodeKnownYAML(raw, &p); err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: parse: %w", profileRel, err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("%s/profile.yaml:schema_version: expected 1", profileRel)
	}
	for field, value := range map[string]string{"id": p.ID, "version": p.Version} {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:%s", profileRel, field), value); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(profileName(p)) == "" {
		return nil, fmt.Errorf("%s/profile.yaml:display.name: required", profileRel)
	}
	if strings.TrimSpace(profileSummary(p)) == "" {
		return nil, fmt.Errorf("%s/profile.yaml:display.summary: required", profileRel)
	}
	if p.ID != slot.ProfileRef.ID {
		return nil, fmt.Errorf("%s/profile.yaml:id: got %q, want profile_ref id %q", profileRel, p.ID, slot.ProfileRef.ID)
	}
	if p.Version != slot.ProfileRef.Version {
		return nil, fmt.Errorf("%s/profile.yaml:version: got %q, want profile_ref version %q", profileRel, p.Version, slot.ProfileRef.Version)
	}
	instructions := filepath.Join(profileDir, "instructions.md")
	if _, err := os.Stat(instructions); err != nil {
		return nil, fmt.Errorf("%s/instructions.md: required", profileRel)
	}
	for app, grant := range p.RequiredApps {
		if err := validateRefString(fmt.Sprintf("%s/profile.yaml:required_apps.%s", profileRel, app), app); err != nil {
			return nil, err
		}
		for i, scope := range grant.Scopes {
			if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:required_apps.%s.scopes[%d]", profileRel, app, i), scope); err != nil {
				return nil, err
			}
		}
	}
	for i, sub := range p.Subscriptions {
		if err := validateSubscription(fmt.Sprintf("%s/profile.yaml:subscriptions[%d]", profileRel, i), sub); err != nil {
			return nil, err
		}
	}
	for i, approval := range p.ApprovalRequired {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:approval_required[%d]", profileRel, i), approval); err != nil {
			return nil, err
		}
	}
	for i, artifact := range p.Artifacts {
		if err := validateArtifact(root, profileDir, profileRel, i, &artifact); err != nil {
			return nil, err
		}
		p.Artifacts[i] = artifact
	}
	digest, err := digestDir(profileDir)
	if err != nil {
		return nil, err
	}
	p.Path = profileRel
	p.InstructionsPath = filepath.ToSlash(filepath.Join(profileRel, "instructions.md"))
	p.Digest = digest
	return &p, nil
}

func validateArtifact(root, profileDir, profileRel string, idx int, artifact *Artifact) error {
	field := fmt.Sprintf("%s/profile.yaml:artifacts[%d].path", profileRel, idx)
	if err := validateRelativePath(field, artifact.Path); err != nil {
		return err
	}
	if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:artifacts[%d].kind", profileRel, idx), artifact.Kind); err != nil {
		return err
	}
	full := filepath.Join(profileDir, filepath.FromSlash(artifact.Path))
	if !isWithin(profileDir, full) {
		return fmt.Errorf("%s: escapes profile directory", field)
	}
	info, err := os.Lstat(full)
	if err != nil {
		return fmt.Errorf("%s: artifact does not exist", field)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed", field)
	}
	rel, _ := filepath.Rel(root, full)
	artifact.Path = filepath.ToSlash(rel)
	artifact.ProfileID = strings.TrimPrefix(profileRel, "profiles/")
	return nil
}

func validateSubscription(field string, sub Subscription) error {
	if strings.TrimSpace(sub.Event) == "" && strings.TrimSpace(sub.Type) == "" {
		return fmt.Errorf("%s.event: required", field)
	}
	for name, value := range map[string]string{"app": sub.App, "event": sub.Event, "type": sub.Type, "resource_ref": sub.ResourceRef} {
		if strings.TrimSpace(value) != "" && hasControl(value) {
			return fmt.Errorf("%s.%s: control characters are not allowed", field, name)
		}
	}
	return nil
}

func validateProfileRefID(field, value string) error {
	if err := validateRequiredString(field, value); err != nil {
		return err
	}
	if strings.ContainsAny(value, `/\\`) || strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || strings.Contains(value, "@") && strings.Contains(value, ":") {
		return fmt.Errorf("%s: profile_ref id must be a safe single path segment", field)
	}
	clean := filepath.Clean(value)
	if clean != value || clean == "." || clean == ".." || filepath.IsAbs(value) {
		return fmt.Errorf("%s: profile_ref id must be a safe single path segment", field)
	}
	return nil
}

func validateRefString(field, value string) error {
	if err := validateRequiredString(field, value); err != nil {
		return err
	}
	if strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || strings.Contains(value, "@") && strings.Contains(value, ":") {
		return fmt.Errorf("%s: host or scheme refs are not allowed", field)
	}
	return nil
}

func validateRequiredString(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: required", field)
	}
	if hasControl(value) {
		return fmt.Errorf("%s: control characters are not allowed", field)
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validateRelativePath(field string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%s: required", field)
	}
	if hasControl(value) {
		return fmt.Errorf("%s: control characters are not allowed", field)
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
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinks are not allowed in blueprints", relSlash)
		}
		for _, segment := range strings.Split(relSlash, "/") {
			if segment == ".aw" {
				return fmt.Errorf("%s: .aw runtime state is not allowed in blueprints", relSlash)
			}
		}
		base := strings.ToLower(d.Name())
		if d.IsDir() {
			if shouldSkipPayloadDir(base) {
				return filepath.SkipDir
			}
			if isGeneratedWorktreeDir(relSlash, base) {
				return fmt.Errorf("%s: generated worktrees are not allowed in blueprints", relSlash)
			}
			return nil
		}
		if unsafeFileName(base) {
			return fmt.Errorf("%s: identity material, credentials, tokens, secrets, or generated runtime state are not allowed", relSlash)
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

func shouldSkipPayloadDir(base string) bool {
	switch base {
	case ".git", ".hg", ".svn", "node_modules", ".cache", "dist", "build", "target", "tmp", "vendor", "__pycache__":
		return true
	default:
		return false
	}
}

func isGeneratedWorktreeDir(relSlash, base string) bool {
	return base == "worktrees" || base == "worktree" || base == "generated-worktrees" || (base == "work" && strings.Contains(relSlash, "instances/"))
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
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinks are not allowed in blueprints", path)
		}
		if d.IsDir() {
			if path != root && shouldSkipPayloadDir(strings.ToLower(d.Name())) {
				return filepath.SkipDir
			}
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

func appRequestAppName(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	for _, sep := range []string{".", ":", "/"} {
		if idx := strings.Index(ref, sep); idx > 0 {
			return ref[:idx]
		}
	}
	return ref
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
		key := artifact.ProfileID + "\x00" + artifact.Path + "\x00" + artifact.Kind
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

func blueprintName(bp *Blueprint) string    { return firstNonEmpty(bp.Display.Name, bp.Name) }
func blueprintSummary(bp *Blueprint) string { return firstNonEmpty(bp.Display.Summary, bp.Summary) }
func profileName(p Profile) string          { return firstNonEmpty(p.Display.Name, p.Name) }
func profileSummary(p Profile) string       { return firstNonEmpty(p.Display.Summary, p.Summary) }
