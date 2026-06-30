package blueprint

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/awebai/aw/awid"
	"github.com/mr-tron/base58"
	"gopkg.in/yaml.v3"
)

const DigestScopeLocalImportPayload = "local_import_payload"

type Source struct {
	Kind        string `json:"kind"`
	Ref         string `json:"ref"`
	Digest      string `json:"digest"`
	DigestScope string `json:"digest_scope"`
}

type Blueprint struct {
	SchemaVersion        int                     `json:"schema_version,omitempty" yaml:"schema_version"`
	ID                   string                  `json:"id" yaml:"id"`
	Name                 string                  `json:"name" yaml:"name"`
	Version              string                  `json:"version" yaml:"version"`
	Summary              string                  `json:"summary" yaml:"summary"`
	Description          string                  `json:"description" yaml:"description"`
	Profiles             []BlueprintProfileEntry `json:"profiles" yaml:"profiles"`
	RuntimeHints         []string                `json:"runtime_hints,omitempty" yaml:"runtime_hints"`
	ExpectedApps         []string                `json:"expected_apps,omitempty" yaml:"expected_apps"`
	FirstMissionExamples []string                `json:"first_mission_examples,omitempty" yaml:"first_mission_examples"`
	ReadmeLinks          []string                `json:"readme_links,omitempty" yaml:"readme_links"`
	CustomerReadmeLinks  []string                `json:"customer_readme_links,omitempty" yaml:"customer_readme_links"`
	Source               Source                  `json:"source" yaml:"-"`
	PayloadFiles         []string                `json:"payload_files" yaml:"-"`
	LoadedProfiles       []Profile               `json:"loaded_profiles" yaml:"-"`
	Missions             *Missions               `json:"missions,omitempty" yaml:"-"`
}

type BlueprintProfileEntry struct {
	ID           string   `json:"id" yaml:"id"`
	DefaultCount int      `json:"default_count,omitempty" yaml:"default_count"`
	Min          int      `json:"min,omitempty" yaml:"min"`
	Max          int      `json:"max,omitempty" yaml:"max"`
	RuntimeHints []string `json:"runtime_hints,omitempty" yaml:"runtime_hints"`
}

type Profile struct {
	SchemaVersion      int            `json:"schema_version,omitempty" yaml:"schema_version"`
	ID                 string         `json:"id" yaml:"id"`
	Name               string         `json:"name" yaml:"name"`
	Version            string         `json:"version" yaml:"version"`
	Mission            string         `json:"mission" yaml:"mission"`
	AcceptedWork       []string       `json:"accepted_work" yaml:"accepted_work"`
	Instructions       string         `json:"instructions" yaml:"instructions"`
	RuntimeAssumptions []string       `json:"runtime_assumptions" yaml:"runtime_assumptions"`
	Scope              string         `json:"scope,omitempty" yaml:"scope,omitempty"`
	MemoryPolicy       map[string]any `json:"memory_policy" yaml:"memory_policy"`
	ExpectedApps       []string       `json:"expected_apps,omitempty" yaml:"expected_apps"`
	EventSubscriptions []Subscription `json:"event_subscriptions,omitempty" yaml:"event_subscriptions"`
	ApprovalRequired   []string       `json:"approval_required,omitempty" yaml:"approval_required"`
	Artifacts          []PathResource `json:"artifacts,omitempty" yaml:"artifacts"`
	Skills             []PathResource `json:"skills,omitempty" yaml:"skills"`
	LearningHints      map[string]any `json:"learning_hints,omitempty" yaml:"learning_hints"`
	Path               string         `json:"path" yaml:"-"`
	Digest             string         `json:"digest" yaml:"-"`
	InstructionPath    string         `json:"instruction_path" yaml:"-"`
}

type Subscription struct {
	App         string         `json:"app,omitempty" yaml:"app"`
	Event       string         `json:"event" yaml:"event"`
	ResourceRef string         `json:"resource_ref,omitempty" yaml:"resource_ref"`
	Filter      map[string]any `json:"filter,omitempty" yaml:"filter"`
}

type PathResource struct {
	Path      string `json:"path" yaml:"path"`
	Kind      string `json:"kind,omitempty" yaml:"kind"`
	ProfileID string `json:"profile_id,omitempty" yaml:"-"`
}

type Missions struct {
	Missions []Mission `json:"missions" yaml:"missions"`
}

type Mission struct {
	ID      string `json:"id" yaml:"id"`
	Title   string `json:"title" yaml:"title"`
	Summary string `json:"summary,omitempty" yaml:"summary"`
}

type Plan struct {
	Source                 Source                 `json:"source"`
	Blueprint              BlueprintSummary       `json:"blueprint"`
	Profiles               []ProfileSummary       `json:"profiles"`
	ImportPreview          ImportPreview          `json:"import_preview"`
	MaterializationPreview MaterializationPreview `json:"materialization_preview"`
	FilesWouldWrite        []string               `json:"files_would_write"`
	CommandsWouldRun       []string               `json:"commands_would_run"`
	RequiredHumanDecisions []string               `json:"required_human_decisions"`
	OptionalNextSteps      []string               `json:"optional_next_steps"`
}

type BlueprintSummary struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	Summary               string   `json:"summary"`
	Description           string   `json:"description"`
	Digest                string   `json:"digest"`
	ExpectedApps          []string `json:"expected_apps,omitempty"`
	ExpectedAppsSemantics string   `json:"expected_apps_semantics,omitempty"`
	RuntimeHints          []string `json:"runtime_hints,omitempty"`
	FirstMissionExamples  []string `json:"first_mission_examples,omitempty"`
}

type ProfileSummary struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Version                string                 `json:"version"`
	Digest                 string                 `json:"digest"`
	DefaultCount           int                    `json:"default_count"`
	Min                    int                    `json:"min"`
	Max                    int                    `json:"max"`
	Mission                string                 `json:"mission"`
	AcceptedWork           []string               `json:"accepted_work"`
	RuntimeAssumptions     []string               `json:"runtime_assumptions"`
	Scope                  string                 `json:"scope,omitempty"`
	MemoryPolicy           map[string]any         `json:"memory_policy"`
	ExpectedApps           []string               `json:"expected_apps,omitempty"`
	ExpectedAppsSemantics  string                 `json:"expected_apps_semantics,omitempty"`
	EventSubscriptions     []Subscription         `json:"event_subscriptions,omitempty"`
	ApprovalRequired       []string               `json:"approval_required,omitempty"`
	MaterializationPreview ProfileMaterialization `json:"materialization_preview"`
}

type ProfileMaterialization struct {
	InstructionsPath string         `json:"instructions_path"`
	Skills           []PathResource `json:"skills,omitempty"`
	Artifacts        []PathResource `json:"artifacts,omitempty"`
}

type ImportPreview struct {
	OptionalLayer               bool     `json:"optional_layer"`
	RequiresLibrarySubscription bool     `json:"requires_library_subscription"`
	SeparateFutureStep          bool     `json:"separate_future_step"`
	LibraryEndpoint             string   `json:"library_endpoint"`
	WouldUploadOnImport         bool     `json:"would_upload_on_import"`
	PayloadDigest               string   `json:"payload_digest"`
	PayloadFiles                []string `json:"payload_files"`
}

type MaterializationPreview struct {
	OptionalLayer                         bool     `json:"optional_layer"`
	Target                                string   `json:"target"`
	SeparateFutureStep                    bool     `json:"separate_future_step"`
	WouldRecordAWProfileRefsOnMaterialize bool     `json:"would_record_aw_profile_refs_on_materialize"`
	WouldWriteOnInspect                   []string `json:"would_write_on_inspect"`
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
	raw, err := os.ReadFile(filepath.Join(abs, "blueprint.yaml"))
	if err != nil {
		return nil, fmt.Errorf("blueprint.yaml: %w", err)
	}
	var blueprint Blueprint
	if err := decodeKnownYAML(raw, &blueprint); err != nil {
		return nil, fmt.Errorf("blueprint.yaml: parse: %w", err)
	}
	if err := validateBlueprint(&blueprint); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "README.md")); err != nil {
		return nil, fmt.Errorf("README.md: required")
	}
	profiles := make([]Profile, 0, len(blueprint.Profiles))
	for _, entry := range blueprint.Profiles {
		profile, err := loadProfile(abs, entry)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, *profile)
	}
	if missions, err := loadOptionalMissions(abs); err != nil {
		return nil, err
	} else {
		blueprint.Missions = missions
	}
	digest, files, err := digestDir(abs)
	if err != nil {
		return nil, err
	}
	blueprint.Source = Source{Kind: "local_dir", Ref: abs, Digest: digest, DigestScope: DigestScopeLocalImportPayload}
	blueprint.PayloadFiles = files
	blueprint.LoadedProfiles = profiles
	return &blueprint, nil
}

func InspectPlan(bp *Blueprint) Plan {
	profilesByID := map[string]Profile{}
	for _, profile := range bp.LoadedProfiles {
		profilesByID[profile.ID] = profile
	}
	profileSummaries := make([]ProfileSummary, 0, len(bp.Profiles))
	for _, entry := range bp.Profiles {
		profile := profilesByID[entry.ID]
		count, min, max := normalizedCounts(entry)
		profileSummaries = append(profileSummaries, ProfileSummary{
			ID:                     profile.ID,
			Name:                   profile.Name,
			Version:                profile.Version,
			Digest:                 profile.Digest,
			DefaultCount:           count,
			Min:                    min,
			Max:                    max,
			Mission:                profile.Mission,
			AcceptedWork:           append([]string(nil), profile.AcceptedWork...),
			RuntimeAssumptions:     append([]string(nil), profile.RuntimeAssumptions...),
			Scope:                  strings.TrimSpace(profile.Scope),
			MemoryPolicy:           profile.MemoryPolicy,
			ExpectedApps:           sortedUnique(profile.ExpectedApps),
			ExpectedAppsSemantics:  expectedAppsSemantics(profile.ExpectedApps),
			EventSubscriptions:     append([]Subscription(nil), profile.EventSubscriptions...),
			ApprovalRequired:       sortedUnique(profile.ApprovalRequired),
			MaterializationPreview: ProfileMaterialization{InstructionsPath: profile.InstructionPath, Skills: dedupeResources(profile.Skills), Artifacts: dedupeResources(profile.Artifacts)},
		})
	}
	return Plan{
		Source: bp.Source,
		Blueprint: BlueprintSummary{
			ID:                    bp.ID,
			Name:                  bp.Name,
			Version:               bp.Version,
			Summary:               bp.Summary,
			Description:           bp.Description,
			Digest:                bp.Source.Digest,
			ExpectedApps:          sortedUnique(bp.ExpectedApps),
			ExpectedAppsSemantics: expectedAppsSemantics(bp.ExpectedApps),
			RuntimeHints:          sortedUnique(bp.RuntimeHints),
			FirstMissionExamples:  append([]string(nil), bp.FirstMissionExamples...),
		},
		Profiles:               profileSummaries,
		ImportPreview:          ImportPreview{OptionalLayer: true, RequiresLibrarySubscription: true, SeparateFutureStep: true, LibraryEndpoint: "POST /v1/blueprints/import", WouldUploadOnImport: true, PayloadDigest: bp.Source.Digest, PayloadFiles: append([]string(nil), bp.PayloadFiles...)},
		MaterializationPreview: MaterializationPreview{OptionalLayer: true, Target: "local_home", SeparateFutureStep: true, WouldRecordAWProfileRefsOnMaterialize: true, WouldWriteOnInspect: []string{}},
		FilesWouldWrite:        []string{},
		CommandsWouldRun:       []string{},
		RequiredHumanDecisions: []string{},
		OptionalNextSteps:      []string{"continue with empty profiles (no Library subscription required)", "select profiles/counts from this blueprint", "optionally import blueprint to Library when the Library contract is available", "optionally bind agent identities to Library profile refs", "optionally materialize selected profiles into local homes"},
	}
}

func (p Plan) JSON() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

func CanonicalImportPayload(dir string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	_, files, err := canonicalPayloadDigest(abs, "aweb.blueprint.import-payload.v1")
	if err != nil {
		return nil, err
	}
	return canonicalJSON(map[string]any{
		"schema": "aweb.blueprint.import-payload.v1",
		"files":  files,
	})
}

func loadProfile(root string, entry BlueprintProfileEntry) (*Profile, error) {
	profileRel := filepath.ToSlash(filepath.Join("profiles", entry.ID))
	profileDir := filepath.Join(root, filepath.FromSlash(profileRel))
	if !isWithin(filepath.Join(root, "profiles"), profileDir) {
		return nil, fmt.Errorf("blueprint.yaml:profiles.%s: resolves outside profiles directory", entry.ID)
	}
	raw, err := os.ReadFile(filepath.Join(profileDir, "profile.yaml"))
	if err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: %w", profileRel, err)
	}
	var profile Profile
	if err := decodeKnownYAML(raw, &profile); err != nil {
		return nil, fmt.Errorf("%s/profile.yaml: parse: %w", profileRel, err)
	}
	if err := validateProfile(root, profileDir, profileRel, entry, &profile); err != nil {
		return nil, err
	}
	digest, _, err := canonicalPayloadDigest(profileDir, "aweb.blueprint.profile-payload.v1")
	if err != nil {
		return nil, err
	}
	profile.Path = profileRel
	profile.Digest = digest
	return &profile, nil
}

func loadOptionalMissions(root string) (*Missions, error) {
	path := filepath.Join(root, "missions.yaml")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("missions.yaml: %w", err)
	}
	var missions Missions
	if err := decodeKnownYAML(raw, &missions); err != nil {
		return nil, fmt.Errorf("missions.yaml: parse: %w", err)
	}
	for i, mission := range missions.Missions {
		prefix := fmt.Sprintf("missions.yaml:missions[%d]", i)
		if err := validateRefString(prefix+".id", mission.ID); err != nil {
			return nil, err
		}
		if err := validateRequiredString(prefix+".title", mission.Title); err != nil {
			return nil, err
		}
		if strings.TrimSpace(mission.Summary) != "" && hasDisallowedTextControl(mission.Summary) {
			return nil, fmt.Errorf("%s.summary: control characters are not allowed", prefix)
		}
	}
	return &missions, nil
}

func validateBlueprint(bp *Blueprint) error {
	if bp.SchemaVersion != 0 && bp.SchemaVersion != 1 {
		return fmt.Errorf("blueprint.yaml:schema_version: expected 1")
	}
	for field, value := range map[string]string{"id": bp.ID, "name": bp.Name, "version": bp.Version} {
		if err := validateRequiredString("blueprint.yaml:"+field, value); err != nil {
			return err
		}
	}
	for field, value := range map[string]string{"summary": bp.Summary, "description": bp.Description} {
		if err := validateRequiredFreeTextString("blueprint.yaml:"+field, value); err != nil {
			return err
		}
	}
	if err := validateRefString("blueprint.yaml:id", bp.ID); err != nil {
		return err
	}
	if len(bp.Profiles) == 0 {
		return fmt.Errorf("blueprint.yaml:profiles: at least one profile is required")
	}
	seen := map[string]bool{}
	for i, profile := range bp.Profiles {
		prefix := fmt.Sprintf("blueprint.yaml:profiles[%d]", i)
		if err := validateProfileID(prefix+".id", profile.ID); err != nil {
			return err
		}
		if seen[profile.ID] {
			return fmt.Errorf("%s.id: duplicate %q", prefix, profile.ID)
		}
		seen[profile.ID] = true
		if err := validateCounts(prefix, profile); err != nil {
			return err
		}
		for j, hint := range profile.RuntimeHints {
			if err := validateRequiredString(fmt.Sprintf("%s.runtime_hints[%d]", prefix, j), hint); err != nil {
				return err
			}
		}
	}
	for i, hint := range bp.RuntimeHints {
		if err := validateRequiredString(fmt.Sprintf("blueprint.yaml:runtime_hints[%d]", i), hint); err != nil {
			return err
		}
	}
	for i, app := range bp.ExpectedApps {
		if err := validateRefString(fmt.Sprintf("blueprint.yaml:expected_apps[%d]", i), app); err != nil {
			return err
		}
	}
	for i, example := range bp.FirstMissionExamples {
		if err := validateRequiredFreeTextString(fmt.Sprintf("blueprint.yaml:first_mission_examples[%d]", i), example); err != nil {
			return err
		}
	}
	for i, link := range append(append([]string{}, bp.ReadmeLinks...), bp.CustomerReadmeLinks...) {
		if err := validateRequiredString(fmt.Sprintf("blueprint.yaml:readme_links[%d]", i), link); err != nil {
			return err
		}
	}
	return nil
}

func validateProfile(root, profileDir, profileRel string, entry BlueprintProfileEntry, profile *Profile) error {
	if profile.SchemaVersion != 0 && profile.SchemaVersion != 1 {
		return fmt.Errorf("%s/profile.yaml:schema_version: expected 1", profileRel)
	}
	for field, value := range map[string]string{"id": profile.ID, "name": profile.Name, "version": profile.Version, "instructions": profile.Instructions} {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:%s", profileRel, field), value); err != nil {
			return err
		}
	}
	if err := validateRequiredFreeTextString(fmt.Sprintf("%s/profile.yaml:mission", profileRel), profile.Mission); err != nil {
		return err
	}
	if profile.ID != entry.ID {
		return fmt.Errorf("%s/profile.yaml:id: got %q, want blueprint profile id %q", profileRel, profile.ID, entry.ID)
	}
	if len(profile.AcceptedWork) == 0 {
		return fmt.Errorf("%s/profile.yaml:accepted_work: at least one item is required", profileRel)
	}
	for i, work := range profile.AcceptedWork {
		if err := validateRequiredFreeTextString(fmt.Sprintf("%s/profile.yaml:accepted_work[%d]", profileRel, i), work); err != nil {
			return err
		}
	}
	if len(profile.RuntimeAssumptions) == 0 {
		return fmt.Errorf("%s/profile.yaml:runtime_assumptions: at least one item is required", profileRel)
	}
	for i, assumption := range profile.RuntimeAssumptions {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:runtime_assumptions[%d]", profileRel, i), assumption); err != nil {
			return err
		}
	}
	if scope := strings.TrimSpace(profile.Scope); scope != "" && scope != "local" && scope != "global" {
		return fmt.Errorf("%s/profile.yaml:scope: expected local or global", profileRel)
	}
	if err := validateMemoryPolicy(fmt.Sprintf("%s/profile.yaml:memory_policy", profileRel), profile.MemoryPolicy); err != nil {
		return err
	}
	if err := validateRelativePath(fmt.Sprintf("%s/profile.yaml:instructions", profileRel), profile.Instructions); err != nil {
		return err
	}
	instructionFull := filepath.Join(profileDir, filepath.FromSlash(profile.Instructions))
	if !isWithin(profileDir, instructionFull) {
		return fmt.Errorf("%s/profile.yaml:instructions: escapes profile directory", profileRel)
	}
	if err := requireRegularFile(instructionFull, fmt.Sprintf("%s/profile.yaml:instructions", profileRel)); err != nil {
		return err
	}
	rel, _ := filepath.Rel(root, instructionFull)
	profile.InstructionPath = filepath.ToSlash(rel)
	for i, app := range profile.ExpectedApps {
		if err := validateRefString(fmt.Sprintf("%s/profile.yaml:expected_apps[%d]", profileRel, i), app); err != nil {
			return err
		}
	}
	for i, sub := range profile.EventSubscriptions {
		if err := validateSubscription(fmt.Sprintf("%s/profile.yaml:event_subscriptions[%d]", profileRel, i), sub); err != nil {
			return err
		}
	}
	for i, approval := range profile.ApprovalRequired {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:approval_required[%d]", profileRel, i), approval); err != nil {
			return err
		}
	}
	for i := range profile.Artifacts {
		if err := validateResource(root, profileDir, profileRel, "artifacts", i, &profile.Artifacts[i]); err != nil {
			return err
		}
	}
	for i := range profile.Skills {
		if err := validateResource(root, profileDir, profileRel, "skills", i, &profile.Skills[i]); err != nil {
			return err
		}
	}
	return nil
}

func validateCounts(prefix string, profile BlueprintProfileEntry) error {
	if profile.DefaultCount < 0 || profile.Min < 0 || profile.Max < 0 {
		return fmt.Errorf("%s: counts and ranges must be non-negative", prefix)
	}
	count, min, max := normalizedCounts(profile)
	if min > count || count > max {
		return fmt.Errorf("%s: require min <= default_count <= max", prefix)
	}
	return nil
}

func normalizedCounts(profile BlueprintProfileEntry) (int, int, int) {
	count := profile.DefaultCount
	if count == 0 {
		count = 1
	}
	min := profile.Min
	max := profile.Max
	if max == 0 {
		max = count
	}
	return count, min, max
}

func validateSubscription(field string, sub Subscription) error {
	if err := validateRefString(field+".app", sub.App); err != nil {
		return err
	}
	if err := validateRequiredString(field+".event", sub.Event); err != nil {
		return err
	}
	if strings.TrimSpace(sub.ResourceRef) != "" && hasControl(sub.ResourceRef) {
		return fmt.Errorf("%s.resource_ref: control characters are not allowed", field)
	}
	return nil
}

func validateResource(root, profileDir, profileRel, field string, idx int, resource *PathResource) error {
	prefix := fmt.Sprintf("%s/profile.yaml:%s[%d]", profileRel, field, idx)
	if err := validateRelativePath(prefix+".path", resource.Path); err != nil {
		return err
	}
	if strings.TrimSpace(resource.Kind) != "" {
		if err := validateRequiredString(prefix+".kind", resource.Kind); err != nil {
			return err
		}
	}
	full := filepath.Join(profileDir, filepath.FromSlash(resource.Path))
	if !isWithin(profileDir, full) {
		return fmt.Errorf("%s.path: escapes profile directory", prefix)
	}
	if err := requireRegularFile(full, prefix+".path"); err != nil {
		return err
	}
	rel, _ := filepath.Rel(root, full)
	resource.Path = filepath.ToSlash(rel)
	resource.ProfileID = strings.TrimPrefix(profileRel, "profiles/")
	return nil
}

func requireRegularFile(path, field string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: file does not exist", field)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed", field)
	}
	if info.IsDir() {
		return fmt.Errorf("%s: must be a file", field)
	}
	return nil
}

func decodeKnownYAML(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode(out)
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
			if isGeneratedRuntimeDir(relSlash, base) {
				return fmt.Errorf("%s: generated worktrees or runtime state are not allowed in blueprints", relSlash)
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

func isGeneratedRuntimeDir(relSlash, base string) bool {
	return base == "worktrees" || base == "worktree" || base == "generated-worktrees" || base == "runtime" || (base == "work" && strings.Contains(relSlash, "instances/"))
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

var (
	privateKeyPEMRe        = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	didKeyCandidateRe      = regexp.MustCompile(`\bdid:key:z[1-9A-HJ-NP-Za-km-z]+\b`)
	didAWCandidateRe       = regexp.MustCompile(`\bdid:aw:([1-9A-HJ-NP-Za-km-z]{20,})\b`)
	credentialAssignmentRe = regexp.MustCompile(`(?i)(?:\b|["'])(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|password|team[_-]?certificate|token|secret)(?:\b|["'])\s*[:=]\s*["']?([^\s"'<>]{4,})`)
	// A credential key opening a YAML block scalar (key: | or key: >, with optional
	// indent/chomp modifiers and a trailing comment). The value is on the indented
	// lines that follow; hasBlockScalarCredentialAssignment walks those lines.
	blockScalarHeaderRe = regexp.MustCompile(`(?i)^[ \t]*["']?(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret[_-]?key|client[_-]?secret|password|team[_-]?certificate|token|secret)["']?[ \t]*[:=][ \t]*[|>][0-9+-]*[ \t]*(?:#.*)?$`)
	// Well-known secret token shapes (distinctive prefixes with no English-word
	// overlap): aweb keys, GitHub tokens, Slack, Stripe. Used to catch a secret
	// that is not the leading token on a block-scalar line, where the prose-safe
	// leading-token rule does not reach - without the prose false positives a
	// broad entropy scan would cause. PEM private keys are already caught by
	// privateKeyPEMRe across the whole content.
	knownSecretTokenRe      = regexp.MustCompile(`(?i)^(?:aw_sk_|gh[oprsu]_|github_pat_|xox[abprs]-|sk_(?:live|test)_)[A-Za-z0-9_-]{6,}`)
	teamCertificateHeaderRe = regexp.MustCompile(`(?i)(?:\b|["'])x-awid-team-certificate(?:\b|["'])\s*:\s*["']?[A-Za-z0-9+/=_-]{8,}\b`)
	jwtCandidateRe          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	// Base64/base64url key blobs may start or end with non-word alphabet chars
	// such as + or /. Do not use \b: it misses those edge cases. Instead require
	// string edges or explicit non-base64 delimiters and capture only the token.
	longBase64BlobRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/=_-])([A-Za-z0-9+/=_-]{64,})(?:[^A-Za-z0-9+/=_-]|$)`)
)

func unsafeContent(s string) bool {
	if privateKeyPEMRe.MatchString(s) || hasCredentialAssignment(s) || hasBlockScalarCredentialAssignment(s) || teamCertificateHeaderRe.MatchString(s) || jwtCandidateRe.MatchString(s) || hasLongBase64Blob(s) {
		return true
	}
	for _, candidate := range didKeyCandidateRe.FindAllString(s, -1) {
		if _, err := awid.ExtractPublicKey(candidate); err == nil {
			return true
		}
	}
	for _, match := range didAWCandidateRe.FindAllStringSubmatch(s, -1) {
		if len(match) < 2 {
			continue
		}
		decoded, err := base58.Decode(match[1])
		if err == nil && len(decoded) == 20 {
			return true
		}
	}
	return false
}

func hasCredentialAssignment(s string) bool {
	for _, m := range credentialAssignmentRe.FindAllStringSubmatch(s, -1) {
		if len(m) >= 3 && credentialAssignmentIsMaterial(m[1], m[2]) {
			return true
		}
	}
	return false
}

// hasBlockScalarCredentialAssignment catches a credential whose value is a YAML
// block scalar (key: | or key: >), which the inline credentialAssignmentRe misses
// because its value match stops at the block indicator. It walks EVERY indented
// line of the block (to a dedent or EOF), not just the first, so a placeholder or
// prose line followed by a real secret line cannot smuggle it past. Each line's
// leading token is extracted like an inline value (quote-stripped, placeholder
// excluded) and run through the same credentialAssignmentIsMaterial rules, so a
// quoted secret or a secret with trailing text is caught while a placeholder or
// bare-keyword prose word passes. A secret that is a non-leading token (a bullet-
// or comment-style line) is caught by knownSecretTokenRe shape, which the
// leading-token rule does not reach and which a prose-FP-prone entropy scan would
// not be safe for.
func hasBlockScalarCredentialAssignment(s string) bool {
	// Normalize line endings first: a CRLF/CR file would otherwise leave a \r on
	// each line and defeat the per-line header anchors - an easy evasion.
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, header := range lines {
		m := blockScalarHeaderRe.FindStringSubmatch(header)
		if m == nil {
			continue
		}
		key := m[1]
		keyIndent := len(header) - len(strings.TrimLeft(header, " \t"))
		for _, body := range lines[i+1:] {
			trimmed := strings.TrimLeft(body, " \t")
			if trimmed == "" {
				continue // blank lines stay within the block scalar
			}
			if len(body)-len(trimmed) <= keyIndent {
				break // a dedent to the key's level or shallower ends the block
			}
			// Classify the line's leading token the same way the inline path
			// handles a value (quote-stripped, placeholder excluded). The key's
			// confidence does the prose/secret discrimination - a high-confidence
			// key flags any leading token; a bare token/secret needs entropy - so a
			// quoted secret, or a secret with trailing text, is caught while a
			// placeholder or a bare-keyword prose word still passes.
			fields := strings.Fields(trimmed)
			if len(fields) == 0 {
				continue
			}
			if v := leadingCredentialValue(fields[0]); v != "" && credentialAssignmentIsMaterial(key, v) {
				return true
			}
			// A known-shape secret can also hide as a non-leading token (a bullet-
			// or comment-style line); catch those by shape, which the prose-safe
			// leading-token rule above does not reach.
			for _, f := range fields {
				if knownSecretTokenRe.MatchString(leadingCredentialValue(f)) {
					return true
				}
			}
		}
	}
	return false
}

// leadingCredentialValue extracts the credential-candidate value from a token the
// same way the inline path does: it strips one optional surrounding quote (inline
// allows ["']?value) and takes the leading run before any remaining quote or
// angle bracket. A <...> placeholder starts with an angle bracket, so it yields
// "", as does a run too short to be material.
func leadingCredentialValue(tok string) string {
	if len(tok) > 0 && (tok[0] == '"' || tok[0] == '\'') {
		tok = tok[1:]
	}
	if i := strings.IndexAny(tok, `"'<>`); i >= 0 {
		tok = tok[:i]
	}
	if len(tok) < 4 {
		return ""
	}
	return tok
}

// credentialAssignmentIsMaterial decides whether a `<key>: <value>` match is a
// real credential or documentation prose, after stripping trailing prose
// punctuation ("secret: none." -> "none"). High-confidence keys (api_key,
// access_token, secret_key, client_secret, password, team_certificate, ...) are
// material for ANY value - an all-lowercase api_key/password value is still a
// leaked credential. Only the generic bare keys that genuinely appear in prose
// (bare "token", bare "secret") get the prose exception: they are material only
// when the value carries entropy (a digit, uppercase, or structural char), so
// "token: bearer", "secret: none", "token: false" pass while
// token=secret_token_value is still caught.
func credentialAssignmentIsMaterial(key, value string) bool {
	value = strings.TrimRight(value, `.,;:!?)]}`)
	if len(value) < 4 {
		return false
	}
	if !isProseAmbiguousCredentialKey(key) {
		return true
	}
	return credentialValueHasEntropy(value)
}

// isProseAmbiguousCredentialKey reports the bare keys generic enough to occur in
// natural prose (bare "token", bare "secret"); every other credential key
// (api_key, access_token, secret_key, client_secret, password, team_certificate)
// is high-confidence and flagged for any value.
func isProseAmbiguousCredentialKey(key string) bool {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key)) {
	case "token", "secret":
		return true
	default:
		return false
	}
}

func credentialValueHasEntropy(value string) bool {
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return true
		}
	}
	return false
}

func hasLongBase64Blob(s string) bool {
	for _, match := range longBase64BlobRe.FindAllStringSubmatch(s, -1) {
		if len(match) < 2 {
			continue
		}
		if decodesAsMaterialBase64(match[1]) {
			return true
		}
	}
	return false
}

func decodesAsMaterialBase64(candidate string) bool {
	candidate = strings.Trim(candidate, "'\"`.,;:()[]{}")
	if len(candidate) < 64 || !hasMixedBase64TokenShape(candidate) {
		return false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		padded := candidate
		if rem := len(padded) % 4; rem != 0 {
			padded += strings.Repeat("=", 4-rem)
		}
		decoded, err := enc.DecodeString(padded)
		if err == nil && len(decoded) >= 48 && parsesAsKeyOrCertificateMaterial(decoded) {
			return true
		}
	}
	return false
}

func parsesAsKeyOrCertificateMaterial(decoded []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(decoded); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(decoded); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(decoded); err == nil {
		return true
	}
	if _, err := x509.ParsePKIXPublicKey(decoded); err == nil {
		return true
	}
	if _, err := x509.ParseCertificate(decoded); err == nil {
		return true
	}
	if certs, err := x509.ParseCertificates(decoded); err == nil && len(certs) > 0 {
		return true
	}
	return false
}

func hasMixedBase64TokenShape(candidate string) bool {
	var hasLower, hasUpper, hasDigit bool
	for _, r := range candidate {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '/' || r == '_' || r == '-' || r == '=':
			// base64/base64url alphabet
		default:
			return false
		}
	}
	return hasLower && hasUpper && hasDigit
}

func digestDir(root string) (string, []string, error) {
	digest, files, err := canonicalPayloadDigest(root, "aweb.blueprint.import-payload.v1")
	if err != nil {
		return "", nil, err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return digest, paths, nil
}

type canonicalPayloadFile struct {
	ContentUTF8 string `json:"content_utf8"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
}

func canonicalPayloadDigest(root string, schema string) (string, []canonicalPayloadFile, error) {
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
		return "", nil, err
	}
	sort.Strings(paths)
	files := make([]canonicalPayloadFile, 0, len(paths))
	for _, path := range paths {
		rel, _ := filepath.Rel(root, path)
		relSlash := filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", nil, err
		}
		if !utf8.Valid(data) {
			return "", nil, fmt.Errorf("%s: blueprint canonical import payload requires UTF-8 text", relSlash)
		}
		fileHash := sha256.Sum256(data)
		files = append(files, canonicalPayloadFile{Path: relSlash, SHA256: "sha256:" + hex.EncodeToString(fileHash[:]), ContentUTF8: string(data)})
	}
	canonical, err := canonicalJSON(map[string]any{"schema": schema, "files": files})
	if err != nil {
		return "", nil, err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), files, nil
}

func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func validateProfileID(field, value string) error {
	if err := validateRequiredString(field, value); err != nil {
		return err
	}
	if strings.ContainsAny(value, `/\\`) || strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || strings.Contains(value, "@") && strings.Contains(value, ":") {
		return fmt.Errorf("%s: profile id must be a safe single path segment", field)
	}
	clean := filepath.Clean(value)
	if clean != value || clean == "." || clean == ".." || filepath.IsAbs(value) {
		return fmt.Errorf("%s: profile id must be a safe single path segment", field)
	}
	return nil
}

func validateMemoryPolicy(field string, policy map[string]any) error {
	if len(policy) == 0 {
		return fmt.Errorf("%s: required", field)
	}
	mode, err := requiredStringMapValue(field, policy, "mode")
	if err != nil {
		return err
	}
	if err := validateRequiredString(field+".mode", mode); err != nil {
		return err
	}
	proposalTarget, err := requiredStringMapValue(field, policy, "proposal_target")
	if err != nil {
		return err
	}
	if err := validateRefString(field+".proposal_target", proposalTarget); err != nil {
		return err
	}
	return nil
}

func requiredStringMapValue(field string, values map[string]any, key string) (string, error) {
	value, ok := values[key]
	if !ok {
		return "", fmt.Errorf("%s.%s: required", field, key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s.%s: must be a string", field, key)
	}
	return text, nil
}

func validateRelativePath(field, value string) error {
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

func validateRequiredFreeTextString(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s: required", field)
	}
	if hasDisallowedTextControl(value) {
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

func hasDisallowedTextControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return true
		}
	}
	return false
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func expectedAppsSemantics(apps []string) string {
	if len(apps) == 0 {
		return ""
	}
	return "setup_hints_not_grants"
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func dedupeResources(in []PathResource) []PathResource {
	seen := map[string]PathResource{}
	keys := []string{}
	for _, resource := range in {
		key := resource.ProfileID + "\x00" + resource.Path + "\x00" + resource.Kind
		if _, ok := seen[key]; !ok {
			seen[key] = resource
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := make([]PathResource, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}
