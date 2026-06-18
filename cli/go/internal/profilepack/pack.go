package profilepack

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
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const DigestScopeLocalImportPayload = "local_import_payload"

type Source struct {
	Kind        string `json:"kind"`
	Ref         string `json:"ref"`
	Digest      string `json:"digest"`
	DigestScope string `json:"digest_scope"`
}

type Pack struct {
	SchemaVersion        int                `json:"schema_version,omitempty" yaml:"schema_version"`
	ID                   string             `json:"id" yaml:"id"`
	Name                 string             `json:"name" yaml:"name"`
	Version              string             `json:"version" yaml:"version"`
	Summary              string             `json:"summary" yaml:"summary"`
	Description          string             `json:"description" yaml:"description"`
	Profiles             []PackProfileEntry `json:"profiles" yaml:"profiles"`
	RuntimeHints         []string           `json:"runtime_hints,omitempty" yaml:"runtime_hints"`
	ExpectedApps         []string           `json:"expected_apps,omitempty" yaml:"expected_apps"`
	FirstMissionExamples []string           `json:"first_mission_examples,omitempty" yaml:"first_mission_examples"`
	ReadmeLinks          []string           `json:"readme_links,omitempty" yaml:"readme_links"`
	CustomerReadmeLinks  []string           `json:"customer_readme_links,omitempty" yaml:"customer_readme_links"`
	Source               Source             `json:"source" yaml:"-"`
	PayloadFiles         []string           `json:"payload_files" yaml:"-"`
	LoadedProfiles       []Profile          `json:"loaded_profiles" yaml:"-"`
	Missions             *Missions          `json:"missions,omitempty" yaml:"-"`
}

type PackProfileEntry struct {
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
	ProfilePack            ProfilePackSummary     `json:"profile_pack"`
	Profiles               []ProfileSummary       `json:"profiles"`
	ImportPreview          ImportPreview          `json:"import_preview"`
	MaterializationPreview MaterializationPreview `json:"materialization_preview"`
	FilesWouldWrite        []string               `json:"files_would_write"`
	CommandsWouldRun       []string               `json:"commands_would_run"`
	RequiredHumanDecisions []string               `json:"required_human_decisions"`
	OptionalNextSteps      []string               `json:"optional_next_steps"`
}

type ProfilePackSummary struct {
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

func LoadLocalDir(dir string) (*Pack, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("profile-pack source %s is not a directory", dir)
	}
	if err := scanUnsafeSource(abs); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(abs, "pack.yaml"))
	if err != nil {
		return nil, fmt.Errorf("pack.yaml: %w", err)
	}
	var pack Pack
	if err := decodeKnownYAML(raw, &pack); err != nil {
		return nil, fmt.Errorf("pack.yaml: parse: %w", err)
	}
	if err := validatePack(&pack); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "README.md")); err != nil {
		return nil, fmt.Errorf("README.md: required")
	}
	profiles := make([]Profile, 0, len(pack.Profiles))
	for _, entry := range pack.Profiles {
		profile, err := loadProfile(abs, entry)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, *profile)
	}
	if missions, err := loadOptionalMissions(abs); err != nil {
		return nil, err
	} else {
		pack.Missions = missions
	}
	digest, files, err := digestDir(abs)
	if err != nil {
		return nil, err
	}
	pack.Source = Source{Kind: "local_dir", Ref: abs, Digest: digest, DigestScope: DigestScopeLocalImportPayload}
	pack.PayloadFiles = files
	pack.LoadedProfiles = profiles
	return &pack, nil
}

func InspectPlan(pack *Pack) Plan {
	profilesByID := map[string]Profile{}
	for _, profile := range pack.LoadedProfiles {
		profilesByID[profile.ID] = profile
	}
	profileSummaries := make([]ProfileSummary, 0, len(pack.Profiles))
	for _, entry := range pack.Profiles {
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
			MemoryPolicy:           profile.MemoryPolicy,
			ExpectedApps:           sortedUnique(profile.ExpectedApps),
			ExpectedAppsSemantics:  expectedAppsSemantics(profile.ExpectedApps),
			EventSubscriptions:     append([]Subscription(nil), profile.EventSubscriptions...),
			ApprovalRequired:       sortedUnique(profile.ApprovalRequired),
			MaterializationPreview: ProfileMaterialization{InstructionsPath: profile.InstructionPath, Skills: dedupeResources(profile.Skills), Artifacts: dedupeResources(profile.Artifacts)},
		})
	}
	return Plan{
		Source: pack.Source,
		ProfilePack: ProfilePackSummary{
			ID:                    pack.ID,
			Name:                  pack.Name,
			Version:               pack.Version,
			Summary:               pack.Summary,
			Description:           pack.Description,
			Digest:                pack.Source.Digest,
			ExpectedApps:          sortedUnique(pack.ExpectedApps),
			ExpectedAppsSemantics: expectedAppsSemantics(pack.ExpectedApps),
			RuntimeHints:          sortedUnique(pack.RuntimeHints),
			FirstMissionExamples:  append([]string(nil), pack.FirstMissionExamples...),
		},
		Profiles:               profileSummaries,
		ImportPreview:          ImportPreview{OptionalLayer: true, RequiresLibrarySubscription: true, SeparateFutureStep: true, LibraryEndpoint: "POST /v1/profile-packs/import", WouldUploadOnImport: true, PayloadDigest: pack.Source.Digest, PayloadFiles: append([]string(nil), pack.PayloadFiles...)},
		MaterializationPreview: MaterializationPreview{OptionalLayer: true, Target: "local_home", SeparateFutureStep: true, WouldRecordAWProfileRefsOnMaterialize: true, WouldWriteOnInspect: []string{}},
		FilesWouldWrite:        []string{},
		CommandsWouldRun:       []string{},
		RequiredHumanDecisions: []string{},
		OptionalNextSteps:      []string{"continue with empty profiles (no Library subscription required)", "select profiles/counts from this pack", "optionally import pack to Library when the Library contract is available", "optionally bind agent identities to Library profile refs", "optionally materialize selected profiles into local homes"},
	}
}

func (p Plan) JSON() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

func CanonicalImportPayload(dir string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	_, files, err := canonicalPayloadDigest(abs, "aweb.profile-pack.import-payload.v1")
	if err != nil {
		return nil, err
	}
	return canonicalJSON(map[string]any{
		"schema": "aweb.profile-pack.import-payload.v1",
		"files":  files,
	})
}

func loadProfile(root string, entry PackProfileEntry) (*Profile, error) {
	profileRel := filepath.ToSlash(filepath.Join("profiles", entry.ID))
	profileDir := filepath.Join(root, filepath.FromSlash(profileRel))
	if !isWithin(filepath.Join(root, "profiles"), profileDir) {
		return nil, fmt.Errorf("pack.yaml:profiles.%s: resolves outside profiles directory", entry.ID)
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
	digest, _, err := canonicalPayloadDigest(profileDir, "aweb.profile-pack.profile-payload.v1")
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
		if strings.TrimSpace(mission.Summary) != "" && hasControl(mission.Summary) {
			return nil, fmt.Errorf("%s.summary: control characters are not allowed", prefix)
		}
	}
	return &missions, nil
}

func validatePack(pack *Pack) error {
	if pack.SchemaVersion != 0 && pack.SchemaVersion != 1 {
		return fmt.Errorf("pack.yaml:schema_version: expected 1")
	}
	for field, value := range map[string]string{"id": pack.ID, "name": pack.Name, "version": pack.Version, "summary": pack.Summary, "description": pack.Description} {
		if err := validateRequiredString("pack.yaml:"+field, value); err != nil {
			return err
		}
	}
	if err := validateRefString("pack.yaml:id", pack.ID); err != nil {
		return err
	}
	if len(pack.Profiles) == 0 {
		return fmt.Errorf("pack.yaml:profiles: at least one profile is required")
	}
	seen := map[string]bool{}
	for i, profile := range pack.Profiles {
		prefix := fmt.Sprintf("pack.yaml:profiles[%d]", i)
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
	for i, hint := range pack.RuntimeHints {
		if err := validateRequiredString(fmt.Sprintf("pack.yaml:runtime_hints[%d]", i), hint); err != nil {
			return err
		}
	}
	for i, app := range pack.ExpectedApps {
		if err := validateRefString(fmt.Sprintf("pack.yaml:expected_apps[%d]", i), app); err != nil {
			return err
		}
	}
	for i, example := range pack.FirstMissionExamples {
		if err := validateRequiredString(fmt.Sprintf("pack.yaml:first_mission_examples[%d]", i), example); err != nil {
			return err
		}
	}
	for i, link := range append(append([]string{}, pack.ReadmeLinks...), pack.CustomerReadmeLinks...) {
		if err := validateRequiredString(fmt.Sprintf("pack.yaml:readme_links[%d]", i), link); err != nil {
			return err
		}
	}
	return nil
}

func validateProfile(root, profileDir, profileRel string, entry PackProfileEntry, profile *Profile) error {
	if profile.SchemaVersion != 0 && profile.SchemaVersion != 1 {
		return fmt.Errorf("%s/profile.yaml:schema_version: expected 1", profileRel)
	}
	for field, value := range map[string]string{"id": profile.ID, "name": profile.Name, "version": profile.Version, "mission": profile.Mission, "instructions": profile.Instructions} {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:%s", profileRel, field), value); err != nil {
			return err
		}
	}
	if profile.ID != entry.ID {
		return fmt.Errorf("%s/profile.yaml:id: got %q, want pack profile id %q", profileRel, profile.ID, entry.ID)
	}
	if len(profile.AcceptedWork) == 0 {
		return fmt.Errorf("%s/profile.yaml:accepted_work: at least one item is required", profileRel)
	}
	for i, work := range profile.AcceptedWork {
		if err := validateRequiredString(fmt.Sprintf("%s/profile.yaml:accepted_work[%d]", profileRel, i), work); err != nil {
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
	if len(profile.MemoryPolicy) == 0 {
		return fmt.Errorf("%s/profile.yaml:memory_policy: required", profileRel)
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

func validateCounts(prefix string, profile PackProfileEntry) error {
	if profile.DefaultCount < 0 || profile.Min < 0 || profile.Max < 0 {
		return fmt.Errorf("%s: counts and ranges must be non-negative", prefix)
	}
	count, min, max := normalizedCounts(profile)
	if min > count || count > max {
		return fmt.Errorf("%s: require min <= default_count <= max", prefix)
	}
	return nil
}

func normalizedCounts(profile PackProfileEntry) (int, int, int) {
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
			return fmt.Errorf("%s: symlinks are not allowed in profile packs", relSlash)
		}
		for _, segment := range strings.Split(relSlash, "/") {
			if segment == ".aw" {
				return fmt.Errorf("%s: .aw runtime state is not allowed in profile packs", relSlash)
			}
		}
		base := strings.ToLower(d.Name())
		if d.IsDir() {
			if shouldSkipPayloadDir(base) {
				return filepath.SkipDir
			}
			if isGeneratedRuntimeDir(relSlash, base) {
				return fmt.Errorf("%s: generated worktrees or runtime state are not allowed in profile packs", relSlash)
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

func digestDir(root string) (string, []string, error) {
	digest, files, err := canonicalPayloadDigest(root, "aweb.profile-pack.import-payload.v1")
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
			return fmt.Errorf("%s: symlinks are not allowed in profile packs", path)
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
			return "", nil, fmt.Errorf("%s: profile-pack canonical import payload requires UTF-8 text", relSlash)
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

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
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
