package blueprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/internal/agentdocs"
	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/pathpreflight"
	"gopkg.in/yaml.v3"
)

// MaterializeOptions selects a local blueprint profile and its home layout.
// Force permits replacing existing profile files after destination preflight.
type MaterializeOptions struct {
	SourceDir   string
	ProfileID   string
	TargetDir   string
	Force       bool
	RuntimeKind string
}

// MaterializeResult records the selected profile, upstream provenance, files
// written and assets the consumer could not place.
type MaterializeResult struct {
	ProfileRef             string   `json:"profile_ref"`
	ProfileVersion         string   `json:"profile_version"`
	ProfileDigest          string   `json:"profile_digest"`
	SourceBlueprintRef     string   `json:"source_blueprint_ref,omitempty"`
	SourceBlueprintVersion string   `json:"source_blueprint_version,omitempty"`
	SourceBlueprintDigest  string   `json:"source_blueprint_digest,omitempty"`
	TargetDir              string   `json:"target_dir"`
	FilesWritten           []string `json:"files_written"`
	Warnings               []string `json:"warnings,omitempty"`
}

type materializedProfileRef struct {
	LibraryURL             string   `json:"library_url,omitempty"`
	ManagedSet             []string `json:"managed_set,omitempty"`
	ProfileDigest          string   `json:"profile_digest"`
	ProfileRef             string   `json:"profile_ref"`
	ProfileVersion         string   `json:"profile_version"`
	RuntimeKind            string   `json:"runtime_kind,omitempty"`
	SourceBlueprintDigest  string   `json:"source_blueprint_digest,omitempty"`
	SourceBlueprintRef     string   `json:"source_blueprint_ref,omitempty"`
	SourceBlueprintVersion string   `json:"source_blueprint_version,omitempty"`
}

type materializeProvenance struct {
	SourceBlueprint bool
	LibraryURL      string
}

// MaterializeLocalProfile validates a local blueprint and writes its selected
// profile into the bounded home layout described in
// docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 200–214.
func MaterializeLocalProfile(opts MaterializeOptions) (*MaterializeResult, error) {
	if strings.TrimSpace(opts.ProfileID) == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	if strings.TrimSpace(opts.TargetDir) == "" {
		return nil, fmt.Errorf("target directory is required")
	}
	bp, err := LoadLocalDir(opts.SourceDir)
	if err != nil {
		return nil, err
	}
	runtimeKind := strings.TrimSpace(opts.RuntimeKind)
	if runtimeKind == "" {
		runtimeKind = "claude-code"
	}
	return materializeLoadedProfile(loadedProfileOptions{Blueprint: bp, ProfileID: opts.ProfileID, TargetDir: opts.TargetDir, Overwrite: opts.Force, RuntimeKind: runtimeKind, Provenance: materializeProvenance{SourceBlueprint: true}})
}

type loadedProfileOptions struct {
	Blueprint   *Blueprint
	ProfileID   string
	TargetDir   string
	Overwrite   bool
	RuntimeKind string
	Provenance  materializeProvenance
}

func materializeLoadedProfile(options loadedProfileOptions) (*MaterializeResult, error) {
	bp := options.Blueprint
	profileID := options.ProfileID
	targetDir := options.TargetDir
	force := options.Overwrite
	runtimeKind := options.RuntimeKind
	provenance := options.Provenance
	runtimeKind = strings.TrimSpace(runtimeKind)
	if runtimeKind == "" {
		runtimeKind = "claude-code"
	}
	profile, ok := findProfile(bp, profileID)
	if !ok {
		return nil, fmt.Errorf("profile %q not found in blueprint", profileID)
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, err
	}
	ops, err := materializeOps(bp, profile, runtimeKind, provenance)
	if err != nil {
		return nil, err
	}
	policy := preserveExistingProfileFiles
	if force {
		policy = replaceExistingProfileFiles
	}
	plan := materializeWritePlan{TargetRoot: absTarget, Operations: ops, CollisionPolicy: policy}
	if err := plan.preflight(); err != nil {
		return nil, err
	}
	written, err := plan.write()
	if err != nil {
		return nil, err
	}
	result := &MaterializeResult{
		ProfileRef:     profile.ID,
		ProfileVersion: profile.Version,
		ProfileDigest:  profile.Digest,
		TargetDir:      absTarget,
		FilesWritten:   written,
	}
	if provenance.SourceBlueprint {
		result.SourceBlueprintRef = bp.ID
		result.SourceBlueprintVersion = bp.Version
		result.SourceBlueprintDigest = bp.Source.Digest
	}
	return result, nil
}

func materializeOps(bp *Blueprint, profile Profile, runtimeKind string, provenance materializeProvenance) ([]materializeWriteOp, error) {
	instructions, err := os.ReadFile(filepath.Join(bp.Source.Ref, filepath.FromSlash(profile.InstructionPath)))
	if err != nil {
		return nil, err
	}
	agents, err := composeAgentsMarkdown(bp, profile, instructions, provenance)
	if err != nil {
		return nil, err
	}
	ops := []materializeWriteOp{
		{Kind: opFile, Rel: "AGENTS.md", Data: agents},
	}
	if isClaudeRuntimeKind(runtimeKind) {
		ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: "CLAUDE.md", LinkTarget: "AGENTS.md"})
	}
	profileYAML, err := materializeCopyOp(bp.Source.Ref, filepath.ToSlash(filepath.Join(profile.Path, "profile.yaml")), filepath.ToSlash(filepath.Join(".aw", "profile", "profile.yaml")))
	if err != nil {
		return nil, err
	}
	ops = append(ops, profileYAML)
	instructionSource, err := materializeCopyOp(bp.Source.Ref, profile.InstructionPath, filepath.ToSlash(filepath.Join(".aw", "profile", "instructions.md")))
	if err != nil {
		return nil, err
	}
	ops = append(ops, instructionSource)
	for _, skill := range profile.Skills {
		skillName, err := skillNameFromPath(profile.ID, skill.Path)
		if err != nil {
			return nil, err
		}
		for _, sourcePath := range skillPayloadPaths(bp.PayloadFiles, profile.ID, skillName) {
			sourceRel, err := resourceSourceRel(profile.ID, "skills", sourcePath)
			if err != nil {
				return nil, err
			}
			rootDest := filepath.ToSlash(filepath.Join("skills", filepath.FromSlash(sourceRel)))
			op, err := materializeCopyOp(bp.Source.Ref, sourcePath, rootDest)
			if err != nil {
				return nil, err
			}
			ops = append(ops, op)
			profileDest := filepath.ToSlash(filepath.Join(".aw", "profile", "skills", filepath.FromSlash(sourceRel)))
			op, err = materializeCopyOp(bp.Source.Ref, sourcePath, profileDest)
			if err != nil {
				return nil, err
			}
			ops = append(ops, op)
		}
		if isClaudeRuntimeKind(runtimeKind) {
			ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: filepath.ToSlash(filepath.Join(".claude", "skills", skillName)), LinkTarget: filepath.ToSlash(filepath.Join("..", "..", "skills", skillName))})
		}
	}
	for _, artifact := range profile.Artifacts {
		sourceRel, err := resourceSourceRel(profile.ID, "artifacts", artifact.Path)
		if err != nil {
			return nil, err
		}
		rootDest := filepath.ToSlash(filepath.Join("artifacts", filepath.FromSlash(sourceRel)))
		op, err := materializeCopyOp(bp.Source.Ref, artifact.Path, rootDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		profileDest := filepath.ToSlash(filepath.Join(".aw", "profile", "artifacts", filepath.FromSlash(sourceRel)))
		op, err = materializeCopyOp(bp.Source.Ref, artifact.Path, profileDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	refRel := filepath.ToSlash(filepath.Join(".aw", "profile", "ref.json"))
	managedSet := make([]string, 0, len(ops)+1)
	for _, op := range ops {
		managedSet = append(managedSet, filepath.ToSlash(op.Rel))
	}
	managedSet = append(managedSet, refRel)
	ref := materializedProfileRef{
		LibraryURL:     strings.TrimSpace(provenance.LibraryURL),
		ManagedSet:     managedSet,
		ProfileDigest:  profile.Digest,
		ProfileRef:     profile.ID,
		ProfileVersion: profile.Version,
		RuntimeKind:    strings.TrimSpace(runtimeKind),
	}
	if provenance.SourceBlueprint {
		ref.SourceBlueprintDigest = bp.Source.Digest
		ref.SourceBlueprintRef = bp.ID
		ref.SourceBlueprintVersion = bp.Version
	}
	refBytes, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return nil, err
	}
	refBytes = append(refBytes, '\n')
	ops = append(ops, materializeWriteOp{Kind: opFile, Rel: refRel, Data: refBytes})
	return ops, nil
}

func isClaudeRuntimeKind(runtimeKind string) bool {
	kind := strings.ToLower(strings.TrimSpace(runtimeKind))
	return kind == "" || kind == "claude-code"
}

func composeAgentsMarkdown(bp *Blueprint, profile Profile, instructions []byte, provenance materializeProvenance) ([]byte, error) {
	var b strings.Builder
	writeParagraph := func(title string, lines []string) {
		if len(lines) == 0 {
			return
		}
		b.WriteString("## ")
		b.WriteString(title)
		b.WriteString("\n\n")
		for i, line := range lines {
			if i > 0 {
				b.WriteString("\n")
			}
			b.WriteString(line)
		}
		b.WriteString("\n\n")
	}
	b.WriteString("# ")
	b.WriteString(profile.Name)
	b.WriteString("\n\n")
	b.WriteString("> Profile ")
	b.WriteString(profile.ID)
	b.WriteString(" v")
	b.WriteString(profile.Version)
	if provenance.SourceBlueprint {
		b.WriteString(" · blueprint ")
		b.WriteString(bp.ID)
		b.WriteString(" v")
		b.WriteString(bp.Version)
	} else {
		b.WriteString(" · created")
	}
	b.WriteString("\n\n")
	if strings.TrimSpace(profile.Mission) != "" {
		writeParagraph("Mission", []string{profile.Mission})
	}
	if len(profile.AcceptedWork) > 0 {
		writeParagraph("Work you take on", bulletLines(profile.AcceptedWork))
	}
	if strings.TrimSpace(string(instructions)) != "" {
		normalized := strings.TrimRight(string(instructions), " \t\r\n")
		writeParagraph("Instructions", strings.Split(normalized, "\n"))
	}
	if len(profile.ExpectedApps) > 0 {
		writeParagraph("Apps you use", bulletLines(profile.ExpectedApps))
	}
	if len(profile.ApprovalRequired) > 0 {
		writeParagraph("Actions requiring human approval", bulletLines(profile.ApprovalRequired))
	}
	if len(profile.MemoryPolicy) > 0 {
		mode, err := requiredStringMapValue("memory_policy", profile.MemoryPolicy, "mode")
		if err != nil {
			return nil, err
		}
		proposalTarget, err := requiredStringMapValue("memory_policy", profile.MemoryPolicy, "proposal_target")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(mode) != "" || strings.TrimSpace(proposalTarget) != "" {
			lines := []string{"Mode: " + mode, "Proposal target: " + proposalTarget, "", "Your full profile is kept under .aw/profile/. To change how you work, propose a", "new profile version from there; " + proposalTarget + " reviews and mints it."}
			writeParagraph("Memory and learning", lines)
		}
	}
	if len(profile.Skills) > 0 {
		lines := []string{"These skills are installed and discoverable by your harness:", ""}
		for _, skill := range profile.Skills {
			name, err := skillNameFromPath(profile.ID, skill.Path)
			if err != nil {
				return nil, err
			}
			lines = append(lines, "- "+name)
		}
		writeParagraph("Skills", lines)
	}
	out := strings.TrimRight(b.String(), "\n") + "\n"
	return []byte(out), nil
}

func bulletLines(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, "- "+value)
		}
	}
	return out
}

func findProfile(bp *Blueprint, id string) (Profile, bool) {
	for _, profile := range bp.LoadedProfiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func skillPayloadPaths(payloadFiles []string, profileID, skillName string) []string {
	prefix := filepath.ToSlash(filepath.Join("profiles", profileID, "skills", skillName)) + "/"
	paths := make([]string, 0)
	for _, payloadPath := range payloadFiles {
		if strings.HasPrefix(payloadPath, prefix) {
			paths = append(paths, payloadPath)
		}
	}
	sort.Strings(paths)
	return paths
}

func skillNameFromPath(profileID, blueprintRelativePath string) (string, error) {
	rel, err := resourceSourceRel(profileID, "skills", blueprintRelativePath)
	if err != nil {
		return "", err
	}
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || parts[0] == "" {
		return "", fmt.Errorf("skill path %q must include a skill directory", blueprintRelativePath)
	}
	return parts[0], nil
}

func resourceSourceRel(profileID, category, blueprintRelativePath string) (string, error) {
	prefix := filepath.ToSlash(filepath.Join("profiles", profileID, category)) + "/"
	if !strings.HasPrefix(blueprintRelativePath, prefix) {
		return "", fmt.Errorf("%s path %q is outside profile %s %s directory", category, blueprintRelativePath, profileID, category)
	}
	rel := strings.TrimPrefix(blueprintRelativePath, prefix)
	if err := validateRelativePath(category, rel); err != nil {
		return "", err
	}
	return rel, nil
}

// LibraryHomeFile is one file or runtime symlink in a materialize response.
// Path is relative to the home and remains subject to ValidateHomePath; a
// response never authorizes writes outside the profile layout.
type LibraryHomeFile struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	ContentUTF8 string `json:"content_utf8,omitempty"`
	Target      string `json:"target,omitempty"`
}

// LibraryProfilePayloadFile is one UTF-8 file in a profile-relative Library
// payload. SHA256, when present, must match ContentUTF8 before materialization.
type LibraryProfilePayloadFile struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256,omitempty"`
	ContentUTF8 string `json:"content_utf8,omitempty"`
}

// ValidateLibraryProfilePayloadOptions binds a Library payload to the requested
// profile identity and the nonempty digest supplied by its producer.
type ValidateLibraryProfilePayloadOptions struct {
	ProfileRef     string
	ProfileVersion string
	ProfileDigest  string
	Files          []LibraryProfilePayloadFile
}

// MaterializeLibraryProfilePayloadOptions supplies a fetched profile, its
// source provenance and the destination home. Force permits replacing existing
// profile files, subject to the same path and symlink preflight.
type MaterializeLibraryProfilePayloadOptions struct {
	TargetDir        string
	LibraryURL       string
	BlueprintRef     string
	BlueprintVersion string
	BlueprintDigest  string
	ProfileRef       string
	ProfileVersion   string
	ProfileDigest    string
	RuntimeKind      string
	Files            []LibraryProfilePayloadFile
	Force            bool
}

// ValidateLibraryProfilePayloadDigest verifies the profile shape, per-file
// hashes and required profile digest without writing files. The result proves
// byte consistency, not independent publisher authentication
// (docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 168–176).
func ValidateLibraryProfilePayloadDigest(opts ValidateLibraryProfilePayloadOptions) (string, error) {
	if err := validateProfileID("profile_ref", opts.ProfileRef); err != nil {
		return "", err
	}
	if err := validateRequiredString("profile_version", opts.ProfileVersion); err != nil {
		return "", err
	}
	_, digest, err := validateLibraryProfilePayload(ValidateLibraryProfilePayloadOptions{ProfileRef: opts.ProfileRef, ProfileVersion: opts.ProfileVersion, ProfileDigest: opts.ProfileDigest, Files: opts.Files})
	return digest, err
}

// MaterializeLibraryProfilePayload validates the fetched profile before writing
// its declared assets into the bounded home layout. It records upstream
// provenance and reports undeclared assets as warnings.
func MaterializeLibraryProfilePayload(opts MaterializeLibraryProfilePayloadOptions) (result *MaterializeResult, err error) {
	if strings.TrimSpace(opts.TargetDir) == "" {
		return nil, fmt.Errorf("target directory is required")
	}
	hasSourceBlueprint := strings.TrimSpace(opts.BlueprintRef) != "" || strings.TrimSpace(opts.BlueprintVersion) != "" || strings.TrimSpace(opts.BlueprintDigest) != ""
	if hasSourceBlueprint {
		if err := validateRefString("blueprint_ref", opts.BlueprintRef); err != nil {
			return nil, err
		}
		if err := validateRequiredString("blueprint_version", opts.BlueprintVersion); err != nil {
			return nil, err
		}
	}
	if err := validateProfileID("profile_ref", opts.ProfileRef); err != nil {
		return nil, err
	}
	if err := validateRequiredString("profile_version", opts.ProfileVersion); err != nil {
		return nil, err
	}
	files, _, err := validateLibraryProfilePayload(ValidateLibraryProfilePayloadOptions{ProfileRef: opts.ProfileRef, ProfileVersion: opts.ProfileVersion, ProfileDigest: opts.ProfileDigest, Files: opts.Files})
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "aw-library-profile-payload-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(tmp); cleanupErr != nil {
			warning := fmt.Errorf("remove temporary Library payload %s: %w. Remove that temporary directory manually", tmp, cleanupErr)
			if result != nil {
				// The home is already materialized; cleanup must not turn its
				// accepted result into a retry that writes the home again.
				result.Warnings = append(result.Warnings, warning.Error())
			} else {
				err = errors.Join(err, warning)
			}
		}
	}()
	profileDir := filepath.Join(tmp, "profiles", opts.ProfileRef)
	if err := writeLibraryProfilePayloadFiles(tmp, profileDir, files); err != nil {
		return nil, err
	}
	blueprintRef := strings.TrimSpace(opts.BlueprintRef)
	blueprintVersion := strings.TrimSpace(opts.BlueprintVersion)
	if !hasSourceBlueprint {
		blueprintRef = "created-profile-payload"
		blueprintVersion = "0.0.0"
	}
	blueprintYAML, err := json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"id":             blueprintRef,
		"name":           blueprintRef,
		"version":        blueprintVersion,
		"summary":        "Fetched from Library",
		"description":    "Profile source fetched from Library for local materialization.",
		"profiles":       []map[string]any{{"id": opts.ProfileRef, "default_count": 1}},
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "blueprint.yaml"), append(blueprintYAML, '\n'), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# "+opts.BlueprintRef+"\n"), 0o644); err != nil {
		return nil, err
	}
	bp, err := LoadLocalDir(tmp)
	if err != nil {
		return nil, err
	}
	profile, ok := findProfile(bp, opts.ProfileRef)
	if !ok {
		return nil, fmt.Errorf("profile %q not found in library payload", opts.ProfileRef)
	}
	bp.Source.Kind = "library_blueprint_profile_payload"
	bp.Source.DigestScope = DigestScopeLocalImportPayload
	// Public get-profile responses intentionally carry no blueprint digest; do
	// not leak the synthetic one-profile wrapper digest into the home pin. Shelf
	// and local callers that have a real upstream blueprint digest pass it here.
	bp.Source.Digest = strings.TrimSpace(opts.BlueprintDigest)
	result, err = materializeLoadedProfile(loadedProfileOptions{Blueprint: bp, ProfileID: opts.ProfileRef, TargetDir: opts.TargetDir, Overwrite: opts.Force, RuntimeKind: opts.RuntimeKind, Provenance: materializeProvenance{SourceBlueprint: hasSourceBlueprint, LibraryURL: opts.LibraryURL}})
	if err != nil {
		return nil, err
	}
	result.Warnings = undeclaredLibraryProfileAssetWarnings(bp, profile)
	return result, nil
}

// Library may legitimately publish profile assets this consumer does not know
// how to place, so this is deliberately diagnostic rather than a rejection.
// Reporting the paths prevents a successful mint from being mistaken for local
// delivery while leaving producer policy at the producer boundary.
func undeclaredLibraryProfileAssetWarnings(bp *Blueprint, profile Profile) []string {
	reachable := map[string]bool{
		filepath.ToSlash(filepath.Join(profile.Path, "profile.yaml")): true,
		profile.InstructionPath: true,
	}
	for _, artifact := range profile.Artifacts {
		reachable[artifact.Path] = true
	}
	for _, skill := range profile.Skills {
		skillName, err := skillNameFromPath(profile.ID, skill.Path)
		if err != nil {
			continue
		}
		for _, payloadPath := range skillPayloadPaths(bp.PayloadFiles, profile.ID, skillName) {
			reachable[payloadPath] = true
		}
	}
	prefix := filepath.ToSlash(profile.Path) + "/"
	paths := make([]string, 0)
	for _, payloadPath := range bp.PayloadFiles {
		if strings.HasPrefix(payloadPath, prefix) && !reachable[payloadPath] {
			paths = append(paths, strings.TrimPrefix(payloadPath, prefix))
		}
	}
	sort.Strings(paths)
	warnings := make([]string, 0, len(paths))
	for _, path := range paths {
		warnings = append(warnings, fmt.Sprintf("library profile asset %s is not declared by profile.yaml and was not materialized (warning only)", path))
	}
	return warnings
}

// validateLibraryProfilePayload implements docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 168–176.
// Network payload structure and hashes are checked before any target write.
func validateLibraryProfilePayload(options ValidateLibraryProfilePayloadOptions) ([]LibraryProfilePayloadFile, string, error) {
	profileRef := options.ProfileRef
	profileVersion := options.ProfileVersion
	profileDigest := options.ProfileDigest
	files := options.Files

	validated, err := validateLibraryProfilePayloadStructure(profileRef, profileVersion, files)
	if err != nil {
		return nil, "", err
	}
	digest, err := libraryProfilePayloadDigest(validated)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(profileDigest) == "" {
		return nil, "", fmt.Errorf("library profile response is missing its digest. Fetch the profile again from a Library that supplies a profile digest")
	}
	if strings.TrimSpace(profileDigest) != digest {
		return nil, "", fmt.Errorf("library profile payload digest mismatch: fetched files digest %s, expected %s", digest, strings.TrimSpace(profileDigest))
	}
	return validated, digest, nil
}

func validateLibraryProfilePayloadStructure(profileRef, profileVersion string, files []LibraryProfilePayloadFile) ([]LibraryProfilePayloadFile, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("library get-profile response missing files")
	}
	seen := map[string]bool{}
	out := make([]LibraryProfilePayloadFile, 0, len(files))
	var profileYAML string
	for _, file := range files {
		rel := file.Path
		if err := validateNormalizedPOSIXRelativePath("library profile file", rel); err != nil {
			return nil, err
		}
		if seen[rel] {
			return nil, fmt.Errorf("duplicate library profile file %s", rel)
		}
		seen[rel] = true
		if containsCanonicalJSONLineSeparator(file.ContentUTF8) {
			return nil, fmt.Errorf("library profile file %s contains U+2028/U+2029, which are not allowed in blueprint payloads", rel)
		}
		if rel == "profile.yaml" {
			profileYAML = file.ContentUTF8
		}
		out = append(out, file)
	}
	if !seen["profile.yaml"] {
		return nil, fmt.Errorf("library get-profile response missing profile.yaml")
	}
	var doc struct {
		ID      string `yaml:"id"`
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal([]byte(profileYAML), &doc); err != nil {
		return nil, fmt.Errorf("library profile profile.yaml: parse: %w", err)
	}
	if strings.TrimSpace(doc.ID) != strings.TrimSpace(profileRef) {
		return nil, fmt.Errorf("library profile profile.yaml id %q does not match response profile_ref %q", strings.TrimSpace(doc.ID), strings.TrimSpace(profileRef))
	}
	if strings.TrimSpace(doc.Version) != strings.TrimSpace(profileVersion) {
		return nil, fmt.Errorf("library profile profile.yaml version %q does not match response version %q", strings.TrimSpace(doc.Version), strings.TrimSpace(profileVersion))
	}
	return out, nil
}

func libraryProfilePayloadDigest(files []LibraryProfilePayloadFile) (string, error) {
	payloadFiles := make([]canonicalPayloadFile, 0, len(files))
	for _, file := range files {
		sha, err := verifyLibraryProfilePayloadFileSHA(file)
		if err != nil {
			return "", err
		}
		payloadFiles = append(payloadFiles, canonicalPayloadFile{Path: file.Path, SHA256: sha, ContentUTF8: file.ContentUTF8})
	}
	sort.Slice(payloadFiles, func(i, j int) bool { return payloadFiles[i].Path < payloadFiles[j].Path })
	canonical, err := canonicalJSON(map[string]any{"schema": "aweb.blueprint.profile-payload.v1", "files": payloadFiles})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func verifyLibraryProfilePayloadFileSHA(file LibraryProfilePayloadFile) (string, error) {
	want := strings.TrimSpace(file.SHA256)
	if want == "" {
		return "", fmt.Errorf("library profile file %s missing sha256", file.Path)
	}
	if !strings.HasPrefix(want, "sha256:") || len(want) != len("sha256:")+64 {
		return "", fmt.Errorf("library profile file %s has invalid sha256 %q", file.Path, want)
	}
	gotBytes := sha256.Sum256([]byte(file.ContentUTF8))
	got := "sha256:" + hex.EncodeToString(gotBytes[:])
	if want != got {
		return "", fmt.Errorf("library profile file %s sha256 mismatch", file.Path)
	}
	return want, nil
}

func writeLibraryProfilePayloadFiles(root, profileDir string, files []LibraryProfilePayloadFile) error {
	for _, file := range files {
		rel := file.Path
		dest := filepath.Join(profileDir, filepath.FromSlash(rel))
		if !isWithin(profileDir, dest) {
			return fmt.Errorf("library profile file %s escapes profile directory", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := pathpreflight.PreflightFile(dest, "library profile file", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
			return err
		}
		if err := os.WriteFile(dest, []byte(file.ContentUTF8), 0o644); err != nil {
			return err
		}
	}
	if err := pathpreflight.PreflightDir(root, "library profile payload", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	return nil
}

// WriteLibraryHomeFiles preflights every response entry, then writes only the
// profile layout permitted by docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 200–214.
// The released force argument selects collision handling; the internal write
// plan uses a named policy. No writes occur when preflight rejects any entry.
func WriteLibraryHomeFiles(targetDir string, files []LibraryHomeFile, force bool) ([]string, error) {
	policy := preserveExistingProfileFiles
	if force {
		policy = replaceExistingProfileFiles
	}
	return writeLibraryHomeFiles(libraryHomeWriteOptions{TargetDir: targetDir, Files: files, CollisionPolicy: policy})
}

type materializeCollisionPolicy uint8

const (
	preserveExistingProfileFiles materializeCollisionPolicy = iota
	replaceExistingProfileFiles
)

type libraryHomeWriteOptions struct {
	TargetDir       string
	Files           []LibraryHomeFile
	CollisionPolicy materializeCollisionPolicy
}

func writeLibraryHomeFiles(options libraryHomeWriteOptions) ([]string, error) {
	targetDir, files := options.TargetDir, options.Files

	if strings.TrimSpace(targetDir) == "" {
		return nil, fmt.Errorf("target directory is required")
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, err
	}
	ops := make([]materializeWriteOp, 0, len(files))
	for _, file := range files {
		rel := file.Path
		kind := materializeWriteKind(strings.TrimSpace(file.Kind))
		switch kind {
		case opFile:
			ops = append(ops, materializeWriteOp{Kind: opFile, Rel: rel, Data: []byte(file.ContentUTF8)})
		case opSymlink:
			ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: rel, LinkTarget: filepath.ToSlash(strings.TrimSpace(file.Target))})
		default:
			return nil, fmt.Errorf("unsupported materialized home file kind %q for %s. Use file or a documented runtime symlink", file.Kind, rel)
		}
	}
	plan := materializeWritePlan{TargetRoot: absTarget, Operations: ops, CollisionPolicy: options.CollisionPolicy}
	if err := plan.preflight(); err != nil {
		return nil, err
	}
	return plan.write()
}

type materializeWriteKind string

const (
	opFile    materializeWriteKind = "file"
	opSymlink materializeWriteKind = "symlink"
)

type materializeWriteOp struct {
	Kind       materializeWriteKind
	Rel        string
	Data       []byte
	LinkTarget string
}

func materializeCopyOp(sourceRoot, sourceRel, destRel string) (materializeWriteOp, error) {
	if err := validateRelativePath("source", sourceRel); err != nil {
		return materializeWriteOp{}, err
	}
	if err := validateRelativePath("destination", destRel); err != nil {
		return materializeWriteOp{}, err
	}
	data, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(sourceRel)))
	if err != nil {
		return materializeWriteOp{}, err
	}
	return materializeWriteOp{Kind: opFile, Rel: filepath.ToSlash(destRel), Data: data}, nil
}

type materializeWritePlan struct {
	TargetRoot      string
	Operations      []materializeWriteOp
	CollisionPolicy materializeCollisionPolicy
}

func (plan materializeWritePlan) preflight() error {
	targetRoot, ops := plan.TargetRoot, plan.Operations
	if err := ensureMaterializeTargetRoot(targetRoot); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, op := range ops {
		rel := filepath.ToSlash(op.Rel)
		if seen[rel] {
			return fmt.Errorf("duplicate materialized destination %s", rel)
		}
		seen[rel] = true
		if err := ValidateHomePath(op.Rel); err != nil {
			return err
		}
		if err := validateMaterializeDestination(targetRoot, op, plan.CollisionPolicy); err != nil {
			return err
		}
		if err := validateHomeOp(op); err != nil {
			return err
		}
	}
	return nil
}

func ensureMaterializeTargetRoot(targetRoot string) error {
	clean := filepath.Clean(targetRoot)
	if err := pathpreflight.PreflightDir(clean, "target directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return err
	}
	return pathpreflight.PreflightDir(clean, "target directory", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func validateMaterializeDestination(targetRoot string, op materializeWriteOp, policy materializeCollisionPolicy) error {
	rel := filepath.ToSlash(op.Rel)
	if err := validateRelativePath("destination", rel); err != nil {
		return err
	}
	path := filepath.Join(targetRoot, filepath.FromSlash(rel))
	if op.Kind == opSymlink {
		if op.LinkTarget == "" || filepath.IsAbs(op.LinkTarget) || strings.Contains(op.LinkTarget, "://") {
			return fmt.Errorf("%s has invalid symlink target", rel)
		}
		targetPath := filepath.Clean(filepath.Join(filepath.Dir(path), filepath.FromSlash(op.LinkTarget)))
		if !isWithin(targetRoot, targetPath) {
			return fmt.Errorf("%s symlink target escapes target directory", rel)
		}
		if err := rejectSymlinkedExistingSymlinkTarget(targetRoot, filepath.Dir(path), op.LinkTarget, rel); err != nil {
			return err
		}
	}
	if !isWithin(targetRoot, path) {
		return fmt.Errorf("destination %s escapes target directory", rel)
	}
	if op.Kind == opFile {
		if err := pathpreflight.PreflightFile(path, rel, pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
			return err
		}
		if _, err := os.Lstat(path); err == nil && policy == preserveExistingProfileFiles {
			return fmt.Errorf("%s already exists; pass --force to overwrite", rel)
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := pathpreflight.RejectSymlinkedExistingComponents(filepath.Dir(path), rel, pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if policy == replaceExistingProfileFiles {
			return nil
		}
		return fmt.Errorf("%s already exists; pass --force to overwrite", rel)
	}
	if policy == replaceExistingProfileFiles && info.IsDir() {
		fileProjection, err := isClaudeSkillFileProjectionDirectory(path, op)
		if err != nil {
			return err
		}
		if fileProjection {
			return nil
		}
	}
	return fmt.Errorf("%s already exists and is not a symlink", rel)
}

func isClaudeSkillFileProjectionDirectory(path string, op materializeWriteOp) (bool, error) {
	rel := filepath.ToSlash(op.Rel)
	parts := strings.Split(rel, "/")
	if len(parts) != 3 || parts[0] != ".claude" || parts[1] != "skills" || parts[2] == "" {
		return false, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	if len(entries) != 1 || entries[0].Name() != "SKILL.md" || entries[0].Type()&os.ModeSymlink == 0 {
		return false, nil
	}
	target, err := os.Readlink(filepath.Join(path, "SKILL.md"))
	if err != nil {
		return false, err
	}
	expected := filepath.ToSlash(filepath.Join("..", filepath.FromSlash(op.LinkTarget), "SKILL.md"))
	return filepath.ToSlash(target) == expected, nil
}

func rejectSymlinkedExistingSymlinkTarget(targetRoot, baseDir, linkTarget, label string) error {
	current := filepath.Clean(baseDir)
	if !isWithin(targetRoot, current) {
		return fmt.Errorf("%s symlink target escapes target directory", label)
	}
	parts := strings.Split(filepath.FromSlash(linkTarget), string(filepath.Separator))
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			if !isWithin(targetRoot, current) {
				return fmt.Errorf("%s symlink target escapes target directory", label)
			}
			continue
		}
		current = filepath.Join(current, part)
		if !isWithin(targetRoot, filepath.Clean(current)) {
			return fmt.Errorf("%s symlink target escapes target directory", label)
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s symlink target %s must not be a symlink", label, filepath.ToSlash(current))
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("%s symlink target parent %s must be a directory", label, filepath.ToSlash(current))
		}
	}
	return nil
}

// write carries preflight's collision policy into publication. Exclusive file
// commits and symlink creation preserve a destination created concurrently
// (docs/blueprint-materialization-contract.md, “5. Materialization semantics,” lines 200–214).
func (plan materializeWritePlan) write() ([]string, error) {
	written := make([]string, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		path := filepath.Join(plan.TargetRoot, filepath.FromSlash(op.Rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, materializePublicationError(op.Rel, err)
		}
		if op.Kind == opSymlink {
			var err error
			if plan.CollisionPolicy == preserveExistingProfileFiles {
				err = os.Symlink(op.LinkTarget, path)
			} else {
				err = replaceRuntimeProjection(path, op)
			}
			if err != nil {
				return nil, materializePublicationError(op.Rel, err)
			}
		} else {
			data := op.Data
			// The profile owns the body; doc injection owns its marked block.
			if filepath.ToSlash(op.Rel) == "AGENTS.md" {
				existing, err := os.ReadFile(path)
				if err == nil {
					data = []byte(agentdocs.PreserveMarkedBlock(string(existing), string(data)))
				} else if !os.IsNotExist(err) {
					return nil, materializePublicationError(op.Rel, err)
				}
			}
			options := atomicfile.Options{Mode: 0644, Exclusive: plan.CollisionPolicy == preserveExistingProfileFiles}
			if err := options.Write(path, data); err != nil {
				return nil, materializePublicationError(op.Rel, err)
			}
		}
		written = append(written, filepath.ToSlash(op.Rel))
	}
	return written, nil
}

func materializePublicationError(rel string, err error) error {
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("profile destination %q appeared during materialization: %w. Use another home or resolve the conflicting destination before retrying", rel, err)
	}
	return fmt.Errorf("publish profile destination %q: %w. Repair the destination before retrying", rel, err)
}

// replaceRuntimeProjection replaces a symlink or the file projection written by
// aw-v1.32.5's blueprint materializer; unmanaged directories remain untouched.
func replaceRuntimeProjection(path string, op materializeWriteOp) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.IsDir() {
			fileProjection, err := isClaudeSkillFileProjectionDirectory(path, op)
			if err != nil {
				return err
			}
			if !fileProjection {
				return fmt.Errorf("%s existing directory is not a Claude skill file projection", op.Rel)
			}
			err = os.RemoveAll(path)
		} else if info.Mode()&os.ModeSymlink != 0 {
			err = os.Remove(path)
		} else {
			return fmt.Errorf("%s existing file is not a runtime projection", op.Rel)
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(op.LinkTarget, path)
}
