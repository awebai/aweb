package blueprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/internal/pathpreflight"
	"gopkg.in/yaml.v3"
)

type MaterializeOptions struct {
	SourceDir   string
	ProfileID   string
	TargetDir   string
	Force       bool
	RuntimeKind string
}

type MaterializeResult struct {
	ProfileRef             string   `json:"profile_ref"`
	ProfileVersion         string   `json:"profile_version"`
	ProfileDigest          string   `json:"profile_digest"`
	SourceBlueprintRef     string   `json:"source_blueprint_ref,omitempty"`
	SourceBlueprintVersion string   `json:"source_blueprint_version,omitempty"`
	SourceBlueprintDigest  string   `json:"source_blueprint_digest,omitempty"`
	TargetDir              string   `json:"target_dir"`
	FilesWritten           []string `json:"files_written"`
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
	return materializeLoadedProfile(bp, opts.ProfileID, opts.TargetDir, opts.Force, runtimeKind, materializeProvenance{SourceBlueprint: true})
}

func materializeLoadedProfile(bp *Blueprint, profileID, targetDir string, force bool, runtimeKind string, provenance materializeProvenance) (*MaterializeResult, error) {
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
	if err := preflightMaterializeWrites(absTarget, ops, force); err != nil {
		return nil, err
	}
	written, err := writeMaterializedFiles(absTarget, ops)
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
		sourceRel, err := resourceSourceRel(profile.ID, "skills", skill.Path)
		if err != nil {
			return nil, err
		}
		rootDest := filepath.ToSlash(filepath.Join("skills", filepath.FromSlash(sourceRel)))
		op, err := materializeCopyOp(bp.Source.Ref, skill.Path, rootDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		profileDest := filepath.ToSlash(filepath.Join(".aw", "profile", "skills", filepath.FromSlash(sourceRel)))
		op, err = materializeCopyOp(bp.Source.Ref, skill.Path, profileDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		if isClaudeRuntimeKind(runtimeKind) {
			ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: filepath.ToSlash(filepath.Join(".claude", "skills", skillName, "SKILL.md")), LinkTarget: filepath.ToSlash(filepath.Join("..", "..", "..", "skills", skillName, "SKILL.md"))})
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
		mode, _ := profile.MemoryPolicy["mode"].(string)
		proposalTarget, _ := profile.MemoryPolicy["proposal_target"].(string)
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

type LibraryHomeFile struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	ContentUTF8 string `json:"content_utf8,omitempty"`
	Target      string `json:"target,omitempty"`
}

type LibraryProfilePayloadFile struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256,omitempty"`
	ContentUTF8 string `json:"content_utf8,omitempty"`
}

type ValidateLibraryProfilePayloadOptions struct {
	ProfileRef     string
	ProfileVersion string
	ProfileDigest  string
	Files          []LibraryProfilePayloadFile
}

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

func ValidateLibraryProfilePayloadDigest(opts ValidateLibraryProfilePayloadOptions) (string, error) {
	if err := validateProfileID("profile_ref", opts.ProfileRef); err != nil {
		return "", err
	}
	if err := validateRequiredString("profile_version", opts.ProfileVersion); err != nil {
		return "", err
	}
	_, digest, err := validateLibraryProfilePayload(opts.ProfileRef, opts.ProfileVersion, opts.ProfileDigest, opts.Files)
	return digest, err
}

func MaterializeLibraryProfilePayload(opts MaterializeLibraryProfilePayloadOptions) (*MaterializeResult, error) {
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
	files, _, err := validateLibraryProfilePayload(opts.ProfileRef, opts.ProfileVersion, opts.ProfileDigest, opts.Files)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "aw-library-profile-payload-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
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
	if _, ok := findProfile(bp, opts.ProfileRef); !ok {
		return nil, fmt.Errorf("profile %q not found in library payload", opts.ProfileRef)
	}
	bp.Source.Kind = "library_blueprint_profile_payload"
	bp.Source.DigestScope = DigestScopeLocalImportPayload
	// Public get-profile responses intentionally carry no blueprint digest; do
	// not leak the synthetic one-profile wrapper digest into the home pin. Shelf
	// and local callers that have a real upstream blueprint digest pass it here.
	bp.Source.Digest = strings.TrimSpace(opts.BlueprintDigest)
	return materializeLoadedProfile(bp, opts.ProfileRef, opts.TargetDir, opts.Force, opts.RuntimeKind, materializeProvenance{SourceBlueprint: hasSourceBlueprint, LibraryURL: opts.LibraryURL})
}

func validateLibraryProfilePayload(profileRef, profileVersion, profileDigest string, files []LibraryProfilePayloadFile) ([]LibraryProfilePayloadFile, string, error) {
	validated, err := validateLibraryProfilePayloadStructure(profileRef, profileVersion, files)
	if err != nil {
		return nil, "", err
	}
	digest, err := libraryProfilePayloadDigest(validated)
	if err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(profileDigest) != "" && strings.TrimSpace(profileDigest) != digest {
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

func WriteLibraryHomeFiles(targetDir string, files []LibraryHomeFile, force bool) ([]string, error) {
	if strings.TrimSpace(targetDir) == "" {
		return nil, fmt.Errorf("target directory is required")
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, err
	}
	ops := make([]materializeWriteOp, 0, len(files))
	for _, file := range files {
		rel := filepath.ToSlash(strings.TrimSpace(file.Path))
		kind := strings.TrimSpace(file.Kind)
		switch kind {
		case "file":
			ops = append(ops, materializeWriteOp{Kind: opFile, Rel: rel, Data: []byte(file.ContentUTF8)})
		case "symlink":
			ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: rel, LinkTarget: filepath.ToSlash(strings.TrimSpace(file.Target))})
		default:
			return nil, fmt.Errorf("unsupported materialized home file kind %q for %s", file.Kind, rel)
		}
	}
	if err := preflightMaterializeWrites(absTarget, ops, force); err != nil {
		return nil, err
	}
	return writeMaterializedFiles(absTarget, ops)
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

func preflightMaterializeWrites(targetRoot string, ops []materializeWriteOp, force bool) error {
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
		if err := validateMaterializeDestination(targetRoot, op, force); err != nil {
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

func validateMaterializeDestination(targetRoot string, op materializeWriteOp, force bool) error {
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
		if _, err := os.Lstat(path); err == nil && !force {
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
		if force {
			return nil
		}
		return fmt.Errorf("%s already exists; pass --force to overwrite", rel)
	}
	return fmt.Errorf("%s already exists and is not a symlink", rel)
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

func writeMaterializedFiles(targetRoot string, ops []materializeWriteOp) ([]string, error) {
	written := make([]string, 0, len(ops))
	for _, op := range ops {
		path := filepath.Join(targetRoot, filepath.FromSlash(op.Rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if op.Kind == opSymlink {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			if err := os.Symlink(op.LinkTarget, path); err != nil {
				return nil, err
			}
		} else {
			if err := os.WriteFile(path, op.Data, 0o644); err != nil {
				return nil, err
			}
		}
		written = append(written, filepath.ToSlash(op.Rel))
	}
	return written, nil
}

func compareMaterializedTrees(wantDir, gotDir string) error {
	return filepath.WalkDir(wantDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(wantDir, path)
		gotPath := filepath.Join(gotDir, rel)
		wantInfo, err := os.Lstat(path)
		if err != nil {
			return err
		}
		gotInfo, err := os.Lstat(gotPath)
		if err != nil {
			return err
		}
		if wantInfo.Mode()&os.ModeSymlink != 0 {
			if gotInfo.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("%s: got non-symlink", rel)
			}
			wantLink, _ := os.Readlink(path)
			gotLink, _ := os.Readlink(gotPath)
			if wantLink != gotLink {
				return fmt.Errorf("%s: symlink target %q, want %q", rel, gotLink, wantLink)
			}
			return nil
		}
		if gotInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: got symlink, want file", rel)
		}
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(gotPath)
		if err != nil {
			return err
		}
		if !bytes.Equal(want, got) {
			return fmt.Errorf("%s: file content mismatch", rel)
		}
		return nil
	})
}
