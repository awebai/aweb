package profilepack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/internal/pathpreflight"
)

type MaterializeOptions struct {
	SourceDir string
	ProfileID string
	TargetDir string
	Force     bool
}

type MaterializeResult struct {
	ProfileRef               string   `json:"profile_ref"`
	ProfileVersion           string   `json:"profile_version"`
	ProfileDigest            string   `json:"profile_digest"`
	SourceProfilePackRef     string   `json:"source_profile_pack_ref"`
	SourceProfilePackVersion string   `json:"source_profile_pack_version"`
	SourceProfilePackDigest  string   `json:"source_profile_pack_digest"`
	TargetDir                string   `json:"target_dir"`
	FilesWritten             []string `json:"files_written"`
}

type materializedProfileRef struct {
	ProfileDigest            string `json:"profile_digest"`
	ProfileRef               string `json:"profile_ref"`
	ProfileVersion           string `json:"profile_version"`
	SourceProfilePackDigest  string `json:"source_profile_pack_digest"`
	SourceProfilePackRef     string `json:"source_profile_pack_ref"`
	SourceProfilePackVersion string `json:"source_profile_pack_version"`
}

func MaterializeLocalProfile(opts MaterializeOptions) (*MaterializeResult, error) {
	if strings.TrimSpace(opts.ProfileID) == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	if strings.TrimSpace(opts.TargetDir) == "" {
		return nil, fmt.Errorf("target directory is required")
	}
	pack, err := LoadLocalDir(opts.SourceDir)
	if err != nil {
		return nil, err
	}
	profile, ok := findProfile(pack, opts.ProfileID)
	if !ok {
		return nil, fmt.Errorf("profile %q not found in profile pack", opts.ProfileID)
	}
	absTarget, err := filepath.Abs(opts.TargetDir)
	if err != nil {
		return nil, err
	}
	ops, err := materializeOps(pack, profile)
	if err != nil {
		return nil, err
	}
	if err := preflightMaterializeWrites(absTarget, ops, opts.Force); err != nil {
		return nil, err
	}
	written, err := writeMaterializedFiles(absTarget, ops)
	if err != nil {
		return nil, err
	}
	return &MaterializeResult{
		ProfileRef:               profile.ID,
		ProfileVersion:           profile.Version,
		ProfileDigest:            profile.Digest,
		SourceProfilePackRef:     pack.ID,
		SourceProfilePackVersion: pack.Version,
		SourceProfilePackDigest:  pack.Source.Digest,
		TargetDir:                absTarget,
		FilesWritten:             written,
	}, nil
}

func materializeOps(pack *Pack, profile Profile) ([]materializeWriteOp, error) {
	ref := materializedProfileRef{
		ProfileDigest:            profile.Digest,
		ProfileRef:               profile.ID,
		ProfileVersion:           profile.Version,
		SourceProfilePackDigest:  pack.Source.Digest,
		SourceProfilePackRef:     pack.ID,
		SourceProfilePackVersion: pack.Version,
	}
	refBytes, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		return nil, err
	}
	refBytes = append(refBytes, '\n')
	instructions, err := os.ReadFile(filepath.Join(pack.Source.Ref, filepath.FromSlash(profile.InstructionPath)))
	if err != nil {
		return nil, err
	}
	agents, err := composeAgentsMarkdown(pack, profile, instructions)
	if err != nil {
		return nil, err
	}
	ops := []materializeWriteOp{
		{Kind: opFile, Rel: "AGENTS.md", Data: agents},
		{Kind: opSymlink, Rel: "CLAUDE.md", LinkTarget: "AGENTS.md"},
		{Kind: opFile, Rel: filepath.ToSlash(filepath.Join(".aw", "profile", "ref.json")), Data: refBytes},
	}
	profileYAML, err := materializeCopyOp(pack.Source.Ref, filepath.ToSlash(filepath.Join(profile.Path, "profile.yaml")), filepath.ToSlash(filepath.Join(".aw", "profile", "profile.yaml")))
	if err != nil {
		return nil, err
	}
	ops = append(ops, profileYAML)
	instructionSource, err := materializeCopyOp(pack.Source.Ref, profile.InstructionPath, filepath.ToSlash(filepath.Join(".aw", "profile", "instructions.md")))
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
		op, err := materializeCopyOp(pack.Source.Ref, skill.Path, rootDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		profileDest := filepath.ToSlash(filepath.Join(".aw", "profile", "skills", filepath.FromSlash(sourceRel)))
		op, err = materializeCopyOp(pack.Source.Ref, skill.Path, profileDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		ops = append(ops, materializeWriteOp{Kind: opSymlink, Rel: filepath.ToSlash(filepath.Join(".claude", "skills", skillName, "SKILL.md")), LinkTarget: filepath.ToSlash(filepath.Join("..", "..", "..", "skills", skillName, "SKILL.md"))})
	}
	for _, artifact := range profile.Artifacts {
		sourceRel, err := resourceSourceRel(profile.ID, "artifacts", artifact.Path)
		if err != nil {
			return nil, err
		}
		rootDest := filepath.ToSlash(filepath.Join("artifacts", filepath.FromSlash(sourceRel)))
		op, err := materializeCopyOp(pack.Source.Ref, artifact.Path, rootDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
		profileDest := filepath.ToSlash(filepath.Join(".aw", "profile", "artifacts", filepath.FromSlash(sourceRel)))
		op, err = materializeCopyOp(pack.Source.Ref, artifact.Path, profileDest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return ops, nil
}

func composeAgentsMarkdown(pack *Pack, profile Profile, instructions []byte) ([]byte, error) {
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
	b.WriteString(" · pack ")
	b.WriteString(pack.ID)
	b.WriteString(" v")
	b.WriteString(pack.Version)
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

func findProfile(pack *Pack, id string) (Profile, bool) {
	for _, profile := range pack.LoadedProfiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func skillNameFromPath(profileID, packRelativePath string) (string, error) {
	rel, err := resourceSourceRel(profileID, "skills", packRelativePath)
	if err != nil {
		return "", err
	}
	parts := strings.Split(rel, "/")
	if len(parts) < 2 || parts[0] == "" {
		return "", fmt.Errorf("skill path %q must include a skill directory", packRelativePath)
	}
	return parts[0], nil
}

func resourceSourceRel(profileID, category, packRelativePath string) (string, error) {
	prefix := filepath.ToSlash(filepath.Join("profiles", profileID, category)) + "/"
	if !strings.HasPrefix(packRelativePath, prefix) {
		return "", fmt.Errorf("%s path %q is outside profile %s %s directory", category, packRelativePath, profileID, category)
	}
	rel := strings.TrimPrefix(packRelativePath, prefix)
	if err := validateRelativePath(category, rel); err != nil {
		return "", err
	}
	return rel, nil
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
	if op.Kind == opSymlink {
		if op.LinkTarget == "" || filepath.IsAbs(op.LinkTarget) || strings.Contains(op.LinkTarget, "://") {
			return fmt.Errorf("%s has invalid symlink target", rel)
		}
	}
	path := filepath.Join(targetRoot, filepath.FromSlash(rel))
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
