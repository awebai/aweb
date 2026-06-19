package profilepack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	ops := []materializeWriteOp{{Rel: filepath.ToSlash(filepath.Join(".aw", "profile", "ref.json")), Data: refBytes}}
	instruction, err := materializeCopyOp(pack.Source.Ref, profile.InstructionPath, "instructions.md")
	if err != nil {
		return nil, err
	}
	ops = append(ops, instruction)
	for _, skill := range profile.Skills {
		dest, err := resourceDestPath(profile.ID, "skills", skill.Path)
		if err != nil {
			return nil, err
		}
		op, err := materializeCopyOp(pack.Source.Ref, skill.Path, dest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	for _, artifact := range profile.Artifacts {
		dest, err := resourceDestPath(profile.ID, "artifacts", artifact.Path)
		if err != nil {
			return nil, err
		}
		op, err := materializeCopyOp(pack.Source.Ref, artifact.Path, dest)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
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

func findProfile(pack *Pack, id string) (Profile, bool) {
	for _, profile := range pack.LoadedProfiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return Profile{}, false
}

func resourceDestPath(profileID, category, packRelativePath string) (string, error) {
	prefix := filepath.ToSlash(filepath.Join("profiles", profileID, category)) + "/"
	if !strings.HasPrefix(packRelativePath, prefix) {
		return "", fmt.Errorf("%s path %q is outside profile %s %s directory", category, packRelativePath, profileID, category)
	}
	rel := strings.TrimPrefix(packRelativePath, prefix)
	if err := validateRelativePath(category, rel); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(category, filepath.FromSlash(rel))), nil
}

type materializeWriteOp struct {
	Rel  string
	Data []byte
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
	return materializeWriteOp{Rel: filepath.ToSlash(destRel), Data: data}, nil
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
		if err := validateMaterializeDestination(targetRoot, rel, force); err != nil {
			return err
		}
	}
	return nil
}

func ensureMaterializeTargetRoot(targetRoot string) error {
	clean := filepath.Clean(targetRoot)
	if err := rejectSymlinkedExistingDirs(clean, "target directory"); err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("target directory must not be a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("target must be a directory")
	}
	return nil
}

func rejectSymlinkedExistingDirs(path, label string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	current := volume
	if filepath.IsAbs(clean) {
		current += string(filepath.Separator)
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
	}
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		if current == "" || current == string(filepath.Separator) || strings.HasSuffix(current, string(filepath.Separator)) {
			current = current + part
		} else {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if isAllowedAmbientSymlinkPrefix(current) {
				continue
			}
			return fmt.Errorf("%s parent %s must not be a symlink", label, filepath.ToSlash(current))
		}
		if !info.IsDir() {
			return fmt.Errorf("%s parent %s must be a directory", label, filepath.ToSlash(current))
		}
	}
	return nil
}

func isAllowedAmbientSymlinkPrefix(path string) bool {
	tempDir := filepath.Clean(os.TempDir())
	rel, err := filepath.Rel(filepath.Clean(path), tempDir)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}

func validateMaterializeDestination(targetRoot, rel string, force bool) error {
	if err := validateRelativePath("destination", rel); err != nil {
		return err
	}
	path := filepath.Join(targetRoot, filepath.FromSlash(rel))
	if !isWithin(targetRoot, path) {
		return fmt.Errorf("destination %s escapes target directory", rel)
	}
	if err := rejectSymlinkedParents(targetRoot, rel); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", rel)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s must be a regular file", rel)
		}
		if !force {
			return fmt.Errorf("%s already exists; pass --force to overwrite", rel)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rejectSymlinkedParents(targetRoot, rel string) error {
	parentRel := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
	if parentRel == "." {
		return nil
	}
	current := targetRoot
	for _, part := range strings.Split(parentRel, "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination parent %s must not be a symlink", filepath.ToSlash(strings.TrimPrefix(current, targetRoot+string(filepath.Separator))))
		}
		if !info.IsDir() {
			return fmt.Errorf("destination parent %s must be a directory", filepath.ToSlash(strings.TrimPrefix(current, targetRoot+string(filepath.Separator))))
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
		if err := os.WriteFile(path, op.Data, 0o644); err != nil {
			return nil, err
		}
		written = append(written, filepath.ToSlash(op.Rel))
	}
	return written, nil
}
