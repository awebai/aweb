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
	written := []string{}
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
	if err := writeMaterializedFile(absTarget, filepath.Join(".aw", "profile", "ref.json"), refBytes, opts.Force, &written); err != nil {
		return nil, err
	}
	if err := copyMaterializedFile(pack.Source.Ref, absTarget, profile.InstructionPath, "instructions.md", opts.Force, &written); err != nil {
		return nil, err
	}
	for _, skill := range profile.Skills {
		dest, err := resourceDestPath(profile.ID, "skills", skill.Path)
		if err != nil {
			return nil, err
		}
		if err := copyMaterializedFile(pack.Source.Ref, absTarget, skill.Path, dest, opts.Force, &written); err != nil {
			return nil, err
		}
	}
	for _, artifact := range profile.Artifacts {
		dest, err := resourceDestPath(profile.ID, "artifacts", artifact.Path)
		if err != nil {
			return nil, err
		}
		if err := copyMaterializedFile(pack.Source.Ref, absTarget, artifact.Path, dest, opts.Force, &written); err != nil {
			return nil, err
		}
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

func copyMaterializedFile(sourceRoot, targetRoot, sourceRel, destRel string, force bool, written *[]string) error {
	if err := validateRelativePath("source", sourceRel); err != nil {
		return err
	}
	if err := validateRelativePath("destination", destRel); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(sourceRel)))
	if err != nil {
		return err
	}
	return writeMaterializedFile(targetRoot, destRel, data, force, written)
}

func writeMaterializedFile(targetRoot, rel string, data []byte, force bool, written *[]string) error {
	if err := validateRelativePath("destination", rel); err != nil {
		return err
	}
	path := filepath.Join(targetRoot, filepath.FromSlash(rel))
	if !isWithin(targetRoot, path) {
		return fmt.Errorf("destination %s escapes target directory", rel)
	}
	if _, err := os.Lstat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", rel)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	*written = append(*written, filepath.ToSlash(rel))
	return nil
}
