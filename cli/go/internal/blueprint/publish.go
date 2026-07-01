package blueprint

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PublishableProfile is one profile's payload extracted from a local blueprint
// source, ready to POST to the Library's create-shelf-profile.
type PublishableProfile struct {
	ProfileRef             string
	ProfileVersion         string
	ProfileDigest          string
	SourceBlueprintRef     string
	SourceBlueprintVersion string
	Files                  []LibraryProfilePayloadFile
}

// ExtractProfilePayload loads a local blueprint source and extracts one profile's
// profile-relative payload files (with sha256) - the local-Go equivalent of the
// service's collect_files, ready for the Library's create-shelf-profile. profileRef
// may be empty when the source has exactly one profile; it is required when the
// source has more than one.
func ExtractProfilePayload(sourceDir, profileRef string) (*PublishableProfile, error) {
	bp, err := LoadLocalDir(sourceDir)
	if err != nil {
		return nil, err
	}
	profile, err := resolvePublishProfile(bp, profileRef)
	if err != nil {
		return nil, err
	}
	profileDir := filepath.Join(sourceDir, filepath.FromSlash(profile.Path))
	digest, canonical, err := canonicalPayloadDigest(profileDir, "aweb.blueprint.profile-payload.v1")
	if err != nil {
		return nil, err
	}
	files := make([]LibraryProfilePayloadFile, len(canonical))
	for i, f := range canonical {
		files[i] = LibraryProfilePayloadFile{Path: f.Path, SHA256: f.SHA256, ContentUTF8: f.ContentUTF8}
	}
	return &PublishableProfile{
		ProfileRef:             profile.ID,
		ProfileVersion:         profile.Version,
		ProfileDigest:          digest,
		SourceBlueprintRef:     bp.ID,
		SourceBlueprintVersion: bp.Version,
		Files:                  files,
	}, nil
}

// resolvePublishProfile selects the profile to publish: an explicit ref is looked
// up; an empty ref defaults to the sole profile and is an error when the source
// carries more than one.
func resolvePublishProfile(bp *Blueprint, profileRef string) (Profile, error) {
	if strings.TrimSpace(profileRef) != "" {
		p, ok := findProfile(bp, profileRef)
		if !ok {
			return Profile{}, fmt.Errorf("profile %q not found in %s", profileRef, bp.ID)
		}
		return p, nil
	}
	switch len(bp.LoadedProfiles) {
	case 0:
		return Profile{}, fmt.Errorf("blueprint %s has no profiles to publish", bp.ID)
	case 1:
		return bp.LoadedProfiles[0], nil
	default:
		refs := make([]string, 0, len(bp.LoadedProfiles))
		for _, p := range bp.LoadedProfiles {
			refs = append(refs, p.ID)
		}
		return Profile{}, fmt.Errorf("source has %d profiles (%s); --profile is required to select one", len(refs), strings.Join(refs, ", "))
	}
}
