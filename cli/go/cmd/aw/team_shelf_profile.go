package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/awebai/aw/internal/blueprint"
)

// A team's shelf holds the profiles that team has evolved - the output of the
// propose/approve/mint loop. Creating an agent has to materialize those rather than
// the public catalog's stock copy, or approved team learning reaches nobody until
// somebody runs two further commands by hand.
//
// The shelf is resolved ONCE, in preflight, and the payload is carried forward to
// materialization. Resolving twice - once to inspect, once to write - would leave a
// window in which an approved proposal mints a new version, so the bytes that were
// checked need not be the bytes that land.
type teamProfileSource struct {
	// Shelf is the payload to materialize, nil when the public catalog is the source.
	Shelf *libraryShelfProfileResponse
	// FromShelf records the decision itself rather than leaving callers to infer it
	// from Shelf being non-nil, so an honest output line has something to read.
	FromShelf bool
	// LineageUnknown marks a shelf profile that records no source blueprint. That is
	// a state the service produces deliberately: create-shelf-profile authors a
	// profile from files with no blueprint, and delete-blueprint detaches shelf
	// profiles rather than orphaning them.
	LineageUnknown bool
}

// Describe states the source of a resolution. It reports a version and digest only
// for the shelf, because only the shelf payload is in hand here - the public profile
// is not fetched until materialization, so this cannot state a public version without
// asserting something nothing has read. A caller that needs the published version and
// digest for either source must build that line from the MaterializeResult afterwards,
// which carries both.
func (s teamProfileSource) Describe(selector libraryProfileSelector) string {
	if !s.FromShelf || s.Shelf == nil {
		return fmt.Sprintf("public catalog %s: %s", strings.TrimSpace(selector.LibraryURL), strings.TrimSpace(selector.ProfileRef))
	}
	lineage := strings.TrimSpace(s.Shelf.SourceBlueprintRef)
	if s.LineageUnknown {
		lineage = "no recorded source blueprint"
	}
	return fmt.Sprintf("team shelf: %s %s %s (%s)", strings.TrimSpace(s.Shelf.ProfileRef), strings.TrimSpace(s.Shelf.Version), strings.TrimSpace(s.Shelf.Digest), lineage)
}

// resolveTeamProfileSourceForHome decides whether this role comes from the team's
// shelf or the public catalog, and refuses rather than guessing when the shelf
// answers something that does not match what was asked for.
func resolveTeamProfileSourceForHome(homeDir string, selector libraryProfileSelector) (teamProfileSource, error) {
	profileRef := strings.TrimSpace(selector.ProfileRef)
	if profileRef == "" {
		return teamProfileSource{}, fmt.Errorf("profile ref is required to resolve a team profile source")
	}
	// The requested blueprint ref is required because the lineage check below is the
	// only thing standing between a request for one blueprint's role and a shelf entry
	// imported from another. With it empty that check cannot run, and every caller
	// today happens to default it - but "unreachable because of a caller" is not the
	// same as safe, and a future caller that omits it would silently accept any
	// lineage rather than fail.
	requested := strings.TrimSpace(selector.SourceBlueprintRef)
	if requested == "" {
		return teamProfileSource{}, fmt.Errorf("source blueprint ref is required to resolve a team profile source for %s; without it a shelf profile from any blueprint would be accepted", profileRef)
	}
	shelf, found, err := lookupTeamShelfProfile(homeDir, profileRef)
	if err != nil {
		return teamProfileSource{}, err
	}
	if !found {
		return teamProfileSource{}, nil
	}
	// The shelf is keyed by profile_ref alone - GET /v1/profiles/{profile_ref},
	// scoped to the team by certificate - so the blueprint the caller named is never
	// part of the lookup. Without this check a shelf entry imported from a different
	// blueprint would be materialized under the requested lineage silently, and every
	// digest assertion would still pass. team_refresh.go applies the same distrust to
	// the profile_ref dimension for the same reason.
	recorded := strings.TrimSpace(shelf.SourceBlueprintRef)
	if recorded != "" && recorded != requested {
		return teamProfileSource{}, fmt.Errorf(
			"team shelf profile %s records source blueprint %q but %q was requested; refusing to materialize a different lineage. Import the profile from %q, or request %q",
			profileRef, recorded, requested, requested, recorded)
	}
	return teamProfileSource{Shelf: shelf, FromShelf: true, LineageUnknown: recorded == ""}, nil
}

// lookupTeamShelfProfile reports absence separately from failure. Only a 404 means
// "this team has no shelf profile for that role"; a 403, a 5xx, a missing plugin or
// a transport failure are all errors, because falling back to the public catalog on
// any of them substitutes stock bytes for a team's own while reporting success.
func lookupTeamShelfProfile(homeDir, profileRef string) (*libraryShelfProfileResponse, bool, error) {
	var shelf *libraryShelfProfileResponse
	err := withWorkingDir(homeDir, func() error {
		var callErr error
		shelf, callErr = callLibraryGetShelfProfile(profileRef)
		return callErr
	})
	if err != nil {
		if status, ok := libraryToolStatus(err); ok && status == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("library get-shelf-profile %s: %w", profileRef, err)
	}
	// Pin the answer to what was asked. A response for a different profile_ref would
	// otherwise be written into this home under the requested name.
	if strings.TrimSpace(shelf.ProfileRef) != strings.TrimSpace(profileRef) {
		return nil, false, fmt.Errorf("library returned shelf profile_ref %q for a lookup of %q; refusing to materialize a different profile", shelf.ProfileRef, profileRef)
	}
	return shelf, true, nil
}

// applyTeamLibraryProfileToHome materializes whichever source was resolved. The
// shelf branch records NO library_url on purpose: refreshLibraryProfileInHome
// branches on that field alone, so recording it would make this home correct exactly
// once and send its next refresh back to the public catalog.
func applyTeamLibraryProfileToHome(homeDir string, selector libraryProfileSelector, source teamProfileSource, force bool) (*blueprint.MaterializeResult, []string, error) {
	if !source.FromShelf {
		return applyPublicLibraryProfileToHome(homeDir, selector, force)
	}
	runtimeKind, err := materializeRuntimeKindForSelector(selector)
	if err != nil {
		return nil, nil, err
	}
	shelf := source.Shelf
	var materialized *blueprint.MaterializeResult
	err = withWorkingDir(homeDir, func() error {
		var mErr error
		materialized, mErr = blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
			TargetDir:        homeDir,
			BlueprintRef:     strings.TrimSpace(shelf.SourceBlueprintRef),
			BlueprintVersion: strings.TrimSpace(shelf.SourceBlueprintVersion),
			BlueprintDigest:  strings.TrimSpace(shelf.SourceBlueprintDigest),
			ProfileRef:       strings.TrimSpace(shelf.ProfileRef),
			ProfileVersion:   strings.TrimSpace(shelf.Version),
			ProfileDigest:    strings.TrimSpace(shelf.Digest),
			RuntimeKind:      runtimeKind,
			Files:            shelf.Files,
			Force:            force,
		})
		if mErr != nil {
			return fmt.Errorf("local profile materialize: %w", mErr)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return materialized, materialized.FilesWritten, nil
}
