package main

import (
	"errors"
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
	// ShelfConsulted records that the shelf actually answered - found or 404 - as
	// opposed to never having been askable. The zero value is false so that a source
	// nobody filled in reports "not consulted" rather than claiming an absence it
	// never established.
	ShelfConsulted bool
}

// A shelf lookup has three outcomes, not two. Collapsing "could not ask" into
// "absent" is the same defect as the fallback this change exists to remove: it
// reports a team's own profile as missing on evidence that never addressed the
// question.
type shelfLookupOutcome int

const (
	shelfProfileFound shelfLookupOutcome = iota
	shelfProfileAbsent
	shelfNotConsultable
)

// errTeamShelfNotConsultable marks the one shelf failure that is not a failure of
// the shelf: the Library plugin the shelf read dispatches through is not installed.
// The public read is a direct HTTP GET with no such prerequisite, so a plugin-free
// home can materialize a public profile while being unable to ask about a shelf at
// all - which is most homes, and every `aw team create` that bootstraps one.
//
// Injected into the call and matched with errors.Is rather than recognized from the
// message text, so rewording the user-facing install hint cannot silently turn this
// branch into an ordinary error.
var errTeamShelfNotConsultable = errors.New("the aw Library plugin is not installed, so this team's shelf cannot be consulted")

// Describe states the source of a resolution. It reports a version and digest only
// for the shelf, because only the shelf payload is in hand here - the public profile
// is not fetched until materialization, so this cannot state a public version without
// asserting something nothing has read. A caller that needs the published version and
// digest for either source must build that line from the MaterializeResult afterwards,
// which carries both.
func (s teamProfileSource) Describe(selector libraryProfileSelector) string {
	if !s.FromShelf || s.Shelf == nil {
		line := fmt.Sprintf("public catalog %s: %s", strings.TrimSpace(selector.LibraryURL), strings.TrimSpace(selector.ProfileRef))
		// A shelf that was asked and answered 404 is an established absence. A shelf
		// that could not be asked is not, and saying so is the difference between
		// reporting a fact and asserting one nothing checked.
		if !s.ShelfConsulted {
			line += " (team shelf not consulted: Library plugin is not installed)"
		}
		return line
	}
	lineage := strings.TrimSpace(s.Shelf.SourceBlueprintRef)
	if s.LineageUnknown {
		lineage = "no recorded source blueprint"
	}
	return fmt.Sprintf("team shelf: %s %s %s (%s)", strings.TrimSpace(s.Shelf.ProfileRef), strings.TrimSpace(s.Shelf.Version), strings.TrimSpace(s.Shelf.Digest), lineage)
}

// resolveTeamProfileSource decides whether this role comes from the team's
// shelf or the public catalog, and refuses rather than guessing when the shelf
// answers something that does not match what was asked for.
func resolveTeamProfileSource(teamAuthorityDir string, selector libraryProfileSelector) (teamProfileSource, error) {
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
	shelf, outcome, err := lookupTeamShelfProfile(teamAuthorityDir, profileRef)
	if err != nil {
		return teamProfileSource{}, err
	}
	switch outcome {
	case shelfNotConsultable:
		return teamProfileSource{}, nil
	case shelfProfileAbsent:
		return teamProfileSource{ShelfConsulted: true}, nil
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
	return teamProfileSource{Shelf: shelf, FromShelf: true, LineageUnknown: recorded == "", ShelfConsulted: true}, nil
}

// lookupTeamShelfProfile separates absence from failure from unanswerable. Only a
// 404 means "this team has no shelf profile for that role". A 403, a 5xx or a
// transport failure are errors, because falling back to the public catalog on any of
// them substitutes stock bytes for a team's own while reporting success. An
// uninstalled Library plugin is neither: the shelf was never askable from here, so
// the public catalog is the only available source and the caller must say so rather
// than report an absence.
func lookupTeamShelfProfile(teamAuthorityDir, profileRef string) (*libraryShelfProfileResponse, shelfLookupOutcome, error) {
	var shelf *libraryShelfProfileResponse
	err := withWorkingDir(teamAuthorityDir, func() error {
		var callErr error
		shelf, callErr = callLibraryGetShelfProfileWithMissingErr(profileRef, errTeamShelfNotConsultable)
		return callErr
	})
	if err != nil {
		if errors.Is(err, errTeamShelfNotConsultable) {
			return nil, shelfNotConsultable, nil
		}
		if status, ok := libraryToolStatus(err); ok && status == http.StatusNotFound {
			return nil, shelfProfileAbsent, nil
		}
		return nil, shelfProfileAbsent, fmt.Errorf("library get-shelf-profile %s: %w", profileRef, err)
	}
	// Pin the answer to what was asked. A response for a different profile_ref would
	// otherwise be written into this home under the requested name.
	if strings.TrimSpace(shelf.ProfileRef) != strings.TrimSpace(profileRef) {
		return nil, shelfProfileAbsent, fmt.Errorf("library returned shelf profile_ref %q for a lookup of %q; refusing to materialize a different profile", shelf.ProfileRef, profileRef)
	}
	return shelf, shelfProfileFound, nil
}

// resolveTeamProfileSourcesForPlans resolves where every plan's profile comes from
// BEFORE any home is created, so a roster either knows the source of all of them or
// fails having written nothing. The target homes do not exist yet at this point,
// which is why the read is authorized from teamAuthorityDir instead.
//
// Each role is resolved ONCE and the payload carried forward. Resolving again at
// materialization would reopen the window teamProfileSource exists to close: an
// approved proposal can mint a new version between the check and the write, so the
// bytes that were inspected need not be the bytes that land.
//
// Plans materializing from a local blueprint directory are skipped: their bytes come
// from disk and there is no shelf in the question.
func resolveTeamProfileSourcesForPlans(teamAuthorityDir string, plans []teamHumanAddedAgent) error {
	// One role can appear on several plans, and the shelf answers the same for each.
	resolved := map[string]teamProfileSource{}
	for i := range plans {
		if plans[i].Profile == nil || strings.TrimSpace(plans[i].LocalBlueprintDir) != "" {
			continue
		}
		key := strings.TrimSpace(plans[i].Profile.ProfileRef) + "\x00" + strings.TrimSpace(plans[i].Profile.SourceBlueprintRef)
		source, ok := resolved[key]
		if !ok {
			var err error
			source, err = resolveTeamProfileSource(teamAuthorityDir, *plans[i].Profile)
			if err != nil {
				return fmt.Errorf("resolve profile source for %s: %w", strings.TrimSpace(plans[i].Name), err)
			}
			resolved[key] = source
		}
		plans[i].Source = &source
		plans[i].ProfileSource = source.Describe(*plans[i].Profile)
	}
	return nil
}

// applyTeamLibraryProfileToHome materializes whichever source was resolved. The
// shelf branch records NO library_url on purpose: refreshLibraryProfileInHome
// branches on that field alone, so recording it would make this home correct exactly
// once and send its next refresh back to the public catalog.
func applyTeamLibraryProfileToHome(homeDir string, selector libraryProfileSelector, source *teamProfileSource, force bool) (*blueprint.MaterializeResult, []string, error) {
	// An unresolved source is a wiring mistake, not a public profile. Defaulting it
	// would make a call site that skipped the preflight materialize stock bytes and
	// report success - the exact failure this change exists to remove.
	if source == nil {
		return nil, nil, fmt.Errorf("internal: the profile source for %s was not resolved before materialization", homeDir)
	}
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
