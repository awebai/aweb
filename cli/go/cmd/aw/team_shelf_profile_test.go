package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
)

// The shelf verb is only reachable from a home that can sign as a team member, so
// every test here needs a workspace before the plugin call will dispatch at all.
// Without it the call fails with "current directory is not initialized for aw",
// which is an error - and a test asserting only that an error occurred would pass on
// it while proving nothing about the shelf.
func newShelfTestHome(t *testing.T, libraryURL string) string {
	t.Helper()
	home := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	// The workspace library URL is deliberately unroutable: the PLUGIN manifest
	// origin is what dispatches get-shelf-profile, and pointing the workspace at a
	// real host would let a misrouted call reach the live service instead of failing.
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)
	writeLibraryShelfManifestPluginForTest(t, home, libraryURL)
	// pluginDir() resolves from AW_HOME (or ~/.aw), NOT from the working directory,
	// so without this the per-home manifest above is ignored and the real installed
	// library plugin dispatches to the live service instead of the stub.
	t.Setenv("AW_HOME", filepath.Join(home, ".aw"))
	return home
}

// The shelf and public payloads for the same role must differ in CONTENT, not only
// in digest. A digest mismatch tells a reader that two things differ; a file whose
// text is visibly the shelf's tells them which one landed, without reconstructing
// anything. The mutation in TestShelfResolutionMutation depends on this too: with
// identical fixtures, deleting the shelf branch reds nothing.
const (
	// The shelf version the fixtures declare AND report. materialize cross-checks
	// profile.yaml against the payload version, so these cannot drift apart.
	testShelfProfileVersion    = "0.1.11"
	testShelfInstructionsBody  = "Shelf instructions: the team's evolved copy.\n"
	testPublicInstructionsBody = "Public instructions: the stock catalog copy.\n"
)

func testShelfProfileFiles(t *testing.T, scope string) []blueprint.LibraryProfilePayloadFile {
	t.Helper()
	return withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: testProfileYAML("coordinator", scope, testShelfProfileVersion)},
		{Path: "instructions.md", ContentUTF8: testShelfInstructionsBody},
	})
}

func testPublicProfileFiles(t *testing.T, scope string) []blueprint.LibraryProfilePayloadFile {
	t.Helper()
	return withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: testProfileYAML("coordinator", scope, "0.1.0")},
		{Path: "instructions.md", ContentUTF8: testPublicInstructionsBody},
	})
}

func testProfileYAML(profileRef, scope, version string) string {
	body := "id: " + profileRef + "\nname: Coordinator\nversion: " + version + "\n" +
		"mission: Coordinate the team.\naccepted_work: [coordination]\n" +
		"instructions: instructions.md\nruntime_assumptions: [local shell]\n" +
		"memory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"
	if strings.TrimSpace(scope) != "" {
		body += "scope: " + scope + "\n"
	}
	return body
}

// testLibraryProfilePayloadDigest in library_profile_test.go pins the version to
// 0.1.0 (or 0.2.0 by sniffing the body), and materialize cross-checks profile.yaml
// against the version it is given - so a fixture on any other version needs its own
// digest computed at that version.
func testShelfPayloadDigest(t *testing.T, version string, files []blueprint.LibraryProfilePayloadFile) string {
	t.Helper()
	result, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        t.TempDir(),
		BlueprintRef:     "aweb.team",
		BlueprintVersion: "0.1.0",
		ProfileRef:       "coordinator",
		ProfileVersion:   version,
		RuntimeKind:      "local-shell",
		Files:            files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.ProfileDigest
}

// shelfStub serves get-shelf-profile for one profile_ref and counts what was asked
// of it, so a test can assert the shelf was actually consulted rather than that the
// answer happened to be right.
type shelfStub struct {
	Status       int
	ProfileRef   string
	Version      string
	Digest       string
	BlueprintRef string
	Files        []blueprint.LibraryProfilePayloadFile
	ShelfGets    int
	PublicGets   int
}

func (s *shelfStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/blueprints/"):
			s.PublicGets++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blueprint_ref": "aweb.team", "blueprint_version": "0.1.0",
				"profile_ref": s.ProfileRef, "version": "0.1.0",
				"digest": testShelfPayloadDigest(t, "0.1.0", testPublicProfileFiles(t, "local")),
				"files":  testPublicProfileFiles(t, "local"),
			})
		case strings.HasPrefix(r.URL.Path, "/v1/profiles/"):
			s.ShelfGets++
			if s.Status != 0 && s.Status != http.StatusOK {
				w.WriteHeader(s.Status)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Shelf profile not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref": s.ProfileRef, "version": s.Version, "digest": s.Digest,
				"source_blueprint_ref": s.BlueprintRef, "source_blueprint_version": "0.1.0",
				"files": s.Files,
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
}

// Criterion 1: a team carrying a shelf profile gets the SHELF bytes, proved by
// reading them back off disk rather than by trusting a digest the command reported.
func TestShelfProfileResolutionMaterializesShelfBytes(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "aweb.team",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	// The scope is EXPLICIT on purpose. That is the shape of the reported command -
	// `aw team admin extend aweb.team/developer:local=claude-code` - and it is the path the
	// divergence guard deliberately skips, because an explicitly declared scope
	// overrides both profiles and there is nothing to compare. So this is the one path
	// no guard test exercises, and it is the one the bug was reported on.
	//
	// Do not simplify this to a scope-inferring selector. The shelf fetch must be
	// unconditional with respect to scope explicitness: if it ever becomes a rider on
	// the guard's condition, an inferring spec would still resolve the shelf while an
	// explicit one silently materialized public bytes, and every guard test would stay
	// green. This test asserts both halves - the shelf was consulted, AND the bytes on
	// disk are the shelf's - because either alone can be satisfied by a fetch whose
	// result is dropped, or by a payload that happens to match.
	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code",
		IdentityScope: "local",
	}
	resolved, err := resolveTeamProfileSource(home, selector)
	if err != nil {
		t.Fatalf("resolveTeamProfileSource: %v", err)
	}
	if !resolved.FromShelf {
		t.Fatalf("shelf profile present but resolution chose public: %+v", resolved)
	}
	if stub.ShelfGets == 0 {
		t.Fatal("the shelf was never consulted; a right answer without a query proves nothing")
	}
	// An explicit :local scope consults no profile.yaml on either side, so a public
	// fetch here would be pure waste and a sign the shelf branch is half-wired.
	if stub.PublicGets != 0 {
		t.Fatalf("explicit-scope shelf resolution fetched the public catalog %d times, want 0", stub.PublicGets)
	}

	if _, _, err := applyTeamLibraryProfileToHome(home, selector, &resolved, true); err != nil {
		t.Fatalf("applyTeamLibraryProfileToHome: %v", err)
	}
	assertHomeCarriesShelfProfile(t, home, stub.Digest)
}

func assertHomeCarriesShelfProfile(t *testing.T, home, shelfDigest string) {
	t.Helper()
	ref, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatalf("readRecordedProfileRef: %v", err)
	}
	if ref.ProfileDigest != shelfDigest {
		t.Fatalf("recorded digest %q, want the shelf digest %q", ref.ProfileDigest, shelfDigest)
	}
	// The load-bearing omission: refreshLibraryProfileInHome branches on library_url
	// alone, so recording it would send the next refresh back to the public catalog
	// and silently undo this.
	if strings.TrimSpace(ref.LibraryURL) != "" {
		t.Fatalf("shelf-sourced home recorded library_url %q; the next refresh would revert it to public", ref.LibraryURL)
	}
	body, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read materialized instructions: %v", err)
	}
	if !strings.Contains(string(body), strings.TrimSpace(testShelfInstructionsBody)) {
		t.Fatalf("materialized bytes are not the shelf's: %q", string(body))
	}
	if strings.Contains(string(body), strings.TrimSpace(testPublicInstructionsBody)) {
		t.Fatalf("materialized bytes contain the public copy: %q", string(body))
	}
}

// Describe carries two acceptance criteria - the output states which source was used
// with version and digest, and no line claims something that did not happen - so it
// needs assertions of its own rather than being covered incidentally by whatever
// output line eventually calls it.
func TestDescribeReportsOnlyWhatTheSourceHasRead(t *testing.T) {
	selector := libraryProfileSelector{
		LibraryURL: "https://library.example", SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator",
	}

	shelf := teamProfileSource{FromShelf: true, Shelf: &libraryShelfProfileResponse{
		ProfileRef: "coordinator", Version: "0.1.11", Digest: "sha256:abc123",
		SourceBlueprintRef: "aweb.team",
	}}
	got := shelf.Describe(selector)
	for _, want := range []string{"team shelf", "coordinator", "0.1.11", "sha256:abc123", "aweb.team"} {
		if !strings.Contains(got, want) {
			t.Fatalf("shelf description omits %q, which an acceptance criterion requires: %q", want, got)
		}
	}

	unknown := teamProfileSource{FromShelf: true, LineageUnknown: true, Shelf: &libraryShelfProfileResponse{
		ProfileRef: "coordinator", Version: "0.1.11", Digest: "sha256:abc123",
	}}
	if !strings.Contains(unknown.Describe(selector), "no recorded source blueprint") {
		t.Fatalf("an absent lineage must be stated rather than left blank: %q", unknown.Describe(selector))
	}

	// The public branch holds no payload - the public profile is not fetched until
	// materialization - so it must not report a version or digest AT ALL.
	//
	// Asserted as EXACT EQUALITY rather than as the absence of selected substrings.
	// The criterion is a property - no output line claims something that did not
	// happen - and a denylist only ever forbids the violations its author enumerated:
	// forbidding "latest" leaves "version 9.9.9" green. Equality fails closed for the
	// whole class, including the claims nobody thought of, and it is shorter than the
	// denylist it replaces.
	//
	// The shelf arm above stays substring-based on purpose: there the criterion is that
	// specific things are PRESENT. Direction decides the instrument - presence wants
	// containment, absence wants equality.
	//
	// ShelfConsulted is set here because this arm is the shelf answering 404 - an
	// ESTABLISHED absence. The unconsulted arm is a different line and is asserted in
	// TestShelfNotConsultableIsReportedAsNotConsultedNotAbsent, also by equality.
	public := teamProfileSource{ShelfConsulted: true}
	if got, want := public.Describe(selector), "public catalog https://library.example: coordinator"; got != want {
		t.Fatalf("public description must state the source and the ref and claim nothing else:\n  got  %q\n  want %q", got, want)
	}

	// And the zero value must not claim an established absence. A source nobody filled
	// in has consulted nothing, so the honest line is the not-consulted one - the
	// polarity of ShelfConsulted is chosen to make the forgetful case fail toward
	// saying less rather than toward asserting a 404 that never happened.
	if got, want := (teamProfileSource{}).Describe(selector), "public catalog https://library.example: coordinator (team shelf not consulted: Library plugin is not installed)"; got != want {
		t.Fatalf("an unfilled source must not report an established absence:\n  got  %q\n  want %q", got, want)
	}

	// FromShelf set without a payload is a caller error, not a panic.
	if broken := (teamProfileSource{FromShelf: true}).Describe(selector); !strings.Contains(broken, "public catalog") {
		t.Fatalf("a shelf source with no payload must degrade rather than dereference nil: %q", broken)
	}
}

// Criterion 2: absence falls back to public, and the shelf must actually have been
// asked. A fixture where the shelf is never queried cannot fail.
func TestShelfProfileAbsenceFallsBackToPublic(t *testing.T) {
	stub := &shelfStub{ProfileRef: "coordinator", Status: http.StatusNotFound}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	resolved, err := resolveTeamProfileSource(home, selector)
	if err != nil {
		t.Fatalf("a 404 from the shelf is absence, not an error: %v", err)
	}
	if resolved.FromShelf {
		t.Fatal("no shelf profile exists but resolution chose the shelf")
	}
	if stub.ShelfGets != 1 {
		t.Fatalf("shelf gets=%d, want exactly 1: absence has to be observed, not assumed", stub.ShelfGets)
	}
}

// The distinction eve required: unreachable is not absence. Falling back here would
// reproduce this very bug with a more confident message.
func TestShelfProfileUnreachableIsAnErrorNotAFallback(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusBadGateway} {
		stub := &shelfStub{ProfileRef: "coordinator", Status: status}
		server := stub.server(t)
		home := newShelfTestHome(t, server.URL)
		selector := libraryProfileSelector{
			LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
			ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
		}
		_, err := resolveTeamProfileSource(home, selector)
		shelfGets := stub.ShelfGets
		server.Close()
		if err == nil {
			t.Fatalf("status %d was treated as absence; an unreachable shelf must fail closed", status)
		}
		// Asserting only that AN error occurred would pass on a workspace that was
		// never initialized, which is how this test passed before it could reach the
		// shelf at all. Require the error to be THIS status, and require the shelf to
		// have been asked.
		got, ok := libraryToolStatus(err)
		if !ok || got != status {
			t.Fatalf("error did not carry status %d (got %d, typed=%v): %v", status, got, ok, err)
		}
		if shelfGets != 1 {
			t.Fatalf("shelf gets=%d for status %d, want exactly 1", shelfGets, status)
		}
	}
}

// Finding 1: the shelf is keyed by profile_ref alone, so a shelf entry from another
// blueprint would otherwise be materialized under the requested lineage silently.
func TestShelfProfileLineageMismatchRefuses(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "other.blueprint",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	_, err := resolveTeamProfileSource(home, selector)
	if err == nil {
		t.Fatal("a shelf profile from a different blueprint was accepted for the requested one")
	}
	if !strings.Contains(err.Error(), "other.blueprint") || !strings.Contains(err.Error(), "aweb.team") {
		t.Fatalf("the error must name both lineages so the operator can tell what happened: %v", err)
	}
}

// The lineage check is the only thing between a request for one blueprint's role and
// a shelf entry imported from another, so a request that carries no blueprint ref must
// be refused rather than silently accepting any lineage. Every caller today defaults
// the field, which makes this unreachable in practice - and "unreachable because of a
// caller" is not the same as safe, so the guard is asserted here rather than trusted.
func TestShelfProfileRequestWithoutLineageIsRefused(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "other.blueprint",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	_, err := resolveTeamProfileSource(home, selector)
	if err == nil {
		t.Fatal("a request with no source blueprint ref was accepted; any shelf lineage would match")
	}
	if !strings.Contains(err.Error(), "source blueprint ref is required") {
		t.Fatalf("refusal must name the missing field: %v", err)
	}
	// It has to refuse BEFORE consulting the shelf: asking first and then rejecting the
	// answer would make the refusal depend on what the shelf happens to hold.
	if stub.ShelfGets != 0 {
		t.Fatalf("shelf was consulted %d times before the request was validated, want 0", stub.ShelfGets)
	}
}

// An empty lineage is a state the service produces deliberately -
// create-shelf-profile takes files with no source blueprint, and delete-blueprint
// detaches rather than orphans - so it is usable, not a mismatch.
func TestShelfProfileEmptyLineageIsUsable(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	resolved, err := resolveTeamProfileSource(home, selector)
	if err != nil {
		t.Fatalf("a shelf profile with no recorded lineage must be usable: %v", err)
	}
	if !resolved.FromShelf || !resolved.LineageUnknown {
		t.Fatalf("empty lineage must resolve to the shelf and be reported as unknown: %+v", resolved)
	}
}

// Criterion 4, and the one a create-only test cannot see: after a shelf-sourced
// create, a refresh must leave the home on the shelf profile rather than silently
// restoring the public one.
func TestShelfSourcedHomeStaysOnShelfAfterRefresh(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "aweb.team",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	resolved, err := resolveTeamProfileSource(home, selector)
	if err != nil {
		t.Fatalf("resolveTeamProfileSource: %v", err)
	}
	if _, _, err := applyTeamLibraryProfileToHome(home, selector, &resolved, true); err != nil {
		t.Fatalf("applyTeamLibraryProfileToHome: %v", err)
	}
	assertHomeCarriesShelfProfile(t, home, stub.Digest)

	old, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatalf("readRecordedProfileRef: %v", err)
	}
	if _, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code"); err != nil {
		t.Fatalf("refresh after a shelf-sourced create: %v", err)
	}
	assertHomeCarriesShelfProfile(t, home, stub.Digest)
}

// A home with no Library plugin cannot ASK the shelf - the shelf read dispatches
// through the plugin manifest while the public read is a direct HTTP GET, so the two
// have different prerequisites. That makes three outcomes, not two: shelf present,
// shelf established-absent, and could-not-ask. Collapsing the third into absence is
// the original bug in a new place; making it an error breaks every plugin-free
// create and add, which is most of them.
func TestShelfNotConsultableIsReportedAsNotConsultedNotAbsent(t *testing.T) {
	home := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	// A workspace, so the failure is the MISSING PLUGIN and not an uninitialized
	// directory - those are different causes and only one is the case under test.
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)
	t.Setenv("AW_HOME", filepath.Join(home, ".aw"))

	selector := libraryProfileSelector{LibraryURL: "https://library.example", ProfileRef: "coordinator", SourceBlueprintRef: "aweb.team", RuntimeKind: "local-shell"}
	source, err := resolveTeamProfileSource(home, selector)
	if err != nil {
		t.Fatalf("a home without the Library plugin must resolve to the public catalog, not fail: %v", err)
	}
	if source.FromShelf {
		t.Fatal("no plugin means no shelf answer; FromShelf must be false")
	}
	if source.ShelfConsulted {
		t.Fatal("the shelf was never asked, so ShelfConsulted must be false")
	}
	// The reported line must not claim an absence it never established.
	got := source.Describe(selector)
	want := "public catalog https://library.example: coordinator (team shelf not consulted: Library plugin is not installed)"
	if got != want {
		t.Fatalf("describe\n got %q\nwant %q", got, want)
	}
}

// eve's open requirement: the reported line must be built FROM Describe and asserted
// on WHAT THE COMMAND PRINTED. A test on Describe alone cannot close it - the failure
// mode is a correct, tested, UNCALLED Describe sitting beside a different inline line
// that actually ships.
//
// So this chains the whole path: a real shelf resolution against the stub, through
// the preflight that assigns the plan's reported source, into the formatter that
// renders the command's human output. Nothing here constructs the expected string by
// hand except the values the shelf itself returned.
func TestRosterOutputNamesTheShelfSourceItMaterialized(t *testing.T) {
	files := testShelfProfileFiles(t, "local")
	stub := &shelfStub{
		ProfileRef: "coordinator", Version: testShelfProfileVersion, BlueprintRef: "aweb.team",
		Digest: testShelfPayloadDigest(t, testShelfProfileVersion, files), Files: files,
	}
	server := stub.server(t)
	defer server.Close()
	home := newShelfTestHome(t, server.URL)

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	plans := []teamHumanAddedAgent{{Name: "aw-coord", HomeDir: filepath.Join(home, "aw-coord"), Profile: &selector}}
	if err := resolveTeamProfileSourcesForPlans(home, plans); err != nil {
		t.Fatal(err)
	}
	if stub.ShelfGets != 1 {
		t.Fatalf("preflight must consult the shelf exactly once, got %d", stub.ShelfGets)
	}

	human := formatTeamHumanAdd(teamHumanAddOutput{
		Status: "extended", AgentsRoot: home, Agents: plans,
	})

	// The printed line must carry the version and digest the SHELF reported, so a
	// public materialization cannot produce this output.
	for _, want := range []string{"team shelf", "coordinator", testShelfProfileVersion, stub.Digest} {
		if !strings.Contains(human, want) {
			t.Fatalf("the command's output omits %q, so a reader cannot tell which source landed:\n%s", want, human)
		}
	}
	// And it must not still be claiming the old unconditional success line, which was
	// true of the shelf and the public catalog alike.
	if strings.Contains(human, "Library profile(s) adopted and materialized.") {
		t.Fatalf("the unconditional line survived alongside the source line:\n%s", human)
	}
}

// The ordinary path: a roster on a team with no reachable shelf must still
// materialize, must land the PUBLIC bytes, and must say that the shelf was not
// consulted rather than reporting an absence it never established.
//
// This exists because the existing suite does not cover it. A mutation making
// "not consultable" an error reds exactly one test - a create-path one - so the
// roster path's shelf wiring has no end-to-end coverage to inherit.
func TestRosterWithNoReachableShelfMaterializesPublicAndSaysSo(t *testing.T) {
	stub := &shelfStub{ProfileRef: "coordinator", Status: http.StatusNotFound}
	server := stub.server(t)
	defer server.Close()

	home := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)
	// No plugin manifest written: this is the plugin-free home that every bootstrap
	// starts from, and the case that must not become an error.
	t.Setenv("AW_HOME", filepath.Join(home, ".aw"))

	selector := libraryProfileSelector{
		LibraryURL: server.URL, SourceBlueprintRef: "aweb.team",
		ProfileRef: "coordinator", RuntimeKind: "claude-code", IdentityScope: "local",
	}
	target := filepath.Join(home, "aw-coord")
	plans := []teamHumanAddedAgent{{Name: "aw-coord", HomeDir: target, Profile: &selector}}
	if err := resolveTeamProfileSourcesForPlans(home, plans); err != nil {
		t.Fatalf("a plugin-free roster must resolve, not fail: %v", err)
	}
	if stub.ShelfGets != 0 {
		t.Fatalf("with no plugin the shelf cannot have been reached, got %d gets", stub.ShelfGets)
	}
	if plans[0].Source == nil || plans[0].Source.FromShelf {
		t.Fatalf("expected a public source, got %+v", plans[0].Source)
	}
	// The roster loop creates the home before materializing into it; the resolution
	// above deliberately happens before that, which is why it is authorized from the
	// anchor rather than from a directory that does not exist yet.
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyTeamLibraryProfileToHome(target, selector, plans[0].Source, true); err != nil {
		t.Fatal(err)
	}
	// The PUBLIC bytes, read back off disk - not a digest the command reported.
	body, err := os.ReadFile(filepath.Join(target, ".aw", "profile", "instructions.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != testPublicInstructionsBody {
		t.Fatalf("public path did not land the public bytes:\n got %q\nwant %q", body, testPublicInstructionsBody)
	}
	human := formatTeamHumanAdd(teamHumanAddOutput{Status: "extended", AgentsRoot: home, Agents: plans})
	if !strings.Contains(human, "team shelf not consulted") {
		t.Fatalf("output must say the shelf was never asked rather than imply an absence:\n%s", human)
	}
}

// Criterion 3 is unqualified: no output line claims an action that did not occur.
// A create from a LOCAL BLUEPRINT DIRECTORY sets ProfileMode "library" in the shared
// block but never sets a source, so it fell through to the old unconditional line and
// claimed two things that are both false on that path - nothing was ADOPTED, and it is
// not a Library profile at all.
//
// Asserted against the real formatter fed the struct the command itself produced, so
// it fails if the command stops setting the source as well as if the line comes back.
func TestLocalBlueprintCreateDoesNotClaimALibraryAdoption(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	fixture := filepath.Join(engineeringBlueprintFixtureRoot(t), "source")
	// The configure step injects coordination docs and refuses on an uninitialized
	// directory. Without a workspace this test fails during SETUP, which would look
	// like a red on the property while proving nothing about the output line.
	// The configure step fetches the team's active instructions, so the workspace has
	// to point at something that answers. Serving only that one route keeps any other
	// call a visible failure rather than a silent success.
	aweb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/instructions/active" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": "# Team instructions\n"})
	}))
	defer aweb.Close()

	home := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, aweb.URL, "default:acme.com", "developer", did, priv)
	t.Setenv("AW_HOME", filepath.Join(home, ".aw"))

	selector := libraryProfileSelector{
		SourceBlueprintRef: "aweb.team", ProfileRef: "developer", RuntimeKind: "claude-code",
	}
	out := teamHumanCreateOutput{Status: "created", TeamName: "acme"}
	if err := finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{
		HomeDir: home, Selector: &selector, LocalBlueprintDir: fixture, HumanOutput: &out,
	}, nil); err != nil {
		t.Fatal(err)
	}
	human := formatTeamHumanCreate(out)
	if strings.Contains(human, "adopted") {
		t.Fatalf("a local-blueprint create claims an adoption that did not happen:\n%s", human)
	}
	if !strings.Contains(human, fixture) {
		t.Fatalf("the line must name the local blueprint it materialized from:\n%s", human)
	}
}

// The unset-source branch is unreachable today - every materialize path sets a
// source - but nothing in the type system forbids the state, and it took
// enumerating every call site to establish even that. It is reachable by the next
// branch that forgets, which is exactly how the defect it replaced arose.
//
// So it gets a test that REACHES it. A guard nobody can trigger is the thing this
// team keeps finding; this one fires, and it fires without claiming an adoption.
func TestCreateOutputAnnouncesAMissingSourceRatherThanClaimingAdoption(t *testing.T) {
	// The state a forgetful future branch would produce: library mode, no source.
	human := formatTeamHumanCreate(teamHumanCreateOutput{
		Status: "created", TeamName: "acme", ProfileMode: "library",
	})
	if !strings.Contains(human, "BUG:") {
		t.Fatalf("an unset source must announce itself loudly:\n%s", human)
	}
	if strings.Contains(human, "adopted") {
		t.Fatalf("the unset branch must not claim an adoption that did not happen:\n%s", human)
	}
	// And it must not silently print nothing about the profile either - the failure
	// mode of deleting the branch outright.
	if !strings.Contains(human, "materialized") {
		t.Fatalf("the unset branch must still report that a profile was materialized:\n%s", human)
	}
}
