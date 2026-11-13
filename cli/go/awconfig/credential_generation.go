package awconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

// An identity home's credentials (its identity, signing key, team selection,
// memberships, team certificates and installed chain) are what a
// long-running reader such as aw custody serve builds its client from. The
// credential projection is a digest of exactly those inputs, resolved the
// way the loader resolves them, for every membership, so any change to them
// by any writer changes it. A supported writer changes them as one update
// under the home's credential lock: it marks the home with its operation and
// the committed base it started from, writes, and publishes the next
// generation with the projection it left. A home whose projection is not the
// one its manifest publishes was changed by another writer and is never
// published over; an update interrupted before it published is recovered
// only by the same operation. This establishes coherence, not authority.

const (
	credentialManifestFile = "credential-generation.json"
	credentialMarkerFile   = "credential-update.json"
	credentialLockFile     = "credential-update.lock"
	// credentialReaderLockFile is held shared by a reader serving the home
	// (aw custody serve) for its lifetime, and exclusively by a supported
	// writer while no reader serves it.
	credentialReaderLockFile = "credential-reader.lock"
)

var (
	// ErrCredentialUpdateIncomplete is an update begun and not published,
	// which only the same operation may complete.
	ErrCredentialUpdateIncomplete = errors.New("credential_update_incomplete")
	// ErrCredentialUpdateUnpublished is a home whose credentials changed
	// without a published generation.
	ErrCredentialUpdateUnpublished = errors.New("credential_update_unpublished")
)

// CredentialOperation names one supported update: its command and a digest
// of the inputs that identify it, so a retry of the same update is
// recognized and any other is not.
type CredentialOperation struct {
	Command string `json:"command"`
	Intent  string `json:"intent"`
}

// CredentialIntent is the digest of an operation's identifying inputs.
func CredentialIntent(fields map[string]any) string {
	data, _ := json.Marshal(fields)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CredentialBase is the committed generation and projection an update
// started from.
type CredentialBase struct {
	Generation int64  `json:"generation"`
	Projection string `json:"projection"`
}

// CredentialMarker marks an update in progress or interrupted.
type CredentialMarker struct {
	TxID             string              `json:"txid"`
	Operation        CredentialOperation `json:"operation"`
	Base             CredentialBase      `json:"base"`
	TargetGeneration int64               `json:"target_generation"`
}

type credentialManifest struct {
	Generation int64  `json:"generation"`
	Projection string `json:"projection"`
}

// CredentialState is what a home publishes and what it holds now.
type CredentialState struct {
	// Generation and Projection are the manifest's, zero and "" when the home
	// has published none.
	Generation int64
	Projection string
	// Marker is the update in progress or interrupted, if any.
	Marker *CredentialMarker
	// Current is the projection of the home's credentials now.
	Current string
}

// Committed reports whether the home's marker, if any, belongs to an update
// that published its generation and the home's current projection.
func (s CredentialState) Committed() bool {
	return s.Marker != nil && s.Marker.TargetGeneration <= s.Generation && s.Projection == s.Current
}

// Published reports whether the home holds exactly what its manifest
// publishes, with no update incomplete.
func (s CredentialState) Published() bool {
	return (s.Marker == nil || s.Committed()) && s.Projection == s.Current
}

// ReadCredentialState reads home's manifest, marker and current projection.
func ReadCredentialState(home string) (CredentialState, error) {
	capture, err := CaptureCredentials(home)
	if err != nil {
		return CredentialState{}, err
	}
	return capture.State, nil
}

// CredentialCapture is one reading of a home's credential inputs.
type CredentialCapture struct {
	// Files holds each present input's bytes by its home-relative slash path.
	Files map[string][]byte
	// Projection is the digest of these inputs.
	Projection string
	// State is the home's manifest and marker as read with these inputs.
	State CredentialState
}

// CaptureCredentials reads home's credential inputs once. Every derived value
// a reader needs comes from this one reading.
func CaptureCredentials(home string) (*CredentialCapture, error) {
	files := map[string][]byte{}
	read := func(rel string) error {
		data, err := readPrivateRegular(filepath.Join(home, filepath.FromSlash(rel)))
		if err == nil && data != nil {
			files[rel] = data
		}
		return err
	}
	for _, rel := range []string{"identity.yaml", "signing.key", "teams.yaml", "workspace.yaml", "id-chain.json"} {
		if err := read(rel); err != nil {
			return nil, err
		}
	}
	var teams TeamState
	var workspace WorktreeWorkspace
	if err := yaml.Unmarshal(files["teams.yaml"], &teams); err != nil {
		return nil, fmt.Errorf("teams.yaml: %w", err)
	}
	if err := yaml.Unmarshal(files["workspace.yaml"], &workspace); err != nil {
		return nil, fmt.Errorf("workspace.yaml: %w", err)
	}
	certPaths := map[string]bool{}
	for _, m := range teams.Memberships {
		certPaths[m.CertPath] = true
	}
	for _, m := range workspace.Memberships {
		certPaths[m.CertPath] = true
	}
	certs := map[string]any{}
	for stored := range certPaths {
		if strings.TrimSpace(stored) == "" {
			continue
		}
		path, err := IdentityHomeStoredPath(IdentityHome{Root: home}, stored)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(home, path)
		if err != nil {
			return nil, err
		}
		rel = filepath.ToSlash(rel)
		if err := read(rel); err != nil {
			return nil, err
		}
		certs[rel] = digestOrAbsent(files[rel])
	}
	teamMemberships := []map[string]string{}
	for _, m := range teams.Memberships {
		teamMemberships = append(teamMemberships, map[string]string{"team_id": m.TeamID, "alias": m.Alias, "cert_path": m.CertPath,
			"registry_url": m.RegistryURL, "aweb_url": m.AwebURL})
	}
	workspaceMemberships := []map[string]string{}
	for _, m := range workspace.Memberships {
		workspaceMemberships = append(workspaceMemberships, map[string]string{"team_id": m.TeamID, "alias": m.Alias, "cert_path": m.CertPath,
			"workspace_id": m.WorkspaceID})
	}
	for _, list := range [][]map[string]string{teamMemberships, workspaceMemberships} {
		sort.Slice(list, func(i, j int) bool { return list[i]["team_id"] < list[j]["team_id"] })
	}
	projection, _ := json.Marshal(map[string]any{
		"identity":     digestOrAbsent(files["identity.yaml"]),
		"signing_key":  digestOrAbsent(files["signing.key"]),
		"chain":        digestOrAbsent(files["id-chain.json"]),
		"certificates": certs,
		"teams":        map[string]any{"active_team": teams.ActiveTeam, "memberships": teamMemberships},
		"workspace":    map[string]any{"aweb_url": workspace.AwebURL, "api_key": workspace.APIKey, "memberships": workspaceMemberships},
	})
	sum := sha256.Sum256(projection)
	capture := &CredentialCapture{Files: files, Projection: hex.EncodeToString(sum[:])}
	manifest, marker, err := readCredentialRecords(home)
	if err != nil {
		return nil, err
	}
	capture.State = CredentialState{Marker: marker, Current: capture.Projection}
	if manifest != nil {
		capture.State.Generation, capture.State.Projection = manifest.Generation, manifest.Projection
	}
	return capture, nil
}

// WriteTo writes the captured inputs into dir, a fresh private directory, as
// read-only files at their home-relative paths.
func (c *CredentialCapture) WriteTo(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	for rel, data := range c.Files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0o400); err != nil {
			return err
		}
	}
	return nil
}

// validateCredentialBaseline accepts a home whose identity names the key it
// holds, when it holds both.
func validateCredentialBaseline(home string) error {
	capture, err := CaptureCredentials(home)
	if err != nil {
		return err
	}
	identityData, key := capture.Files["identity.yaml"], capture.Files["signing.key"]
	if identityData == nil || key == nil {
		return nil
	}
	var identity WorktreeIdentity
	if err := yaml.Unmarshal(identityData, &identity); err != nil {
		return err
	}
	signingKey, err := awid.ParseSigningKey(key)
	if err != nil {
		return err
	}
	if did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); strings.TrimSpace(identity.DID) != "" && strings.TrimSpace(identity.DID) != did {
		return fmt.Errorf("the identity names %s but the signing key is %s", identity.DID, did)
	}
	return nil
}

func digestOrAbsent(data []byte) any {
	if data == nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readPrivateRegular reads path, nil when absent; anything there that is not
// a regular file is an error.
func readPrivateRegular(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if data == nil && err == nil {
		data = []byte{}
	}
	return data, err
}

func readCredentialRecords(home string) (*credentialManifest, *CredentialMarker, error) {
	var manifest *credentialManifest
	if data, err := readPrivateRegular(filepath.Join(home, credentialManifestFile)); err != nil {
		return nil, nil, err
	} else if data != nil {
		manifest = &credentialManifest{}
		if err := json.Unmarshal(data, manifest); err != nil || manifest.Generation < 1 || manifest.Projection == "" {
			return nil, nil, fmt.Errorf("%s is not a credential manifest", filepath.Join(home, credentialManifestFile))
		}
	}
	var marker *CredentialMarker
	if data, err := readPrivateRegular(filepath.Join(home, credentialMarkerFile)); err != nil {
		return nil, nil, err
	} else if data != nil {
		marker = &CredentialMarker{}
		if err := json.Unmarshal(data, marker); err != nil || marker.TxID == "" {
			return nil, nil, fmt.Errorf("%s is not a credential update marker", filepath.Join(home, credentialMarkerFile))
		}
	}
	return manifest, marker, nil
}

// LockCredentialReader marks home as served by a reader, without waiting. The
// reader holds it for as long as it serves; ErrLockUnavailable means a
// supported writer is updating the home.
func LockCredentialReader(home string) (*fileLock, error) {
	return TryLockShared(filepath.Join(home, credentialReaderLockFile))
}

// LockCredentialsShared takes home's credential lock shared, without
// waiting: a reader holds it while it captures the home's credentials.
func LockCredentialsShared(home string) (*fileLock, error) {
	return TryLockShared(filepath.Join(home, credentialLockFile))
}

// UpdateCredentials runs write as op's update of home, under home's
// credential lock. Another operation's interrupted update refuses with
// ErrCredentialUpdateIncomplete; an interrupted update of exactly op is
// recovered, and published even when write has nothing left to change. While
// a reader serves home, an update starts only from a published home, and a
// change made without a generation refuses with
// ErrCredentialUpdateUnpublished; with no reader there is nothing to keep
// coherent, and the update publishes over the home as it finds it, once it
// validates, holding the reader lock so no reader starts meanwhile. Refusals
// come before write runs.
//
// write calls begin before its first change; begin refuses with
// ErrCredentialUpdateUnpublished if the home changed since the update
// started. A write that returns without calling begin changes nothing and,
// unless it recovers op, publishes nothing. Once begun, a write that fails
// leaves the update for op to recover; one that succeeds publishes the next
// generation with the projection it left.
func UpdateCredentials(home string, op CredentialOperation, write func(begin func() error) error) error {
	// Lock order: the reader lease, then the update lock. A writer that takes
	// the lease has no reader to keep coherent and keeps it for the whole
	// update, so none starts meanwhile; only a real conflict means the home is
	// served (or another such writer holds it). It never waits for the lease,
	// since a starting reader holds the lease while it waits for the update
	// lock.
	served := false
	reader, err := TryLockExclusive(filepath.Join(home, credentialReaderLockFile))
	switch {
	case err == nil:
		defer reader.Close()
	case errors.Is(err, ErrLockUnavailable):
		served = true
	default:
		return err
	}
	lock, err := LockExclusive(filepath.Join(home, credentialLockFile))
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := ReadCredentialState(home)
	if err != nil {
		return err
	}
	if state.Committed() {
		if err := os.Remove(filepath.Join(home, credentialMarkerFile)); err != nil {
			return err
		}
		state.Marker = nil
	}
	base := CredentialBase{Generation: state.Generation, Projection: state.Projection}
	recovering := state.Marker != nil
	switch {
	case state.Marker != nil:
		if state.Marker.Operation != op || state.Marker.Base != base {
			return fmt.Errorf("%w: %s holds an interrupted %s update; only that update may complete it", ErrCredentialUpdateIncomplete, home, state.Marker.Operation.Command)
		}
	case state.Generation == 0:
		// A home that never published has no committed claim to protect: its
		// first supported update starts from what it holds.
	case state.Projection == state.Current:
	case served:
		return fmt.Errorf("%w: %s's credentials changed without a published generation while it is served", ErrCredentialUpdateUnpublished, home)
	default:
		if err := validateCredentialBaseline(home); err != nil {
			return fmt.Errorf("%w: %s's credentials changed without a published generation and cannot be adopted: %v", ErrCredentialUpdateUnpublished, home, err)
		}
	}
	started := state.Current
	begun := false
	begin := func() error {
		if begun {
			return nil
		}
		// The home must still be what this update started from: an older aw
		// that ignores this lock may have written while the update waited.
		now, err := CaptureCredentials(home)
		if err != nil {
			return err
		}
		if now.Projection != started {
			return fmt.Errorf("%w: %s's credentials changed while the %s update was prepared", ErrCredentialUpdateUnpublished, home, op.Command)
		}
		txid := make([]byte, 16)
		if _, err := rand.Read(txid); err != nil {
			return err
		}
		data, err := json.Marshal(CredentialMarker{TxID: hex.EncodeToString(txid), Operation: op, Base: base, TargetGeneration: base.Generation + 1})
		if err != nil {
			return err
		}
		if err := atomicWriteFile(filepath.Join(home, credentialMarkerFile), data); err != nil {
			return err
		}
		begun = true
		return nil
	}
	if err := write(begin); err != nil {
		return err
	}
	// Recovering an interrupted update of op publishes it even when nothing
	// was left to write; otherwise an update that never began publishes
	// nothing.
	if !begun && !recovering {
		return nil
	}
	after, err := CaptureCredentials(home)
	if err != nil {
		return err
	}
	data, err := json.Marshal(credentialManifest{Generation: base.Generation + 1, Projection: after.Projection})
	if err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Join(home, credentialManifestFile), data); err != nil {
		return err
	}
	return os.Remove(filepath.Join(home, credentialMarkerFile))
}

// AdoptCredentials publishes home's current credentials as its next
// generation when they are not the published ones, after validate accepts
// their capture. Only a restarting reader adopts, under the exclusive lock:
// it never adopts an interrupted update, which refuses with
// ErrCredentialUpdateIncomplete, and it removes a committed update's
// leftover marker. It reports whether it published.
func AdoptCredentials(home string, validate func(*CredentialCapture) error) (bool, error) {
	lock, err := LockExclusive(filepath.Join(home, credentialLockFile))
	if err != nil {
		return false, err
	}
	defer lock.Close()
	capture, err := CaptureCredentials(home)
	if err != nil {
		return false, err
	}
	state := capture.State
	if state.Committed() {
		if err := os.Remove(filepath.Join(home, credentialMarkerFile)); err != nil {
			return false, err
		}
		state.Marker = nil
	}
	if state.Marker != nil {
		return false, fmt.Errorf("%w: %s holds an interrupted %s update", ErrCredentialUpdateIncomplete, home, state.Marker.Operation.Command)
	}
	if state.Generation > 0 && state.Projection == state.Current {
		return false, nil
	}
	if err := validate(capture); err != nil {
		return false, err
	}
	data, err := json.Marshal(credentialManifest{Generation: state.Generation + 1, Projection: capture.Projection})
	if err != nil {
		return false, err
	}
	return true, atomicWriteFile(filepath.Join(home, credentialManifestFile), data)
}
