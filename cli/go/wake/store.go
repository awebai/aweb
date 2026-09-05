package wake

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
	"time"
)

// DeliverySession is the value the spawn hook records alongside the home. The
// broker's exclusivity check reads this field rather than inferring the mode
// (§4, §6): two presentation surfaces on one identity double every wake.
const DeliverySession = "session"

// DefaultHintCap bounds the pending hint store per instance (§4).
const DefaultHintCap = 512

// Store is the on-disk state directory:
//
//	<dir>/registry.d/<key>.json    one registration per instance home
//	<dir>/instances.d/<key>.json   pending hints, last attempt, rate limit, pause
//	<dir>/status.json              what `aw wake status` reads when the daemon is down
//	<dir>/lock/                    the one-daemon-per-host lock
//	<dir>/control.sock             the daemon's local control socket
//
// <key> is the SHA-256 of the canonical instance home path. Nothing under the
// directory is a presented mark, and nothing under it holds message content.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir, creating the directory tree.
func NewStore(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("wake: empty state directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: abs}
	for _, sub := range []string{"", "registry.d", "instances.d"} {
		if err := os.MkdirAll(filepath.Join(abs, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Dir() string                  { return s.dir }
func (s *Store) LockDir() string              { return filepath.Join(s.dir, "lock") }
func (s *Store) SocketPath() string           { return filepath.Join(s.dir, "control.sock") }
func (s *Store) StatusPath() string           { return filepath.Join(s.dir, "status.json") }
func (s *Store) registryPath(k string) string { return filepath.Join(s.dir, "registry.d", k+".json") }
func (s *Store) instancePath(k string) string { return filepath.Join(s.dir, "instances.d", k+".json") }

// CanonicalHome normalises an instance home to the absolute, symlink-resolved
// path the key is derived from. Two spellings of one home must not become two
// registrations.
func CanonicalHome(home string) (string, error) {
	home = strings.TrimSpace(home)
	if home == "" {
		return "", errors.New("home is required")
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("home must be an absolute path, got %q", home)
	}
	clean := filepath.Clean(home)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved, nil
	}
	// A home that does not exist yet is normal: the hook registers after the
	// home is created, but the broker must not refuse a path it cannot stat.
	return clean, nil
}

// HomeKey is the state-file name for a canonical home.
func HomeKey(canonicalHome string) string {
	sum := sha256.Sum256([]byte(canonicalHome))
	return hex.EncodeToString(sum[:])
}

// Registration is what the OATS spawn hook records.
type Registration struct {
	Home         string    `json:"home"`
	IdentityHome string    `json:"identity_home"`
	Delivery     string    `json:"delivery"`
	Backend      string    `json:"backend,omitempty"`
	RegisteredAt time.Time `json:"registered_at"`
}

// Validate enforces the exclusivity check and the explicit-home rule.
func (r Registration) Validate() error {
	if strings.TrimSpace(r.Home) == "" || !filepath.IsAbs(strings.TrimSpace(r.Home)) {
		return fmt.Errorf("--home must be an absolute instance home path")
	}
	identityHome := strings.TrimSpace(r.IdentityHome)
	if identityHome == "" || !filepath.IsAbs(identityHome) {
		return fmt.Errorf("--identity-home must be an absolute identity home path")
	}
	// An identity home the broker cannot read is a refusal, not a pending
	// registration: the daemon would build this identity's client from it, and
	// a registration it can never serve should fail the hook now rather than
	// sit in status pretending to be a wake path.
	if info, err := os.Stat(identityHome); err != nil {
		return fmt.Errorf("--identity-home %s is not readable: %w", identityHome, err)
	} else if !info.IsDir() {
		return fmt.Errorf("--identity-home %s is not a directory", identityHome)
	}
	if !strings.EqualFold(strings.TrimSpace(r.Delivery), DeliverySession) {
		return fmt.Errorf(
			"refusing to register %s: --delivery must be %q (AWEB_DELIVERY=session). The broker and a live native channel are two presentation surfaces on one identity, and running both doubles every wake",
			strings.TrimSpace(r.Home), DeliverySession)
	}
	switch strings.ToLower(strings.TrimSpace(r.Backend)) {
	case "", "tmux", "herdr":
	default:
		return fmt.Errorf("--backend must be tmux or herdr, got %q", r.Backend)
	}
	return nil
}

// InstanceState is the durable per-instance state: what the broker has tried,
// never what it believes arrived.
type InstanceState struct {
	Home           string    `json:"home"`
	Pending        []Hint    `json:"pending"`
	Evicted        int       `json:"evicted"`
	Paused         bool      `json:"paused"`
	FirstPresentAt time.Time `json:"first_present_at,omitempty"`
	Inactive       bool      `json:"inactive,omitempty"`
	LastInspectAt  time.Time `json:"last_inspect_at,omitempty"`
	LastAttemptAt  time.Time `json:"last_attempt_at,omitempty"`
	LastSubmitAt   time.Time `json:"last_submit_at,omitempty"`
	LastState      string    `json:"last_state,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	UnreadCount    int       `json:"unread_count,omitempty"`
}

// ConfirmedLive reports whether one live inspect has been seen.
func (s InstanceState) ConfirmedLive() bool { return !s.FirstPresentAt.IsZero() }

// AddHint inserts a hint into the pending set, collapsing a hint already
// pending under the same key. It returns whether the set changed.
//
// Eviction is oldest-first and counted, because the note requires a backlog and
// every eviction to be visible in status rather than silent (§4).
func (s *InstanceState) AddHint(h Hint, cap int) bool {
	if cap <= 0 {
		cap = DefaultHintCap
	}
	key := h.DedupeKey()
	for i := range s.Pending {
		if s.Pending[i].DedupeKey() == key {
			// Already pending: keep the earliest arrival so the coalescing
			// window is measured from when the item first appeared, but adopt
			// a sender-waiting escalation.
			if h.SenderWaiting {
				s.Pending[i].SenderWaiting = true
				s.Pending[i].Intent = IntentSteer
			}
			return false
		}
	}
	s.Pending = append(s.Pending, h)
	for len(s.Pending) > cap {
		s.Pending = s.Pending[1:]
		s.Evicted++
	}
	return true
}

// DurablePending returns the pending hints that survive a restart. Transient
// control signals are excluded: an at-most-once signal that was lost across an
// SSE gap is reported, not replayed (§4).
func (s InstanceState) DurablePending() []Hint {
	out := make([]Hint, 0, len(s.Pending))
	for _, h := range s.Pending {
		if h.Transient {
			continue
		}
		out = append(out, h)
	}
	return out
}

// SaveRegistration writes one registration atomically.
func (s *Store) SaveRegistration(r Registration) error {
	canonical, err := CanonicalHome(r.Home)
	if err != nil {
		return err
	}
	r.Home = canonical
	if r.RegisteredAt.IsZero() {
		r.RegisteredAt = time.Now().UTC()
	}
	return writeJSONAtomic(s.registryPath(HomeKey(canonical)), r)
}

// LoadRegistration reads one registration; ok is false when none exists.
func (s *Store) LoadRegistration(home string) (Registration, bool, error) {
	canonical, err := CanonicalHome(home)
	if err != nil {
		return Registration{}, false, err
	}
	var r Registration
	ok, err := readJSON(s.registryPath(HomeKey(canonical)), &r)
	return r, ok, err
}

// DeleteRegistration removes a registration and its instance state. It reports
// whether a registration was present.
func (s *Store) DeleteRegistration(home string) (bool, error) {
	canonical, err := CanonicalHome(home)
	if err != nil {
		return false, err
	}
	key := HomeKey(canonical)
	existed := true
	if err := os.Remove(s.registryPath(key)); err != nil {
		if !os.IsNotExist(err) {
			return false, err
		}
		existed = false
	}
	if err := os.Remove(s.instancePath(key)); err != nil && !os.IsNotExist(err) {
		return existed, err
	}
	return existed, nil
}

// ListRegistrations reads every registration, ordered by registration time so
// the stream bound admits the oldest first and a restart admits the same set.
func (s *Store) ListRegistrations() ([]Registration, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "registry.d"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []Registration{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var r Registration
		ok, err := readJSON(filepath.Join(s.dir, "registry.d", entry.Name()), &r)
		if err != nil || !ok {
			continue
		}
		if strings.TrimSpace(r.Home) == "" {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].RegisteredAt.Equal(out[j].RegisteredAt) {
			return out[i].RegisteredAt.Before(out[j].RegisteredAt)
		}
		return out[i].Home < out[j].Home
	})
	return out, nil
}

// SaveInstance writes per-instance state atomically, dropping transient hints.
func (s *Store) SaveInstance(state InstanceState) error {
	canonical, err := CanonicalHome(state.Home)
	if err != nil {
		return err
	}
	persisted := state
	persisted.Home = canonical
	persisted.Pending = state.DurablePending()
	return writeJSONAtomic(s.instancePath(HomeKey(canonical)), persisted)
}

// LoadInstance reads per-instance state; a missing file is an empty state.
func (s *Store) LoadInstance(home string) (InstanceState, error) {
	canonical, err := CanonicalHome(home)
	if err != nil {
		return InstanceState{}, err
	}
	var state InstanceState
	ok, err := readJSON(s.instancePath(HomeKey(canonical)), &state)
	if err != nil {
		return InstanceState{}, err
	}
	if !ok {
		return InstanceState{Home: canonical}, nil
	}
	state.Home = canonical
	return state, nil
}

// SaveStatus writes the status snapshot the CLI reads when the daemon is down.
func (s *Store) SaveStatus(status Status) error {
	return writeJSONAtomic(s.StatusPath(), status)
}

// LoadStatus reads the last status snapshot.
func (s *Store) LoadStatus() (Status, bool, error) {
	var status Status
	ok, err := readJSON(s.StatusPath(), &status)
	return status, ok, err
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func readJSON(path string, into any) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(data, into); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return true, nil
}
