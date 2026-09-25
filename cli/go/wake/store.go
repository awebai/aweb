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

// DeliverySession is the legacy value the spawn hook records alongside the
// home when the broker owns the instance's delivery surface.
const DeliverySession = "session"

const (
	// RuntimeDeliveryExternalSession means the native adapter is silent and the
	// broker may own every explicit receive identity for this instance.
	RuntimeDeliveryExternalSession = "external-session"
	// RuntimeDeliveryNativeChannel means Claude's native channel owns the primary
	// identity; broker receive identities must be disjoint attachments.
	RuntimeDeliveryNativeChannel = "native-channel"
	// RuntimeDeliveryNativePi means Pi's native extension owns the primary
	// identity; broker receive identities must be disjoint attachments.
	RuntimeDeliveryNativePi = "native-pi"
)

const (
	ReceiveOwnerSessionHints = "session-hints"
	EventClassMail           = "mail"
	EventClassChat           = "chat"
)

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

// ReceiveIdentity is one broker-owned identity stream attached to a registered
// instance. It is metadata and routing context only: the broker never fetches,
// decrypts or acknowledges message bodies for it.
type ReceiveIdentity struct {
	IdentityHome  string   `json:"identity_home"`
	TeamID        string   `json:"team_id,omitempty"`
	Label         string   `json:"label,omitempty"`
	DeliveryOwner string   `json:"delivery_owner,omitempty"`
	EventClasses  []string `json:"event_classes,omitempty"`
	Controls      bool     `json:"controls,omitempty"`
}

// Registration is what the OATS spawn hook records. The legacy shape is one
// IdentityHome with Delivery=session. The multi-identity shape keeps the same
// instance Home and supplies explicit broker-owned receive identities.
type Registration struct {
	Home                string            `json:"home"`
	IdentityHome        string            `json:"identity_home"`
	Delivery            string            `json:"delivery"`
	RuntimeDelivery     string            `json:"runtime_delivery,omitempty"`
	PrimaryIdentityHome string            `json:"primary_identity_home,omitempty"`
	ReceiveIdentities   []ReceiveIdentity `json:"receive_identities,omitempty"`
	Backend             string            `json:"backend,omitempty"`
	RegisteredAt        time.Time         `json:"registered_at"`
}

// Validate enforces explicit receive ownership, no double-consumed identity
// homes, and the legacy delivery=session compatibility rule.
func (r Registration) Validate() error {
	_, err := r.normalized()
	return err
}

// Normalized returns the canonical form the broker stores and runs. It preserves
// the old one-identity registration by deriving one receive identity from
// IdentityHome when ReceiveIdentities is empty.
func (r Registration) Normalized() (Registration, error) { return r.normalized() }

func (r Registration) normalized() (Registration, error) {
	r = r.clone()
	if strings.TrimSpace(r.Home) == "" || !filepath.IsAbs(strings.TrimSpace(r.Home)) {
		return Registration{}, fmt.Errorf("--home must be an absolute instance home path")
	}
	canonicalHome, err := CanonicalHome(r.Home)
	if err != nil {
		return Registration{}, err
	}
	r.Home = canonicalHome

	switch strings.ToLower(strings.TrimSpace(r.Backend)) {
	case "", "tmux", "herdr":
	default:
		return Registration{}, fmt.Errorf("--backend must be tmux or herdr, got %q", r.Backend)
	}

	runtime := strings.ToLower(strings.TrimSpace(r.RuntimeDelivery))
	if runtime == "" {
		switch strings.ToLower(strings.TrimSpace(r.Delivery)) {
		case DeliverySession:
			runtime = RuntimeDeliveryExternalSession
		case RuntimeDeliveryExternalSession, RuntimeDeliveryNativeChannel, RuntimeDeliveryNativePi:
			runtime = strings.ToLower(strings.TrimSpace(r.Delivery))
		}
	}
	if runtime == "" && len(r.ReceiveIdentities) == 0 {
		// Preserve the old refusal wording for legacy bad registrations.
		return Registration{}, fmt.Errorf(
			"refusing to register %s: --delivery must be %q (AWEB_DELIVERY=session). The broker and a live native channel are two presentation surfaces on one identity, and running both doubles every wake",
			strings.TrimSpace(r.Home), DeliverySession)
	}
	r.RuntimeDelivery = runtime
	if strings.TrimSpace(r.Delivery) == "" {
		if runtime == RuntimeDeliveryExternalSession {
			r.Delivery = DeliverySession
		} else {
			r.Delivery = runtime
		}
	}

	legacy := len(r.ReceiveIdentities) == 0
	if legacy {
		if !strings.EqualFold(strings.TrimSpace(r.Delivery), DeliverySession) {
			return Registration{}, fmt.Errorf(
				"refusing to register %s: --delivery must be %q (AWEB_DELIVERY=session). The broker and a live native channel are two presentation surfaces on one identity, and running both doubles every wake",
				strings.TrimSpace(r.Home), DeliverySession)
		}
		identityHome, err := canonicalReadableIdentityHome(r.IdentityHome, "--identity-home")
		if err != nil {
			return Registration{}, err
		}
		r.IdentityHome = identityHome
		r.RuntimeDelivery = RuntimeDeliveryExternalSession
		r.ReceiveIdentities = []ReceiveIdentity{{
			IdentityHome:  identityHome,
			DeliveryOwner: ReceiveOwnerSessionHints,
			Controls:      true,
		}}
		return r, nil
	}

	switch runtime {
	case RuntimeDeliveryExternalSession, RuntimeDeliveryNativeChannel, RuntimeDeliveryNativePi:
	default:
		return Registration{}, fmt.Errorf("runtime_delivery must be %q, %q, or %q", RuntimeDeliveryExternalSession, RuntimeDeliveryNativeChannel, RuntimeDeliveryNativePi)
	}
	if runtime == RuntimeDeliveryExternalSession && strings.TrimSpace(r.Delivery) != "" && !strings.EqualFold(strings.TrimSpace(r.Delivery), DeliverySession) && !strings.EqualFold(strings.TrimSpace(r.Delivery), RuntimeDeliveryExternalSession) {
		return Registration{}, fmt.Errorf("external-session registrations must keep delivery=%q for compatibility", DeliverySession)
	}
	if runtime != RuntimeDeliveryExternalSession {
		if delivery := strings.ToLower(strings.TrimSpace(r.Delivery)); delivery != "" && delivery != runtime {
			return Registration{}, fmt.Errorf("native mixed registration delivery must be %q, got %q", runtime, r.Delivery)
		}
		if strings.TrimSpace(r.PrimaryIdentityHome) == "" {
			return Registration{}, fmt.Errorf("primary_identity_home is required when runtime_delivery is %q", runtime)
		}
	}

	primary := ""
	if strings.TrimSpace(r.PrimaryIdentityHome) != "" {
		primary, err = canonicalReadableIdentityHome(r.PrimaryIdentityHome, "primary_identity_home")
		if err != nil {
			return Registration{}, err
		}
		r.PrimaryIdentityHome = primary
	}

	seen := map[string]struct{}{}
	controlCount := 0
	for i := range r.ReceiveIdentities {
		binding := &r.ReceiveIdentities[i]
		identityHome, err := canonicalReadableIdentityHome(binding.IdentityHome, fmt.Sprintf("receive_identities[%d].identity_home", i))
		if err != nil {
			return Registration{}, err
		}
		binding.IdentityHome = identityHome
		if _, ok := seen[identityHome]; ok {
			return Registration{}, fmt.Errorf("duplicate receive identity_home %s", identityHome)
		}
		seen[identityHome] = struct{}{}
		if runtime != RuntimeDeliveryExternalSession && primary != "" && identityHome == primary {
			return Registration{}, fmt.Errorf("receive identity_home %s overlaps native primary identity_home", identityHome)
		}
		binding.TeamID = strings.TrimSpace(binding.TeamID)
		binding.Label = strings.TrimSpace(binding.Label)
		owner := strings.ToLower(strings.TrimSpace(binding.DeliveryOwner))
		if owner == "" {
			owner = ReceiveOwnerSessionHints
		}
		if owner != ReceiveOwnerSessionHints {
			return Registration{}, fmt.Errorf("receive_identities[%d].delivery_owner must be %q", i, ReceiveOwnerSessionHints)
		}
		binding.DeliveryOwner = owner
		classes, err := normalizeEventClasses(binding.EventClasses)
		if err != nil {
			return Registration{}, fmt.Errorf("receive_identities[%d].event_classes: %w", i, err)
		}
		binding.EventClasses = classes
		if runtime != RuntimeDeliveryExternalSession {
			if binding.Controls {
				return Registration{}, fmt.Errorf("receive identity_home %s cannot have runtime controls when native primary owns delivery", identityHome)
			}
			if len(classes) == 0 {
				binding.EventClasses = []string{EventClassMail, EventClassChat}
			} else if !onlyMailChat(classes) {
				return Registration{}, fmt.Errorf("receive identity_home %s may only request mail/chat event classes when native primary owns delivery", identityHome)
			}
		}
		if binding.Controls {
			controlCount++
		}
	}
	if runtime == RuntimeDeliveryExternalSession && controlCount > 1 {
		return Registration{}, fmt.Errorf("at most one receive identity may have controls=true")
	}
	if strings.TrimSpace(r.IdentityHome) == "" && len(r.ReceiveIdentities) > 0 {
		r.IdentityHome = r.ReceiveIdentities[0].IdentityHome
	}
	return r, nil
}

func canonicalReadableIdentityHome(raw, label string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute identity home path", label)
	}
	canonical, err := CanonicalHome(path)
	if err != nil {
		return "", err
	}
	if info, err := os.Stat(canonical); err != nil {
		return "", fmt.Errorf("%s %s is not readable: %w", label, canonical, err)
	} else if !info.IsDir() {
		return "", fmt.Errorf("%s %s is not a directory", label, canonical)
	}
	return canonical, nil
}

func normalizeEventClasses(classes []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, raw := range classes {
		cls := strings.ToLower(strings.TrimSpace(raw))
		if cls == "" {
			continue
		}
		switch cls {
		case EventClassMail, EventClassChat:
		default:
			return nil, fmt.Errorf("unsupported event class %q", raw)
		}
		if _, ok := seen[cls]; ok {
			continue
		}
		seen[cls] = struct{}{}
		out = append(out, cls)
	}
	return out, nil
}

func onlyMailChat(classes []string) bool {
	for _, cls := range classes {
		switch cls {
		case EventClassMail, EventClassChat:
		default:
			return false
		}
	}
	return true
}

func (r Registration) clone() Registration {
	out := r
	if r.ReceiveIdentities != nil {
		out.ReceiveIdentities = make([]ReceiveIdentity, len(r.ReceiveIdentities))
		for i, binding := range r.ReceiveIdentities {
			out.ReceiveIdentities[i] = binding
			out.ReceiveIdentities[i].EventClasses = append([]string(nil), binding.EventClasses...)
		}
	}
	return out
}

func (r Registration) ReceiveBindings() []ReceiveIdentity {
	normalized, err := r.normalized()
	if err != nil {
		return nil
	}
	out := make([]ReceiveIdentity, len(normalized.ReceiveIdentities))
	for i, binding := range normalized.ReceiveIdentities {
		out[i] = binding
		out[i].EventClasses = append([]string(nil), binding.EventClasses...)
	}
	return out
}

func (r Registration) BindingForIdentityHome(identityHome string) (ReceiveIdentity, bool) {
	canonical, err := CanonicalHome(identityHome)
	if err != nil {
		canonical = filepath.Clean(strings.TrimSpace(identityHome))
	}
	for _, binding := range r.ReceiveBindings() {
		if binding.IdentityHome == canonical {
			return binding, true
		}
	}
	return ReceiveIdentity{}, false
}

func (b ReceiveIdentity) label() string {
	if strings.TrimSpace(b.Label) != "" {
		return strings.TrimSpace(b.Label)
	}
	if strings.TrimSpace(b.TeamID) != "" {
		return strings.TrimSpace(b.TeamID)
	}
	return strings.TrimSpace(b.IdentityHome)
}

func (b ReceiveIdentity) allowsKind(kind Kind) bool {
	if b.Controls {
		return true
	}
	classes := b.EventClasses
	if len(classes) == 0 {
		classes = []string{EventClassMail, EventClassChat}
	}
	switch kind {
	case KindMail:
		return containsString(classes, EventClassMail)
	case KindChat:
		return containsString(classes, EventClassChat)
	case KindReconnect:
		return containsString(classes, EventClassMail) || containsString(classes, EventClassChat)
	default:
		return false
	}
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
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

// SaveRegistration writes one registration atomically. It canonicalizes the
// instance home but deliberately does not trust or validate the rest of the
// registration: the daemon applies Registration.Validate while reconciling files
// that may have been written by an older socket fallback.
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
	if err != nil || !ok {
		return r, ok, err
	}
	if normalized, normalizeErr := r.normalized(); normalizeErr == nil {
		r = normalized
	}
	return r, ok, nil
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
		if normalized, normalizeErr := r.normalized(); normalizeErr == nil {
			r = normalized
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
