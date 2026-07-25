package awid

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	LifetimeEphemeral  = "ephemeral"
	LifetimePersistent = "persistent"

	CustodySelf      = "self"
	CustodyCustodial = "custodial"
)

// PinResult describes the outcome of a TOFU pin check.
type PinResult string

const (
	PinOK       PinResult = "ok"       // DID matches stored pin.
	PinNew      PinResult = "new"      // No pin existed; caller should store one.
	PinMismatch PinResult = "mismatch" // DID differs from stored pin.
	PinSkipped  PinResult = "skipped"  // Ephemeral agent — no pin check.
)

// Pin records an agent's TOFU-pinned identity.
type Pin struct {
	Address  string `yaml:"address"`
	Handle   string `yaml:"handle,omitempty"`
	StableID string `yaml:"stable_id,omitempty"`
	// DIDKey is the last did:key observed for this identity when the pin key is
	// a stable_id. It allows key-rotation checks without treating stable_id as a
	// blind trust anchor.
	DIDKey string `yaml:"did_key,omitempty"`
	// LogSeq and LogEntryHash are the anti-rollback checkpoint: the highest
	// DID-log sequence verified for this identity and that entry's hash. They
	// are persisted with the pin so a restart cannot forget what was already
	// verified; a served log that is behind them, or that does not contain this
	// entry, is refused (default-aajc.8).
	LogSeq       int    `yaml:"log_seq,omitempty"`
	LogEntryHash string `yaml:"log_entry_hash,omitempty"`
	FirstSeen    string `yaml:"first_seen"`
	LastSeen     string `yaml:"last_seen"`
	Server       string `yaml:"server"`

	// unknown holds fields written by a client that knows more than this one.
	// They are kept verbatim and re-emitted on Save. Dropping them would let an
	// older binary silently delete a newer one's state — for something like an
	// anti-rollback anchor that is the aajc.8 failure with no error anywhere.
	unknown map[string]*yaml.Node
}

// PinStore manages TOFU identity pins for known agents.
// Pins are keyed by did:key or stable_id (did:aw). The Addresses map is a
// reverse index from address to pin key for the identity-mismatch check.
type PinStore struct {
	mu sync.Mutex `yaml:"-"`
	// undurable records that a continuity change (a new or rotated pin, or an
	// advanced anti-rollback checkpoint) is held in memory but is NOT on disk.
	// While it is set, the in-memory store is ahead of the file, so a pin that
	// looks established here may not exist for the next process. Atomic because
	// the trust paths hold mu across their save and the checkpoint path does not.
	undurable atomic.Bool       `yaml:"-"`
	Pins      map[string]*Pin   `yaml:"pins"`
	Addresses map[string]string `yaml:"addresses"`

	// unknown preserves root-level fields from a newer client; see Pin.unknown.
	unknown map[string]*yaml.Node
}

// NewPinStore returns an empty pin store.
func NewPinStore() *PinStore {
	return &PinStore{
		Pins:      make(map[string]*Pin),
		Addresses: make(map[string]string),
	}
}

// maxPinStoreBytes bounds the trust database read so a huge or runaway file
// cannot exhaust memory before it is even validated.
const maxPinStoreBytes = 8 << 20

// LoadPinStore reads a pin store from disk. Only a genuinely absent file yields
// a fresh empty store; every other failure — unreadable, truncated, oversized,
// or structurally invalid — is returned as an error so the caller fails closed.
// Silently substituting an empty store would reopen first-contact TOFU for every
// identity already pinned.
//
// The accepted shape matches channel-core's PinStore.fromYAML, since Go and Node
// share ~/.config/aw/known_agents.yaml and must agree on what it means.
func LoadPinStore(path string) (*PinStore, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewPinStore(), nil
		}
		return nil, fmt.Errorf("cannot read trust pin store at %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Read one byte past the cap so an oversized file is detected rather than
	// silently truncated into a partial trust database.
	data, err := io.ReadAll(io.LimitReader(f, maxPinStoreBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read trust pin store at %s: %w", path, err)
	}
	if len(data) > maxPinStoreBytes {
		return nil, fmt.Errorf("trust pin store at %s is too large (over %d bytes); refusing to load", path, maxPinStoreBytes)
	}

	ps, err := parsePinStore(data)
	if err != nil {
		return nil, fmt.Errorf("trust pin store at %s is corrupt: %w (the file is left unchanged — repair or remove it)", path, err)
	}
	return ps, nil
}

// parsePinStore decodes and validates the on-disk document. Validation happens
// on raw YAML nodes rather than through struct decoding, because yaml.v3 coerces
// scalars (address: 123 would silently become "123") and honours custom tags,
// neither of which channel-core's JSON_SCHEMA loader accepts.
func parsePinStore(data []byte) (*PinStore, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))

	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			// A present file that yields no document is truncation or
			// corruption; the serializer always emits a mapping, and an
			// intentionally empty store is written as "pins: {}".
			return nil, errors.New("store is empty or has no document (truncated?)")
		}
		return nil, err
	}

	// Exactly one document. Otherwise a file whose first document is an empty
	// store and whose second holds the real pins would load as no pins at all,
	// and js-yaml refuses multi-document input outright.
	var trailing yaml.Node
	if err := dec.Decode(&trailing); err == nil {
		return nil, errors.New("store must be a single document")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}

	doc := &root
	if doc.Kind == yaml.DocumentNode {
		if len(doc.Content) != 1 {
			return nil, errors.New("store is empty or has no document (truncated?)")
		}
		doc = doc.Content[0]
	}
	if doc.Kind == 0 || doc.Tag == "!!null" {
		return nil, errors.New("store is empty or has no document (truncated?)")
	}
	if err := requireMapping(doc, "store root"); err != nil {
		return nil, err
	}

	ps := NewPinStore()
	var pinsNode, addressesNode *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		switch key.Value {
		case "pins":
			pinsNode = value
		case "addresses":
			addressesNode = value
		case mergeKey:
			// A merge key would let one mapping pull in another's fields, which
			// is both a schema hole and the shape behind the js-yaml merge-key
			// advisories. It is not part of this format.
			return nil, errors.New("store must not use YAML merge keys")
		default:
			// Kept verbatim and re-emitted on Save, so a newer client's state
			// survives a round trip through this binary rather than being
			// silently deleted.
			if ps.unknown == nil {
				ps.unknown = map[string]*yaml.Node{}
			}
			if _, dup := ps.unknown[key.Value]; dup {
				return nil, fmt.Errorf("duplicate field %q", key.Value)
			}
			ps.unknown[key.Value] = value
		}
	}

	if pinsNode != nil && present(pinsNode) {
		if err := requireMapping(pinsNode, "'pins'"); err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(pinsNode.Content); i += 2 {
			key, value := pinsNode.Content[i], pinsNode.Content[i+1]
			if key.Value == "" {
				return nil, errors.New("store has an empty pin key")
			}
			if _, dup := ps.Pins[key.Value]; dup {
				return nil, fmt.Errorf("duplicate pin key %q", key.Value)
			}
			pin, err := parsePin(key.Value, value)
			if err != nil {
				return nil, err
			}
			ps.Pins[key.Value] = pin
		}
	}

	if addressesNode != nil && present(addressesNode) {
		if err := requireMapping(addressesNode, "'addresses'"); err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(addressesNode.Content); i += 2 {
			key, value := addressesNode.Content[i], addressesNode.Content[i+1]
			if key.Value == "" {
				return nil, errors.New("store has an empty address key")
			}
			if _, dup := ps.Addresses[key.Value]; dup {
				return nil, fmt.Errorf("duplicate address key %q", key.Value)
			}
			pinKey, err := requireString(value, fmt.Sprintf("address %q", key.Value))
			if err != nil {
				return nil, err
			}
			if pinKey == "" {
				return nil, fmt.Errorf("address %q must reference a non-empty pin key", key.Value)
			}
			ps.Addresses[key.Value] = pinKey
		}
	}

	// The forward and reverse indexes must agree in BOTH directions. Checking
	// only that a reverse entry resolves to some pin leaves a pin whose address
	// has no reverse entry, and CheckPin then reports "new" for an address we
	// actually hold a pin for — first-contact TOFU against a known identity.
	for address, pinKey := range ps.Addresses {
		pin, ok := ps.Pins[pinKey]
		if !ok {
			return nil, fmt.Errorf("address %q references unknown pin", address)
		}
		if pin.Address != address {
			return nil, fmt.Errorf("reverse index for %q points at a pin whose address is %q", address, pin.Address)
		}
	}
	for pinKey, pin := range ps.Pins {
		mapped, ok := ps.Addresses[pin.Address]
		if !ok {
			return nil, fmt.Errorf("pin %q claims address %q with no reverse index entry", pinKey, pin.Address)
		}
		if mapped != pinKey {
			return nil, fmt.Errorf("pin %q claims address %q, but the reverse index points at %q", pinKey, pin.Address, mapped)
		}
	}

	return ps, nil
}

// mergeKey is YAML's merge indicator.
const mergeKey = "<<"

// pinFields are the fields a pin may carry. Anything else is preserved
// verbatim; see Pin.unknown.
var pinFields = map[string]bool{
	"address": true, "handle": true, "stable_id": true, "did_key": true,
	"log_seq": true, "log_entry_hash": true,
	"first_seen": true, "last_seen": true, "server": true,
}

func parsePin(key string, node *yaml.Node) (*Pin, error) {
	if err := requireMapping(node, fmt.Sprintf("pin %q", key)); err != nil {
		return nil, err
	}
	pin := &Pin{}
	seen := map[string]bool{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		name, value := node.Content[i].Value, node.Content[i+1]
		if name == mergeKey {
			return nil, fmt.Errorf("pin %q must not use YAML merge keys", key)
		}
		if seen[name] {
			return nil, fmt.Errorf("pin %q has duplicate field %q", key, name)
		}
		seen[name] = true
		if !pinFields[name] {
			if pin.unknown == nil {
				pin.unknown = map[string]*yaml.Node{}
			}
			pin.unknown[name] = value
			continue
		}

		where := fmt.Sprintf("pin %q field %q", key, name)
		if name == "log_seq" {
			// The anti-rollback checkpoint. Checked on the raw node because an
			// explicit 0 is indistinguishable from an absent field once decoded,
			// so a rolled-back checkpoint would pass silently.
			var n int
			if value.Kind != yaml.ScalarNode || value.Tag != "!!int" || value.Decode(&n) != nil || n < 1 {
				return nil, fmt.Errorf("pin %q field 'log_seq' must be a positive integer", key)
			}
			pin.LogSeq = n
			continue
		}
		text, err := requireString(value, where)
		if err != nil {
			return nil, err
		}
		switch name {
		case "address":
			pin.Address = text
		case "handle":
			pin.Handle = text
		case "stable_id":
			pin.StableID = text
		case "did_key":
			pin.DIDKey = text
		case "log_entry_hash":
			pin.LogEntryHash = text
		case "first_seen":
			pin.FirstSeen = text
		case "last_seen":
			pin.LastSeen = text
		case "server":
			pin.Server = text
		}
	}
	if pin.Address == "" {
		return nil, fmt.Errorf("pin %q field 'address' must be a non-empty string", key)
	}
	if pin.FirstSeen == "" {
		return nil, fmt.Errorf("pin %q field 'first_seen' must be a non-empty string", key)
	}
	if pin.LastSeen == "" {
		return nil, fmt.Errorf("pin %q field 'last_seen' must be a non-empty string", key)
	}
	return pin, nil
}

// present reports whether a mapping entry carries an actual value; an absent or
// explicitly null section is simply an empty section.
func present(n *yaml.Node) bool {
	return n.Kind != 0 && n.Tag != "!!null"
}

func requireMapping(n *yaml.Node, what string) error {
	// The tag check refuses a custom-tagged mapping, which yaml.v3 would
	// otherwise construct happily and js-yaml's JSON_SCHEMA would reject.
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
		return fmt.Errorf("%s must be a mapping", what)
	}
	return nil
}

// requireString refuses type coercion and custom tags. !!timestamp is allowed
// because YAML resolves an unquoted RFC3339 first_seen/last_seen to it, and
// those are the values we ourselves write.
func requireString(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode || (n.Tag != "!!str" && n.Tag != "!!timestamp") {
		return "", fmt.Errorf("%s must be a string", what)
	}
	return n.Value, nil
}

// MarshalYAML re-emits the known schema plus any fields this binary did not
// recognise, so a round trip through an older client preserves a newer one's state.
func (p *Pin) MarshalYAML() (interface{}, error) {
	type known Pin // avoid recursing into this method
	var node yaml.Node
	if err := node.Encode(known(*p)); err != nil {
		return nil, err
	}
	return appendUnknown(&node, p.unknown), nil
}

func (ps *PinStore) MarshalYAML() (interface{}, error) {
	// Built field by field rather than via a struct alias, because PinStore
	// carries a mutex that must not be copied.
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, field := range []struct {
		name  string
		value interface{}
	}{{"pins", ps.Pins}, {"addresses", ps.Addresses}} {
		var v yaml.Node
		if err := v.Encode(field.value); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field.name}, &v)
	}
	return appendUnknown(node, ps.unknown), nil
}

// appendUnknown re-attaches preserved fields in a stable order, so a round trip
// does not churn the file.
func appendUnknown(node *yaml.Node, unknown map[string]*yaml.Node) *yaml.Node {
	names := make([]string, 0, len(unknown))
	for name := range unknown {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, unknown[name])
	}
	return node
}

// Save writes the pin store to disk atomically. Creates parent
// directories if needed. The file is written with 0600 permissions.
func (ps *PinStore) Save(path string) error {
	data, err := yaml.Marshal(ps)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

// CheckPin checks whether a DID matches the stored pin for an address.
// Ephemeral agents always return PinSkipped. If no pin exists for the
// address, returns PinNew. If the stored DID matches, returns PinOK.
// If it differs, returns PinMismatch.
func (ps *PinStore) CheckPin(address, did, lifetime string) PinResult {
	if lifetime == LifetimeEphemeral {
		return PinSkipped
	}
	pinnedDID, ok := ps.Addresses[address]
	if !ok {
		return PinNew
	}
	if pinnedDID == did {
		return PinOK
	}
	return PinMismatch
}

// StorePin records or updates a TOFU pin. If a pin for this DID already
// exists, only last_seen is updated. Otherwise a new pin is created and
// the reverse index is updated.
func (ps *PinStore) StorePin(did, address, handle, server string) {
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, ok := ps.Pins[did]; ok {
		if existing.Address != address {
			delete(ps.Addresses, existing.Address)
			ps.Addresses[address] = did
			existing.Address = address
		}
		existing.LastSeen = now
		existing.Handle = handle
		existing.Server = server
		return
	}
	ps.Pins[did] = &Pin{
		Address:   address,
		Handle:    handle,
		FirstSeen: now,
		LastSeen:  now,
		Server:    server,
	}
	ps.Addresses[address] = did
}

// RemoveAddress removes any reverse index and pin associated with an address.
// Returns true when anything was removed.
func (ps *PinStore) RemoveAddress(address string) bool {
	removed := false
	if pinKey, ok := ps.Addresses[address]; ok {
		delete(ps.Addresses, address)
		if pin, exists := ps.Pins[pinKey]; exists {
			if pin.Address == address {
				delete(ps.Pins, pinKey)
			}
		}
		removed = true
	}
	for pinKey, pin := range ps.Pins {
		if pin == nil || pin.Address != address {
			continue
		}
		delete(ps.Pins, pinKey)
		if mapped, ok := ps.Addresses[address]; ok && mapped == pinKey {
			delete(ps.Addresses, address)
		}
		removed = true
	}
	return removed
}
