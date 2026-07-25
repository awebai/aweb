package awid

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
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
}

// PinStore manages TOFU identity pins for known agents.
// Pins are keyed by did:key or stable_id (did:aw). The Addresses map is a
// reverse index from address to pin key for the identity-mismatch check.
type PinStore struct {
	mu        sync.Mutex        `yaml:"-"`
	Pins      map[string]*Pin   `yaml:"pins"`
	Addresses map[string]string `yaml:"addresses"`
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

// parsePinStore decodes and validates the on-disk document. yaml.v3 already
// rejects duplicate mapping keys, matching js-yaml on the Node side.
func parsePinStore(data []byte) (*PinStore, error) {
	// Decode into a generic document first: yaml.Unmarshal reports no error for
	// an empty input, which would hand back an empty trust store.
	var root map[string]yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			// A present file that yields no document is truncation or
			// corruption; the serializer always emits a mapping, and an
			// intentionally empty store is written as "pins: {}".
			return nil, errors.New("store is empty or has no document (truncated?)")
		}
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			return nil, errors.New("root must be a mapping")
		}
		return nil, err
	}
	if root == nil {
		return nil, errors.New("store is empty or has no document (truncated?)")
	}

	ps := NewPinStore()

	if node, ok := root["pins"]; ok && present(&node) {
		if node.Kind != yaml.MappingNode {
			return nil, errors.New("'pins' must be a mapping")
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "" {
				return nil, errors.New("store has an empty pin key")
			}
			if _, dup := ps.Pins[key.Value]; dup {
				return nil, fmt.Errorf("duplicate pin key %q", key.Value)
			}
			if value.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("pin %q must be a mapping", key.Value)
			}
			// log_seq is the anti-rollback checkpoint. Check it on the raw node:
			// decoded into an int, an explicit 0 is indistinguishable from an
			// absent field, so a rolled-back checkpoint would pass silently.
			if seq := field(value, "log_seq"); seq != nil {
				var n int
				if seq.Tag != "!!int" || seq.Decode(&n) != nil || n < 1 {
					return nil, fmt.Errorf("pin %q field 'log_seq' must be a positive integer", key.Value)
				}
			}
			var pin Pin
			if err := value.Decode(&pin); err != nil {
				return nil, fmt.Errorf("pin %q is malformed: %w", key.Value, err)
			}
			if pin.Address == "" {
				return nil, fmt.Errorf("pin %q field 'address' must be a non-empty string", key.Value)
			}
			if pin.FirstSeen == "" {
				return nil, fmt.Errorf("pin %q field 'first_seen' must be a non-empty string", key.Value)
			}
			if pin.LastSeen == "" {
				return nil, fmt.Errorf("pin %q field 'last_seen' must be a non-empty string", key.Value)
			}
			ps.Pins[key.Value] = &pin
		}
	}

	if node, ok := root["addresses"]; ok && present(&node) {
		if node.Kind != yaml.MappingNode {
			return nil, errors.New("'addresses' must be a mapping")
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Value == "" {
				return nil, errors.New("store has an empty address key")
			}
			if _, dup := ps.Addresses[key.Value]; dup {
				return nil, fmt.Errorf("duplicate address key %q", key.Value)
			}
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" || value.Value == "" {
				return nil, fmt.Errorf("address %q must reference a non-empty pin key", key.Value)
			}
			ps.Addresses[key.Value] = value.Value
		}
	}

	// Every address must resolve to a known pin, or the reverse index is corrupt
	// and identity-mismatch checks silently misfire against a pin that is not there.
	for address, pinKey := range ps.Addresses {
		if _, ok := ps.Pins[pinKey]; !ok {
			return nil, fmt.Errorf("address %q references unknown pin", address)
		}
	}

	// One address, one owner. Two pins claiming the same address is an
	// unresolved identity conflict, and picking either one would be choosing a
	// trust anchor by map-iteration order.
	owner := make(map[string]string, len(ps.Pins))
	for pinKey, pin := range ps.Pins {
		if previous, taken := owner[pin.Address]; taken {
			return nil, fmt.Errorf("address %q is claimed by two pins (%q and %q)", pin.Address, previous, pinKey)
		}
		owner[pin.Address] = pinKey
	}

	return ps, nil
}

// present reports whether a mapping entry carries an actual value; an absent or
// explicitly null section is simply an empty section.
func present(n *yaml.Node) bool {
	return n.Kind != 0 && n.Tag != "!!null"
}

// field returns the value node for a key in a mapping node, or nil if absent.
func field(mapping *yaml.Node, name string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
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
