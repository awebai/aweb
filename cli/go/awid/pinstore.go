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
	// They are decoded to plain values and re-emitted on Save. Dropping them
	// would let an older binary silently delete a newer one's state — for
	// something like an anti-rollback anchor that is the aajc.8 failure with no
	// error anywhere. Plain values rather than raw nodes because a raw graph
	// carries anchors and aliases whose validity depends on document order:
	// re-emitting them in a different position yields an unloadable file.
	unknown map[string]any
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
	unknown map[string]any
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
	seenRoot := map[string]bool{}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if err := requireKeyNode(key, "store"); err != nil {
			return nil, err
		}
		// Raw-node parsing does not get yaml's duplicate-key rejection, so a
		// second "pins" would silently replace the first — a populated store
		// followed by an empty one loads as no pins at all, and every known
		// identity becomes first contact again.
		if seenRoot[key.Value] {
			return nil, fmt.Errorf("duplicate field %q", key.Value)
		}
		seenRoot[key.Value] = true
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
			// Preserved and re-emitted on Save, so a newer client's state
			// survives a round trip through this binary rather than being
			// silently deleted.
			decoded, err := decodeUnknown(value, fmt.Sprintf("field %q", key.Value))
			if err != nil {
				return nil, err
			}
			if ps.unknown == nil {
				ps.unknown = map[string]any{}
			}
			ps.unknown[key.Value] = decoded
		}
	}

	if pinsNode != nil && present(pinsNode) {
		if err := requireMapping(pinsNode, "'pins'"); err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(pinsNode.Content); i += 2 {
			key, value := pinsNode.Content[i], pinsNode.Content[i+1]
			if err := requireKeyNode(key, "pins"); err != nil {
				return nil, err
			}
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
			if err := requireKeyNode(key, "addresses"); err != nil {
				return nil, err
			}
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

// requireKeyNode enforces that a mapping key is a plain string. A custom or
// explicit tag on a KEY (!evil pins:) would otherwise be accepted and silently
// normalised away on the next Save, and Node's JSON_SCHEMA rejects it outright.
func requireKeyNode(n *yaml.Node, what string) error {
	// Checked before the tag, because a merge key carries !!merge and would
	// otherwise be reported as a generic bad key.
	if n.Value == mergeKey {
		return fmt.Errorf("%s must not use YAML merge keys", what)
	}
	if err := requirePlainNode(n, what+" key"); err != nil {
		return err
	}
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return fmt.Errorf("%s has a key that is not a plain string", what)
	}
	return nil
}

// maxUnknownDepth bounds recursion through a preserved subtree so a deeply
// nested document cannot exhaust the stack.
const maxUnknownDepth = 32

// decodeUnknown validates a preserved subtree and returns it as plain values.
//
// Resolved values rather than the raw node are what make preservation safe: a
// raw graph carries anchors and aliases whose validity depends on where they sit
// in the document, so re-emitting them in another position yields a file that no
// longer loads. Conversion is done here rather than through Node.Decode because
// Decode silently discards a custom tag, and because it would turn a bare RFC3339
// lexeme into a time.Time when Node's JSON_SCHEMA reads it as a string.
func decodeUnknown(n *yaml.Node, what string) (any, error) {
	return decodeUnknownNode(n, what, 0)
}

func decodeUnknownNode(n *yaml.Node, what string, depth int) (any, error) {
	if depth > maxUnknownDepth {
		return nil, fmt.Errorf("%s is nested too deeply", what)
	}
	if err := requirePlainNode(n, what); err != nil {
		return nil, err
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		// A timestamp-looking scalar is an ordinary string, as it is in Node.
		case "!!str", "!!timestamp":
			return n.Value, nil
		case "!!bool":
			var v bool
			return v, n.Decode(&v)
		case "!!int":
			var v int64
			return v, n.Decode(&v)
		case "!!float":
			var v float64
			return v, n.Decode(&v)
		case "!!null":
			return nil, nil
		default:
			return nil, fmt.Errorf("%s has an unsupported value type", what)
		}
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return nil, fmt.Errorf("%s has an unsupported value type", what)
		}
		items := make([]any, 0, len(n.Content))
		for i, item := range n.Content {
			value, err := decodeUnknownNode(item, fmt.Sprintf("%s item %d", what, i), depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		return items, nil
	case yaml.MappingNode:
		if n.Tag != "!!map" {
			return nil, fmt.Errorf("%s has an unsupported value type", what)
		}
		// Raw-node parsing loses yaml's duplicate-key and merge-key rejection at
		// nested levels too, so both are enforced here at every depth.
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if err := requireKeyNode(key, what); err != nil {
				return nil, err
			}
			if _, dup := out[key.Value]; dup {
				return nil, fmt.Errorf("%s has duplicate key %q", what, key.Value)
			}
			decoded, err := decodeUnknownNode(value, fmt.Sprintf("%s key %q", what, key.Value), depth+1)
			if err != nil {
				return nil, err
			}
			out[key.Value] = decoded
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s has an unsupported value type", what)
	}
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
		if err := requireKeyNode(node.Content[i], fmt.Sprintf("pin %q", key)); err != nil {
			return nil, err
		}
		name, value := node.Content[i].Value, node.Content[i+1]
		if name == mergeKey {
			return nil, fmt.Errorf("pin %q must not use YAML merge keys", key)
		}
		if seen[name] {
			return nil, fmt.Errorf("pin %q has duplicate field %q", key, name)
		}
		seen[name] = true
		where := fmt.Sprintf("pin %q field %q", key, name)
		if !pinFields[name] {
			decoded, err := decodeUnknown(value, where)
			if err != nil {
				return nil, err
			}
			if pin.unknown == nil {
				pin.unknown = map[string]any{}
			}
			pin.unknown[name] = decoded
			continue
		}

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
	if err := requirePlainNode(n, what); err != nil {
		return err
	}
	// The tag check refuses a custom-tagged mapping, which yaml.v3 would
	// otherwise construct happily and js-yaml's JSON_SCHEMA would reject.
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
		return fmt.Errorf("%s must be a mapping", what)
	}
	return nil
}

// requireString refuses type coercion, custom tags and explicit tags.
//
// A bare RFC3339 lexeme resolves to !!timestamp in yaml.v3, but Node's
// JSON_SCHEMA has no timestamp type and reads the same text as an ordinary
// string. Matching that schema behaviour — rather than keeping a list of fields
// allowed to be timestamps — is what keeps the two runtimes agreeing on a shared
// file. An EXPLICIT !!timestamp tag is rejected, because Node rejects the tag.
func requireString(n *yaml.Node, what string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s must be a string", what)
	}
	if err := requirePlainNode(n, what); err != nil {
		return "", err
	}
	if n.Tag == "!!str" || n.Tag == "!!timestamp" {
		return n.Value, nil
	}
	return "", fmt.Errorf("%s must be a string", what)
}

// requirePlainNode rejects explicit tags, anchors and aliases. Anchors and
// aliases are a document-order dependency: preserving one and re-emitting it
// elsewhere produces a file that no longer loads, and nothing we write uses
// them. They are refused everywhere, like merge keys.
func requirePlainNode(n *yaml.Node, what string) error {
	if n.Kind == yaml.AliasNode {
		return fmt.Errorf("%s must not use YAML aliases", what)
	}
	if n.Anchor != "" {
		return fmt.Errorf("%s must not define a YAML anchor", what)
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("%s must not carry an explicit tag", what)
	}
	return nil
}

// MarshalYAML re-emits the known schema plus any fields this binary did not
// recognise, so a round trip through an older client preserves a newer one's state.
func (p *Pin) MarshalYAML() (interface{}, error) {
	type known Pin // avoid recursing into this method
	var node yaml.Node
	if err := node.Encode(known(*p)); err != nil {
		return nil, err
	}
	return appendUnknown(&node, p.unknown)
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
	return appendUnknown(node, ps.unknown)
}

// appendUnknown re-attaches preserved fields in a stable order. The values are
// plain, so ordering them freely cannot dangle an alias.
func appendUnknown(node *yaml.Node, unknown map[string]any) (*yaml.Node, error) {
	names := make([]string, 0, len(unknown))
	for name := range unknown {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var value yaml.Node
		if err := value.Encode(unknown[name]); err != nil {
			return nil, err
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, &value)
	}
	return node, nil
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
