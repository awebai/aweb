package awid

import (
	"encoding/json"
	"fmt"
	"strings"
)

// receivedHeadsField holds every identity's anti-rollback checkpoints, keyed
// by registry and then stable ID, in the pin store's forward-compatible root
// metadata: one checkpoint per (registry, stable ID), shared with channel-core.
// A pin keeps only its key binding (docs/trust-model.md). Older clients
// preserve the field without inventing an address for an identity.
const receivedHeadsField = "received_identity_heads"

// identityCheckpointWrite records one verified head.
type identityCheckpointWrite struct {
	RegistryURL string
	StableID    string
	Head        *VerifiedLogHead
	// CarriesPinAnchor: the head was verified from the anchor kept on the pin,
	// which this checkpoint now holds; the pin's copy is cleared.
	CarriesPinAnchor bool
}

// identityCheckpoints decodes the checkpoint map; the caller holds the pin
// store lock.
func (c *Client) identityCheckpoints() (map[string]map[string]*VerifiedLogHead, error) {
	heads := map[string]map[string]*VerifiedLogHead{}
	raw, ok := c.pinStore.unknown[receivedHeadsField]
	if !ok {
		return heads, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &heads); err != nil {
		return nil, err
	}
	if heads == nil {
		return nil, fmt.Errorf("invalid identity checkpoints")
	}
	return heads, nil
}

// identityCheckpoint is the checkpoint held for stableID at registryURL, or
// nil when there is none.
func (c *Client) identityCheckpoint(registryURL, stableID string) (*VerifiedLogHead, error) {
	if c.pinStore == nil {
		return nil, nil
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()
	if c.pinStore.undurable.Load() {
		return nil, fmt.Errorf("trust store is not durable")
	}
	heads, err := c.identityCheckpoints()
	if err != nil {
		return nil, err
	}
	head, ok := heads[registryURL][stableID]
	if !ok {
		return nil, nil
	}
	if head == nil || head.Seq < 1 || len(head.EntryHash) != 64 || !isLowerHex(head.EntryHash) || head.CurrentDIDKey == "" {
		return nil, fmt.Errorf("invalid identity checkpoint")
	}
	if _, err := ExtractPublicKey(head.CurrentDIDKey); err != nil {
		return nil, err
	}
	return head, nil
}

// identityCheckpointOrPinAnchor is the checkpoint for stableID at
// registryURL; without one, the anchor an earlier client kept on the pin,
// offered once as the seed it is carried from (fromPin). An unreadable
// checkpoint seeds nothing: the verification then runs from the full log.
func (c *Client) identityCheckpointOrPinAnchor(registryURL, stableID string) (head *VerifiedLogHead, fromPin bool) {
	if checkpoint, err := c.identityCheckpoint(registryURL, stableID); err != nil || checkpoint != nil {
		return checkpoint, false
	}
	if c.pinStore == nil {
		return nil, false
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()
	pin, ok := c.pinStore.Pins[stableID]
	if !ok || pin == nil || pin.LogSeq < 1 || strings.TrimSpace(pin.LogEntryHash) == "" {
		return nil, false
	}
	return &VerifiedLogHead{Seq: pin.LogSeq, EntryHash: pin.LogEntryHash, CurrentDIDKey: pin.DIDKey}, true
}

// identityCheckpointedElsewhere reports a checkpoint for stableID at a
// registry other than registryURL: the identity has moved registries.
func (c *Client) identityCheckpointedElsewhere(registryURL, stableID string) bool {
	if c.pinStore == nil {
		return false
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()
	heads, err := c.identityCheckpoints()
	if err != nil {
		return false
	}
	for registry, identities := range heads {
		if registry != registryURL && identities[stableID] != nil {
			return true
		}
	}
	return false
}

// saveIdentityCheckpoint advances the checkpoint for (registry, stable ID) to
// a verified head. Reading, comparing and saving are one critical section, so
// two verifications cannot both pass the comparison and write out of order. A
// lower sequence is a rollback and an equal sequence with another entry a
// fork; both are refused. A failed save marks the store not durable.
func (c *Client) saveIdentityCheckpoint(write identityCheckpointWrite) error {
	if c.pinStore == nil || write.Head == nil || write.Head.Seq < 1 || strings.TrimSpace(write.Head.EntryHash) == "" {
		return nil
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()
	if c.pinStore.unknown == nil {
		c.pinStore.unknown = make(map[string]any)
	}
	heads, err := c.identityCheckpoints()
	if err != nil {
		return err
	}
	if heads[write.RegistryURL] == nil {
		heads[write.RegistryURL] = map[string]*VerifiedLogHead{}
	}
	old := heads[write.RegistryURL][write.StableID]
	if old != nil && old.Seq > write.Head.Seq {
		return fmt.Errorf("identity checkpoint rollback")
	}
	if old != nil && old.Seq == write.Head.Seq && old.EntryHash != write.Head.EntryHash {
		return fmt.Errorf("identity checkpoint fork")
	}
	heads[write.RegistryURL][write.StableID] = write.Head
	// Plain values are required by the pin store's unknown-field serializer.
	data, err := json.Marshal(heads)
	if err != nil {
		return err
	}
	var plain map[string]any
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	c.pinStore.unknown[receivedHeadsField] = plain
	if write.CarriesPinAnchor {
		if pin, ok := c.pinStore.Pins[write.StableID]; ok && pin != nil {
			pin.LogSeq, pin.LogEntryHash = 0, ""
		}
	}
	if err := c.savePinStore(); err != nil {
		c.pinStore.undurable.Store(true)
		return err
	}
	return nil
}
