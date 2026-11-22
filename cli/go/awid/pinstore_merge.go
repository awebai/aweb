package awid

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// PinStoreConflictError names the keys another writer changed to a different
// value than this writer did.
type PinStoreConflictError struct {
	Keys []string
}

func (e *PinStoreConflictError) Error() string {
	return fmt.Sprintf("another writer changed %v to a different value", e.Keys)
}

// MergePinStoreChanges applies the change a writer made from base to ours on
// top of current, the store as another writer has since committed it. Every
// aw process on one home shares the store, and their changes usually touch
// different keys (each pins the identities it heard from), so those changes
// commute and both are kept. A key both writers changed to different values
// is a real conflict and is refused, with two exceptions that have one right
// answer: a pin that differs only in last_seen keeps the later time, and an
// anti-rollback checkpoint keeps the higher verified sequence. Two
// checkpoints at the same sequence with different entries are a fork and are
// refused.
func MergePinStoreChanges(base, ours, current *PinStore) (*PinStore, error) {
	var conflicts []string
	merged := NewPinStore()

	for _, key := range unionKeys(base.Pins, ours.Pins, current.Pins) {
		pin, ok := mergeEntry(base.Pins[key], ours.Pins[key], current.Pins[key], mergePins)
		if !ok {
			conflicts = append(conflicts, "pin "+key)
			continue
		}
		if pin != nil {
			merged.Pins[key] = pin
		}
	}
	for _, address := range unionKeys(base.Addresses, ours.Addresses, current.Addresses) {
		b, bok := base.Addresses[address]
		o, ook := ours.Addresses[address]
		c, cok := current.Addresses[address]
		value, present, ok := mergePresent(b, bok, o, ook, c, cok)
		if !ok {
			conflicts = append(conflicts, "address "+address)
			continue
		}
		if present {
			merged.Addresses[address] = value
		}
	}
	for _, field := range unionKeys(base.unknown, ours.unknown, current.unknown) {
		b, bok := base.unknown[field]
		o, ook := ours.unknown[field]
		c, cok := current.unknown[field]
		var value any
		var present, ok bool
		if field == receivedHeadsField {
			value, present, ok = mergeIdentityCheckpoints(b, o, c, &conflicts)
		} else {
			value, present, ok = mergePresent(b, bok, o, ook, c, cok)
			if !ok {
				conflicts = append(conflicts, field)
			}
		}
		if !ok {
			continue
		}
		if present {
			if merged.unknown == nil {
				merged.unknown = map[string]any{}
			}
			merged.unknown[field] = value
		}
	}
	if len(conflicts) > 0 {
		return nil, &PinStoreConflictError{Keys: conflicts}
	}
	// The merged store must be one a reader accepts: an address the other
	// writer pointed at a pin this writer removed is a conflict too.
	data, err := merged.Encode()
	if err != nil {
		return nil, err
	}
	reparsed, err := ParsePinStore(data)
	if err != nil {
		return nil, &PinStoreConflictError{Keys: []string{err.Error()}}
	}
	return reparsed, nil
}

// mergeEntry is the three-way rule for one pointer-valued key, where nil means
// absent: a side that left the key unchanged takes the other side's value.
func mergeEntry[T any](base, ours, current *T, both func(base, ours, current *T) (*T, bool)) (*T, bool) {
	switch {
	case reflect.DeepEqual(ours, base):
		return current, true
	case reflect.DeepEqual(current, base), reflect.DeepEqual(current, ours):
		return ours, true
	case ours != nil && current != nil:
		return both(base, ours, current)
	default:
		return nil, false
	}
}

// mergePresent is the three-way rule for a value that may be absent.
func mergePresent[T any](base T, baseOK bool, ours T, oursOK bool, current T, currentOK bool) (T, bool, bool) {
	same := func(a T, aok bool, b T, bok bool) bool { return aok == bok && (!aok || reflect.DeepEqual(a, b)) }
	switch {
	case same(ours, oursOK, base, baseOK):
		return current, currentOK, true
	case same(current, currentOK, base, baseOK), same(current, currentOK, ours, oursOK):
		return ours, oursOK, true
	default:
		var zero T
		return zero, false, false
	}
}

// mergePins resolves a pin both writers changed, field by field against the
// pin both read: a field only one writer changed takes that change, and a
// last_seen both refreshed keeps the later time. Any other field both changed
// differently is a conflict.
func mergePins(base, ours, current *Pin) (*Pin, bool) {
	var from Pin
	if base != nil {
		from = *base
	}
	merged := *ours
	ok := true
	field := func(b, o, c any, set func(any)) {
		if v, _, fieldOK := mergePresent(b, true, o, true, c, true); fieldOK {
			set(v)
		} else {
			ok = false
		}
	}
	field(from.Address, ours.Address, current.Address, func(v any) { merged.Address = v.(string) })
	field(from.Handle, ours.Handle, current.Handle, func(v any) { merged.Handle = v.(string) })
	field(from.StableID, ours.StableID, current.StableID, func(v any) { merged.StableID = v.(string) })
	field(from.DIDKey, ours.DIDKey, current.DIDKey, func(v any) { merged.DIDKey = v.(string) })
	field(from.ConfirmedBy, ours.ConfirmedBy, current.ConfirmedBy, func(v any) { merged.ConfirmedBy = v.(string) })
	field(from.LogSeq, ours.LogSeq, current.LogSeq, func(v any) { merged.LogSeq = v.(int) })
	field(from.LogEntryHash, ours.LogEntryHash, current.LogEntryHash, func(v any) { merged.LogEntryHash = v.(string) })
	field(from.FirstSeen, ours.FirstSeen, current.FirstSeen, func(v any) { merged.FirstSeen = v.(string) })
	field(from.Server, ours.Server, current.Server, func(v any) { merged.Server = v.(string) })
	field(from.unknown, ours.unknown, current.unknown, func(v any) { merged.unknown, _ = v.(map[string]any) })
	merged.LastSeen = ours.LastSeen
	if current.LastSeen > merged.LastSeen {
		merged.LastSeen = current.LastSeen
	}
	if !ok {
		return nil, false
	}
	return &merged, true
}

// mergeIdentityCheckpoints merges the anti-rollback checkpoints per
// (registry, stable ID). A checkpoint both writers advanced keeps the higher
// verified sequence, or the later reading of the same entry; the same
// sequence with another entry is a fork.
func mergeIdentityCheckpoints(base, ours, current any, conflicts *[]string) (any, bool, bool) {
	decode := func(raw any) (map[string]map[string]*VerifiedLogHead, bool) {
		heads := map[string]map[string]*VerifiedLogHead{}
		if raw == nil {
			return heads, true
		}
		data, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(data, &heads) != nil || heads == nil {
			return nil, false
		}
		return heads, true
	}
	b, bok := decode(base)
	o, ook := decode(ours)
	c, cok := decode(current)
	if !bok || !ook || !cok {
		*conflicts = append(*conflicts, receivedHeadsField)
		return nil, false, false
	}
	merged := map[string]map[string]*VerifiedLogHead{}
	ok := true
	for _, registry := range unionKeys(b, o, c) {
		for _, stableID := range unionKeys(b[registry], o[registry], c[registry]) {
			head, headOK := mergeEntry(b[registry][stableID], o[registry][stableID], c[registry][stableID], higherCheckpoint)
			if !headOK {
				*conflicts = append(*conflicts, receivedHeadsField+" "+registry+" "+stableID)
				ok = false
				continue
			}
			if head == nil {
				continue
			}
			if merged[registry] == nil {
				merged[registry] = map[string]*VerifiedLogHead{}
			}
			merged[registry][stableID] = head
		}
	}
	if !ok {
		return nil, false, false
	}
	if len(merged) == 0 {
		return nil, false, true
	}
	// Plain values are required by the pin store's unknown-field serializer.
	data, err := json.Marshal(merged)
	if err != nil {
		*conflicts = append(*conflicts, receivedHeadsField)
		return nil, false, false
	}
	var plain map[string]any
	if err := json.Unmarshal(data, &plain); err != nil {
		*conflicts = append(*conflicts, receivedHeadsField)
		return nil, false, false
	}
	return plain, true, true
}

func higherCheckpoint(_, ours, current *VerifiedLogHead) (*VerifiedLogHead, bool) {
	switch {
	case ours.Seq > current.Seq:
		return ours, true
	case current.Seq > ours.Seq:
		return current, true
	case ours.EntryHash == current.EntryHash:
		// Both verified the same entry; keep the later reading of it.
		if current.FetchedAt.After(ours.FetchedAt) {
			return current, true
		}
		return ours, true
	default:
		return nil, false
	}
}

func unionKeys[V any](maps ...map[string]V) []string {
	seen := map[string]bool{}
	var keys []string
	for _, m := range maps {
		for key := range m {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	sort.Strings(keys)
	return keys
}
