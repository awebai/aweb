package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The trust store had no read command: `aw id pin-store` carried only
// compare-and-set. So every question about what a binding held was answered by
// reading the YAML directly, and during aweb-aauz three agents did exactly that on
// a file being rewritten underneath them - one of them reporting entries absent
// that were present. A store with no read command makes every question an
// experiment.
//
// This is what makes aweb-aava's "a stale binding is reportable by name" reachable:
// the alias and the key it is bound to, printed together, without opening the file.

// pinBinding is one address -> key binding, with the key's shape named rather than
// left for the reader to infer. Comparing a global identity's did:aw against a
// certificate's member_did_key reports a false mismatch - a detector did that for
// alice during the investigation - so the shape is part of the report.
type pinBinding struct {
	Address   string `json:"address"`
	PinKey    string `json:"pin_key"`
	KeyKind   string `json:"key_kind"`
	StableID  string `json:"stable_id,omitempty"`
	DIDKey    string `json:"did_key,omitempty"`
	Handle    string `json:"handle,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
}

type pinListing struct {
	Path     string       `json:"path"`
	Bindings []pinBinding `json:"bindings"`
}

func pinKeyKind(key string) string {
	switch {
	case strings.HasPrefix(key, "did:aw:"):
		return "did:aw"
	case strings.HasPrefix(key, "did:key:"):
		return "did:key"
	default:
		return "unknown"
	}
}

func collectPinBindings(store *awid.PinStore, addressFilter string) []pinBinding {
	filter := strings.TrimSpace(addressFilter)
	bindings := make([]pinBinding, 0, len(store.Addresses))
	for address, key := range store.Addresses {
		if filter != "" && !strings.EqualFold(address, filter) {
			continue
		}
		binding := pinBinding{
			Address: address,
			PinKey:  key,
			KeyKind: pinKeyKind(key),
		}
		// No branch for an address whose key has no pin entry. LoadPinStore validates the
		// forward and reverse indexes against each other and refuses such a store as
		// corrupt (awid/pinstore.go), so it never reaches here through this command - the
		// reader gets the loader's refusal, naming the offending address, instead of a row.
		if pin, ok := store.Pins[key]; ok && pin != nil {
			binding.StableID = pin.StableID
			binding.DIDKey = pin.DIDKey
			binding.Handle = pin.Handle
			binding.FirstSeen = pin.FirstSeen
			binding.LastSeen = pin.LastSeen
		}
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Address < bindings[j].Address })
	return bindings
}

func newPinStoreListCmd() *cobra.Command {
	var path string
	var address string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the address-to-key bindings this store holds",
		// What it reports, and what a reader diagnosing a mismatch will otherwise assume
		// it reports. It shows what is PINNED; it does not resolve each address to its
		// holder's current key, so it cannot tell you a pin is stale - which is the defect
		// class in aweb-aava and the question people will be holding when they run it.
		// And two things measured while diagnosing aweb-aava that a reader cannot get from
		// the listing itself: what last_seen indicates, and that a single read is not the
		// store's state. Both belong here rather than in a document nobody opens mid-defect.
		Long: "List the address-to-key bindings this store holds.\n\n" +
			"This reports the CONTENTS of the store. It does not verify those contents " +
			"against the current keys of the agents named, so it cannot tell you a pin is " +
			"stale: a binding to a retired keypair is listed exactly like a good one. " +
			"Answering that needs resolution per address.\n\n" +
			"last_seen is the closest thing here to that answer. A binding whose last_seen " +
			"stays frozen while its holder is actively sending is a pin that no longer " +
			"matches the sender, because the path that reports a mismatch does not refresh " +
			"it while the verified path does. Two fields, no network.\n\n" +
			"That rule has a resolution, so read it over minutes rather than seconds. " +
			"last_seen is advanced at most once a minute: refreshing it on every accepted " +
			"message forced a store commit per message, and the resident processes sharing " +
			"this file then spent their time losing write races instead of delivering " +
			"wakes. So a healthy binding can read as frozen for up to a minute. That is " +
			"far inside the window ordinary traffic already imposes - a healthy pin goes " +
			"about fifteen minutes between refreshes at p90, and hours at p99, because it " +
			"only refreshes when its holder sends - so the discriminator is unaffected in " +
			"practice. It is stated because a rule with an unstated resolution is one " +
			"somebody will eventually read at the wrong timescale.\n\n" +
			"One read is not the store's state. Several processes write this file, each " +
			"marshalling its whole map, so its contents are whichever wrote last: entries " +
			"and field values can differ between two reads seconds apart. To characterise " +
			"it, copy the file and interrogate the copy - two reads are not of the same " +
			"object, so a difference between them may be the file changing rather than " +
			"anything you did.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(path) == "" {
				defaultPath, err := awconfig.DefaultKnownAgentsPath()
				if err != nil {
					return err
				}
				path = defaultPath
			}
			store, err := awid.LoadPinStore(path)
			if err != nil {
				// Fail rather than report an empty store: an unreadable store and an
				// empty one must not look the same, which is the confusion this
				// command exists to remove.
				return fmt.Errorf("%w; refusing to report a store that could not be read", err)
			}

			listing := pinListing{Path: path, Bindings: collectPinBindings(store, address)}

			if asJSON {
				encoded, err := json.MarshalIndent(listing, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return nil
			}

			if len(listing.Bindings) == 0 {
				if strings.TrimSpace(address) != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "no pinned binding for %s in %s\n", address, path)
					return nil
				}
				fmt.Fprintf(cmd.OutOrStdout(), "no pinned bindings in %s\n", path)
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", path)
			for _, b := range listing.Bindings {
				fmt.Fprintf(cmd.OutOrStdout(), "  %-32s %-8s %s\n", b.Address, b.KeyKind, b.PinKey)
				if b.DIDKey != "" && b.DIDKey != b.PinKey {
					fmt.Fprintf(cmd.OutOrStdout(), "  %-32s %-8s last did:key %s\n", "", "", b.DIDKey)
				}
				if b.FirstSeen != "" || b.LastSeen != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "  %-32s %-8s first_seen %s  last_seen %s\n", "", "", b.FirstSeen, b.LastSeen)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "pin store path (defaults to the standard location)")
	cmd.Flags().StringVar(&address, "address", "", "report only this address")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
