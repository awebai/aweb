package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// Reissuing an alias to a new keypair leaves the previous holder's pin in place,
// so the next holder is reported as an identity mismatch on every message it sends
// and no local diagnostic says why (aweb-aava). The pin is doing its job: an alias
// reissue IS one principal taking over an address from another, and neither a
// rotation announcement nor a replacement announcement covers it, because the new
// holder is not the old key rotated and holds no signature from the address's
// controller. Nothing in the trust model should start accepting that silently.
//
// What was missing is the operator's side of it: a way to say "I know this name
// changed hands, stop trusting the key it carried". That is the ssh-keygen -R
// position, and it is deliberate, local, and auditable rather than automatic.
//
// Keyed on the ADDRESS, not on a retirement event. ar -> ares was a reissue of one
// role to a new keypair and escaped this defect only because the NAME changed - a
// fresh name takes a fresh pin. A cleanup driven by retirements misses a straight
// reissue, in which no retirement need ever run.
type pinForgetResult struct {
	Path    string `json:"path"`
	Address string `json:"address"`
	Removed bool   `json:"removed"`
	// PinKey is the key that was being trusted, captured before removal. The store
	// keeps no history, so if this is not reported here the operator has no record
	// of what they stopped trusting.
	PinKey string `json:"pin_key,omitempty"`
}

func newPinStoreForgetCmd() *cobra.Command {
	var path string
	var address string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "forget",
		Short: "Stop trusting the key currently pinned for an address",
		// The bound belongs in the help text because the command looks like it fixes
		// the mismatch everywhere, and it does not. The store is per-machine, so this
		// clears the binding on THIS host only; an agent on another machine keeps its
		// own stale pin and keeps reporting the mismatch until it runs this too.
		Long: "Stop trusting the key currently pinned for an address.\n\n" +
			"Use this when an alias has changed hands - a name reissued to a new keypair - " +
			"and the new holder is being reported as an identity mismatch. Forgetting the " +
			"binding accepts a new first contact for that name, so run it only when you know " +
			"the name legitimately changed hands.\n\n" +
			"This clears the binding in ONE store on ONE machine. Every other host has its " +
			"own pin store and keeps reporting the mismatch until it runs this too, so " +
			"clearing it here does not establish that the alias is trusted anywhere else.\n\n" +
			"It does not re-pin. The next message from that address is a first contact and " +
			"pins whatever key it presents, which is the same exposure as any first contact.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := strings.TrimSpace(address)
			if addr == "" {
				return fmt.Errorf("--address is required: forget acts on one binding, and an empty address would name every one of them")
			}
			if strings.TrimSpace(path) == "" {
				defaultPath, err := awconfig.DefaultKnownAgentsPath()
				if err != nil {
					return err
				}
				path = defaultPath
			}

			// Read and write under one lock, on the same lock file the compare-and-set
			// protocol uses, so this serializes against it. Loading outside the lock and
			// committing inside would reintroduce the window that protocol exists to close.
			lock, err := lockPinStoreForCAS(path)
			if err != nil {
				return fmt.Errorf("lock trust pin store: %w", err)
			}
			defer func() { _ = lock.Close() }()

			store, err := awid.LoadPinStore(path)
			if err != nil {
				// Refuse rather than rewrite. Saving this process's partial reading of a
				// store it could not parse would drop every binding it failed to model,
				// which is a far worse outcome than the one binding the operator asked
				// about - and it would hit agents who are not party to this change.
				return fmt.Errorf("%w; refusing to rewrite a store that could not be read", err)
			}

			result := pinForgetResult{Path: path, Address: addr}
			// Captured before the removal: afterwards the store cannot answer it.
			result.PinKey = store.Addresses[addr]
			result.Removed = store.RemoveAddress(addr)
			if !result.Removed {
				// Nothing was pinned. Report that as itself: an operator who ran this to
				// explain a mismatch needs to know the mismatch is coming from somewhere
				// else, and "removed nothing" and "removed the stale pin" send them to
				// different next steps.
				result.PinKey = ""
			} else if err := store.Save(path); err != nil {
				return fmt.Errorf("commit trust pin store: %w", err)
			}

			if asJSON {
				encoded, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
				return nil
			}

			if !result.Removed {
				fmt.Fprintf(cmd.OutOrStdout(), "no pinned binding for %s in %s; nothing was forgotten\n", addr, path)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "forgot %s -> %s in %s\n", addr, result.PinKey, path)
			fmt.Fprintf(cmd.OutOrStdout(), "the next message from %s is a first contact and will pin the key it presents\n", addr)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "pin store path (defaults to the standard location)")
	cmd.Flags().StringVar(&address, "address", "", "the address whose binding to forget")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
