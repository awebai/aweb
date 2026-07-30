package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// aweb-aava: the next holder of an alias must never inherit the previous holder's
// key. The store had a read command and a compare-and-set, so the only way to stop
// trusting a reissued alias was to hand-edit shared YAML - which is what produced
// aweb-aavc and aweb-aavd. This is the write half, keyed on the ALIAS.
//
// Keyed on the alias rather than on retirement on purpose: ar -> ares was a reissue
// of one role to a new keypair that escaped this defect only because the NAME
// changed. A cleanup driven by retirement events misses a straight reissue, so the
// address is the key.

func runPinStoreForget(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newPinStoreForgetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pin-store forget failed: %v\n%s", err, out.String())
	}
	return out.String()
}

func TestPinStoreForgetClearsTheBindingForOneAlias(t *testing.T) {
	path := pinStoreFixture(t)

	runPinStoreForget(t, "--path", path, "--address", "juan.aweb.ai/grace")

	store, err := awid.LoadPinStore(path)
	if err != nil {
		// aweb-aavc: a single-entry write must not leave the store in a state its
		// own guard rejects. Loading it back is the only thing that establishes it.
		t.Fatalf("store does not load after forget, so the write left it corrupt: %v", err)
	}
	if key, ok := store.Addresses["juan.aweb.ai/grace"]; ok {
		t.Fatalf("juan.aweb.ai/grace is still bound to %s, so the next holder still inherits it", key)
	}
	if _, ok := store.Pins["did:key:zStaleHolder"]; ok {
		t.Fatal("the pin entry survived the address removal, so the store still holds the retired key")
	}
}

func TestPinStoreForgetLeavesEveryOtherBindingIntact(t *testing.T) {
	path := pinStoreFixture(t)

	runPinStoreForget(t, "--path", path, "--address", "juan.aweb.ai/grace")

	store, err := awid.LoadPinStore(path)
	if err != nil {
		t.Fatalf("load after forget: %v", err)
	}
	// alice is pinned by did:aw stable id and is correct. Clearing one alias must
	// not disturb it: the harm this command exists to fix was one agent's routine
	// pin write interrupting everyone else's messaging.
	if got := store.Addresses["juan.aweb.ai/alice"]; got != "did:aw:aStable" {
		t.Fatalf("alice's binding is now %q, want did:aw:aStable - forget reached beyond the alias it was given", got)
	}
	if _, ok := store.Pins["did:aw:aStable"]; !ok {
		t.Fatal("alice's pin entry was removed by a forget aimed at grace")
	}
}

func TestPinStoreForgetReportsTheKeyItStoppedTrusting(t *testing.T) {
	path := pinStoreFixture(t)

	got := runPinStoreForget(t, "--path", path, "--address", "juan.aweb.ai/grace")

	// The operator is deliberately accepting a new first contact for this name.
	// Naming the key they stopped trusting is what makes that decision auditable
	// afterwards - the removed pin is otherwise unrecoverable from the store.
	for _, want := range []string{"juan.aweb.ai/grace", "did:key:zStaleHolder"} {
		if !strings.Contains(got, want) {
			t.Fatalf("forget does not report %q, so what was un-trusted is not on the record:\n%s", want, got)
		}
	}
}

func TestPinStoreForgetDistinguishesNothingPinnedFromSomethingRemoved(t *testing.T) {
	path := pinStoreFixture(t)

	var first, second struct {
		Address string `json:"address"`
		Removed bool   `json:"removed"`
		PinKey  string `json:"pin_key"`
	}

	out := runPinStoreForget(t, "--path", path, "--address", "juan.aweb.ai/grace", "--json")
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatalf("decode first forget: %v\n%s", err, out)
	}
	if !first.Removed || first.PinKey != "did:key:zStaleHolder" {
		t.Fatalf("first forget reported removed=%v pin_key=%q, want true/did:key:zStaleHolder", first.Removed, first.PinKey)
	}

	// Running it again removes nothing. An absence must not report as a removal:
	// "I cleared that pin" and "there was no pin to clear" send an operator to
	// different next steps, and only the second means the mismatch is elsewhere.
	out = runPinStoreForget(t, "--path", path, "--address", "juan.aweb.ai/grace", "--json")
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatalf("decode second forget: %v\n%s", err, out)
	}
	if second.Removed {
		t.Fatalf("forget reported a removal on an address with no binding:\n%s", out)
	}
	if second.PinKey != "" {
		t.Fatalf("forget named a removed key %q when nothing was pinned", second.PinKey)
	}
}

func TestPinStoreForgetIsReachableFromTheCommandTree(t *testing.T) {
	// Constructing the command in the tests above says nothing about an operator
	// being able to run it. A subcommand nobody registered is a fix nobody can use.
	for _, sub := range pinStoreCmd.Commands() {
		if sub.Name() == "forget" {
			return
		}
	}
	t.Fatal("aw id pin-store has no forget subcommand, so the fix is unreachable from the CLI")
}

func TestPinStoreForgetRefusesAnUnreadableStore(t *testing.T) {
	path := pinStoreFixture(t)
	if err := os.WriteFile(path, []byte("addresses: [not, a, mapping]\n"), 0o600); err != nil {
		t.Fatalf("corrupt fixture: %v", err)
	}

	cmd := newPinStoreForgetCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--path", path, "--address", "juan.aweb.ai/grace"})
	// Fail rather than rewrite: a store this command cannot parse is one whose
	// other bindings it would silently drop by saving its own partial reading.
	if err := cmd.Execute(); err == nil {
		t.Fatalf("forget accepted an unreadable store instead of refusing it:\n%s", out.String())
	}
}
