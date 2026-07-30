package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// aweb-aava criterion 4: a stale binding must be inspectable and reportable BY NAME
// rather than presenting as an unexplained mismatch.
//
// Before this command the only pin-store subcommand was compare-and-set, so the only
// way to ask what a binding held was to read the YAML file directly - which is what
// three people did during the aweb-aauz investigation, on a file being rewritten
// underneath them, and it is why one of them (me) reported entries absent that were
// present. A store with no read command makes every question an experiment.

func pinStoreFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	store := awid.NewPinStore()
	// A local-scope agent: pinned by did:key, no stable id. This is the shape that
	// goes stale when its alias is reissued.
	store.StorePin("did:key:zStaleHolder", "juan.aweb.ai/grace", "", "")
	// A global-scope agent: pinned by its did:aw stable id, which survives rotation.
	store.StorePin("did:aw:aStable", "juan.aweb.ai/alice", "", "")
	if err := store.Save(path); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func runPinStoreList(t *testing.T, args ...string) string {
	t.Helper()
	cmd := newPinStoreListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pin-store list failed: %v\n%s", err, out.String())
	}
	return out.String()
}

func TestPinStoreListReportsEachBindingByName(t *testing.T) {
	path := pinStoreFixture(t)
	got := runPinStoreList(t, "--path", path)

	for _, want := range []string{
		"juan.aweb.ai/grace",
		"did:key:zStaleHolder",
		"juan.aweb.ai/alice",
		"did:aw:aStable",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("listing does not report %q, so a binding is not reportable by name:\n%s", want, got)
		}
	}
}

func TestPinStoreListFiltersByAddress(t *testing.T) {
	path := pinStoreFixture(t)
	got := runPinStoreList(t, "--path", path, "--address", "juan.aweb.ai/grace")

	if !strings.Contains(got, "did:key:zStaleHolder") {
		t.Fatalf("filtered listing dropped the requested binding:\n%s", got)
	}
	if strings.Contains(got, "juan.aweb.ai/alice") {
		t.Fatalf("filtered listing leaked an unrequested binding:\n%s", got)
	}
}

// The residue computation in aweb-aava consumes this, so it has to be machine-readable
// and it has to distinguish the two key shapes - comparing a global identity's did:aw
// against a certificate's member_did_key reports a false mismatch, which one detector
// did for alice during the investigation.
func TestPinStoreListJSONDistinguishesStableIDFromDIDKey(t *testing.T) {
	path := pinStoreFixture(t)
	got := runPinStoreList(t, "--path", path, "--json")

	var payload struct {
		Path     string `json:"path"`
		Bindings []struct {
			Address  string `json:"address"`
			PinKey   string `json:"pin_key"`
			KeyKind  string `json:"key_kind"`
			StableID string `json:"stable_id,omitempty"`
			DIDKey   string `json:"did_key,omitempty"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("--json output is not parseable: %v\n%s", err, got)
	}
	if payload.Path != path {
		t.Fatalf("payload does not name the store it read: %q", payload.Path)
	}
	kinds := map[string]string{}
	for _, b := range payload.Bindings {
		kinds[b.Address] = b.KeyKind
	}
	if kinds["juan.aweb.ai/grace"] != "did:key" {
		t.Fatalf("a did:key binding is not reported as such: %#v", kinds)
	}
	if kinds["juan.aweb.ai/alice"] != "did:aw" {
		t.Fatalf("a did:aw stable-id binding is not reported as such: %#v", kinds)
	}
}

// An empty store must say so rather than printing nothing: "no output" is how an
// absent store and an unreadable one look identical, which is the confusion this
// command exists to remove.
func TestPinStoreListSaysSoWhenThereAreNoBindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	if err := awid.NewPinStore().Save(path); err != nil {
		t.Fatal(err)
	}
	got := runPinStoreList(t, "--path", path)
	if strings.TrimSpace(got) == "" {
		t.Fatal("an empty store produced no output, so empty and unreadable are indistinguishable")
	}
	if !strings.Contains(got, "no pinned") {
		t.Fatalf("an empty store does not state that it is empty:\n%s", got)
	}
}
