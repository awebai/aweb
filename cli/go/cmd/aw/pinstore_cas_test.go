package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

func pinStoreYAML(t *testing.T, store *awid.PinStore) []byte {
	t.Helper()
	data, err := yaml.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pinStoreWithAddress(did, address string) *awid.PinStore {
	store := awid.NewPinStore()
	store.StorePin(did, address, "", "")
	return store
}

func TestCompareAndSetPinStoreAcceptsCurrentPrecondition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	expected := awid.NewPinStore()
	desired := pinStoreWithAddress("did:key:zAlice", "acme.com/alice")

	if err := compareAndSetPinStore(path, pinStoreYAML(t, expected), pinStoreYAML(t, desired)); err != nil {
		t.Fatalf("matching precondition was refused: %v", err)
	}

	got, err := awid.LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addresses["acme.com/alice"] != "did:key:zAlice" {
		t.Fatalf("desired pin was not committed: %#v", got.Addresses)
	}
}

func TestCompareAndSetPinStoreFailsClosedWhenLockCannotBeCreated(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "known_agents.yaml")
	err := compareAndSetPinStore(
		path,
		pinStoreYAML(t, awid.NewPinStore()),
		pinStoreYAML(t, pinStoreWithAddress("did:key:zAlice", "acme.com/alice")),
	)
	if err == nil || !strings.Contains(err.Error(), "lock trust pin store") {
		t.Fatalf("lock failure must visibly refuse the mutation, got %v", err)
	}
	content, readErr := os.ReadFile(blocker)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "unchanged" {
		t.Fatalf("lock failure damaged the existing path: %q", content)
	}
}

// The precondition is a snapshot taken before the lock, so it can be an empty
// store while the file on disk is corrupt. If the load error were swallowed and
// an unreadable store treated as empty, the precondition would match, and the
// commit would overwrite the damaged trust database instead of surfacing it —
// destroying the pins rather than refusing to proceed. Asserting the file is
// unchanged is what separates that from a refusal.
func TestCompareAndSetPinStoreRefusesToCommitOverACorruptStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	corrupt := "pins: 42\naddresses: {}\n"
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}

	err := compareAndSetPinStore(
		path,
		pinStoreYAML(t, awid.NewPinStore()),
		pinStoreYAML(t, pinStoreWithAddress("did:key:zAlice", "acme.com/alice")),
	)
	if err == nil {
		t.Fatal("a corrupt store on disk was committed over, want a visible refusal")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error %q does not report the corrupt store: the mutation was refused by a different check", err)
	}

	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != corrupt {
		t.Fatalf("the corrupt store was overwritten:\n%s", content)
	}
}

func TestCompareAndSetPinStoreRefusesStalePreconditionWithoutOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	expected := awid.NewPinStore()
	alice := pinStoreWithAddress("did:key:zAlice", "acme.com/alice")
	bob := pinStoreWithAddress("did:key:zBob", "acme.com/bob")

	if err := compareAndSetPinStore(path, pinStoreYAML(t, expected), pinStoreYAML(t, alice)); err != nil {
		t.Fatal(err)
	}
	err := compareAndSetPinStore(path, pinStoreYAML(t, expected), pinStoreYAML(t, bob))
	if err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("stale precondition must produce a visible refusal, got %v", err)
	}

	got, err := awid.LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addresses["acme.com/alice"] != "did:key:zAlice" || got.Addresses["acme.com/bob"] != "" {
		t.Fatalf("stale writer damaged the committed store: %#v", got.Addresses)
	}
}

func TestConfigureResolvedClientUsesCASForGoTrustWrites(t *testing.T) {
	path := withHome(t)
	const baseURL = "https://app.aweb.ai/api"
	client, err := aweb.New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := configureResolvedClient(client, &awconfig.Selection{
		Address:       "me@example.com",
		IdentityScope: awid.IdentityModeGlobal,
		BaseURL:       baseURL,
	}, baseURL); err != nil {
		t.Fatal(err)
	}

	otherWriter := pinStoreWithAddress("did:key:zBob", "did:key:zBob")
	if err := otherWriter.Save(path); err != nil {
		t.Fatal(err)
	}
	status := client.Client.CheckTOFUPin(
		context.Background(), awid.Verified, "did:key:zAlice", "did:key:zAlice", "", nil, nil,
	)
	if status != awid.VerificationStale {
		t.Fatalf("stale Go trust decision status=%q, want %q", status, awid.VerificationStale)
	}
	persisted, err := awid.LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Addresses["did:key:zBob"] != "did:key:zBob" || persisted.Addresses["did:key:zAlice"] != "" {
		t.Fatalf("stale Go writer overwrote the current store: %#v", persisted.Addresses)
	}
}

func TestPinStoreCompareAndSetRequestIsBounded(t *testing.T) {
	input := strings.NewReader(strings.Repeat(" ", int(maxPinStoreCASRequestBytes)+1))
	if _, err := decodePinStoreCASRequest(input); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized request must be refused, got %v", err)
	}
}

func TestPinStoreCompareAndSetCommandReadsSnapshotsFromStdin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	expected := string(pinStoreYAML(t, awid.NewPinStore()))
	desired := string(pinStoreYAML(t, pinStoreWithAddress("did:key:zAlice", "acme.com/alice")))
	input := `{"expected_yaml":` + quotedJSON(expected) + `,"desired_yaml":` + quotedJSON(desired) + `}`

	cmd := newPinStoreCompareAndSetCmd()
	cmd.SetArgs([]string{"--path", path})
	cmd.SetIn(strings.NewReader(input))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("command failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("command did not write the pin store: %v", err)
	}
}

func quotedJSON(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return `"` + value + `"`
}
