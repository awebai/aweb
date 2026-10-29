package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

// frozenRootHuman installs, as this machine's registered human, the frozen
// root-issued human of docs/vectors/id-certificates-v1.json: its record and
// its chain, as `aw id human init` leaves them.
func frozenRootHuman(t *testing.T) *awconfig.HumanRecord {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys map[string]struct {
			DIDKey string `json:"did_key"`
			DIDAW  string `json:"did_aw"`
		} `json:"keys"`
		ChildRequests struct {
			Responses map[string]struct {
				CanonicalUTF8 string `json:"canonical_utf8"`
			} `json:"responses"`
		} `json:"child_requests"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	response, err := awid.ParseIDCertificateResponse([]byte(v.ChildRequests.Responses["root-human-issued"].CanonicalUTF8))
	if err != nil {
		t.Fatal(err)
	}
	chain := response["chain"].(map[string]any)
	certificates := chain["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	rec := &awconfig.HumanRecord{StableID: leaf["id"].(string), Domain: leaf["domain"].(string), State: awconfig.HumanRegistered}
	for _, key := range v.Keys {
		if key.DIDAW == rec.StableID {
			rec.DIDKey = key.DIDKey
		}
	}
	if rec.DIDKey == "" {
		t.Fatalf("no frozen key for %s", rec.StableID)
	}
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	dir, err := awconfig.HumanRecordDir(rec.Domain, rec.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(dir, chain); err != nil {
		t.Fatal(err)
	}
	return rec
}

type parentCreateRun struct {
	t           *testing.T
	workingDir  string
	registryURL string
	prompts     int
}

func newParentCreateRun(t *testing.T, registryURL string) *parentCreateRun {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	return &parentCreateRun{t: t, workingDir: t.TempDir(), registryURL: registryURL}
}

func (r *parentCreateRun) create(parentHuman string, atTerminal error) (idCreateOutput, error) {
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		r.t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", key); err != nil {
		r.t.Fatal(err)
	}
	return executeIDCreate(r.workingDir, idCreateOptions{
		Name:            "coordinator",
		Domain:          "example.com",
		RegistryURL:     r.registryURL,
		SkipDNSVerify:   true,
		TXTResolver:     staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(pub), "")}},
		Now:             time.Now,
		ParentHuman:     parentHuman,
		HumanAtTerminal: func() error { return atTerminal },
		Keychain:        awconfig.HumanKeychain{},
		Prompt: func(string) ([]byte, error) {
			r.prompts++
			return nil, errors.New("no human signature is expected here")
		},
	})
}

func (r *parentCreateRun) assertNoAgent() {
	r.t.Helper()
	for _, name := range []string{"identity.yaml", "signing.key", "id-chain.json"} {
		if _, err := os.Stat(filepath.Join(r.workingDir, ".aw", name)); !errors.Is(err, os.ErrNotExist) {
			r.t.Fatalf("%s was written: %v", name, err)
		}
	}
	if r.prompts != 0 {
		r.t.Fatalf("the human was asked to sign %d times", r.prompts)
	}
}

func TestIDCreateParentHumanMustBeARegisteredHumanOnThisMachine(t *testing.T) {
	r := newParentCreateRun(t, "https://registry.example.com")
	if _, err := r.create("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", nil); err == nil || !strings.Contains(err.Error(), "no human") {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()

	human := frozenRootHuman(t)
	human.State = awconfig.HumanDIDRegistered
	if err := awconfig.SaveHumanRecord(human); err != nil {
		t.Fatal(err)
	}
	if _, err := r.create(human.StableID, nil); err == nil || !strings.Contains(err.Error(), "not registered yet") {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()
}

func TestIDCreateParentHumanNeedsAHumanAtTheTerminal(t *testing.T) {
	r := newParentCreateRun(t, "https://registry.example.com")
	human := frozenRootHuman(t)
	refusal := errors.New("this command needs a human at an interactive terminal")
	if _, err := r.create(human.StableID, refusal); !errors.Is(err, refusal) {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()
}

// The human's chain is verified against current status before the agent
// exists. Against the real AWID fixture the frozen human is not registered
// and its domain has no _awid record AWID can resolve, so the human cannot
// issue: no agent is created, registered or left chainless.
func TestIDCreateParentHumanThatCannotIssueLeavesNoAgent(t *testing.T) {
	registryURL := realAWIDFixture(t)
	r := newParentCreateRun(t, registryURL)
	human := frozenRootHuman(t)
	if _, err := r.create(human.StableID, nil); err == nil || !strings.Contains(err.Error(), "cannot issue now") {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()
	registry := awid.NewAWIDRegistryClient(nil, nil)
	if _, _, err := registry.GetNamespaceAddressAt(t.Context(), registryURL, "example.com", "coordinator"); err == nil {
		t.Fatal("the agent's address was claimed")
	}
}

func (r *parentCreateRun) createUnderRoot(parentHuman string, dnsController string) (idCreateOutput, error) {
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		r.t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", key); err != nil {
		r.t.Fatal(err)
	}
	if dnsController == "" {
		dnsController = awid.ComputeDIDKey(pub)
	}
	return executeIDCreate(r.workingDir, idCreateOptions{
		Name:            "coordinator",
		Domain:          "example.com",
		RegistryURL:     r.registryURL,
		SkipDNSVerify:   true,
		TXTResolver:     staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(dnsController, "")}},
		Now:             time.Now,
		ParentHuman:     parentHuman,
		ParentRoot:      true,
		HumanAtTerminal: func() error { return nil },
		Keychain:        awconfig.HumanKeychain{},
		Prompt: func(string) ([]byte, error) {
			r.prompts++
			return nil, errors.New("no human signature is expected under the root")
		},
	})
}

func TestIDCreateNamesOneParent(t *testing.T) {
	r := newParentCreateRun(t, "https://registry.example.com")
	if _, err := r.createUnderRoot("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", ""); err == nil || !strings.Contains(err.Error(), "choose one") {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()
}

// --parent-root checks exact DNS even with --skip-dns-verify: AWID holds the
// root's signature to the DNS controller, so a mismatch would leave the
// agent chainless.
func TestIDCreateParentRootRefusesADNSControllerOtherThanThisMachines(t *testing.T) {
	r := newParentCreateRun(t, "https://registry.example.com")
	other, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.createUnderRoot("", awid.ComputeDIDKey(other)); err == nil || !strings.Contains(err.Error(), "does not match this machine's controller") {
		t.Fatalf("err=%v", err)
	}
	r.assertNoAgent()
}
