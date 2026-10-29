package main

import (
	"encoding/base64"
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

func TestHumanCanIssueOnlyWithAValidHumanChain(t *testing.T) {
	valid, invalid, human, agent := true, false, "human", "agent"
	for name, tc := range map[string]struct {
		verdict awid.IDChainResult
		issues  bool
	}{
		"a valid human":         {awid.IDChainResult{IdentityValid: &valid, Kind: &human, Reason: "verified"}, true},
		"a valid agent":         {awid.IDChainResult{IdentityValid: &valid, Kind: &agent, Reason: "verified"}, false},
		"an invalid chain":      {awid.IDChainResult{IdentityValid: &invalid, Kind: &human, Reason: "revoked"}, false},
		"unavailable evidence":  {awid.IDChainResult{Reason: "evidence_unavailable"}, false},
		"a valid chain no kind": {awid.IDChainResult{IdentityValid: &valid, Reason: "verified"}, false},
	} {
		if err := humanCanIssue("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", tc.verdict); (err == nil) != tc.issues {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
}

// A rerun after a failed chain step releases the certificate its parent
// already recorded: no evidence is read, nothing is signed again and no
// second entry is logged. The fixture's AWID then refuses the registration
// (it cannot resolve the domain's _awid record), which is the failure the
// next rerun would retry.
func TestIDCreateRerunReleasesTheRecordedCertificate(t *testing.T) {
	registryURL := realAWIDFixture(t)
	for _, parent := range []string{"root", "human"} {
		t.Run(parent, func(t *testing.T) {
			r := newParentCreateRun(t, registryURL)
			pub, controllerKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveControllerKey("example.com", controllerKey); err != nil {
				t.Fatal(err)
			}
			agentPub, agentKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			agentID := awid.ComputeStableID(agentPub)
			identityPath := filepath.Join(r.workingDir, ".aw", "identity.yaml")
			if err := awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(agentPub), StableID: agentID, Address: "example.com/coordinator", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: registryURL, RegistryStatus: "registered", CreatedAt: "2026-10-26T00:00:00Z"}); err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(filepath.Join(r.workingDir, ".aw", "signing.key"), agentKey); err != nil {
				t.Fatal(err)
			}
			issuerParent := map[string]any{"kind": "namespace", "id": "example.com"}
			issuanceDir, err := awconfig.ControllerIssuanceDir("example.com")
			if err != nil {
				t.Fatal(err)
			}
			parentHuman := ""
			if parent == "human" {
				human := frozenRootHuman(t)
				parentHuman = human.StableID
				issuerParent = map[string]any{"kind": "identity", "id": human.StableID}
				dir, err := awconfig.HumanRecordDir(human.Domain, human.StableID)
				if err != nil {
					t.Fatal(err)
				}
				issuanceDir = awconfig.IdentityIssuanceDir(dir)
			}
			certificate := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": agentID, "domain": "example.com", "parent": issuerParent, "kind": "agent", "issuer_key": awid.ComputeDIDKey(pub), "issued_at": "2026-10-26T00:05:00Z"}
			payload, err := awid.IDCertificateSigningBytes(certificate)
			if err != nil {
				t.Fatal(err)
			}
			id, err := awid.IDCertificateID(certificate)
			if err != nil {
				t.Fatal(err)
			}
			_, signature, _ := awid.KeySigner(controllerKey)(payload)
			issuance := awconfig.IDIssuanceFileStore{Dir: issuanceDir}
			if err := issuance.Put(&awid.IDIssuanceEntry{CertificateID: id, Signed: map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(signature)}}); err != nil {
				t.Fatal(err)
			}
			_, err = executeIDCreate(r.workingDir, idCreateOptions{
				Name: "coordinator", Domain: "example.com", RegistryURL: registryURL, SkipDNSVerify: true,
				TXTResolver: staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(pub), "")}},
				Now:         time.Now, ParentHuman: parentHuman, ParentRoot: parent == "root",
				HumanAtTerminal: func() error { return nil }, Keychain: awconfig.HumanKeychain{},
				Prompt: func(string) ([]byte, error) { r.prompts++; return nil, errors.New("nothing is signed again") },
			})
			if err == nil || !strings.Contains(err.Error(), "register the certificate of "+agentID) {
				t.Fatalf("err=%v", err)
			}
			entries, err := os.ReadDir(issuanceDir)
			if err != nil || len(entries) != 1 || r.prompts != 0 {
				t.Fatalf("entries=%d prompts=%d (%v)", len(entries), r.prompts, err)
			}
			if _, err := os.Stat(filepath.Join(r.workingDir, ".aw", "id-chain.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a chain AWID refused was installed")
			}
		})
	}
}
