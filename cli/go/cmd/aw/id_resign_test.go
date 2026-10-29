package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

// resignRun is one machine holding both sides of a re-sign: the frozen human
// alice as the issuer, with the coordinator's certificate in her issuance
// log, and the frozen coordinator, a local agent carrying that certificate.
type resignRun struct {
	t         *testing.T
	alice     *awconfig.HumanRecord
	childDir  string
	oldSigned map[string]any
	oldID     string
	prompts   int
}

func newResignRun(t *testing.T) *resignRun {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys map[string]struct {
			SeedHex string `json:"seed_hex"`
			DIDKey  string `json:"did_key"`
		} `json:"keys"`
		Certificates map[string]struct {
			Signed        map[string]any `json:"signed"`
			CertificateID string         `json:"certificate_id"`
		} `json:"certificates"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	r := &resignRun{t: t, alice: frozenRootHuman(t), childDir: t.TempDir(), oldSigned: v.Certificates["coordinator"].Signed, oldID: v.Certificates["coordinator"].CertificateID}
	aliceDir, err := awconfig.HumanRecordDir(r.alice.Domain, r.alice.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if err := (awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(aliceDir)}).Put(&awid.IDIssuanceEntry{CertificateID: r.oldID, Signed: r.oldSigned}); err != nil {
		t.Fatal(err)
	}
	coordinator := v.Keys["coordinator"]
	seed, err := hex.DecodeString(coordinator.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	aw := r.childDir + "/.aw"
	if err := awconfig.SaveWorktreeIdentityTo(aw+"/identity.yaml", &awconfig.WorktreeIdentity{DID: coordinator.DIDKey, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, CreatedAt: "2026-10-26T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(aw+"/signing.key", ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatal(err)
	}
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, r.oldSigned}}
	if err := awconfig.SaveInstalledIDChain(aw, chain); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *resignRun) childOpts() idParentOptions {
	return idParentOptions{
		WorkingDir: r.childDir, TXTResolver: staticTXTResolver{}, HumanAtTerminal: func() error { return nil },
		Keychain: awconfig.HumanKeychain{}, Prompt: func(string) ([]byte, error) { r.prompts++; return nil, errors.New("no human signs here") },
	}
}

func (r *resignRun) issuerOpts() idChildOptions {
	return idChildOptions{
		Issuer:     childIssuerSelection{Human: r.alice.StableID, Domain: r.alice.Domain},
		WorkingDir: r.t.TempDir(), TXTResolver: staticTXTResolver{}, HumanAtTerminal: func() error { return nil },
		Keychain: awconfig.HumanKeychain{}, Prompt: func(string) ([]byte, error) { r.prompts++; return nil, errors.New("no passphrase") },
		Confirm: func(string) (bool, error) { r.t.Fatal("a re-sign asks no fingerprint question"); return false, nil },
		Now:     time.Now,
	}
}

// The local child asks its parent to re-sign exactly the certificate it
// carries, and the parent finds it in its own issuance log.
func TestResignRequestReachesTheIssuanceEntryOfTheCarriedCertificate(t *testing.T) {
	r := newResignRun(t)
	out, raw, err := executeIDParentResign(r.childOpts())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := awid.ParseIDCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	req := signed["request"].(map[string]any)
	old := r.oldSigned["certificate"].(map[string]any)
	if req["operation"] != "resign" || req["invitation_id"] != nil || !reflect.DeepEqual(req["old_certificate"], r.oldSigned) ||
		req["id"] != old["id"] || req["domain"] != old["domain"] || !reflect.DeepEqual(req["parent"], old["parent"]) || req["kind"] != "agent" || req["subject_key"] != old["id"] {
		t.Fatalf("request %v", req)
	}
	outgoing, err := awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(r.childDir + "/.aw")}.Request(out.RequestID)
	if err != nil || outgoing == nil || outgoing.Request != string(raw) || outgoing.State != awconfig.IDRequestOutstanding || outgoing.InvitationID != "" {
		t.Fatalf("outgoing %+v (%v)", outgoing, err)
	}

	received, err := executeIDChildReceive(context.Background(), r.issuerOpts(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if received.Operation != "resign" || received.RequestID != out.RequestID || received.State != awid.IDRequestPending || received.ID != old["id"] || received.Kind != "agent" {
		t.Fatalf("received %+v", received)
	}
	listed, err := listIDChildRequests(context.Background(), r.issuerOpts())
	if err != nil || len(listed) != 1 || listed[0].RequestID != out.RequestID || listed[0].Operation != "resign" {
		t.Fatalf("pending %+v (%v)", listed, err)
	}
	if err := executeIDChildRefuse(context.Background(), r.issuerOpts(), out.RequestID); err != nil {
		t.Fatal(err)
	}
	shown, err := showIDChildRequest(context.Background(), r.issuerOpts(), out.RequestID)
	if err != nil || shown.State != awid.IDRequestFailed {
		t.Fatalf("after refuse %+v (%v)", shown, err)
	}
	if r.prompts != 0 {
		t.Fatalf("a passphrase was asked %d times", r.prompts)
	}
}

// Without current status the parent signs nothing and the request stays
// pending.
func TestResignApprovalSignsNothingWithoutCurrentStatus(t *testing.T) {
	r := newResignRun(t)
	out, raw, err := executeIDParentResign(r.childOpts())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDChildReceive(context.Background(), r.issuerOpts(), raw); err != nil {
		t.Fatal(err)
	}
	if response, err := executeIDChildApprove(context.Background(), r.issuerOpts(), out.RequestID); err == nil || response != nil {
		t.Fatalf("approved without status: %v", err)
	}
	shown, err := showIDChildRequest(context.Background(), r.issuerOpts(), out.RequestID)
	if err != nil || shown.State != awid.IDRequestPending || r.prompts != 0 {
		t.Fatalf("after approve %+v (%v) prompts=%d", shown, err, r.prompts)
	}
}

// A certificate the parent never recorded is refused on receipt: a submitted
// certificate never seeds the issuance log.
func TestResignReceiveRefusesACertificateTheParentDidNotRecord(t *testing.T) {
	r := newResignRun(t)
	_, raw, err := executeIDParentResign(r.childOpts())
	if err != nil {
		t.Fatal(err)
	}
	aliceDir, err := awconfig.HumanRecordDir(r.alice.Domain, r.alice.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(awconfig.IdentityIssuanceDir(aliceDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDChildReceive(context.Background(), r.issuerOpts(), raw); awid.IDCertificateErrorCode(err) != "issuance_not_recorded" {
		t.Fatalf("err=%v", err)
	}
}

// Re-sign is for a local agent carrying an installed chain, as the current
// identity; nothing is signed or recorded otherwise.
func TestResignRequestNeedsALocalChainedAgent(t *testing.T) {
	r := newResignRun(t)
	human := r.childOpts()
	human.Human = r.alice.StableID
	if _, _, err := executeIDParentResign(human); exitCode(err) != 2 {
		t.Fatalf("--human: %v", err)
	}
	if err := os.Remove(r.childDir + "/.aw/id-chain.json"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeIDParentResign(r.childOpts()); exitCode(err) != 2 {
		t.Fatalf("no chain: %v", err)
	}
	if entries, err := os.ReadDir(awconfig.IdentityRequestsDir(r.childDir + "/.aw")); !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
		t.Fatalf("a refused request was recorded: %v", entries)
	}
}

// Import of the parent's re-signed certificate takes its domain from the
// carried chain and verifies before replacing it: without current status the
// old chain and the outstanding request stay as they were.
func TestResignImportVerifiesBeforeReplacingTheCarriedChain(t *testing.T) {
	r := newResignRun(t)
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ChildRequests struct {
			Requests map[string]struct {
				CanonicalUTF8 string `json:"canonical_utf8"`
			} `json:"requests"`
			Responses map[string]struct {
				CanonicalUTF8 string `json:"canonical_utf8"`
			} `json:"responses"`
		} `json:"child_requests"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	request := v.ChildRequests.Requests["local-resign"].CanonicalUTF8
	signed, err := awid.ParseIDCertificateRequest([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	requestID := signed["request"].(map[string]any)["request_id"].(string)
	store := awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(r.childDir + "/.aw")}
	if err := store.Put(&awconfig.IDOutgoingRequest{RequestID: requestID, Request: request, State: awconfig.IDRequestOutstanding}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.childDir + "/.aw/id-chain.json")
	if err != nil {
		t.Fatal(err)
	}
	opts := r.childOpts()
	opts.TXTResolver = staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(r.alice.DIDKey, "https://registry.example.com")}}
	if _, err := executeIDParentImport(context.Background(), opts, []byte(v.ChildRequests.Responses["local-resigned"].CanonicalUTF8)); awid.IDCertificateErrorCode(err) != "evidence_unavailable" {
		t.Fatalf("imported without current status: %v", err)
	}
	after, err := os.ReadFile(r.childDir + "/.aw/id-chain.json")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the carried chain changed (%v)", err)
	}
	outgoing, err := store.Request(requestID)
	if err != nil || outgoing.State != awconfig.IDRequestOutstanding || outgoing.Response != "" {
		t.Fatalf("outgoing %+v (%v)", outgoing, err)
	}
}

// The namespace root re-signs nothing: its certificates are registered and
// keep their signature across its rotation.
func TestResignIsNotReceivedByTheRoot(t *testing.T) {
	r := newResignRun(t)
	_, raw, err := executeIDParentResign(r.childOpts())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", key); err != nil {
		t.Fatal(err)
	}
	root := r.issuerOpts()
	root.Issuer = childIssuerSelection{AsRoot: true, Domain: "example.com"}
	root.TXTResolver = staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(pub), "https://registry.example.com")}}
	if _, err := executeIDChildReceive(context.Background(), root, raw); exitCode(err) != 2 {
		t.Fatalf("err=%v", err)
	}
}

// A registered agent keeps its signature across its parent's rotation, so it
// asks for no re-sign.
func TestResignRequestRefusesARegisteredAgent(t *testing.T) {
	r := newResignRun(t)
	path := r.childDir + "/.aw/identity.yaml"
	identity, err := awconfig.LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	identity.StableID, identity.Address, identity.IdentityScope = "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4", "example.com/coordinator", awid.IdentityModeGlobal
	identity.RegistryURL, identity.RegistryStatus = "https://registry.example.com", "registered"
	if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeIDParentResign(r.childOpts()); exitCode(err) != 2 {
		t.Fatalf("err=%v", err)
	}
}
