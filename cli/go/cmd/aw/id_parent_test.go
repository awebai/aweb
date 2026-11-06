package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// parentRun is one machine holding both sides: a namespace root that
// invites, and a human prepared on the request path that answers.
type parentRun struct {
	child   *childHarness
	human   idHumanInitOutput
	prompts int
}

func newParentRun(t *testing.T, registryURL string) *parentRun {
	t.Helper()
	child := newChildHarness(t, registryURL)
	answers := []string{humanPassphrase, humanPassphrase}
	human, err := executeIDHumanInit(context.Background(), idHumanInitOptions{
		Domain: "example.com", HumanAtTerminal: func() error { return nil }, Keychain: awconfig.HumanKeychain{},
		Prompt: func(string) ([]byte, error) { a := answers[0]; answers = answers[1:]; return []byte(a), nil },
		Now:    time.Now,
	})
	if err != nil || human.Status != "prepared" {
		t.Fatalf("prepare: %+v %v", human, err)
	}
	return &parentRun{child: child, human: human}
}

func (p *parentRun) opts() idParentOptions {
	return idParentOptions{
		Human: p.human.ID, Domain: "example.com", WorkingDir: p.child.opts.WorkingDir, RegistryURL: p.child.opts.RegistryURL,
		TXTResolver: p.child.opts.TXTResolver, HumanAtTerminal: func() error { return nil }, Keychain: awconfig.HumanKeychain{},
		Prompt: func(string) ([]byte, error) { p.prompts++; return []byte(humanPassphrase), nil },
	}
}

func (p *parentRun) requests(t *testing.T) awconfig.IDRequestFileStore {
	t.Helper()
	dir, err := awconfig.HumanRecordDir("example.com", p.human.ID)
	if err != nil {
		t.Fatal(err)
	}
	return awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(dir)}
}

// The prepared human's request reaches its issuer bound to the invitation,
// and the fingerprint the human is told to pass on is the one the issuer
// confirms against.
func TestParentRequestBindsAtTheIssuerWithTheToldFingerprint(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	inv := p.child.invite("human")
	out, raw, err := executeIDParentRequest(p.opts(), inv.InvitationID, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if p.prompts != 1 || out.ID != p.human.ID || out.Kind != "human" {
		t.Fatalf("out=%+v prompts=%d", out, p.prompts)
	}
	outgoing, err := p.requests(t).Request(out.RequestID)
	if err != nil || outgoing == nil || outgoing.State != awconfig.IDRequestOutstanding || outgoing.Request != string(raw) || outgoing.InvitationID != inv.InvitationID {
		t.Fatalf("outgoing %+v (%v)", outgoing, err)
	}
	received, err := executeIDChildReceive(context.Background(), p.child.opts, raw)
	if err != nil {
		t.Fatal(err)
	}
	if received.RequestID != out.RequestID || received.Fingerprint != out.Fingerprint || received.ID != p.human.ID || received.Kind != "human" {
		t.Fatalf("issuer sees %+v, requester was told %+v", received, out)
	}
}

func TestParentRequestNamesItsInvitationAndOneParent(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	inv := p.child.invite("human")
	for name, call := range map[string]func() error{
		"no invitation": func() error { _, _, err := executeIDParentRequest(p.opts(), "", "", true); return err },
		"two parents": func() error {
			_, _, err := executeIDParentRequest(p.opts(), inv.InvitationID, "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", true)
			return err
		},
		"no parent": func() error { _, _, err := executeIDParentRequest(p.opts(), inv.InvitationID, "", false); return err },
		"a domain-looking parent ID": func() error {
			_, _, err := executeIDParentRequest(p.opts(), inv.InvitationID, "example.com", false)
			return err
		},
		"a human not prepared here": func() error {
			opts := p.opts()
			opts.Human = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
			_, _, err := executeIDParentRequest(opts, inv.InvitationID, "", true)
			return err
		},
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: a request was exported", name)
		}
	}
	if entries, err := os.ReadDir(p.requests(t).Dir); !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
		t.Fatalf("a refused request was recorded: %v", entries)
	}
	if p.prompts != 0 {
		t.Fatalf("the human was asked to sign %d times", p.prompts)
	}
}

// frozenOutstanding prepares here the frozen root-issued human with its frozen
// request outstanding, and returns the frozen response to it.
func (p *parentRun) frozenOutstanding(t *testing.T) (response []byte, requestID string) {
	t.Helper()
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
	request := v.ChildRequests.Requests["root-human-issue"].CanonicalUTF8
	signed, err := awid.ParseIDCertificateRequest([]byte(request))
	if err != nil {
		t.Fatal(err)
	}
	r := signed["request"].(map[string]any)
	frozen := &awconfig.HumanRecord{StableID: r["id"].(string), DIDKey: r["subject_key"].(string), Domain: "example.com", State: awconfig.HumanPrepared, Path: awconfig.HumanPathRequest}
	if err := awconfig.SaveHumanRecord(frozen); err != nil {
		t.Fatal(err)
	}
	p.human.ID = frozen.StableID
	if err := p.requests(t).Put(&awconfig.IDOutgoingRequest{RequestID: r["request_id"].(string), InvitationID: r["invitation_id"].(string), Request: request, State: awconfig.IDRequestOutstanding}); err != nil {
		t.Fatal(err)
	}
	return []byte(v.ChildRequests.Responses["root-human-issued"].CanonicalUTF8), r["request_id"].(string)
}

// assertOutstanding checks that nothing of the response was kept or installed
// and that the human was never asked to sign.
func (p *parentRun) assertOutstanding(t *testing.T, requestID string) {
	t.Helper()
	outgoing, err := p.requests(t).Request(requestID)
	if err != nil || outgoing.State != awconfig.IDRequestOutstanding || outgoing.Response != "" {
		t.Fatalf("outgoing %+v (%v)", outgoing, err)
	}
	dir, err := awconfig.HumanRecordDir("example.com", p.human.ID)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := awconfig.LoadInstalledIDChain(dir); err != nil || installed != nil {
		t.Fatalf("a chain was installed: %v %v", installed, err)
	}
	if rec, err := awconfig.LoadHumanRecord("example.com", p.human.ID); err != nil || rec.State != awconfig.HumanPrepared || rec.RegisteredAt != "" {
		t.Fatalf("human record %+v (%v)", rec, err)
	}
	if p.prompts != 0 {
		t.Fatalf("the human was asked to sign %d times", p.prompts)
	}
}

// Import answers only an outstanding request of this requester, and verifies
// before anything is installed. No registry answers at the --registry
// origin, so the root-issued response has no current status: it is refused,
// the request stays outstanding and no chain is installed. Nothing here
// resolves a name.
func TestParentImportVerifiesBeforeInstalling(t *testing.T) {
	p := newParentRun(t, "http://127.0.0.1:1")
	other := *p
	response, requestID := p.frozenOutstanding(t)
	if _, err := executeIDParentImport(context.Background(), other.opts(), response); awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
		t.Fatalf("a response to another requester's request: %v", err)
	}
	if _, err := executeIDParentImport(context.Background(), p.opts(), response); awid.IDCertificateErrorCode(err) != "evidence_unavailable" {
		t.Fatalf("imported without current status: %v", err)
	}
	p.assertOutstanding(t, requestID)
}

// The requester reads status from the registry its domain's _awid record
// names, as the issuer does; a --registry that contradicts it is refused.
func TestParentImportRefusesARegistryTheDomainDoesNotName(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	response, requestID := p.frozenOutstanding(t)
	resolver := p.child.opts.TXTResolver.(staticTXTResolver)
	controller := resolver["_awid.example.com"][0]
	resolver["_awid.example.com"] = []string{strings.TrimSuffix(controller, ";") + "; registry=https://registry.other.example;"}
	if _, err := executeIDParentImport(context.Background(), p.opts(), response); exitCode(err) != 2 {
		t.Fatalf("err=%v", err)
	}
	p.assertOutstanding(t, requestID)
}

// An identity that already has an installed chain does not request a first
// certificate: importing one would replace its working chain before AWID
// accepted the new certificate.
func TestParentRequestRefusesAnIdentityThatHasAChain(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	installChainedAgent(t, p.child.opts.WorkingDir)
	inv := p.child.invite("agent")
	opts := p.opts()
	opts.Human = ""
	if _, _, err := executeIDParentRequest(opts, inv.InvitationID, "", true); exitCode(err) != 2 {
		t.Fatalf("err=%v", err)
	}
	if entries, err := os.ReadDir(p.child.opts.WorkingDir + "/.aw/requests"); !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
		t.Fatalf("a refused request was recorded: %v", entries)
	}
}

// A request already imported takes only its own exact response again.
func TestParentImportOfAnImportedRequestTakesOnlyItsResponse(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	response, requestID := p.frozenOutstanding(t)
	store := p.requests(t)
	outgoing, err := store.Request(requestID)
	if err != nil {
		t.Fatal(err)
	}
	outgoing.State, outgoing.Response, outgoing.Registration = awconfig.IDRequestImported, "{}", "pending"
	if err := store.Put(outgoing); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDParentImport(context.Background(), p.opts(), response); awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
		t.Fatalf("a different response was taken: %v", err)
	}
	if p.prompts != 0 {
		t.Fatalf("the human was asked to sign %d times", p.prompts)
	}
}

// --human signs as the human: it needs the human at the terminal, and a human
// prepared here for the request exchange.
func TestParentRequestAsAHumanNeedsThatHumanPreparedForARequest(t *testing.T) {
	p := newParentRun(t, "https://registry.example.com")
	inv := p.child.invite("human")
	away := p.opts()
	away.HumanAtTerminal = func() error { return &awid.IDCertificateError{Code: "human_approval_required"} }
	if _, _, err := executeIDParentRequest(away, inv.InvitationID, "", true); awid.IDCertificateErrorCode(err) != "human_approval_required" {
		t.Fatalf("without the human: %v", err)
	}
	rec, err := awconfig.LoadHumanRecord("example.com", p.human.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Path = awconfig.HumanPathRoot
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeIDParentRequest(p.opts(), inv.InvitationID, "", true); exitCode(err) != 2 {
		t.Fatalf("a root-path human: %v", err)
	}
	if entries, err := os.ReadDir(p.requests(t).Dir); !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
		t.Fatalf("a refused request was recorded: %v", entries)
	}
	if p.prompts != 0 {
		t.Fatalf("the human was asked to sign %d times", p.prompts)
	}
}
