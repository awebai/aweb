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

// Import answers only an outstanding request of this requester, and verifies
// before anything is installed. Against the real AWID fixture the domain's
// _awid record cannot be resolved, so the root-issued response has no
// current status: it is refused, the request stays outstanding and no chain
// is installed.
func TestParentImportVerifiesBeforeInstalling(t *testing.T) {
	p := newParentRun(t, realAWIDFixture(t))
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
	response := []byte(v.ChildRequests.Responses["root-human-issued"].CanonicalUTF8)

	if _, err := executeIDParentImport(context.Background(), p.opts(), response); awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
		t.Fatalf("a response to no outstanding request: %v", err)
	}

	// The frozen root-issued human, prepared here, with its frozen request outstanding.
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
	store := p.requests(t)
	if err := store.Put(&awconfig.IDOutgoingRequest{RequestID: r["request_id"].(string), InvitationID: r["invitation_id"].(string), Request: request, State: awconfig.IDRequestOutstanding}); err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDParentImport(context.Background(), p.opts(), response); awid.IDCertificateErrorCode(err) != "evidence_unavailable" {
		t.Fatalf("imported without current status: %v", err)
	}
	outgoing, err := store.Request(r["request_id"].(string))
	if err != nil || outgoing.State != awconfig.IDRequestOutstanding || outgoing.Response != "" {
		t.Fatalf("outgoing %+v (%v)", outgoing, err)
	}
	dir, err := awconfig.HumanRecordDir("example.com", frozen.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if installed, err := awconfig.LoadInstalledIDChain(dir); err != nil || installed != nil {
		t.Fatalf("a chain was installed: %v %v", installed, err)
	}
	if p.prompts != 0 {
		t.Fatalf("the human was asked to sign %d times", p.prompts)
	}
	if strings.TrimSpace(frozen.RegisteredAt) != "" {
		t.Fatal("unexpected receipt")
	}
}
