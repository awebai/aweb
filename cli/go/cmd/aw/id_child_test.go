package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

const childNote = "Bob, met at the offsite"

// childHarness is a namespace root on this machine: its controller key and
// the _awid record naming it.
type childHarness struct {
	t         *testing.T
	opts      idChildOptions
	confirms  []string
	answer    bool
	shown     bytes.Buffer
	recipient ed25519.PrivateKey
}

func newChildHarness(t *testing.T, registryURL string) *childHarness {
	t.Helper()
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", key); err != nil {
		t.Fatal(err)
	}
	h := &childHarness{t: t}
	if _, h.recipient, err = awid.GenerateKeypair(); err != nil {
		t.Fatal(err)
	}
	h.opts = idChildOptions{
		Issuer:          childIssuerSelection{AsRoot: true, Domain: "example.com"},
		WorkingDir:      t.TempDir(),
		RegistryURL:     registryURL,
		TXTResolver:     staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(awid.ComputeDIDKey(pub), "")}},
		HumanAtTerminal: func() error { return nil },
		Keychain:        awconfig.HumanKeychain{},
		Prompt:          func(string) ([]byte, error) { return nil, errors.New("no passphrase is asked under the root") },
		Confirm: func(question string) (bool, error) {
			h.confirms = append(h.confirms, question)
			return h.answer, nil
		},
		Show: &h.shown,
		Now:  time.Now,
	}
	return h
}

func (h *childHarness) invite(kind string) idChildInviteOutput {
	h.t.Helper()
	out, err := executeIDChildInvite(context.Background(), h.opts, kind, childNote, 24*time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

// request is the recipient's signed request for the invitation, under its
// own key.
func (h *childHarness) request(inv idChildInviteOutput) ([]byte, string) {
	h.t.Helper()
	pub := h.recipient.Public().(ed25519.PublicKey)
	requestID, err := newInvitationID()
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := awid.SignIDCertificateRequest(map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": requestID, "operation": "issue",
		"id": awid.ComputeStableID(pub), "domain": inv.Domain, "parent": inv.Parent, "kind": inv.Kind,
		"subject_key": awid.ComputeDIDKey(pub), "invitation_id": inv.InvitationID, "old_certificate": nil,
	}, awid.KeySigner(h.recipient))
	if err != nil {
		h.t.Fatal(err)
	}
	return raw, requestID
}

func (h *childHarness) received(kind string) (idChildRequestOutput, string) {
	h.t.Helper()
	raw, requestID := h.request(h.invite(kind))
	out, err := executeIDChildReceive(context.Background(), h.opts, raw)
	if err != nil {
		h.t.Fatal(err)
	}
	return out, requestID
}

func (h *childHarness) state(requestID string) *awid.IDInvitation {
	h.t.Helper()
	issuer, err := selectChildIssuer(context.Background(), h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	found, err := findReceivedRequest(issuer, requestID)
	if err != nil || found.invitation == nil {
		h.t.Fatalf("no invitation request %s: %v", requestID, err)
	}
	return found.invitation
}

func (h *childHarness) issued() int {
	h.t.Helper()
	dir, err := awconfig.ControllerIssuanceDir("example.com")
	if err != nil {
		h.t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return len(entries)
}

func TestChildInviteExportsNeitherTheRecipientNoteNorAnyKey(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	out := h.invite("human")
	exported, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exported), childNote) || strings.Contains(formatIDChildInvite(out), childNote) {
		t.Fatalf("the invitation exports the private note: %s", exported)
	}
	if out.Kind != "human" || out.Domain != "example.com" || out.Parent["kind"] != "namespace" || out.Parent["id"] != "example.com" {
		t.Fatalf("invitation %+v", out)
	}
	dir, err := awconfig.ControllerInvitationsDir("example.com")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := awconfig.IDInvitationFileStore{Dir: dir}.Invitation(out.InvitationID)
	if err != nil || inv == nil || inv.Recipient != childNote || inv.Mode != awid.IDInvitationSelfCustodial {
		t.Fatalf("stored invitation %+v (%v)", inv, err)
	}
}

func TestChildInviteRefusesAnIncompleteInvitation(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	for name, call := range map[string]func() error{
		"no kind": func() error {
			_, err := executeIDChildInvite(context.Background(), h.opts, "", childNote, time.Hour)
			return err
		},
		"unknown kind": func() error {
			_, err := executeIDChildInvite(context.Background(), h.opts, "robot", childNote, time.Hour)
			return err
		},
		"no recipient": func() error {
			_, err := executeIDChildInvite(context.Background(), h.opts, "human", " ", time.Hour)
			return err
		},
		"no expiry left": func() error {
			_, err := executeIDChildInvite(context.Background(), h.opts, "human", childNote, 0)
			return err
		},
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: invited", name)
		}
	}
	h.opts.Issuer.Human = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
	if _, err := executeIDChildInvite(context.Background(), h.opts, "human", childNote, time.Hour); err == nil || !strings.Contains(err.Error(), "choose one") {
		t.Fatalf("two issuers: %v", err)
	}
}

func TestChildReceiveBindsTheRequestAndShowsItsOwnFingerprint(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	out, requestID := h.received("human")
	want, err := awid.IDKeyFingerprint(awid.ComputeDIDKey(h.recipient.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestID != requestID || out.State != awid.IDRequestPending || out.Fingerprint != want {
		t.Fatalf("received %+v want fingerprint %s", out, want)
	}
	issuer, err := selectChildIssuer(context.Background(), h.opts)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := awid.IDChildRequests(issuer.invitations)
	if err != nil || len(listed) != 1 || listed[0].RequestID != requestID {
		t.Fatalf("pending %+v (%v)", listed, err)
	}
	if strings.Contains(formatIDChildPending(listed), childNote) {
		t.Fatal("pending shows the private note")
	}
}

// N88(d): the fingerprint the issuer confirms is the one of the stored
// request's own key, for the request it then approves. A no signs nothing
// and leaves the request pending and the invitation live.
func TestChildApproveOfAHumanAsksAboutTheStoredRequestsFingerprint(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	received, requestID := h.received("human")
	h.answer = false
	response, err := executeIDChildApprove(context.Background(), h.opts, requestID)
	if code := awid.IDCertificateErrorCode(err); code != "human_approval_required" || response != nil {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if len(h.confirms) != 1 || !strings.Contains(h.confirms[0], received.Fingerprint) || !strings.Contains(h.confirms[0], childNote) || !strings.HasSuffix(h.confirms[0], "[y/N] ") {
		t.Fatalf("asked %q", h.confirms)
	}
	if !strings.Contains(h.shown.String(), received.ID) || !strings.Contains(h.shown.String(), received.Fingerprint) {
		t.Fatalf("shown:\n%s", h.shown.String())
	}
	inv := h.state(requestID)
	if inv.Request.State != awid.IDRequestPending || inv.Void || h.issued() != 0 {
		t.Fatalf("state=%s void=%v issued=%d", inv.Request.State, inv.Void, h.issued())
	}
}

func TestChildApproveOfAHumanNeedsItsIssuerAtTheTerminal(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	_, requestID := h.received("human")
	refusal := errors.New("this command needs a human at an interactive terminal")
	h.opts.HumanAtTerminal = func() error { return refusal }
	h.answer = true
	if response, err := executeIDChildApprove(context.Background(), h.opts, requestID); !errors.Is(err, refusal) || response != nil {
		t.Fatalf("err=%v", err)
	}
	if len(h.confirms) != 0 || h.issued() != 0 || h.state(requestID).Request.State != awid.IDRequestPending {
		t.Fatalf("confirms=%d issued=%d", len(h.confirms), h.issued())
	}
}

// A confirmed approval still signs only against current status. Against the
// real AWID fixture the domain's _awid record cannot be resolved, so the
// root has no open epoch: nothing is signed and the request stays pending.
func TestChildApproveSignsNothingWithoutCurrentStatus(t *testing.T) {
	h := newChildHarness(t, realAWIDFixture(t))
	_, requestID := h.received("human")
	h.answer = true
	response, err := executeIDChildApprove(context.Background(), h.opts, requestID)
	if code := awid.IDCertificateErrorCode(err); code != "evidence_unavailable" || response != nil {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if h.issued() != 0 || h.state(requestID).Request.State != awid.IDRequestPending {
		t.Fatalf("issued=%d", h.issued())
	}
}

func TestChildRefuseSignsNothingAndEndsTheRequest(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	_, requestID := h.received("agent")
	issuer, err := selectChildIssuer(context.Background(), h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.RefuseIDChildRequest(issuer.invitations, requestID); err != nil {
		t.Fatal(err)
	}
	if state := h.state(requestID).Request.State; state != awid.IDRequestFailed {
		t.Fatalf("state=%s", state)
	}
	if response, err := executeIDChildApprove(context.Background(), h.opts, requestID); err == nil || response != nil {
		t.Fatal("approved a refused request")
	}
	if h.issued() != 0 {
		t.Fatal("a refused request was signed")
	}
}

// The current agent identity issues only agents: it may invite an agent
// child, never a human one.
// installChainedAgent makes workingDir's identity the frozen coordinator
// agent, with its alice -> coordinator chain installed, and returns its ID.
func installChainedAgent(t *testing.T, workingDir string) string {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Certificates map[string]struct {
			Signed map[string]any `json:"signed"`
		} `json:"certificates"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}
	agentID := v.Certificates["coordinator"].Signed["certificate"].(map[string]any)["id"].(string)
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	aw := workingDir + "/.aw"
	if err := awconfig.SaveWorktreeIdentityTo(aw+"/identity.yaml", &awconfig.WorktreeIdentity{DID: awid.ComputeDIDKey(pub), StableID: agentID, Address: "example.com/coordinator", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://registry.example.com", RegistryStatus: "registered", CreatedAt: "2026-10-26T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(aw+"/signing.key", key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveInstalledIDChain(aw, chain); err != nil {
		t.Fatal(err)
	}
	return agentID
}

func TestChildInviteUnderAnAgentInvitesOnlyAgents(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	agentID := installChainedAgent(t, h.opts.WorkingDir)
	h.opts.Issuer = childIssuerSelection{}
	if _, err := executeIDChildInvite(context.Background(), h.opts, "human", childNote, time.Hour); err == nil || !strings.Contains(err.Error(), "an agent cannot invite a human") {
		t.Fatalf("err=%v", err)
	}
	out, err := executeIDChildInvite(context.Background(), h.opts, "agent", childNote, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if out.Parent["kind"] != "identity" || out.Parent["id"] != agentID || out.Domain != "example.com" {
		t.Fatalf("invitation %+v", out)
	}
}

// receive, approve and refuse each hold the issuer's lock across their
// read-modify-write, so two runs by one issuer never both write.
func TestChildCommandsWaitForTheIssuersLock(t *testing.T) {
	h := newChildHarness(t, "https://registry.example.com")
	inv := h.invite("agent")
	issuer, err := selectChildIssuer(context.Background(), h.opts)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := awconfig.LockExclusive(childIssuerLockPath(issuer))
	if err != nil {
		t.Fatal(err)
	}
	raw, requestID := h.request(inv)
	done := make(chan error, 1)
	go func() {
		_, err := executeIDChildReceive(context.Background(), h.opts, raw)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("receive did not wait for the lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h.state(requestID).Request.State != awid.IDRequestPending {
		t.Fatal("the request was not bound")
	}
}
