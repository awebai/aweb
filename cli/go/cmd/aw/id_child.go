package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The parent side of the request exchange (docs/id-certificates.md §6). The
// issuer fixes an invitation privately (`child invite`), the recipient
// exports a request naming it, and the issuer receives it, reviews it and
// approves or refuses it. Files and `-` for stdin/stdout are the transport.
// The issuer is selected explicitly: --as-root --domain D for the namespace
// root, --human <did:aw> for a human on this machine, and otherwise the
// current agent identity.

var (
	idChildAsRoot   bool
	idChildDomain   string
	idChildHuman    string
	idChildKind     string
	idChildNote     string
	idChildExpires  time.Duration
	idChildOut      string
	idChildRegistry string

	idChildCmd = &cobra.Command{
		Use:   "child",
		Short: "Invite, receive and approve requests from children you issue",
	}
	idChildInviteCmd = &cobra.Command{
		Use:   "invite",
		Short: "Fix an invitation for one child before it exports its request",
		Long: "Fix an invitation for one child of --kind, and print what the recipient\n" +
			"needs to export its request: invitation ID, parent, domain, kind and expiry.\n" +
			"--recipient is your private note of who it is for; it is never exported.\n" +
			"An invitation expires after --expires (7 days by default).",
		Args: cobra.NoArgs,
		RunE: runIDChildInvite,
	}
	idChildReceiveCmd = &cobra.Command{
		Use:   "receive <request-file|->",
		Short: "Receive a child's request against one of your invitations",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDChildReceive,
	}
	idChildPendingCmd = &cobra.Command{
		Use:   "pending",
		Short: "List the requests bound to your invitations",
		Args:  cobra.NoArgs,
		RunE:  runIDChildPending,
	}
	idChildShowCmd = &cobra.Command{
		Use:   "show <request-id>",
		Short: "Show one received request and the fingerprint of its key",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDChildShow,
	}
	idChildApproveCmd = &cobra.Command{
		Use:   "approve <request-id>",
		Short: "Sign the certificate for one received request",
		Long: "Sign the certificate for one received request and write the response\n" +
			"(--out, or stdout). A human child needs your confirmation at an interactive\n" +
			"terminal that its key fingerprint matches what the recipient told you over a\n" +
			"separate trusted channel; nothing else approves it.",
		Args: cobra.ExactArgs(1),
		RunE: runIDChildApprove,
	}
	idChildRefuseCmd = &cobra.Command{
		Use:   "refuse <request-id>",
		Short: "Refuse one received request without signing",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDChildRefuse,
	}
)

func init() {
	for _, cmd := range []*cobra.Command{idChildInviteCmd, idChildReceiveCmd, idChildPendingCmd, idChildShowCmd, idChildApproveCmd, idChildRefuseCmd} {
		cmd.Flags().BoolVar(&idChildAsRoot, "as-root", false, "Act as the namespace root, with this machine's controller key")
		cmd.Flags().StringVar(&idChildDomain, "domain", "", "Namespace domain (with --as-root or --human)")
		cmd.Flags().StringVar(&idChildHuman, "human", "", "Act as this human on this machine (did:aw)")
		cmd.Flags().StringVar(&idChildRegistry, "registry", "", "Registry origin for --as-root, when the domain's _awid record names none")
		idChildCmd.AddCommand(cmd)
	}
	idChildInviteCmd.Flags().StringVar(&idChildKind, "kind", "", "Kind of the child: human or agent")
	idChildInviteCmd.Flags().StringVar(&idChildNote, "recipient", "", "Your private note of who the invitation is for")
	idChildInviteCmd.Flags().DurationVar(&idChildExpires, "expires", 7*24*time.Hour, "How long the invitation stays open")
	idChildApproveCmd.Flags().StringVar(&idChildOut, "out", "-", "Where to write the response (- for stdout)")
	identityCmd.AddCommand(idChildCmd)
}

// childIssuerSelection is how a command names its issuer.
type childIssuerSelection struct {
	AsRoot bool
	Domain string
	Human  string
}

type idChildOptions struct {
	IdentityHome    string
	Issuer          childIssuerSelection
	WorkingDir      string
	RegistryURL     string
	TXTResolver     awid.TXTResolver
	HumanAtTerminal func() error
	Keychain        awid.HumanKeyStore
	Prompt          awid.PassphrasePrompt
	Confirm         awid.ConfirmPrompt
	Show            io.Writer
	Now             func() time.Time
}

func idChildOptionsFromFlags() idChildOptions {
	wd, _ := os.Getwd()
	return idChildOptions{
		Issuer:          childIssuerSelection{AsRoot: idChildAsRoot, Domain: idChildDomain, Human: idChildHuman},
		WorkingDir:      wd,
		RegistryURL:     idChildRegistry,
		HumanAtTerminal: humanAtTerminal,
		Keychain:        awconfig.HumanKeychain{},
		Prompt:          awid.TerminalPassphrasePrompt(),
		Confirm:         awid.TerminalConfirmPrompt(),
		Show:            os.Stderr,
		Now:             time.Now,
	}
}

// selectedChildIssuer is the issuer a command acts as, with its domain and
// the registry its status comes from.
type selectedChildIssuer struct {
	*childIssuer
	domain      string
	registryURL string
	kind        string
}

func selectChildIssuer(ctx context.Context, opts idChildOptions) (*selectedChildIssuer, error) {
	sel := opts.Issuer
	switch {
	case sel.AsRoot && strings.TrimSpace(sel.Human) != "":
		return nil, usageError("--as-root and --human name different issuers; choose one")
	case sel.AsRoot:
		domain, err := normalizeIDCreateDomain(sel.Domain, false)
		if err != nil {
			return nil, err
		}
		key, err := awconfig.LoadControllerKey(domain)
		if err != nil {
			return nil, fmt.Errorf("load namespace controller key for %s: %w", domain, err)
		}
		if err := checkRootController(ctx, opts.TXTResolver, domain, key); err != nil {
			return nil, err
		}
		registry, registryURL, err := childIssuerRegistry(ctx, opts, domain)
		if err != nil {
			return nil, err
		}
		issuer, err := rootIssuer(domain, key, registry, opts.TXTResolver, registryURL)
		if err != nil {
			return nil, err
		}
		return &selectedChildIssuer{childIssuer: issuer, domain: domain, registryURL: registryURL, kind: "root"}, nil
	case strings.TrimSpace(sel.Human) != "":
		domain, err := normalizeIDCreateDomain(sel.Domain, false)
		if err != nil {
			return nil, err
		}
		human, err := loadHumanParent(domain, strings.TrimSpace(sel.Human))
		if err != nil {
			return nil, err
		}
		registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
		registry.DefaultRegistryURL = human.record.RegistryURL
		issuer := human.issuer(opts.Keychain, opts.Prompt, opts.TXTResolver, registry, human.record.RegistryURL)
		return &selectedChildIssuer{childIssuer: issuer, domain: domain, registryURL: human.record.RegistryURL, kind: "human"}, nil
	}
	return currentAgentIssuer(opts)
}

// childIssuerRegistry is the registry the root's status comes from: the one
// its _awid record names, or --registry when the record names none.
func childIssuerRegistry(ctx context.Context, opts idChildOptions, domain string) (*awid.RegistryClient, string, error) {
	authority, err := awid.VerifyExactDomainAuthority(ctx, opts.TXTResolver, domain)
	if err != nil {
		return nil, "", fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	registryURL, err := domainRegistryURL(authority, opts.RegistryURL)
	if err != nil {
		return nil, "", err
	}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	registry.DefaultRegistryURL = registryURL
	return registry, registryURL, nil
}

// currentAgentIssuer is the current identity issuing as an agent: it signs
// with its own key and presents its own installed chain. An agent issues
// only agents.
func currentAgentIssuer(opts idChildOptions) (*selectedChildIssuer, error) {
	identity, err := resolveIDExchangeIdentity(opts.WorkingDir, opts.IdentityHome)
	if err != nil {
		return nil, err
	}
	key, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(identity.IdentityPath)
	chain, err := awconfig.LoadInstalledIDChain(dir)
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, usageError("%s has no installed chain, so it issues no children; select --as-root or --human", identity.StableID)
	}
	certificates := chain.Bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	domain := leaf["domain"].(string)
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return nil, err
	}
	registryURL := opts.RegistryURL
	if registryURL == "" {
		registryURL = identity.RegistryURL
	}
	if registryURL == "" {
		authority, err := awid.VerifyExactDomainAuthority(context.Background(), opts.TXTResolver, domain)
		if err != nil {
			return nil, err
		}
		registryURL, err = domainRegistryURL(authority, "")
		if err != nil {
			return nil, err
		}
	}
	issuer := &childIssuer{
		parent:      map[string]any{"kind": "identity", "id": identityID(identity)},
		parentChain: certificates,
		issuance:    awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(dir)},
		invitations: awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(dir)},
		signer:      func(string) awid.IDCertificateSigner { return awid.KeySigner(key) },
		evidence: func(ctx context.Context, _, _ string) (*awid.IDChainEvidence, error) {
			subject := awid.IDChainSubject{ID: identityID(identity), DIDKey: identity.DID}
			return idStatusAt(registry, opts.TXTResolver, registryURL).IDChainEvidence(ctx, chain.Bundle, subject, domain), nil
		},
	}
	return &selectedChildIssuer{childIssuer: issuer, domain: domain, registryURL: registryURL, kind: "agent"}, nil
}

type idChildInviteOutput struct {
	InvitationID string         `json:"invitation_id"`
	Parent       map[string]any `json:"parent"`
	Domain       string         `json:"domain"`
	Kind         string         `json:"kind"`
	ExpiresAt    string         `json:"expires_at"`
}

func runIDChildInvite(cmd *cobra.Command, args []string) error {
	out, err := executeIDChildInvite(cmd.Context(), idChildOptionsFromFlags(), idChildKind, idChildNote, idChildExpires)
	if err != nil {
		return err
	}
	printOutput(out, formatIDChildInvite)
	return nil
}

func executeIDChildInvite(ctx context.Context, opts idChildOptions, kind, recipient string, expires time.Duration) (idChildInviteOutput, error) {
	if kind != "human" && kind != "agent" {
		return idChildInviteOutput{}, usageError("--kind must be human or agent")
	}
	if strings.TrimSpace(recipient) == "" {
		return idChildInviteOutput{}, usageError("--recipient is required: your private note of who the invitation is for")
	}
	if expires <= 0 {
		return idChildInviteOutput{}, usageError("--expires must be positive")
	}
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return idChildInviteOutput{}, err
	}
	if kind == "human" && issuer.kind == "agent" {
		return idChildInviteOutput{}, usageError("an agent cannot invite a human; select --as-root or --human")
	}
	id, err := newInvitationID()
	if err != nil {
		return idChildInviteOutput{}, err
	}
	inv := &awid.IDInvitation{
		InvitationID: id,
		Mode:         awid.IDInvitationSelfCustodial,
		Parent:       issuer.parent,
		Domain:       issuer.domain,
		Kind:         kind,
		Recipient:    strings.TrimSpace(recipient),
		ExpiresAt:    opts.Now().Add(expires).UTC().Format("2006-01-02T15:04:05Z"),
	}
	if err := issuer.invitations.PutInvitation(inv); err != nil {
		return idChildInviteOutput{}, err
	}
	return idChildInviteOutput{InvitationID: inv.InvitationID, Parent: inv.Parent, Domain: inv.Domain, Kind: inv.Kind, ExpiresAt: inv.ExpiresAt}, nil
}

func newInvitationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func runIDChildReceive(cmd *cobra.Command, args []string) error {
	raw, err := readExchangeFile(args[0])
	if err != nil {
		return err
	}
	out, err := executeIDChildReceive(cmd.Context(), idChildOptionsFromFlags(), raw)
	if err != nil {
		return err
	}
	printOutput(out, formatIDChildRequest)
	return nil
}

func executeIDChildReceive(ctx context.Context, opts idChildOptions, raw []byte) (idChildRequestOutput, error) {
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	lock, err := lockChildIssuer(issuer)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	defer lock.Close()
	signed, err := awid.ParseIDCertificateRequest(raw)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	req := signed["request"].(map[string]any)
	// A request ID names one request across both stores: each library
	// receive checks its own store, and this checks the other.
	existing, _, err := lookupReceivedRequest(issuer, req["request_id"].(string))
	if err != nil {
		return idChildRequestOutput{}, err
	}
	if req["operation"] == "resign" {
		if err := issuerResigns(issuer); err != nil {
			return idChildRequestOutput{}, err
		}
		if existing.invitation != nil {
			return idChildRequestOutput{}, &awid.IDCertificateError{Code: "request_conflict"}
		}
		entry, err := awid.ReceiveIDResignRequest(issuer.issuance, raw)
		if err != nil {
			return idChildRequestOutput{}, err
		}
		return receivedRequest{resign: entry}.output()
	}
	if existing.resign != nil {
		return idChildRequestOutput{}, &awid.IDCertificateError{Code: "request_conflict"}
	}
	inv, err := awid.ReceiveIDChildRequest(issuer.invitations, issuer.parent, raw)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	return receivedRequest{invitation: inv}.output()
}

// issuerResigns refuses a re-sign under the namespace root: the root's
// certificates are registered, and a registered certificate keeps its
// signature across key rotation.
func issuerResigns(issuer *selectedChildIssuer) error {
	if issuer.kind == "root" {
		return usageError("the namespace root re-signs nothing: its certificates are registered and survive its key rotation")
	}
	return nil
}

// idChildRequestOutput is a request as the issuer reviews it. The private
// recipient note is shown only to the issuer, never exported.
type idChildRequestOutput struct {
	RequestID      string         `json:"request_id"`
	Operation      string         `json:"operation"`
	InvitationID   string         `json:"invitation_id,omitempty"`
	State          string         `json:"state"`
	ID             string         `json:"id"`
	Domain         string         `json:"domain"`
	Parent         map[string]any `json:"parent"`
	Kind           string         `json:"kind"`
	Fingerprint    string         `json:"fingerprint"`
	InvitationVoid bool           `json:"invitation_void"`
	CertificateID  string         `json:"certificate_id,omitempty"`
	Purpose        string         `json:"purpose,omitempty"`
	ExpiresAt      string         `json:"expires_at,omitempty"`
	Recipient      string         `json:"recipient,omitempty"`
	// OldCertificateID is the certificate a re-sign request presents.
	OldCertificateID string `json:"old_certificate_id,omitempty"`
}

// receivedRequest is one request the issuer received: an issue bound to one
// of its invitations, or a re-sign attached to the issuance entry of the
// certificate it presents.
type receivedRequest struct {
	invitation *awid.IDInvitation
	resign     *awid.IDIssuanceEntry
}

func (r receivedRequest) record() *awid.IDRequestRecord {
	if r.resign != nil {
		return r.resign.Resign
	}
	return r.invitation.Request
}

func (r receivedRequest) output() (idChildRequestOutput, error) {
	record := r.record()
	signed, err := awid.ParseIDCertificateRequest([]byte(record.Request))
	if err != nil {
		return idChildRequestOutput{}, err
	}
	req := signed["request"].(map[string]any)
	fingerprint, err := awid.IDKeyFingerprint(req["subject_key"].(string))
	if err != nil {
		return idChildRequestOutput{}, err
	}
	out := idChildRequestOutput{
		RequestID: record.RequestID, Operation: req["operation"].(string), State: record.State,
		ID: req["id"].(string), Domain: req["domain"].(string), Parent: req["parent"].(map[string]any), Kind: req["kind"].(string),
		Fingerprint: fingerprint, CertificateID: record.NewCertificateID,
	}
	if r.resign != nil {
		out.OldCertificateID = r.resign.CertificateID
		return out, nil
	}
	inv := r.invitation
	out.Purpose = inv.Purpose
	out.InvitationID, out.InvitationVoid, out.ExpiresAt, out.Recipient = inv.InvitationID, inv.Void, inv.ExpiresAt, inv.Recipient
	return out, nil
}

// findReceivedRequest finds requestID among the issuer's invitations and
// then among its re-sign requests.
func findReceivedRequest(issuer *selectedChildIssuer, requestID string) (receivedRequest, error) {
	found, ok, err := lookupReceivedRequest(issuer, requestID)
	if err != nil {
		return receivedRequest{}, err
	}
	if !ok {
		return receivedRequest{}, usageError("no received request %s", requestID)
	}
	return found, nil
}

func lookupReceivedRequest(issuer *selectedChildIssuer, requestID string) (receivedRequest, bool, error) {
	all, err := issuer.invitations.Invitations()
	if err != nil {
		return receivedRequest{}, false, err
	}
	for _, inv := range all {
		if inv.Request != nil && inv.Request.RequestID == requestID {
			return receivedRequest{invitation: inv}, true, nil
		}
	}
	entry, err := issuer.issuance.EntryForRequest(requestID)
	if err != nil || entry == nil {
		return receivedRequest{}, false, err
	}
	return receivedRequest{resign: entry}, true, nil
}

// listIDChildRequests lists the issuer's received requests: issues, then
// re-signs. Private invitation notes are not listed.
func listIDChildRequests(ctx context.Context, opts idChildOptions) ([]awid.IDChildRequest, error) {
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return nil, err
	}
	listed, err := awid.IDChildRequests(issuer.invitations)
	if err != nil {
		return nil, err
	}
	entries, err := issuer.issuance.ResignEntries()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		out, err := receivedRequest{resign: entry}.output()
		if err != nil {
			return nil, err
		}
		listed = append(listed, awid.IDChildRequest{RequestID: out.RequestID, Operation: out.Operation, State: out.State, CertificateID: out.CertificateID, ID: out.ID, Domain: out.Domain, Parent: out.Parent, Kind: out.Kind})
	}
	return listed, nil
}

func showIDChildRequest(ctx context.Context, opts idChildOptions, requestID string) (idChildRequestOutput, error) {
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	found, err := findReceivedRequest(issuer, requestID)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	return found.output()
}

func executeIDChildRefuse(ctx context.Context, opts idChildOptions, requestID string) error {
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return err
	}
	lock, err := lockChildIssuer(issuer)
	if err != nil {
		return err
	}
	defer lock.Close()
	found, err := findReceivedRequest(issuer, requestID)
	if err != nil {
		return err
	}
	if found.resign != nil {
		return awid.RefuseIDResignRequest(issuer.issuance, requestID)
	}
	return awid.RefuseIDChildRequest(issuer.invitations, requestID)
}

func runIDChildPending(cmd *cobra.Command, args []string) error {
	listed, err := listIDChildRequests(cmd.Context(), idChildOptionsFromFlags())
	if err != nil {
		return err
	}
	printOutput(listed, formatIDChildPending)
	return nil
}

func runIDChildShow(cmd *cobra.Command, args []string) error {
	out, err := showIDChildRequest(cmd.Context(), idChildOptionsFromFlags(), args[0])
	if err != nil {
		return err
	}
	printOutput(out, formatIDChildRequest)
	return nil
}

func runIDChildRefuse(cmd *cobra.Command, args []string) error {
	if err := executeIDChildRefuse(cmd.Context(), idChildOptionsFromFlags(), args[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Refused %s; nothing was signed.\n", args[0])
	return nil
}

func runIDChildApprove(cmd *cobra.Command, args []string) error {
	response, err := executeIDChildApprove(cmd.Context(), idChildOptionsFromFlags(), args[0])
	if err != nil {
		return err
	}
	return writeExchangeFile(idChildOut, response)
}

// executeIDChildApprove signs the certificate for one received request. For
// a human child it first shows the request the issuer is about to sign,
// with the fingerprint of the stored request's own key, and asks the human
// at the terminal whether it matches what the recipient said. A no refuses
// with nothing signed; the request stays pending.
func executeIDChildApprove(ctx context.Context, opts idChildOptions, requestID string) ([]byte, error) {
	issuer, err := selectChildIssuer(ctx, opts)
	if err != nil {
		return nil, err
	}
	found, err := findReceivedRequest(issuer, requestID)
	if err != nil {
		return nil, err
	}
	if found.resign != nil {
		if err := issuerResigns(issuer); err != nil {
			return nil, err
		}
	}
	out, err := found.output()
	if err != nil {
		return nil, err
	}
	pending := found.record().State == awid.IDRequestPending
	approval := awid.IDHumanApproval{}
	if out.Kind == "human" && pending {
		if err := opts.HumanAtTerminal(); err != nil {
			return nil, fmt.Errorf("approving a human needs its issuer at the terminal: %w", err)
		}
		if opts.Show != nil {
			_, _ = fmt.Fprint(opts.Show, formatIDChildRequest(out))
		}
		confirmed, err := opts.Confirm(fmt.Sprintf("Fingerprint %s. Does it match what %s told you? [y/N] ", out.Fingerprint, out.Recipient))
		if err != nil {
			return nil, err
		}
		if !confirmed {
			return nil, &awid.IDCertificateError{Code: "human_approval_required"}
		}
		approval = awid.IDHumanApproval{Interactive: true, Confirmed: true}
	}
	var evidence *awid.IDChainEvidence
	if pending {
		signed, err := awid.ParseIDCertificateRequest([]byte(found.record().Request))
		if err != nil {
			return nil, err
		}
		r := signed["request"].(map[string]any)
		if evidence, err = issuer.evidence(ctx, r["id"].(string), r["subject_key"].(string)); err != nil {
			return nil, err
		}
	}
	// Evidence is read and the human asked before the lock is taken; the
	// library rereads the request under it and signs only that one.
	lock, err := lockChildIssuer(issuer)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if found.resign != nil {
		return awid.ApproveIDResignRequest(issuer.issuance, requestID, issuer.parent["id"].(string), issuer.parentChain, evidence, issuer.domain, issuer.signer(out.ID), opts.Now())
	}
	return awid.ApproveIDChildRequest(issuer.invitations, issuer.issuance, requestID, approval, issuer.parentChain, evidence, issuer.signer(out.ID), opts.Now())
}

// childIssuerLockPath is the issuer's transaction lock, beside its
// invitations: receive, approve and refuse hold it across their
// read-modify-write of an invitation and the issuance log.
func childIssuerLockPath(issuer *selectedChildIssuer) string {
	return issuer.invitations.Dir + ".lock"
}

func lockChildIssuer(issuer *selectedChildIssuer) (io.Closer, error) {
	lock, err := awconfig.LockExclusive(childIssuerLockPath(issuer))
	if err != nil {
		return nil, fmt.Errorf("lock the issuer's records: %w", err)
	}
	return lock, nil
}

func readExchangeFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	}
	return os.ReadFile(path)
}

func writeExchangeFile(path string, data []byte) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(append(data, '\n'))
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return usageError("refusing to overwrite %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func formatIDChildInvite(v any) string {
	out := v.(idChildInviteOutput)
	parent := out.Parent["id"]
	return fmt.Sprintf("Invitation:  %s\nParent:      %s %v\nDomain:      %s\nKind:        %s\nExpires:     %s\n\nSend the recipient these values; they export their request against them.\n",
		out.InvitationID, out.Parent["kind"], parent, out.Domain, out.Kind, out.ExpiresAt)
}

func formatIDChildRequest(v any) string {
	out := v.(idChildRequestOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Request:     %s (%s, %s)\n", out.RequestID, out.Operation, out.State))
	if out.Purpose != "" {
		fmt.Fprintf(&sb, "Purpose:     %s\n", out.Purpose)
	}
	if out.Operation != "resign" {
		sb.WriteString(fmt.Sprintf("Recipient:   %s (your private note)\n", out.Recipient))
	}
	sb.WriteString(fmt.Sprintf("Child:       %s\n", out.ID))
	sb.WriteString(fmt.Sprintf("Kind:        %s\n", out.Kind))
	sb.WriteString(fmt.Sprintf("Parent:      %s %v\n", out.Parent["kind"], out.Parent["id"]))
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Domain))
	if out.Operation == "resign" {
		sb.WriteString(fmt.Sprintf("Re-signs:    %s\n", out.OldCertificateID))
	} else {
		sb.WriteString(fmt.Sprintf("Invitation:  %s (expires %s)\n", out.InvitationID, out.ExpiresAt))
	}
	sb.WriteString(fmt.Sprintf("Fingerprint: %s\n", out.Fingerprint))
	if out.InvitationVoid {
		sb.WriteString("Invitation:  VOID (a different key was presented)\n")
	}
	if out.CertificateID != "" {
		sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertificateID))
	}
	return sb.String()
}

func formatIDChildPending(v any) string {
	listed := v.([]awid.IDChildRequest)
	if len(listed) == 0 {
		return "No received requests.\n"
	}
	var sb strings.Builder
	for _, r := range listed {
		void := ""
		if r.InvitationVoid {
			void = " invitation void"
		}
		sb.WriteString(fmt.Sprintf("%s  %-6s %-8s %-6s %s%s\n", r.RequestID, r.Operation, r.State, r.Kind, r.ID, void))
		if r.CertificateID != "" {
			sb.WriteString(fmt.Sprintf("    certificate %s\n", r.CertificateID))
		}
	}
	return sb.String()
}
