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
	registryURL, err := humanInitRegistryURL(authority, opts.RegistryURL)
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
	identity, err := resolveIdentityForDir(opts.WorkingDir)
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
	registryURL := identity.RegistryURL
	issuer := &childIssuer{
		parent:      map[string]any{"kind": "identity", "id": identity.StableID},
		parentChain: certificates,
		issuance:    awconfig.IDIssuanceFileStore{Dir: awconfig.IdentityIssuanceDir(dir)},
		invitations: awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(dir)},
		signer:      func(string) awid.IDCertificateSigner { return awid.KeySigner(key) },
		evidence: func(ctx context.Context, _, _ string) (*awid.IDChainEvidence, error) {
			subject := awid.IDChainSubject{ID: identity.StableID, DIDKey: identity.DID}
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
	inv, err := awid.ReceiveIDChildRequest(issuer.invitations, issuer.parent, raw)
	if err != nil {
		return idChildRequestOutput{}, err
	}
	return childRequestOutput(inv)
}

// idChildRequestOutput is a request as the issuer reviews it. The private
// recipient note is shown only to the issuer, never exported.
type idChildRequestOutput struct {
	RequestID      string         `json:"request_id"`
	InvitationID   string         `json:"invitation_id"`
	State          string         `json:"state"`
	ID             string         `json:"id"`
	Domain         string         `json:"domain"`
	Parent         map[string]any `json:"parent"`
	Kind           string         `json:"kind"`
	Fingerprint    string         `json:"fingerprint"`
	InvitationVoid bool           `json:"invitation_void"`
	CertificateID  string         `json:"certificate_id,omitempty"`
	ExpiresAt      string         `json:"expires_at"`
	Recipient      string         `json:"recipient"`
}

func childRequestOutput(inv *awid.IDInvitation) (idChildRequestOutput, error) {
	signed, err := awid.ParseIDCertificateRequest([]byte(inv.Request.Request))
	if err != nil {
		return idChildRequestOutput{}, err
	}
	r := signed["request"].(map[string]any)
	fingerprint, err := awid.IDKeyFingerprint(r["subject_key"].(string))
	if err != nil {
		return idChildRequestOutput{}, err
	}
	return idChildRequestOutput{
		RequestID: inv.Request.RequestID, InvitationID: inv.InvitationID, State: inv.Request.State,
		ID: r["id"].(string), Domain: inv.Domain, Parent: inv.Parent, Kind: inv.Kind, Fingerprint: fingerprint,
		InvitationVoid: inv.Void, CertificateID: inv.Request.NewCertificateID, ExpiresAt: inv.ExpiresAt, Recipient: inv.Recipient,
	}, nil
}

func childRequestByID(issuer *selectedChildIssuer, requestID string) (*awid.IDInvitation, error) {
	all, err := issuer.invitations.Invitations()
	if err != nil {
		return nil, err
	}
	for _, inv := range all {
		if inv.Request != nil && inv.Request.RequestID == requestID {
			return inv, nil
		}
	}
	return nil, usageError("no received request %s", requestID)
}

func runIDChildPending(cmd *cobra.Command, args []string) error {
	issuer, err := selectChildIssuer(cmd.Context(), idChildOptionsFromFlags())
	if err != nil {
		return err
	}
	listed, err := awid.IDChildRequests(issuer.invitations)
	if err != nil {
		return err
	}
	printOutput(listed, formatIDChildPending)
	return nil
}

func runIDChildShow(cmd *cobra.Command, args []string) error {
	issuer, err := selectChildIssuer(cmd.Context(), idChildOptionsFromFlags())
	if err != nil {
		return err
	}
	inv, err := childRequestByID(issuer, args[0])
	if err != nil {
		return err
	}
	out, err := childRequestOutput(inv)
	if err != nil {
		return err
	}
	printOutput(out, formatIDChildRequest)
	return nil
}

func runIDChildRefuse(cmd *cobra.Command, args []string) error {
	issuer, err := selectChildIssuer(cmd.Context(), idChildOptionsFromFlags())
	if err != nil {
		return err
	}
	lock, err := lockChildIssuer(issuer)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := awid.RefuseIDChildRequest(issuer.invitations, args[0]); err != nil {
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
	inv, err := childRequestByID(issuer, requestID)
	if err != nil {
		return nil, err
	}
	out, err := childRequestOutput(inv)
	if err != nil {
		return nil, err
	}
	approval := awid.IDHumanApproval{}
	if inv.Kind == "human" && inv.Request.State == awid.IDRequestPending {
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
	if inv.Request.State == awid.IDRequestPending {
		signed, err := awid.ParseIDCertificateRequest([]byte(inv.Request.Request))
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
	sb.WriteString(fmt.Sprintf("Request:     %s (%s)\n", out.RequestID, out.State))
	sb.WriteString(fmt.Sprintf("Recipient:   %s (your private note)\n", out.Recipient))
	sb.WriteString(fmt.Sprintf("Child:       %s\n", out.ID))
	sb.WriteString(fmt.Sprintf("Kind:        %s\n", out.Kind))
	sb.WriteString(fmt.Sprintf("Parent:      %s %v\n", out.Parent["kind"], out.Parent["id"]))
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Domain))
	sb.WriteString(fmt.Sprintf("Invitation:  %s (expires %s)\n", out.InvitationID, out.ExpiresAt))
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
		sb.WriteString(fmt.Sprintf("%s  %-8s %-6s %s%s\n", r.RequestID, r.State, r.Kind, r.ID, void))
		if r.CertificateID != "" {
			sb.WriteString(fmt.Sprintf("    certificate %s\n", r.CertificateID))
		}
	}
	return sb.String()
}
