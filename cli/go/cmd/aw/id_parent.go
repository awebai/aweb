package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The child side of the request exchange (docs/id-certificates.md §6). The
// requester exports a request against the invitation its parent fixed,
// then imports the parent's response: verified before anything is
// installed, installed atomically, and registered by default with the
// child's own proof and the same invitation ID. The requester is explicit:
// --human <did:aw> for a human prepared on this machine, otherwise the
// current agent identity. The parent is explicit too: --parent <did:aw> or
// --parent-root, never inferred.

var (
	idParentHuman        string
	idParentDomain       string
	idParentInvitationID string
	idParentParent       string
	idParentRoot         bool
	idParentResign       bool
	idParentOut          string
	idParentRegistry     string
	idParentNoRegister   bool

	idParentCmd = &cobra.Command{
		Use:   "parent",
		Short: "Request and import your own certificate from a parent",
	}
	idParentRequestCmd = &cobra.Command{
		Use:   "request",
		Short: "Export a certificate request against a parent's invitation",
		Long: "Export a certificate request against the invitation your parent fixed: its\n" +
			"--invitation-id, --domain and parent (--parent <did:aw> or --parent-root).\n" +
			"Send the request file to the parent over your chosen channel, and tell them\n" +
			"the fingerprint shown here through a different trusted channel.\n\n" +
			"With --resign, a local agent (whose ID is its did:key) instead asks the parent\n" +
			"of the certificate it carries to re-sign it with the parent's current key,\n" +
			"after the parent rotated its key.",
		Args: cobra.NoArgs,
		RunE: runIDParentRequest,
	}
	idParentImportCmd = &cobra.Command{
		Use:   "import <response-file|->",
		Short: "Import the parent's response to your request and register it",
		Long: "Verify the parent's response against your outstanding request, install the\n" +
			"chain and register it at AWID with your own key (--no-register leaves the\n" +
			"registration pending). A failed registration keeps the signed response;\n" +
			"run import again to retry it.",
		Args: cobra.ExactArgs(1),
		RunE: runIDParentImport,
	}
)

func init() {
	for _, cmd := range []*cobra.Command{idParentRequestCmd, idParentImportCmd} {
		cmd.Flags().StringVar(&idParentHuman, "human", "", "Act as this human prepared on this machine (did:aw)")
		cmd.Flags().StringVar(&idParentDomain, "domain", "", "Namespace domain of the invitation")
		idParentCmd.AddCommand(cmd)
	}
	idParentRequestCmd.Flags().StringVar(&idParentInvitationID, "invitation-id", "", "Invitation ID the parent gave you")
	idParentRequestCmd.Flags().StringVar(&idParentParent, "parent", "", "did:aw of the parent identity")
	idParentRequestCmd.Flags().BoolVar(&idParentRoot, "parent-root", false, "The parent is the namespace root of --domain")
	idParentRequestCmd.Flags().BoolVar(&idParentResign, "resign", false, "Ask the parent to re-sign the certificate this local agent carries")
	idParentRequestCmd.Flags().StringVar(&idParentOut, "out", "-", "Where to write the request (- for stdout)")
	idParentImportCmd.Flags().StringVar(&idParentRegistry, "registry", "", "Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)")
	idParentImportCmd.Flags().BoolVar(&idParentNoRegister, "no-register", false, "Install the certificate but leave its AWID registration pending")
	identityCmd.AddCommand(idParentCmd)
}

type idParentOptions struct {
	Human           string
	Domain          string
	WorkingDir      string
	RegistryURL     string
	NoRegister      bool
	TXTResolver     awid.TXTResolver
	HumanAtTerminal func() error
	Keychain        awid.HumanKeyStore
	Prompt          awid.PassphrasePrompt
}

func idParentOptionsFromFlags() idParentOptions {
	wd, _ := os.Getwd()
	return idParentOptions{
		Human: idParentHuman, Domain: idParentDomain, WorkingDir: wd, RegistryURL: idParentRegistry, NoRegister: idParentNoRegister,
		HumanAtTerminal: humanAtTerminal, Keychain: awconfig.HumanKeychain{}, Prompt: awid.TerminalPassphrasePrompt(),
	}
}

// requester is who asks a parent for its own certificate.
type requester struct {
	id     string
	didKey string
	domain string
	kind   string
	dir    string
	signer func(description string) awid.IDCertificateSigner
	human  *awconfig.HumanRecord
}

func (r *requester) requests() awconfig.IDRequestFileStore {
	return awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(r.dir)}
}

func selectRequester(opts idParentOptions) (*requester, error) {
	if strings.TrimSpace(opts.Human) == "" {
		identity, err := resolveIdentityForDir(opts.WorkingDir)
		if err != nil {
			return nil, err
		}
		key, err := resolveIdentitySigningKey(identity)
		if err != nil {
			return nil, err
		}
		id := identity.StableID
		if id == "" {
			id = identity.DID
		}
		dir := filepath.Dir(identity.IdentityPath)
		named := opts.Domain
		if strings.TrimSpace(named) == "" {
			// An agent carrying a chain belongs to its chain's namespace.
			installed, err := awconfig.LoadInstalledIDChain(dir)
			if err != nil {
				return nil, err
			}
			if installed != nil {
				certificates := installed.Bundle["certificates"].([]any)
				named, _ = certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)["domain"].(string)
			}
		}
		domain, err := normalizeIDCreateDomain(named, false)
		if err != nil {
			return nil, err
		}
		return &requester{id: id, didKey: identity.DID, domain: domain, kind: "agent", dir: dir,
			signer: func(string) awid.IDCertificateSigner { return awid.KeySigner(key) }}, nil
	}
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return nil, err
	}
	if err := opts.HumanAtTerminal(); err != nil {
		return nil, fmt.Errorf("--human signs as %s: %w", opts.Human, err)
	}
	rec, err := awconfig.LoadHumanRecord(domain, strings.TrimSpace(opts.Human))
	if err != nil {
		return nil, err
	}
	if rec == nil || rec.Path != awconfig.HumanPathRequest {
		return nil, usageError("no human %s prepared on this machine for a request in %s (prepare it with `aw id human init --domain %s`)", opts.Human, domain, domain)
	}
	dir, err := awconfig.HumanRecordDir(domain, rec.StableID)
	if err != nil {
		return nil, err
	}
	return &requester{id: rec.StableID, didKey: rec.DIDKey, domain: domain, kind: "human", dir: dir, human: rec,
		signer: func(description string) awid.IDCertificateSigner {
			return awid.HumanSigner(opts.Keychain, rec.StableID, description, opts.Prompt)
		}}, nil
}

type idParentRequestOutput struct {
	RequestID    string `json:"request_id"`
	InvitationID string `json:"invitation_id"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Fingerprint  string `json:"fingerprint"`
}

func runIDParentRequest(cmd *cobra.Command, args []string) error {
	var out idParentRequestOutput
	var raw []byte
	var err error
	if idParentResign {
		if idParentInvitationID != "" || idParentParent != "" || idParentRoot || idParentDomain != "" {
			return usageError("--resign takes its parent, domain and certificate from the installed chain; it takes no --invitation-id, --parent, --parent-root or --domain")
		}
		out, raw, err = executeIDParentResign(idParentOptionsFromFlags())
	} else {
		out, raw, err = executeIDParentRequest(idParentOptionsFromFlags(), idParentInvitationID, idParentParent, idParentRoot)
	}
	if err != nil {
		return err
	}
	if err := writeExchangeFile(idParentOut, raw); err != nil {
		return err
	}
	if idParentResign {
		fmt.Fprintf(os.Stderr, "Re-sign request %s for %s. Send it to your parent; import its response with `aw id parent import`.\n", out.RequestID, out.ID)
		return nil
	}
	fmt.Fprintf(os.Stderr, "Request %s for %s (%s).\nTell your parent this fingerprint through a different trusted channel: %s\n", out.RequestID, out.ID, out.Kind, out.Fingerprint)
	return nil
}

// executeIDParentRequest builds, signs and records the request; the caller
// writes the returned request file.
func executeIDParentRequest(opts idParentOptions, invitationID, parentID string, parentRoot bool) (idParentRequestOutput, []byte, error) {
	if !idInvitationIDPattern(invitationID) {
		return idParentRequestOutput{}, nil, usageError("--invitation-id is required: the ID of the invitation your parent fixed")
	}
	var parent map[string]any
	switch {
	case parentRoot && strings.TrimSpace(parentID) != "":
		return idParentRequestOutput{}, nil, usageError("--parent and --parent-root name different parents; choose one")
	case parentRoot:
		parent = nil
	case strings.HasPrefix(strings.TrimSpace(parentID), "did:aw:"):
		parent = map[string]any{"kind": "identity", "id": strings.TrimSpace(parentID)}
	default:
		return idParentRequestOutput{}, nil, usageError("name the parent: --parent <did:aw> or --parent-root")
	}
	r, err := selectRequester(opts)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	// A first certificate only: importing one would replace the identity's
	// working chain before AWID accepted the new certificate.
	installed, err := awconfig.LoadInstalledIDChain(r.dir)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	if installed != nil {
		return idParentRequestOutput{}, nil, usageError("%s already has an installed ID chain; a request issues only a first certificate", r.id)
	}
	if parent == nil {
		parent = map[string]any{"kind": "namespace", "id": r.domain}
	}
	requestID, err := newInvitationID()
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	request := map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": requestID, "operation": "issue",
		"id": r.id, "domain": r.domain, "parent": parent, "kind": r.kind, "subject_key": r.didKey,
		"invitation_id": invitationID, "old_certificate": nil,
	}
	raw, err := awid.SignIDCertificateRequest(request, r.signer("request its certificate from "+fmt.Sprint(parent["id"])))
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	if err := r.requests().Put(&awconfig.IDOutgoingRequest{RequestID: requestID, InvitationID: invitationID, Request: string(raw), State: awconfig.IDRequestOutstanding}); err != nil {
		return idParentRequestOutput{}, nil, err
	}
	fingerprint, err := awid.IDKeyFingerprint(r.didKey)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	return idParentRequestOutput{RequestID: requestID, InvitationID: invitationID, ID: r.id, Kind: r.kind, Fingerprint: fingerprint}, raw, nil
}

// executeIDParentResign builds, signs and records a re-sign request for the
// current local agent: the same id, domain, parent and kind as the
// certificate it carries, which travels with the request so its parent can
// find it in its own issuance log. The caller writes the returned request
// file.
func executeIDParentResign(opts idParentOptions) (idParentRequestOutput, []byte, error) {
	if strings.TrimSpace(opts.Human) != "" {
		return idParentRequestOutput{}, nil, usageError("--resign is for the current local agent; a human is registered and keeps its signature")
	}
	identity, err := resolveIdentityForDir(opts.WorkingDir)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	if identity.StableID != "" && identity.StableID != identity.DID {
		return idParentRequestOutput{}, nil, usageError("%s is registered at AWID and keeps its signature across its parent's rotation; only a local agent is re-signed", identity.StableID)
	}
	key, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	dir := filepath.Dir(identity.IdentityPath)
	installed, err := awconfig.LoadInstalledIDChain(dir)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	if installed == nil {
		return idParentRequestOutput{}, nil, usageError("%s has no installed certificate to re-sign", identity.DID)
	}
	certificates := installed.Bundle["certificates"].([]any)
	old := certificates[len(certificates)-1].(map[string]any)
	c := old["certificate"].(map[string]any)
	if c["id"] != identity.DID {
		return idParentRequestOutput{}, nil, usageError("the installed certificate names %v, not %s", c["id"], identity.DID)
	}
	requestID, err := newInvitationID()
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	request := map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": requestID, "operation": "resign",
		"id": c["id"], "domain": c["domain"], "parent": c["parent"], "kind": c["kind"], "subject_key": identity.DID,
		"invitation_id": nil, "old_certificate": old,
	}
	raw, err := awid.SignIDCertificateRequest(request, awid.KeySigner(key))
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	store := awconfig.IDRequestFileStore{Dir: awconfig.IdentityRequestsDir(dir)}
	if err := store.Put(&awconfig.IDOutgoingRequest{RequestID: requestID, Request: string(raw), State: awconfig.IDRequestOutstanding}); err != nil {
		return idParentRequestOutput{}, nil, err
	}
	fingerprint, err := awid.IDKeyFingerprint(identity.DID)
	if err != nil {
		return idParentRequestOutput{}, nil, err
	}
	return idParentRequestOutput{RequestID: requestID, ID: identity.DID, Kind: c["kind"].(string), Fingerprint: fingerprint}, raw, nil
}

var invitationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func idInvitationIDPattern(id string) bool { return invitationIDPattern.MatchString(id) }

type idParentImportOutput struct {
	RequestID    string `json:"request_id"`
	ID           string `json:"id"`
	Registration string `json:"registration"`
	RegisteredAt string `json:"registered_at,omitempty"`
}

func runIDParentImport(cmd *cobra.Command, args []string) error {
	raw, err := readExchangeFile(args[0])
	if err != nil {
		return err
	}
	out, err := executeIDParentImport(cmd.Context(), idParentOptionsFromFlags(), raw)
	if err != nil {
		return err
	}
	printOutput(out, formatIDParentImport)
	return nil
}

// executeIDParentImport verifies the response against the outstanding
// request it answers, installs the chain, and then registers it unless
// asked not to. A response already imported is not verified or installed
// again; only its pending registration is retried.
func executeIDParentImport(ctx context.Context, opts idParentOptions, raw []byte) (idParentImportOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	response, err := awid.ParseIDCertificateResponse(raw)
	if err != nil {
		return idParentImportOutput{}, err
	}
	requestID := response["request_id"].(string)
	r, err := selectRequester(opts)
	if err != nil {
		return idParentImportOutput{}, err
	}
	store := r.requests()
	outgoing, err := store.Request(requestID)
	if err != nil {
		return idParentImportOutput{}, err
	}
	if outgoing == nil {
		return idParentImportOutput{}, &awid.IDCertificateError{Code: "request_binding_mismatch"}
	}
	call, cancel := commandAPIContext(nil, ctx)
	authority, err := awid.VerifyExactDomainAuthority(call, opts.TXTResolver, r.domain)
	cancel()
	if err != nil {
		return idParentImportOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(r.domain), err)
	}
	registryURL, err := domainRegistryURL(authority, opts.RegistryURL)
	if err != nil {
		return idParentImportOutput{}, err
	}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	registry.DefaultRegistryURL = registryURL

	chain := response["chain"].(map[string]any)
	if outgoing.State == awconfig.IDRequestOutstanding {
		signed, err := awid.ParseIDCertificateRequest([]byte(outgoing.Request))
		if err != nil {
			return idParentImportOutput{}, err
		}
		subject := awid.IDChainSubject{ID: r.id, DIDKey: r.didKey}
		evidence := idStatusAt(registry, opts.TXTResolver, registryURL).IDChainEvidence(ctx, chain, subject, r.domain)
		imported, err := awid.ImportIDCertificateResponse(signed, raw, evidence, r.domain)
		if err != nil {
			return idParentImportOutput{}, err
		}
		if err := awconfig.SaveInstalledIDChain(r.dir, imported.Chain); err != nil {
			return idParentImportOutput{}, err
		}
		outgoing.State, outgoing.Response = awconfig.IDRequestImported, string(raw)
		if imported.RegistrationPending {
			outgoing.Registration = "pending"
		}
		if err := store.Put(outgoing); err != nil {
			return idParentImportOutput{}, err
		}
	} else if outgoing.Response != string(raw) {
		return idParentImportOutput{}, &awid.IDCertificateError{Code: "request_binding_mismatch"}
	}

	out := idParentImportOutput{RequestID: requestID, ID: r.id, Registration: outgoing.Registration, RegisteredAt: outgoing.RegisteredAt}
	if outgoing.Registration != "pending" || opts.NoRegister {
		return out, nil
	}
	call, cancel = commandAPIContext(nil, ctx)
	err = registry.RegisterIdentitySigned(call, registryURL, r.didKey, r.id, r.signer("register its did:aw at "+registryURL))
	cancel()
	var already *awid.AlreadyRegisteredError
	if errors.As(err, &already) && already.ExistingDIDKey == r.didKey {
		err = nil
	}
	if err != nil {
		return out, fmt.Errorf("register %s (run import again to retry): %w", r.id, err)
	}
	invitationID := outgoing.InvitationID
	call, cancel = commandAPIContext(nil, ctx)
	receipt, err := registry.RegisterIDCertificateAt(call, registryURL, chain, r.signer("register its certificate at "+registryURL), nil, &invitationID)
	cancel()
	if err != nil {
		return out, fmt.Errorf("register the certificate of %s (run import again to retry): %w", r.id, err)
	}
	outgoing.Registration = "registered"
	outgoing.RegisteredAt, _ = receipt["registered_at"].(string)
	if err := store.Put(outgoing); err != nil {
		return out, err
	}
	if r.human != nil {
		r.human.State, r.human.RegistryURL, r.human.RegisteredAt = awconfig.HumanRegistered, registryURL, outgoing.RegisteredAt
		if err := awconfig.SaveHumanRecord(r.human); err != nil {
			return out, err
		}
	}
	out.Registration, out.RegisteredAt = outgoing.Registration, outgoing.RegisteredAt
	return out, nil
}

func formatIDParentImport(v any) string {
	out := v.(idParentImportOutput)
	switch out.Registration {
	case "registered":
		return fmt.Sprintf("Installed the certificate of %s.\nRegistered at AWID; authority is checked against the tree at each use.\n", out.ID)
	case "pending":
		return fmt.Sprintf("Installed the certificate of %s.\nAWID registration is pending; run import again to register it.\n", out.ID)
	}
	return fmt.Sprintf("Installed the certificate of %s.\n", out.ID)
}
