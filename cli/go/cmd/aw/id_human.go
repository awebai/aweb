package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// `aw id human init --domain X --as-root` is the same-machine first-human
// path (docs/id-certificates.md §6): the human creates their own key, the
// local namespace controller issues the human's certificate directly, and
// the human registers it with its own key proof. There is no request or
// invitation. Each step is recorded before the next, so a failed or
// ambiguous run is retried from its records, never by minting again.

var (
	idHumanInitDomain   string
	idHumanInitAsRoot   bool
	idHumanInitRegistry string

	idHumanCmd = &cobra.Command{
		Use:   "human",
		Short: "Human identities in a namespace's identity tree",
	}
	idHumanInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Create your human ID, issued by this machine's namespace controller",
		Long: "Create your human ID in --domain and have the namespace controller on this\n" +
			"machine issue its certificate (--as-root).\n\n" +
			"The human key is kept in the OS keychain, encrypted under a passphrase you\n" +
			"choose; every signature asks for that passphrase on the terminal. This needs\n" +
			"a human at an interactive terminal: it refuses without one and inside an\n" +
			"agent runtime. A run that fails resumes from where it stopped.",
		RunE: runIDHumanInit,
	}
)

func init() {
	idHumanInitCmd.Flags().StringVar(&idHumanInitDomain, "domain", "", "Namespace domain")
	idHumanInitCmd.Flags().BoolVar(&idHumanInitAsRoot, "as-root", false, "Issue the certificate with this machine's namespace controller key")
	idHumanInitCmd.Flags().StringVar(&idHumanInitRegistry, "registry", "", "Registry origin, when the domain's _awid record names none")
	idHumanCmd.AddCommand(idHumanInitCmd)
	identityCmd.AddCommand(idHumanCmd)
}

type idHumanInitOutput struct {
	Status       string `json:"status"`
	ID           string `json:"id"`
	DIDKey       string `json:"did_key"`
	Domain       string `json:"domain"`
	RegistryURL  string `json:"registry_url"`
	RegisteredAt string `json:"registered_at"`
}

type idHumanInitOptions struct {
	Domain      string
	AsRoot      bool
	RegistryURL string
	// HumanAtTerminal says whether a human can be asked: a controlling
	// terminal is attached and the process is not an agent runtime.
	HumanAtTerminal func() error
	Keychain        awid.HumanKeyStore
	Prompt          awid.PassphrasePrompt
	TXTResolver     awid.TXTResolver
	Now             func() time.Time
	Progress        func(string)
}

func runIDHumanInit(cmd *cobra.Command, args []string) error {
	out, err := executeIDHumanInit(cmd.Context(), idHumanInitOptions{
		Domain:          idHumanInitDomain,
		AsRoot:          idHumanInitAsRoot,
		RegistryURL:     idHumanInitRegistry,
		HumanAtTerminal: humanAtTerminal,
		Keychain:        awconfig.HumanKeychain{},
		Prompt:          awid.TerminalPassphrasePrompt(),
		Now:             time.Now,
		Progress:        func(line string) { fmt.Fprintln(os.Stderr, line) },
	})
	if err != nil {
		return err
	}
	printOutput(out, formatIDHumanInit)
	return nil
}

// agentRuntimeMarkers are environment variables an agent runtime sets for
// the processes it runs. Finding one refuses a human-only command; their
// absence proves nothing, and a terminal is still required.
var agentRuntimeMarkers = []string{"OATS_INSTANCE_HOME", "OATS_INSTANCE"}

// humanAtTerminal refuses a human-only command that no human can answer:
// one without a controlling terminal, or one run inside an agent runtime.
// It is a barrier against accidents, not proof that a human is present.
func humanAtTerminal() error {
	for _, name := range agentRuntimeMarkers {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("this command needs a human at a terminal; it refuses inside an agent runtime (%s is set)", name)
		}
	}
	if !awid.ControllingTerminalAttached() {
		return errors.New("this command needs a human at an interactive terminal")
	}
	return nil
}

func executeIDHumanInit(ctx context.Context, opts idHumanInitOptions) (idHumanInitOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	if !opts.AsRoot {
		return idHumanInitOutput{}, errors.New("--as-root is required: a human prepared on another machine is admitted with the request exchange, not here")
	}
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	if err := opts.HumanAtTerminal(); err != nil {
		return idHumanInitOutput{}, err
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return idHumanInitOutput{}, fmt.Errorf("load namespace controller key for %s: %w (run `aw id namespace prepare-controller --domain %s` first)", domain, err, domain)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	lookup, cancel := commandAPIContext(nil, ctx)
	authority, err := awid.VerifyExactDomainAuthority(lookup, opts.TXTResolver, domain)
	cancel()
	if err != nil {
		return idHumanInitOutput{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	if strings.TrimSpace(authority.ControllerDID) != controllerDID {
		return idHumanInitOutput{}, fmt.Errorf("DNS controller %s for %s does not match this machine's controller %s", authority.ControllerDID, domain, controllerDID)
	}
	registryURL, err := humanInitRegistryURL(authority, opts.RegistryURL)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	registry := awid.NewAWIDRegistryClient(nil, opts.TXTResolver)
	registry.DefaultRegistryURL = registryURL

	rec, err := resumableHumanRecord(domain)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	if rec == nil {
		if rec, err = prepareHuman(domain, registryURL, opts); err != nil {
			return idHumanInitOutput{}, err
		}
	} else {
		progress(fmt.Sprintf("Resuming %s from %s.", rec.StableID, rec.State))
		if _, err := opts.Keychain.LoadHumanKey(rec.StableID); err != nil {
			return idHumanInitOutput{}, fmt.Errorf("resume %s: %w", rec.StableID, err)
		}
	}
	signer := func(description string) awid.IDCertificateSigner {
		return awid.HumanSigner(opts.Keychain, rec.StableID, description, opts.Prompt)
	}

	if rec.State == awconfig.HumanPrepared {
		call, cancel := commandAPIContext(nil, ctx)
		err := registry.RegisterIdentitySigned(call, rec.RegistryURL, rec.DIDKey, rec.StableID, signer("register its did:aw at "+rec.RegistryURL))
		cancel()
		var already *awid.AlreadyRegisteredError
		if errors.As(err, &already) && already.ExistingDIDKey == rec.DIDKey {
			err = nil
		}
		if err != nil {
			return idHumanInitOutput{}, fmt.Errorf("register %s: %w", rec.StableID, err)
		}
		rec.State = awconfig.HumanDIDRegistered
		if err := awconfig.SaveHumanRecord(rec); err != nil {
			return idHumanInitOutput{}, err
		}
	}

	call, cancel := commandAPIContext(nil, ctx)
	err = ensureStandaloneNamespace(call, registry, &idCreatePlan{Domain: domain, ControllerDID: controllerDID, RegistryURL: rec.RegistryURL}, controllerKey)
	cancel()
	if err != nil {
		return idHumanInitOutput{}, fmt.Errorf("register namespace %s at %s: %w", domain, rec.RegistryURL, err)
	}
	bundle, err := rootIssuedHumanChain(ctx, rec, controllerKey, registry, opts)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	call, cancel = commandAPIContext(nil, ctx)
	receipt, err := registry.RegisterIDCertificateAt(call, rec.RegistryURL, bundle, signer("register its human certificate at "+rec.RegistryURL), nil, nil)
	cancel()
	if err != nil {
		return idHumanInitOutput{}, fmt.Errorf("register the certificate of %s (run this command again to retry it): %w", rec.StableID, err)
	}
	dir, err := awconfig.HumanRecordDir(domain, rec.StableID)
	if err != nil {
		return idHumanInitOutput{}, err
	}
	if err := awconfig.SaveInstalledIDChain(dir, bundle); err != nil {
		return idHumanInitOutput{}, err
	}
	rec.State = awconfig.HumanRegistered
	rec.RegisteredAt, _ = receipt["registered_at"].(string)
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		return idHumanInitOutput{}, err
	}
	return idHumanInitOutput{Status: "registered", ID: rec.StableID, DIDKey: rec.DIDKey, Domain: domain, RegistryURL: rec.RegistryURL, RegisteredAt: rec.RegisteredAt}, nil
}

// humanInitRegistryURL is the registry the human registers at and reads
// status from: the one the domain's _awid record names, or the --registry
// origin when the record names none. A --registry that contradicts the
// record is refused.
func humanInitRegistryURL(authority awid.DomainAuthority, override string) (string, error) {
	named := strings.TrimSpace(authority.RegistryURL)
	override = strings.TrimSpace(override)
	if override == "" {
		return named, nil
	}
	if named != "" && named != awid.DefaultAWIDRegistryURL && named != override {
		return "", fmt.Errorf("--registry %s contradicts the registry %s that %s names", override, named, authority.DNSName)
	}
	return override, nil
}

// resumableHumanRecord is the one unfinished human record of domain, if
// any. Two unfinished records are refused rather than guessed between.
func resumableHumanRecord(domain string) (*awconfig.HumanRecord, error) {
	records, err := awconfig.HumanRecords(domain)
	if err != nil {
		return nil, err
	}
	var unfinished []*awconfig.HumanRecord
	for _, rec := range records {
		if rec.State != awconfig.HumanRegistered {
			unfinished = append(unfinished, rec)
		}
	}
	switch len(unfinished) {
	case 0:
		return nil, nil
	case 1:
		return unfinished[0], nil
	}
	ids := []string{}
	for _, rec := range unfinished {
		ids = append(ids, rec.StableID)
	}
	return nil, fmt.Errorf("more than one unfinished human in %s: %s", domain, strings.Join(ids, ", "))
}

// prepareHuman makes the human key, stores it in the keychain under a new
// passphrase, then writes the record that later steps resume from.
func prepareHuman(domain, registryURL string, opts idHumanInitOptions) (*awconfig.HumanRecord, error) {
	public, key, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	defer wipeBytes(key)
	rec := &awconfig.HumanRecord{
		StableID:    awid.ComputeStableID(public),
		DIDKey:      awid.ComputeDIDKey(public),
		Domain:      domain,
		RegistryURL: registryURL,
		State:       awconfig.HumanPrepared,
	}
	passphrase, err := opts.Prompt(fmt.Sprintf("Choose a passphrase for your human key %s (at least %d characters): ", rec.StableID, awid.HumanKeyMinPassphrase))
	defer wipeBytes(passphrase)
	if err != nil {
		return nil, err
	}
	again, err := opts.Prompt("Type the passphrase again: ")
	defer wipeBytes(again)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(passphrase, again) {
		return nil, errors.New("the passphrases do not match; nothing was created")
	}
	if err := awid.InstallHumanKey(opts.Keychain, rec.StableID, key, passphrase); err != nil {
		return nil, err
	}
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// rootIssuedHumanChain is the human's chain from the namespace root: the
// certificate already recorded in the controller's issuance log, or a new
// one issued now against current status and recorded before it is used.
func rootIssuedHumanChain(ctx context.Context, rec *awconfig.HumanRecord, controllerKey ed25519.PrivateKey, registry *awid.RegistryClient, opts idHumanInitOptions) (map[string]any, error) {
	dir, err := awconfig.ControllerIssuanceDir(rec.Domain)
	if err != nil {
		return nil, err
	}
	issuance := awconfig.IDIssuanceFileStore{Dir: dir}
	entry, err := issuance.EntryForSubject(rec.StableID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		status := awid.NewIDStatusClient(registry, opts.TXTResolver)
		status.Route = func(context.Context, string) (string, error) { return rec.RegistryURL, nil }
		evidence := status.IDChainEvidence(ctx, nil, awid.IDChainSubject{ID: rec.StableID, DIDKey: rec.DIDKey}, rec.Domain)
		child := awid.IDChild{ID: rec.StableID, Domain: rec.Domain, Parent: map[string]any{"kind": "namespace", "id": rec.Domain}, Kind: "human"}
		bundle, err := awid.IssueIDChild(issuance, child, nil, evidence, awid.KeySigner(controllerKey), opts.Now())
		if err != nil {
			return nil, fmt.Errorf("issue the certificate of %s: %w", rec.StableID, err)
		}
		certificates := bundle["certificates"].([]any)
		leaf := certificates[0].(map[string]any)
		if rec.CertificateID, err = awid.IDCertificateID(leaf["certificate"].(map[string]any)); err != nil {
			return nil, err
		}
		return bundle, awconfig.SaveHumanRecord(rec)
	}
	if rec.CertificateID == "" {
		rec.CertificateID = entry.CertificateID
		if err := awconfig.SaveHumanRecord(rec); err != nil {
			return nil, err
		}
	}
	if entry.CertificateID != rec.CertificateID {
		return nil, fmt.Errorf("the controller's issuance log for %s holds %s, the human record names %s", rec.StableID, entry.CertificateID, rec.CertificateID)
	}
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{entry.Signed}}, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func formatIDHumanInit(v any) string {
	out := v.(idHumanInitOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Human:       %s\n", out.ID))
	sb.WriteString(fmt.Sprintf("Key:         %s\n", out.DIDKey))
	sb.WriteString(fmt.Sprintf("Domain:      %s\n", out.Domain))
	sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	sb.WriteString("Registered at AWID; authority is checked against the tree at each use.\n")
	return sb.String()
}
