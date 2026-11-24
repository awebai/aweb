package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var humanFlag, humanDomainFlag string
var activeHuman *humanParticipation

type humanParticipation struct {
	operation   string
	record      *awconfig.HumanRecord
	dir         string
	chain       map[string]any
	sign        awid.InteractiveSigner
	output      io.Writer
	signMu      sync.Mutex
	keyMu       sync.Mutex
	unlockedKey ed25519.PrivateKey
	unlockErr   error
	closed      bool
	stopSignals func()
}

func init() {
	// Cobra finalizers run on success, returned errors and panics. Plugin
	// dispatch has its own defer because it does not execute through Cobra.
	cobra.OnFinalize(func() {
		if activeHuman != nil {
			activeHuman.close()
		}
	})
}

func (h *humanParticipation) close() {
	h.keyMu.Lock()
	defer h.keyMu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	wipeBytes(h.unlockedKey)
	h.unlockedKey = nil
	if h.stopSignals != nil {
		h.stopSignals()
		h.stopSignals = nil
	}
}

func (h *humanParticipation) watchSignals() {
	interrupts := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	h.keyMu.Lock()
	if h.closed {
		h.keyMu.Unlock()
		signal.Stop(interrupts)
		return
	}
	h.stopSignals = func() { signal.Stop(interrupts); close(done) }
	h.keyMu.Unlock()
	go func() {
		select {
		case caught := <-interrupts:
			h.close()
			code := 130
			if caught == syscall.SIGTERM {
				code = 143
			} else if caught == syscall.SIGHUP {
				code = 129
			}
			os.Exit(code)
		case <-done:
		}
	}()
}

// Kept separate from resolveLocalSigningIdentity: arbitrary signing, blueprint
// publishing and worker custody must never inherit human authority.
func humanParticipationAllowed(cmd *cobra.Command) bool {
	return cmd.Annotations[humanCommandAnnotation] != "" || cmd == initCmd || cmd == teamFetchCertCmd || cmd == mailSendCmd || cmd == mailInboxCmd || cmd == mailShowCmd || cmd == mailReplyCmd || (cmd == idRequestCmd && idRequestTeamAuth) ||
		cmd == appCredentialRegisterCmd || cmd == appRoleDesignateCmd || cmd == appCredentialReplaceCmd
}
func humanSelectionRequested() bool { return humanFlag != "" || humanDomainFlag != "" }
func prepareHumanParticipation(cmd *cobra.Command) error {
	if !humanParticipationAllowed(cmd) {
		return usageError("--human is not supported for %s; use human mail or ordinary team-auth requests", cmd.CommandPath())
	}
	h, err := loadHumanParticipationState(humanFlag, humanDomainFlag, awconfig.HumanKeychain{}, awid.TerminalPassphrasePrompt(), humanAtTerminal, cmd.Annotations[humanCommandAnnotation] == "prepared")
	if err != nil {
		return err
	}
	activeHuman = h
	h.operation = cmd.CommandPath()
	h.output = cmd.ErrOrStderr()
	h.watchSignals()
	return nil
}
func loadHumanParticipation(id, domain string, store awid.HumanKeyStore, prompt awid.PassphrasePrompt, terminal func() error) (*humanParticipation, error) {
	return loadHumanParticipationState(id, domain, store, prompt, terminal, false)
}

// Only enrollment and certificate registration may select a prepared human.
// The same terminal and encrypted-key signer are used before and after issuance.
func loadHumanParticipationState(id, domain string, store awid.HumanKeyStore, prompt awid.PassphrasePrompt, terminal func() error, allowPrepared bool) (*humanParticipation, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(domain) == "" {
		return nil, usageError("--human and --human-domain are both required")
	}
	if identityHomeFlag != "" || strings.TrimSpace(os.Getenv(awconfig.IdentityHomeEnv)) != "" {
		return nil, usageError("--human conflicts with --identity-home or AWEB_IDENTITY_HOME; select one principal")
	}
	if err := terminal(); err != nil {
		return nil, err
	}
	rec, err := awconfig.LoadHumanRecord(domain, id)
	if err != nil {
		return nil, err
	}
	if rec == nil || (rec.State != awconfig.HumanRegistered && (!allowPrepared || (rec.State != awconfig.HumanPrepared && rec.State != awconfig.HumanDIDRegistered))) {
		return nil, usageError("human %s is not registered on this device in %s", id, domain)
	}
	dir, err := awconfig.HumanRecordDir(domain, id)
	if err != nil {
		return nil, err
	}
	installed, err := awconfig.LoadInstalledIDChain(dir)
	if err != nil {
		return nil, err
	}
	if installed == nil && rec.State == awconfig.HumanRegistered {
		return nil, usageError("selected human has no installed ID chain")
	}
	var chain map[string]any
	if installed != nil {
		subject, err := installed.Subject(rec.DIDKey)
		if err != nil || subject.ID != rec.StableID {
			return nil, usageError("installed ID chain does not belong to selected human")
		}
		certificates := installed.Bundle["certificates"].([]any)
		leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
		if leaf["kind"] != "human" {
			return nil, usageError("selected ID chain is not a human identity")
		}
		chain = installed.Bundle
	}
	h := newHumanSigningSession(rec, store, prompt)
	h.dir, h.chain = dir, chain
	return h, nil
}

// Every human path shares this one command-owned unlock and wipe boundary.
// Callers validate their own command-specific record/chain before using it.
func newHumanSigningSession(rec *awconfig.HumanRecord, store awid.HumanKeyStore, prompt awid.PassphrasePrompt) *humanParticipation {
	id := rec.StableID
	n := 0
	h := &humanParticipation{record: rec, output: os.Stderr}
	sign := func(payload []byte, description string) (string, []byte, error) {
		h.signMu.Lock()
		defer h.signMu.Unlock()
		h.keyMu.Lock()
		if h.closed {
			h.keyMu.Unlock()
			return "", nil, fmt.Errorf("human command has ended")
		}
		if h.unlockErr != nil {
			err := h.unlockErr
			h.keyMu.Unlock()
			return "", nil, err
		}
		needsUnlock := h.unlockedKey == nil
		h.keyMu.Unlock()
		n++
		if _, err := fmt.Fprintf(h.output, "Sign as %s to signature %d: %s; %s.\n", id, n, h.operation, description); err != nil {
			return "", nil, err
		}
		if needsUnlock {
			// Do not hold keyMu while waiting on the terminal: an interrupt
			// must be able to close the command even during its first prompt.
			blob, err := store.LoadHumanKey(id)
			var passphrase []byte
			var key ed25519.PrivateKey
			if err == nil {
				passphrase, err = prompt(fmt.Sprintf("Unlock human %s for %s.\nPassphrase for that human key: ", id, h.operation))
			}
			h.keyMu.Lock()
			// Hold the key lock through decryption and ownership transfer, so
			// signal cleanup cannot exit with an unowned decrypted key.
			if err == nil && h.closed {
				err = fmt.Errorf("human command has ended")
			}
			if err == nil && !h.closed {
				key, err = awid.ImportHumanKeyBackup(blob, passphrase)
			}
			wipeBytes(passphrase)
			if err == nil && awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != rec.DIDKey {
				err = fmt.Errorf("keychain key does not match the selected human")
			}
			if err != nil || h.closed {
				wipeBytes(key)
				if err == nil {
					err = fmt.Errorf("human command has ended")
				}
				h.unlockErr = err
				h.keyMu.Unlock()
				return "", nil, err
			}
			h.unlockedKey = key
			h.keyMu.Unlock()
		}
		h.keyMu.Lock()
		defer h.keyMu.Unlock()
		if h.closed {
			return "", nil, fmt.Errorf("human command has ended")
		}
		return awid.KeySigner(h.unlockedKey)(payload)
	}
	h.sign = sign
	return h
}
func (h *humanParticipation) membership(team string) (*awconfig.TeamState, *awconfig.TeamMembership, *awid.TeamCertificate, error) {
	state, err := awconfig.LoadTeamStateFromIdentityHome(h.dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if state == nil {
		return nil, nil, nil, usageError("selected human has no team certificate; use aw id team fetch-cert --human")
	}
	if team == "" {
		team = state.ActiveTeam
		if team == "" && len(state.Memberships) == 1 {
			team = state.Memberships[0].TeamID
		}
	}
	m := state.Membership(team)
	if m == nil {
		return nil, nil, nil, usageError("select an installed human team certificate with --team")
	}
	cert, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(h.dir, m.TeamID)
	if err != nil {
		return nil, nil, nil, err
	}
	if cert.Team != m.TeamID || cert.MemberDIDKey != h.record.DIDKey || cert.MemberDIDAW != h.record.StableID {
		return nil, nil, nil, usageError("human team certificate does not match selected key, ID and team")
	}
	return state, m, cert, nil
}
func (h *humanParticipation) client(team, url string) (*aweb.Client, *awconfig.Selection, error) {
	_, m, cert, err := h.membership(team)
	if err != nil {
		return nil, nil, err
	}
	url = selectedAwebServiceURL(serviceURLSelection{URL: url, StoredURL: m.AwebURL})
	if url == "" {
		return nil, nil, usageError("human team is not connected; run aw init --human with --url")
	}
	raw, err := awid.NewWithInteractiveSigner(url, h.record.DIDKey, cert, h.sign)
	if err != nil {
		return nil, nil, err
	}
	c := &aweb.Client{Client: raw}
	workingDir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("read current directory for human participation: %w", err)
	}
	sel := &awconfig.Selection{WorkingDir: workingDir, IdentityHome: h.dir, ExternalIdentityHome: true, BaseURL: url, AwebURL: url, TeamID: m.TeamID, Alias: cert.Alias, Address: cert.MemberAddress, DID: h.record.DIDKey, StableID: h.record.StableID, Domain: h.record.Domain, RegistryURL: m.RegistryURL, IdentityScope: cert.IdentityScope}
	if err := configureResolvedClient(c, sel, url); err != nil {
		return nil, nil, err
	}
	return c, sel, nil
}
func resolveParticipationRequestIdentity() (*localSigningIdentity, error) {
	if activeHuman == nil {
		return resolveLocalSigningIdentity()
	}
	h := activeHuman
	_, m, _, err := h.membership(teamFlag)
	if err != nil {
		return nil, err
	}
	return &localSigningIdentity{DIDKey: h.record.DIDKey, StableID: h.record.StableID, IdentityHome: h.dir, WorkingDir: h.dir, TeamID: m.TeamID, InteractiveSigner: h.sign, IDChain: h.chain}, nil
}
func runHumanConnect(cmd *cobra.Command) error {
	// Creation/configuration flags must not accidentally turn human connect into
	// an agent bootstrap or mutate the adjacent worktree.
	for _, name := range []string{"new-account", "new-team", "join-from", "admission-team-id", "workspace-team", "global", "local", "setup-channel", "setup-hooks", "remove-notify-hook"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return usageError("--human connect does not support --%s", name)
		}
	}
	h := activeHuman
	state, m, cert, err := h.membership(initTeam)
	if err != nil {
		return err
	}
	url := selectedAwebServiceURL(serviceURLSelection{AwebURL: initAwebURL, URL: initURL, StoredURL: m.AwebURL})
	if url == "" {
		return usageError("human connect requires --url")
	}
	c, _, err := h.client(m.TeamID, url)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read hostname for human connect: %w", err)
	}
	body := connectRequest{Hostname: hostname, WorkspacePath: h.dir, HumanName: resolveHumanNameValue(initHumanName, "human")}
	resp, err := postConnectClient(ctx, c.Client, cert, body)
	if err != nil {
		return err
	}
	if resp.AgentType != "human" {
		return usageError("selected identity did not verify as human at connect; check its ID enrollment")
	}
	m.AwebURL = url
	state.ActiveTeam = m.TeamID
	if err := awconfig.SaveTeamStateToIdentityHome(h.dir, state); err != nil {
		return err
	}
	return printOutput(connectOutput{Status: "connected", TeamID: resp.TeamID, Alias: resp.Alias, AwebURL: url, StableID: h.record.StableID, Address: cert.MemberAddress, IdentityScope: cert.IdentityScope}, formatConnect)
}
func runHumanFetchCert(cmd *cobra.Command) error {
	h := activeHuman
	domain := awconfig.NormalizeDomain(teamFetchCertNamespace)
	team := strings.TrimSpace(teamFetchCertTeam)
	id := strings.TrimSpace(teamFetchCertID)
	if domain == "" || team == "" || id == "" {
		return usageError("--namespace, --team and --cert-id are required")
	}
	teamID := awid.BuildTeamID(domain, team)
	state, err := awconfig.LoadTeamStateFromIdentityHome(h.dir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if state == nil {
		state = &awconfig.TeamState{}
	}
	path, err := awconfig.TeamCertificatePathFromIdentityHome(h.dir, teamID)
	if err != nil {
		return err
	}
	if old, err := awid.LoadTeamCertificate(path); err == nil && old.CertificateID != id && !teamFetchCertForce {
		return usageError("certificate already installed; use --force to replace it")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	registryURL := firstNonEmpty(teamFetchCertRegistry, h.record.RegistryURL)
	trustRecordedRegistryOrigin(registry.Resolver, registryURL, h.record.RegistryOperatorOrigin)
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	cert, err := registry.FetchTeamCertificateWithSigner(ctx, registryURL, domain, team, id, h.record.DIDKey, h.sign)
	if err != nil {
		return err
	}
	if cert.Team != teamID || cert.MemberDIDAW != h.record.StableID {
		return usageError("fetched certificate does not match selected human ID and team")
	}
	if err := checkCurrentTeamCertificate(ctx, teamCertificateInstall{RegistryURL: registryURL, Registry: registry}, cert); err != nil {
		return err
	}
	rel, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(h.dir, teamID, cert)
	if err != nil {
		return err
	}
	m := state.Membership(teamID)
	if m == nil {
		state.Memberships = append(state.Memberships, awconfig.TeamMembership{TeamID: teamID})
		m = &state.Memberships[len(state.Memberships)-1]
	}
	m.Alias = cert.Alias
	m.CertPath = filepath.ToSlash(rel)
	m.JoinedAt = cert.IssuedAt
	m.RegistryURL = registryURL
	m.RegistryOperatorOrigin = operatorRegistryOrigin(registryURL, firstNonEmpty(m.RegistryOperatorOrigin, h.record.RegistryOperatorOrigin))
	if state.ActiveTeam == "" {
		state.ActiveTeam = teamID
	}
	if err := awconfig.SaveTeamStateToIdentityHome(h.dir, state); err != nil {
		return err
	}
	return printOutput(teamFetchCertOutput{Status: "installed", TeamID: teamID, Alias: cert.Alias, CertificateID: id, CertPath: rel}, formatTeamFetchCert)
}

// Only a manifest invocation is scanned. Stop at a built-in command so its
// local --human flags (for example id parent request) remain Cobra's property.
func humanSelectorsForPlugin(args []string) ([]string, error) {
	name, _ := firstNonFlagArg(args)
	if name == "" || isReservedRootCommandName(name) {
		return args, nil
	}
	out := []string{}
	for i := 0; i < len(args); i++ {
		key, value, has := strings.Cut(args[i], "=")
		if key != "--human" && key != "--human-domain" {
			out = append(out, args[i])
			continue
		}
		if !has {
			i++
			if i >= len(args) {
				return nil, usageError("missing value for %s", key)
			}
			value = args[i]
		}
		if strings.TrimSpace(value) == "" {
			return nil, usageError("%s requires a value", key)
		}
		if key == "--human" {
			humanFlag = value
		} else {
			humanDomainFlag = value
		}
	}
	return out, nil
}

func setHumanMailOperation(recipient, subject, body string) {
	if activeHuman == nil {
		return
	}
	sum := sha256.Sum256([]byte(body))
	activeHuman.operation = fmt.Sprintf("mail to %q; subject %q; body sha256 %.12x", recipient, subject, sum)
}

func (h *humanParticipation) certificateSigner(description string) awid.IDCertificateSigner {
	return func(payload []byte) (string, []byte, error) { return h.sign(payload, description) }
}

const humanSigningHelp = "\n\nWhen acting as a human, the first signature asks once for the selected person's\nkeychain passphrase at a real terminal. Each signature is described; the key\nstays in memory for this command, including confirmation waits, and is wiped\non success, error or interruption. Another command asks again."
