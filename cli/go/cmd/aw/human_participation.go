package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var humanFlag, humanDomainFlag string
var activeHuman *humanParticipation

type humanParticipation struct {
	operation string
	record    *awconfig.HumanRecord
	dir       string
	chain     map[string]any
	sign      awid.InteractiveSigner
}

// Kept separate from resolveLocalSigningIdentity: arbitrary signing, blueprint
// publishing and worker custody must never inherit human authority.
func humanParticipationAllowed(cmd *cobra.Command) bool {
	return cmd == initCmd || cmd == teamFetchCertCmd || cmd == mailSendCmd || cmd == mailInboxCmd || cmd == mailShowCmd || cmd == mailReplyCmd || (cmd == idRequestCmd && idRequestTeamAuth)
}
func humanSelectionRequested() bool { return humanFlag != "" || humanDomainFlag != "" }
func prepareHumanParticipation(cmd *cobra.Command) error {
	if !humanParticipationAllowed(cmd) {
		return usageError("--human is not supported for %s; use human mail or ordinary team-auth requests", cmd.CommandPath())
	}
	h, err := loadHumanParticipation(humanFlag, humanDomainFlag, awconfig.HumanKeychain{}, awid.TerminalPassphrasePrompt(), humanAtTerminal)
	if err != nil {
		return err
	}
	activeHuman = h
	return nil
}
func loadHumanParticipation(id, domain string, store awid.HumanKeyStore, prompt awid.PassphrasePrompt, terminal func() error) (*humanParticipation, error) {
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
	if rec == nil || rec.State != awconfig.HumanRegistered {
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
	if installed == nil {
		return nil, usageError("selected human has no installed ID chain")
	}
	subject, err := installed.Subject(rec.DIDKey)
	if err != nil || subject.ID != rec.StableID {
		return nil, usageError("installed ID chain does not belong to selected human")
	}
	certificates := installed.Bundle["certificates"].([]any)
	leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
	if leaf["kind"] != "human" {
		return nil, usageError("selected ID chain is not a human identity")
	}
	n := 0
	h := &humanParticipation{record: rec, dir: dir, chain: installed.Bundle}
	sign := func(payload []byte, description string) (string, []byte, error) {
		n++
		return awid.HumanSigner(store, id, fmt.Sprintf("signature %d: %s", n, h.operation+"; "+description), prompt)(payload)
	}
	h.sign = sign
	return h, nil
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
	if url == "" {
		url = firstNonEmpty(strings.TrimSpace(os.Getenv("AWEB_URL")), m.AwebURL)
	}
	if url == "" {
		return nil, nil, usageError("human team is not connected; run aw init --human with --url")
	}
	raw, err := awid.NewWithInteractiveSigner(url, h.record.DIDKey, cert, h.sign)
	if err != nil {
		return nil, nil, err
	}
	c := &aweb.Client{Client: raw}
	sel := &awconfig.Selection{WorkingDir: mustGetwd(), IdentityHome: h.dir, ExternalIdentityHome: true, BaseURL: url, AwebURL: url, TeamID: m.TeamID, Alias: cert.Alias, Address: cert.MemberAddress, DID: h.record.DIDKey, StableID: h.record.StableID, Domain: h.record.Domain, RegistryURL: m.RegistryURL, IdentityScope: cert.IdentityScope}
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
	url := firstNonEmpty(initAwebURL, initURL, m.AwebURL, strings.TrimSpace(os.Getenv("AWEB_URL")))
	if url == "" {
		return usageError("human connect requires --url")
	}
	c, _, err := h.client(m.TeamID, url)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	hostname, _ := os.Hostname()
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
	printOutput(connectOutput{Status: "connected", TeamID: resp.TeamID, Alias: resp.Alias, AwebURL: url, StableID: h.record.StableID, Address: cert.MemberAddress, IdentityScope: cert.IdentityScope}, formatConnect)
	return nil
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
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := firstNonEmpty(teamFetchCertRegistry, h.record.RegistryURL)
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
	if state.ActiveTeam == "" {
		state.ActiveTeam = teamID
	}
	if err := awconfig.SaveTeamStateToIdentityHome(h.dir, state); err != nil {
		return err
	}
	printOutput(teamFetchCertOutput{Status: "installed", TeamID: teamID, Alias: cert.Alias, CertificateID: id, CertPath: rel}, formatTeamFetchCert)
	return nil
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
