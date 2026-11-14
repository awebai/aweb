package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

const ownerActDeliveryPath = "/.well-known/aweb-owner-act"

// handoffLifetime bounds a command that waits on a browser handoff: the app
// expires a handoff after at most ten minutes.
const handoffLifetime = 11 * time.Minute

var appCmd = &cobra.Command{
	Use:   "app",
	Short: "Act on an installed app's roles held by a team's humans",
	Long: "Roles that an app's manifest declares under owner_acts are held by human members of the team.\n" +
		"The team owner binds and unbinds holders with signed acts; a holder registers a passkey\n" +
		"at the app's human origin in a browser that aw opens.",
}

var appRoleCmd = &cobra.Command{Use: "role", Short: "Designate or revoke a holder of an app role, as the team owner"}

var appCredentialCmd = &cobra.Command{Use: "credential", Short: "Register or replace a holder's passkey for an app role"}

var (
	appRoleFlag, appPrincipalFlag, appCredentialFileFlag, appNoticeContactFlag, appOutFlag string
	appYesFlag                                                                             bool
)

var appCredentialRegisterCmd = &cobra.Command{
	Use:   "register <app>",
	Short: "Register a passkey for an app role, as the holder, and export it for the team owner",
	Long: "Opens the app's human origin in a browser, where you create a passkey, and writes the public\n" +
		"credential with your team certificate to --out (or stdout). Read its fingerprint to the team\n" +
		"owner over a channel your custodian does not control, such as in person or a call.",
	Args: cobra.ExactArgs(1),
}

var appRoleDesignateCmd = &cobra.Command{
	Use:   "designate <app>",
	Short: "Designate a human member as a holder of an app role",
	Long: "Signs human-role.designate with the team's controller key. Pass the holder's export with\n" +
		"--credential and sign only after both clients show the same fingerprint. Without --credential,\n" +
		"you are the holder: aw registers your passkey first, then signs.",
	Args: cobra.ExactArgs(1),
}

var appRoleRevokeCmd = &cobra.Command{
	Use:   "revoke <app>",
	Short: "End a holder's holding of an app role",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHumanRoleAct(cmd, "human-role.revoke", args[0])
	},
}

var appCredentialReplaceCmd = &cobra.Command{
	Use:   "replace <app>",
	Short: "Replace a holder's passkey, as the team owner",
	Long: "Signs human-credential.replace with the team's controller key. The current passkey is retired\n" +
		"at once and the replacement takes effect after the app's cooling-off period.",
	Args: cobra.ExactArgs(1),
}

func init() {
	// Assigned here: humanParticipationAllowed names these commands, and a
	// RunE in their literals would make their initialization a cycle.
	appCredentialRegisterCmd.RunE = runAppCredentialRegister
	appRoleDesignateCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runHumanRoleAct(cmd, "human-role.designate", args[0])
	}
	appCredentialReplaceCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runHumanRoleAct(cmd, "human-credential.replace", args[0])
	}
	appCredentialRegisterCmd.Flags().StringVar(&appRoleFlag, "role", "", "The app role, as its manifest names it")
	appCredentialRegisterCmd.Flags().StringVar(&appOutFlag, "out", "", "Write the export to this file instead of stdout")
	for _, cmd := range []*cobra.Command{appRoleDesignateCmd, appRoleRevokeCmd, appCredentialReplaceCmd} {
		cmd.Flags().StringVar(&appRoleFlag, "role", "", "The app role, as its manifest names it")
		cmd.Flags().StringVar(&appPrincipalFlag, "principal", "", "The holder's did:aw")
		cmd.Flags().BoolVar(&appYesFlag, "yes", false, "Sign what is shown without asking")
	}
	for _, cmd := range []*cobra.Command{appRoleDesignateCmd, appCredentialReplaceCmd} {
		cmd.Flags().StringVar(&appCredentialFileFlag, "credential", "", "The holder's export from aw app credential register")
		cmd.Flags().StringVar(&appNoticeContactFlag, "notice-contact", "", "The notice contact, for a role that declares one")
	}
	appRoleRevokeCmd.Flags().StringVar(&appProtectedProfileFlag, "protected-profile", "", "Prepare the act at the protected service this operator-provisioned profile names; the controlling human approves it there")
	appRoleRevokeCmd.Flags().StringVar(&appApproverFlag, "approver", "", "With --protected-profile, the did:aw of the human who approves the act")
	appRoleRevokeCmd.Flags().StringVar(&appRoleReplaceFlag, "replace", "", "With --protected-profile, the id of an earlier unfinished request for this same act, which stays kept, to ask for a separately approved act")
	appRoleResumeCmd.Flags().StringVar(&appProtectedProfileFlag, "protected-profile", "", "The profile the operation was prepared through")
	appRoleCmd.AddCommand(appRoleDesignateCmd, appRoleRevokeCmd, appRoleResumeCmd)
	appCredentialCmd.AddCommand(appCredentialRegisterCmd, appCredentialReplaceCmd)
	appCmd.AddCommand(appRoleCmd, appCredentialCmd)
	appCmd.GroupID = groupUtility
	rootCmd.AddCommand(appCmd)
}

func runAppCredentialRegister(cmd *cobra.Command, args []string) error {
	app, err := installedHolderApp(args[0])
	if err != nil {
		return err
	}
	export, err := registerHolderCredential(cmd, app, appRoleFlag)
	if err != nil {
		return err
	}
	digest, _ := export.Credential.SHA256()
	fmt.Fprintf(cmd.ErrOrStderr(), "Passkey registered for %s at %s.\nFingerprint: %s\n", export.Role, app.Origins.Human, awid.CredentialFingerprint(digest))
	if strings.TrimSpace(appOutFlag) == "" {
		data, err := json.MarshalIndent(export, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}
	return writeHolderExport(appOutFlag, *export)
}

// registerHolderCredential runs a credential handoff as this command's signing
// identity and returns its export.
func registerHolderCredential(cmd *cobra.Command, app *holderApp, roleName string) (*holderCredentialExport, error) {
	opts, err := app.holderOptions(cmd, roleName, "credential")
	if err != nil {
		return nil, err
	}
	certificate, chain, teamID, err := holderMembershipEvidence()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), handoffLifetime)
	defer cancel()
	credential, err := handoff.RegisterCredential(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &holderCredentialExport{
		V: 1, Type: holderExportType, AppID: app.AppID, OwnerActsOrigin: app.Origins.Human,
		InstallationID: opts.Scope.InstallationID, TeamID: teamID, Role: opts.Scope.Role, Principal: opts.Scope.Principal,
		Credential:  awid.HumanCredential{CredentialID: credential.CredentialID, PublicKey: credential.PublicKey, RPID: credential.RPID},
		Certificate: certificate, IDChain: chain,
	}, nil
}

// holderMembershipEvidence is the signing identity's team certificate, in
// X-AWID-Team-Certificate's encoding, and its installed ID chain.
func holderMembershipEvidence() (string, map[string]any, string, error) {
	var (
		cert  *awid.TeamCertificate
		chain map[string]any
		err   error
	)
	if activeHuman != nil {
		_, _, cert, err = activeHuman.membership(teamFlag)
		chain = activeHuman.chain
	} else {
		identity, idErr := resolveParticipationRequestIdentity()
		if idErr != nil {
			return "", nil, "", idErr
		}
		cert, err = awconfig.LoadTeamCertificateForTeamFromIdentityHome(identity.IdentityHome, identity.TeamID)
		if err == nil {
			installed, chainErr := awconfig.LoadInstalledIDChain(filepath.Dir(identity.SigningKeyPath))
			if chainErr != nil {
				return "", nil, "", chainErr
			}
			if installed != nil {
				chain = installed.Bundle
			}
		}
	}
	if err != nil {
		return "", nil, "", err
	}
	if cert == nil {
		return "", nil, "", withErrorCode("team_certificate_required", fmt.Errorf("this identity holds no team certificate; fetch it with aw id team fetch-cert"))
	}
	if chain == nil {
		return "", nil, "", withErrorCode("id_chain_required", fmt.Errorf("this identity has no installed ID chain, so it cannot show that it is a human"))
	}
	encoded, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		return "", nil, "", err
	}
	return encoded, chain, cert.Team, nil
}

// runHumanRoleAct signs and delivers one human-role act as the team owner.
func runHumanRoleAct(cmd *cobra.Command, act, appName string) error {
	app, err := installedHolderApp(appName)
	if err != nil {
		return err
	}
	role, err := app.role(appRoleFlag)
	if err != nil {
		return err
	}
	principal := strings.TrimSpace(appPrincipalFlag)
	if principal == "" {
		return usageError("--principal is required")
	}
	client, selection, err := participationClient()
	if err != nil {
		return err
	}
	// Through a protected service, the act is approved by the controlling
	// human there; aw needs no controller key.
	protected := strings.TrimSpace(appProtectedProfileFlag) != ""
	if !protected && strings.TrimSpace(appRoleReplaceFlag) != "" {
		return usageError("--replace applies only with --protected-profile")
	}
	var teamKey ed25519.PrivateKey
	if !protected {
		if teamKey, err = loadOwnerTeamKey(selection.TeamID); err != nil {
			return err
		}
	}
	installationID, err := roleActInstallation(cmd, app, client, selection.TeamID, protected)
	if err != nil {
		return err
	}
	request := humanRoleActRequest{
		Act: act, AppID: app.AppID, Origin: app.Origins.Human, Role: role,
		InstallationID: installationID, Principal: principal, NoticeContact: strings.TrimSpace(appNoticeContactFlag),
	}
	var holder *holderFacts
	if request.bindsCredential() {
		export, err := holderExportFor(cmd, app, role.Name, principal)
		if err != nil {
			return err
		}
		if err := export.bindsTo(holderBinding{app.AppID, app.Origins.Human, installationID, selection.TeamID, role.Name, principal}); err != nil {
			return err
		}
		ctx, cancel := commandAPIContext(cmd)
		holder, err = verifyHolderEvidence(ctx, export, selection, teamKey)
		cancel()
		if err != nil {
			return err
		}
		request.Credential, request.Certificate = &export.Credential, export.Certificate
	}
	if err := request.check(); err != nil {
		return err
	}
	subject, err := request.subject()
	if err != nil {
		return err
	}
	if protected {
		return runProtectedHumanRoleAct(cmd, act, selection.TeamID, app.Origins.Human, subject)
	}
	fields, err := newOwnerAct(act, selection.TeamID, app.Origins.Human, teamKey, subject, time.Now())
	if err != nil {
		return err
	}
	if _, err := awid.OwnerActSigningBytes(fields); err != nil {
		return err
	}
	stderr := cmd.ErrOrStderr()
	fmt.Fprint(stderr, formatHumanRoleAct(fields, request, app, holder))
	if err := confirmOwnerAct(appYesFlag, cmd.InOrStdin(), stderr); err != nil {
		return err
	}
	signing, signature, err := awid.SignOwnerAct(teamKey, fields)
	if err != nil {
		return err
	}
	result, err := deliverOwnerAct(cmd, app.Origins.Human, request.deliveryBody(signing, signature))
	if err != nil {
		return err
	}
	printOutput(result, func(value any) string {
		r := value.(map[string]any)
		return fmt.Sprintf("%s for %s took effect at %s.\n", r["act"], r["principal"], r["effective_at"])
	})
	return nil
}

// holderExportFor is the export named by --credential, or, without one, the
// export of a credential this command registers for its own identity.
func holderExportFor(cmd *cobra.Command, app *holderApp, roleName, principal string) (*holderCredentialExport, error) {
	if path := strings.TrimSpace(appCredentialFileFlag); path != "" {
		return readHolderExport(path)
	}
	identity, err := resolveParticipationRequestIdentity()
	if err != nil {
		return nil, err
	}
	if identity.StableID != principal {
		return nil, usageError("--credential is required when the holder %s is not this identity (%s)", principal, identity.StableID)
	}
	return registerHolderCredential(cmd, app, roleName)
}

// holderFacts are what the registry says about a holder, shown to the owner.
type holderFacts struct {
	Alias   string
	Address string
	Kind    string
}

// verifyHolderEvidence refuses to bind a holder unless its certificate is an
// active certificate of the team, signed under the team's current key and
// naming the principal, and its ID chain shows the principal's own kind is
// human.
func verifyHolderEvidence(ctx context.Context, e *holderCredentialExport, selection *awconfig.Selection, teamKey ed25519.PrivateKey) (*holderFacts, error) {
	notMember := func(reason string) error {
		return withErrorCode("principal_not_member", fmt.Errorf("%s is not shown to be a current member of %s: %s", e.Principal, selection.TeamID, reason))
	}
	cert, err := awid.DecodeTeamCertificateHeader(e.Certificate)
	if err != nil {
		return nil, notMember(err.Error())
	}
	if cert.Team != selection.TeamID || cert.MemberDIDAW != e.Principal {
		return nil, notMember("the certificate names another team or member")
	}
	domain, name, err := awid.ParseTeamID(selection.TeamID)
	if err != nil {
		return nil, err
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return nil, err
	}
	registryURL := strings.TrimSpace(registry.DefaultRegistryURL)
	team, err := registry.GetTeam(ctx, registryURL, domain, name, teamKey)
	if err != nil {
		return nil, withErrorCode("principal_status_unavailable", fmt.Errorf("read team %s from the registry: %w", selection.TeamID, err))
	}
	// The registry's list of active certificates, read next, stands for
	// registration.
	if _, err := awid.CheckTeamCertificate(e.Certificate, awid.TeamCertificateFacts{
		SubjectDIDKey: cert.MemberDIDKey,
		TeamDIDKey:    team.TeamDIDKey,
		Registered:    awid.RegistrationNotRequired(),
	}); err != nil {
		return nil, notMember("the certificate does not verify under the team's current key")
	}
	active, err := registry.ListCertificates(ctx, registryURL, domain, name, true, teamKey)
	if err != nil {
		return nil, withErrorCode("principal_status_unavailable", fmt.Errorf("list team %s's certificates: %w", selection.TeamID, err))
	}
	current := false
	for _, c := range active {
		if c.CertificateID == cert.CertificateID && c.MemberDIDKey == cert.MemberDIDKey && c.MemberDIDAW == cert.MemberDIDAW && c.RevokedAt == "" {
			current = true
		}
	}
	if !current {
		return nil, notMember("the certificate is not an active certificate of the team")
	}
	kind, err := holderKind(ctx, e, cert)
	if err != nil {
		return nil, err
	}
	return &holderFacts{Alias: cert.Alias, Address: cert.MemberAddress, Kind: kind}, nil
}

// holderKind verifies the holder's ID chain for its certified key and
// returns its kind, which must be human.
func holderKind(ctx context.Context, e *holderCredentialExport, cert *awid.TeamCertificate) (string, error) {
	certificates, _ := e.IDChain["certificates"].([]any)
	domain := ""
	if len(certificates) > 0 {
		last, _ := certificates[len(certificates)-1].(map[string]any)
		inner, _ := last["certificate"].(map[string]any)
		domain, _ = inner["domain"].(string)
	}
	out, err := verifyWhoPresentation(ctx, awid.IDChainSubject{ID: e.Principal, DIDKey: cert.MemberDIDKey}, e.IDChain, domain, whoOptions{TXTResolver: &awid.NetTXTResolver{}})
	if err != nil {
		return "", withErrorCode("principal_status_unavailable", err)
	}
	if out.Outcome == "unavailable" {
		return "", withErrorCode("principal_status_unavailable", fmt.Errorf("the holder's ID chain could not be checked: %s", out.Reason))
	}
	if out.IdentityValid == nil || !*out.IdentityValid || out.Kind == nil {
		return "", withErrorCode("principal_not_human", fmt.Errorf("the holder's ID chain does not verify: %s", out.Reason))
	}
	if *out.Kind != "human" {
		return "", withErrorCode("principal_not_human", fmt.Errorf("%s is a %s, not a human", e.Principal, *out.Kind))
	}
	return *out.Kind, nil
}

func formatHumanRoleAct(fields map[string]any, r humanRoleActRequest, app *holderApp, holder *holderFacts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Owner act %s for team %s\n", fields["act"], fields["team_id"])
	fmt.Fprintf(&b, "  app:        %s at %s\n", r.AppID, r.Origin)
	fmt.Fprintf(&b, "  role:       %s (%s, %s)\n", r.Role.Name, r.AppID, r.Role.Label)
	fmt.Fprintf(&b, "  principal:  %s\n", r.Principal)
	if holder != nil {
		fmt.Fprintf(&b, "              alias %s, address %s, kind %s\n", holder.Alias, holder.Address, holder.Kind)
	}
	if r.Credential != nil {
		digest, _ := r.Credential.SHA256()
		fmt.Fprintf(&b, "  credential: browser passkey at %s\n", r.Credential.RPID)
		fmt.Fprintf(&b, "  fingerprint: %s\n", awid.CredentialFingerprint(digest))
	}
	if r.NoticeContact != "" {
		fmt.Fprintf(&b, "  notice contact: %s\n", r.NoticeContact)
	}
	fmt.Fprintf(&b, "  verifier:   %s\n", fields["aud"])
	fmt.Fprintf(&b, "  signer:     %s\n", fields["team_key_did"])
	return b.String()
}

// ownerActTransport carries owner-act deliveries to an app.
var ownerActTransport = func() http.RoundTripper { return awid.NewAPITransport() }

// errOwnerActAppliedEarlier is the receiver's 409 applied_earlier: this
// exact act took effect on an earlier delivery. No other answer means that,
// whatever its body says.
var errOwnerActAppliedEarlier = errors.New("the app already applied this act")

// roleActInstallation is app's active installation for a role act. Through a
// protected service the lookup waits out the service's explicit throttle
// hints within its own bound, handoff.DefaultRetryWithin from now and never
// past the command's own deadline, before the prepare, which then has a bound
// of its own. A local act reads it once within the API timeout.
func roleActInstallation(cmd *cobra.Command, app *holderApp, client *aweb.Client, teamID string, protected bool) (string, error) {
	if !protected {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		return app.installation(ctx, client, teamID)
	}
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, handoff.DefaultRetryWithin)
	defer cancel()
	return app.installationWithinBound(ctx, client, teamID)
}

// deliverOwnerAct posts a signed act to the app's human origin, with no
// team-auth and no redirect, and returns the app's answer.
func deliverOwnerAct(cmd *cobra.Command, humanOrigin string, body map[string]any) (map[string]any, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(humanOrigin + ownerActDeliveryPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout: awid.APITimeout(), Transport: ownerActTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reply, err := readAllBounded(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		code := handoff.RefusalCode(reply)
		if code == "" {
			code = fmt.Sprintf("owner_act_http_%d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusConflict && code == "applied_earlier" {
			return nil, withErrorCode(code, errOwnerActAppliedEarlier)
		}
		return nil, withErrorCode(code, fmt.Errorf("%s refused the act (%d %s)", humanOrigin, resp.StatusCode, code))
	}
	var result map[string]any
	if err := json.Unmarshal(reply, &result); err != nil {
		return nil, fmt.Errorf("read the app's answer: %w", err)
	}
	return result, nil
}
