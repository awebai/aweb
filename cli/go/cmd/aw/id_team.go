package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// --- output types ---

type teamCreateOutput struct {
	Status      string `json:"status"`
	TeamID      string `json:"team_id"`
	TeamDIDKey  string `json:"team_did_key"`
	TeamKeyPath string `json:"team_key_path"`
	RegistryURL string `json:"registry_url,omitempty"`
}

type teamInviteOutput struct {
	Status   string `json:"status"`
	InviteID string `json:"invite_id"`
	Token    string `json:"token"`
}

type teamAcceptInviteOutput struct {
	Status   string `json:"status"`
	TeamID   string `json:"team_id"`
	Alias    string `json:"alias"`
	CertPath string `json:"cert_path"`
}

type teamAddMemberOutput struct {
	Status        string `json:"status"`
	Member        string `json:"member"`
	TeamID        string `json:"team_id"`
	MemberAddress string `json:"member_address,omitempty"`
	CertificateID string `json:"certificate_id"`
}

type teamRemoveMemberOutput struct {
	Status        string `json:"status"`
	TeamID        string `json:"team_id"`
	MemberAddress string `json:"member_address"`
}

type teamAddOutput struct {
	Status   string `json:"status"`
	TeamID   string `json:"team_id"`
	Alias    string `json:"alias"`
	CertPath string `json:"cert_path"`
}

type teamSwitchOutput struct {
	Status     string `json:"status"`
	ActiveTeam string `json:"active_team"`
}

type teamListItem struct {
	TeamID   string `json:"team_id"`
	Alias    string `json:"alias"`
	Lifetime string `json:"lifetime,omitempty"`
	IssuedAt string `json:"issued_at,omitempty"`
	Active   bool   `json:"active"`
}

type teamListOutput struct {
	ActiveTeam  string         `json:"active_team"`
	Memberships []teamListItem `json:"memberships"`
}

type teamLeaveOutput struct {
	Status     string `json:"status"`
	TeamID     string `json:"team_id"`
	ActiveTeam string `json:"active_team"`
}

type certShowOutput struct {
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
	TeamDIDKey    string `json:"team_did_key"`
	Lifetime      string `json:"lifetime"`
	IssuedAt      string `json:"issued_at"`
	CertificateID string `json:"certificate_id"`
}

type localTeamRegistration struct {
	TeamID      string
	TeamDIDKey  string
	TeamKey     ed25519.PrivateKey
	TeamKeyPath string
}

type localTeamBootstrapResult struct {
	TeamID      string
	TeamDIDKey  string
	TeamKeyPath string
	Certificate *awid.TeamCertificate
}

type acceptedTeamInvite struct {
	Output      *teamAcceptInviteOutput
	Certificate *awid.TeamCertificate
	RegistryURL string
	Domain      string
	TeamName    string
}

// --- flags ---

var (
	teamCreateName        string
	teamCreateNamespace   string
	teamCreateDisplayName string
	teamCreateRegistryURL string

	teamInviteTeam      string
	teamInviteNamespace string
	teamInviteEphemeral bool

	teamAcceptAlias string
	teamAddAlias    string

	teamAddTeam           string
	teamAddNamespace      string
	teamAddMember         string
	teamAddMemberDID      string
	teamAddMemberAlias    string
	teamAddMemberLifetime string
	teamAddMemberDIDAW    string
	teamAddMemberAddress  string

	teamRemoveTeam        string
	teamRemoveNamespace   string
	teamRemoveMember      string
	teamRemoveRegistryURL string
)

// --- commands ---

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Team management (create, invite, membership)",
}

var teamCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a team at awid",
	RunE:  runTeamCreate,
}

var teamInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Generate an invite token for a team",
	RunE:  runTeamInvite,
}

var teamAcceptInviteCmd = &cobra.Command{
	Use:   "accept-invite <token>",
	Short: "Accept a team invite and receive a membership certificate",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamAcceptInvite,
}

var teamAddCmd = &cobra.Command{
	Use:   "add <invite-token>",
	Short: "Join another team with the current identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamAdd,
}

var teamSwitchCmd = &cobra.Command{
	Use:   "switch <team_id>",
	Short: "Switch the active team for this identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamSwitch,
}

var teamListCmd = &cobra.Command{
	Use:   "list",
	Short: "List team memberships for this identity",
	RunE:  runTeamList,
}

var teamLeaveCmd = &cobra.Command{
	Use:   "leave <team_id>",
	Short: "Remove a team membership from this identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamLeave,
}

var teamAddMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a member directly to a team (controller signs certificate)",
	RunE:  runTeamAddMember,
}

var teamRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a member from a team (revoke certificate)",
	RunE:  runTeamRemoveMember,
}

var certShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show the current team certificate",
	RunE:  runCertShow,
}

var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Team certificate operations",
}

func init() {
	teamCreateCmd.Flags().StringVar(&teamCreateName, "name", "", "Team name")
	teamCreateCmd.Flags().StringVar(&teamCreateNamespace, "namespace", "", "Namespace domain")
	teamCreateCmd.Flags().StringVar(&teamCreateDisplayName, "display-name", "", "Team display name")
	teamCreateCmd.Flags().StringVar(&teamCreateRegistryURL, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamCreateCmd)

	teamInviteCmd.Flags().StringVar(&teamInviteTeam, "team", "", "Team name")
	teamInviteCmd.Flags().StringVar(&teamInviteNamespace, "namespace", "", "Namespace domain")
	teamInviteCmd.Flags().BoolVar(&teamInviteEphemeral, "ephemeral", false, "Create ephemeral member invite")
	teamCmd.AddCommand(teamInviteCmd)

	teamAcceptInviteCmd.Flags().StringVar(&teamAcceptAlias, "alias", "", "Alias for the accepting agent (defaults to identity name)")
	teamCmd.AddCommand(teamAcceptInviteCmd)

	teamAddCmd.Flags().StringVar(&teamAddAlias, "alias", "", "Alias for the added team membership (defaults to the current identity name)")
	teamCmd.AddCommand(teamAddCmd)
	teamCmd.AddCommand(teamSwitchCmd)
	teamCmd.AddCommand(teamListCmd)
	teamCmd.AddCommand(teamLeaveCmd)

	teamAddMemberCmd.Flags().StringVar(&teamAddTeam, "team", "", "Team name")
	teamAddMemberCmd.Flags().StringVar(&teamAddNamespace, "namespace", "", "Namespace domain")
	teamAddMemberCmd.Flags().StringVar(&teamAddMember, "member", "", "Member address (e.g. acme.com/alice)")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberDID, "did", "", "Member did:key for direct certificate issuance")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberAlias, "alias", "", "Alias to use with --did")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberLifetime, "lifetime", awid.LifetimeEphemeral, "Certificate lifetime for --did (ephemeral or persistent)")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberDIDAW, "did-aw", "", "Optional stable did:aw when using --did")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberAddress, "address", "", "Optional member address when using --did")
	teamCmd.AddCommand(teamAddMemberCmd)

	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveTeam, "team", "", "Team name")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveNamespace, "namespace", "", "Namespace domain")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveMember, "member", "", "Member address (e.g. acme.com/alice)")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveRegistryURL, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamRemoveMemberCmd)

	identityCmd.AddCommand(teamCmd)

	certCmd.AddCommand(certShowCmd)
	identityCmd.AddCommand(certCmd)
}

// --- implementations ---

func runTeamCreate(cmd *cobra.Command, args []string) error {
	name := strings.ToLower(strings.TrimSpace(teamCreateName))
	domain := awconfig.NormalizeDomain(teamCreateNamespace)
	if name == "" {
		return usageError("--name is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}

	// Load namespace controller key for auth
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return fmt.Errorf("load controller key for %s: %w (run `aw id create --domain %s` first)", domain, err, domain)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(teamCreateRegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(teamCreateRegistryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registration, err := ensureLocalTeamRegistered(
		ctx,
		registry,
		strings.TrimSpace(registry.DefaultRegistryURL),
		domain,
		name,
		strings.TrimSpace(teamCreateDisplayName),
		controllerKey,
	)
	if err != nil {
		return err
	}
	printOutput(teamCreateOutput{
		Status:      "created",
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		RegistryURL: strings.TrimSpace(registry.DefaultRegistryURL),
	}, formatTeamCreate)
	return nil
}

func runTeamInvite(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamInviteTeam))
	domain := awconfig.NormalizeDomain(teamInviteNamespace)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}

	// Read registry URL from the identity in the working directory
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	var registryURL string
	identity, _, identErr := awconfig.LoadWorktreeIdentityFromDir(workingDir)
	if identErr == nil && identity != nil {
		registryURL = strings.TrimSpace(identity.RegistryURL)
	}

	inviteID, token, err := createTeamInviteToken(domain, team, registryURL, teamInviteEphemeral)
	if err != nil {
		return err
	}

	printOutput(teamInviteOutput{
		Status:   "created",
		InviteID: inviteID,
		Token:    token,
	}, formatTeamInvite)
	return nil
}

func runTeamAcceptInvite(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	accepted, err := acceptTeamInviteWithDetails(workingDir, args[0], teamAcceptAlias)
	if err != nil {
		return err
	}
	if err := upsertAcceptedTeamMembershipState(workingDir, accepted.Output, accepted.Certificate, true); err != nil {
		return err
	}
	printOutput(*accepted.Output, formatTeamAcceptInvite)
	return nil
}

func runTeamAdd(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembership(workingDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		teamState = &awconfig.TeamState{}
	}

	accepted, err := acceptTeamInviteWithDetails(workingDir, args[0], teamAddAlias)
	if err != nil {
		return err
	}
	if teamState.Membership(accepted.Output.TeamID) != nil {
		return rollbackAddedTeamCertificate(workingDir, accepted, usageError("team %q is already present in local team memberships", accepted.Output.TeamID))
	}
	if err := upsertAcceptedTeamMembershipState(workingDir, accepted.Output, accepted.Certificate, false); err != nil {
		return rollbackAddedTeamCertificate(workingDir, accepted, err)
	}
	printOutput(teamAddOutput{
		Status:   "added",
		TeamID:   accepted.Output.TeamID,
		Alias:    accepted.Output.Alias,
		CertPath: accepted.Output.CertPath,
	}, formatTeamAdd)
	return nil
}

func runTeamSwitch(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembership(workingDir)
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(args[0])
	if teamState.Membership(teamID) == nil {
		return usageError("team %q is not present in local team memberships; available: %s", teamID, strings.Join(teamState.AvailableTeamIDs(), ", "))
	}
	if strings.EqualFold(strings.TrimSpace(teamState.ActiveTeam), teamID) {
		printOutput(teamSwitchOutput{
			Status:     "already_active",
			ActiveTeam: strings.TrimSpace(teamState.ActiveTeam),
		}, formatTeamSwitch)
		return nil
	}
	teamState.ActiveTeam = teamID
	if err := awconfig.SaveTeamState(workingDir, teamState); err != nil {
		return err
	}
	printOutput(teamSwitchOutput{
		Status:     "switched",
		ActiveTeam: teamState.ActiveTeam,
	}, formatTeamSwitch)
	return nil
}

func runTeamList(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembership(workingDir)
	if err != nil {
		return err
	}

	items := make([]teamListItem, 0, len(teamState.Memberships))
	for _, membership := range teamState.Memberships {
		item := teamListItem{
			TeamID: strings.TrimSpace(membership.TeamID),
			Alias:  strings.TrimSpace(membership.Alias),
			Active: strings.EqualFold(strings.TrimSpace(membership.TeamID), strings.TrimSpace(teamState.ActiveTeam)),
		}
		if cert, err := awconfig.LoadTeamCertificateForTeam(workingDir, membership.TeamID); err == nil && cert != nil {
			item.Lifetime = strings.TrimSpace(cert.Lifetime)
			item.IssuedAt = strings.TrimSpace(cert.IssuedAt)
		}
		items = append(items, item)
	}
	printOutput(teamListOutput{
		ActiveTeam:  strings.TrimSpace(teamState.ActiveTeam),
		Memberships: items,
	}, formatTeamList)
	return nil
}

func runTeamLeave(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembership(workingDir)
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(args[0])
	if teamState.Membership(teamID) == nil {
		return usageError("team %q is not present in local team memberships; available: %s", teamID, strings.Join(teamState.AvailableTeamIDs(), ", "))
	}
	if len(teamState.Memberships) == 1 {
		return usageError("cannot leave the only team; remove the workspace instead")
	}

	teamState.RemoveMembership(teamID)
	if err := awconfig.SaveTeamState(workingDir, teamState); err != nil {
		return err
	}
	certPath := awconfig.TeamCertificatePath(workingDir, teamID)
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	printOutput(teamLeaveOutput{
		Status:     "left",
		TeamID:     teamID,
		ActiveTeam: strings.TrimSpace(teamState.ActiveTeam),
	}, formatTeamLeave)
	return nil
}

func createTeamInviteToken(domain, team, registryURL string, ephemeral bool) (string, string, error) {
	domain = awconfig.NormalizeDomain(domain)
	team = strings.ToLower(strings.TrimSpace(team))
	registryURL = strings.TrimSpace(registryURL)
	if domain == "" {
		return "", "", fmt.Errorf("domain is required")
	}
	if team == "" {
		return "", "", fmt.Errorf("team is required")
	}

	exists, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "", "", usageError("no team key for %s/%s; run `aw id team create` first", domain, team)
	}

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		return "", "", err
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		return "", "", err
	}
	invite := &awconfig.TeamInvite{
		InviteID:    inviteID,
		Domain:      domain,
		TeamName:    team,
		Ephemeral:   ephemeral,
		Secret:      secret,
		RegistryURL: registryURL,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		return "", "", err
	}
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		return "", "", err
	}
	return inviteID, token, nil
}

func acceptTeamInviteWithDetails(workingDir, token, aliasHint string) (*acceptedTeamInvite, error) {
	decoded, err := awconfig.DecodeInviteToken(token)
	if err != nil {
		return nil, err
	}

	invite, err := awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil {
		return nil, fmt.Errorf("invite not found (token may be invalid or expired): %w", err)
	}
	if invite.Secret != decoded.Secret {
		return nil, fmt.Errorf("invalid invite token: secret mismatch")
	}

	teamID := awid.BuildTeamID(invite.Domain, invite.TeamName)

	teamKey, err := awconfig.LoadTeamKey(invite.Domain, invite.TeamName)
	if err != nil {
		return nil, fmt.Errorf("team key for %s not found: %w (accept-invite must run on the machine that created the team)", teamID, err)
	}

	memberDIDKey, err := resolveOrGenerateMemberDIDKey(workingDir, invite.Ephemeral)
	if err != nil {
		return nil, err
	}

	alias := strings.TrimSpace(aliasHint)
	if alias == "" {
		alias = resolveAliasFromIdentity(workingDir)
	}
	if alias == "" {
		return nil, usageError("--alias is required (no identity found to derive alias from)")
	}

	lifetime := awid.LifetimePersistent
	if invite.Ephemeral {
		lifetime = awid.LifetimeEphemeral
	}

	var memberDIDAW, memberAddress string
	if !invite.Ephemeral {
		memberDIDAW, memberAddress = resolveIdentityFieldsForCert(workingDir)
	}

	// Sign certificate
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDIDKey,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         alias,
		Lifetime:      lifetime,
	})
	if err != nil {
		return nil, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, err
	}
	registryURL := strings.TrimSpace(decoded.RegistryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registry.RegisterCertificate(ctx, registryURL, invite.Domain, invite.TeamName, cert, teamKey); err != nil {
		return nil, fmt.Errorf("register certificate at registry: %w", err)
	}

	certPath, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert)
	if err != nil {
		return nil, err
	}

	if err := awconfig.DeleteTeamInvite(invite.InviteID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to delete consumed invite %s: %v\n", invite.InviteID, err)
	}

	return &acceptedTeamInvite{
		Output: &teamAcceptInviteOutput{
			Status:   "accepted",
			TeamID:   teamID,
			Alias:    alias,
			CertPath: certPath,
		},
		Certificate: cert,
		RegistryURL: registryURL,
		Domain:      invite.Domain,
		TeamName:    invite.TeamName,
	}, nil
}

func revokeAcceptedTeamCertificate(accepted *acceptedTeamInvite) error {
	if accepted == nil || accepted.Certificate == nil {
		return nil
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(accepted.RegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid registry url %q: %w", registryURL, err)
		}
	} else {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}

	teamKey, err := awconfig.LoadTeamKey(accepted.Domain, accepted.TeamName)
	if err != nil {
		return fmt.Errorf("load team key for %s/%s: %w", accepted.Domain, accepted.TeamName, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registry.RevokeCertificate(
		ctx,
		registryURL,
		accepted.Domain,
		accepted.TeamName,
		accepted.Certificate.CertificateID,
		teamKey,
	); err != nil {
		return fmt.Errorf("revoke certificate %s: %w", accepted.Certificate.CertificateID, err)
	}
	return nil
}

func runTeamAddMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamAddTeam))
	domain := awconfig.NormalizeDomain(teamAddNamespace)
	member := strings.TrimSpace(teamAddMember)
	memberDID := strings.TrimSpace(teamAddMemberDID)
	memberAlias := strings.TrimSpace(teamAddMemberAlias)
	lifetime := strings.TrimSpace(teamAddMemberLifetime)
	memberDIDAW := strings.TrimSpace(teamAddMemberDIDAW)
	memberAddress := strings.TrimSpace(teamAddMemberAddress)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if member == "" && memberDID == "" {
		return usageError("one of --member or --did is required")
	}
	if member != "" && memberDID != "" {
		return usageError("--member and --did are mutually exclusive")
	}
	if memberDID != "" {
		if memberAlias == "" {
			return usageError("--alias is required when using --did")
		}
		if lifetime != awid.LifetimeEphemeral && lifetime != awid.LifetimePersistent {
			return usageError("invalid --lifetime %q (use %q or %q)", lifetime, awid.LifetimeEphemeral, awid.LifetimePersistent)
		}
	}

	teamID := awid.BuildTeamID(domain, team)

	// Load team key
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return fmt.Errorf("load team key for %s: %w", teamID, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}

	if member != "" {
		// Resolve member's did:key from their address via awid.
		memberDomain, memberName, err := parseAddress(member)
		if err != nil {
			return err
		}

		workingDir, err := os.Getwd()
		if err != nil {
			return err
		}
		lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
		if err != nil {
			return err
		}
		var address *awid.RegistryAddress
		if lookupSigningKey != nil {
			address, _, err = registry.GetNamespaceAddressAtSigned(ctx, strings.TrimSpace(registry.DefaultRegistryURL), memberDomain, memberName, lookupSigningKey)
		} else {
			address, _, err = registry.GetNamespaceAddressAt(ctx, strings.TrimSpace(registry.DefaultRegistryURL), memberDomain, memberName)
		}
		if err != nil {
			return fmt.Errorf("resolve member address %s: %w", member, err)
		}

		memberDID = address.CurrentDIDKey
		memberDIDAW = address.DIDAW
		memberAddress = member
		memberAlias = memberName
		// --lifetime only applies to the direct --did path; address-backed members are always persistent.
		lifetime = awid.LifetimePersistent
	}

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         memberAlias,
		Lifetime:      lifetime,
	})
	if err != nil {
		return err
	}

	// Register at awid
	if err := registry.RegisterCertificate(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, team, cert, teamKey); err != nil {
		return fmt.Errorf("register certificate: %w", err)
	}

	printOutput(teamAddMemberOutput{
		Status:        "added",
		Member:        firstNonEmpty(memberAddress, memberDID),
		TeamID:        teamID,
		MemberAddress: memberAddress,
		CertificateID: cert.CertificateID,
	}, formatTeamAddMember)
	return nil
}

func runTeamRemoveMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamRemoveTeam))
	domain := awconfig.NormalizeDomain(teamRemoveNamespace)
	member := strings.TrimSpace(teamRemoveMember)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if member == "" {
		return usageError("--member is required")
	}

	teamID := awid.BuildTeamID(domain, team)

	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return fmt.Errorf("load team key for %s: %w", teamID, err)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}

	// Resolve registry URL: explicit flag → identity.yaml → default.
	registryURL := strings.TrimSpace(teamRemoveRegistryURL)
	if registryURL == "" {
		if workingDir, wdErr := os.Getwd(); wdErr == nil {
			if identity, _, idErr := awconfig.LoadWorktreeIdentityFromDir(workingDir); idErr == nil && identity != nil {
				registryURL = strings.TrimSpace(identity.RegistryURL)
			}
		}
	}
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, memberName, err := parseAddress(member)
	if err != nil {
		return err
	}
	memberRef, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, memberName)
	if err != nil {
		return fmt.Errorf("resolve team member %s in %s: %w", memberName, teamID, err)
	}

	if err := registry.RevokeCertificate(ctx, registryURL, domain, team, memberRef.CertificateID, teamKey); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}

	printOutput(teamRemoveMemberOutput{
		Status:        "removed",
		TeamID:        teamID,
		MemberAddress: member,
	}, formatTeamRemoveMember)
	return nil
}

func runCertShow(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	cert, _, err := loadCurrentTeamCertificate(workingDir)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	printOutput(certShowOutput{
		TeamID:        cert.Team,
		Alias:         cert.Alias,
		MemberDIDKey:  cert.MemberDIDKey,
		MemberDIDAW:   cert.MemberDIDAW,
		MemberAddress: cert.MemberAddress,
		TeamDIDKey:    cert.TeamDIDKey,
		Lifetime:      cert.Lifetime,
		IssuedAt:      cert.IssuedAt,
		CertificateID: cert.CertificateID,
	}, formatCertShow)
	return nil
}

func loadCurrentTeamCertificate(workingDir string) (*awid.TeamCertificate, string, error) {
	if teamState, err := awconfig.LoadTeamState(workingDir); err == nil && teamState != nil {
		selectedTeamID := strings.TrimSpace(teamFlag)
		selectedMembership := teamState.Membership(selectedTeamID)
		if selectedMembership == nil {
			selectedMembership = teamState.ActiveMembership()
		}
		if selectedMembership == nil {
			return nil, "", fmt.Errorf("teams state is missing selected team membership")
		}
		certPath := filepath.Join(workingDir, ".aw", filepath.FromSlash(strings.TrimSpace(selectedMembership.CertPath)))
		cert, err := awid.LoadTeamCertificate(certPath)
		if err != nil {
			return nil, "", fmt.Errorf("load active team certificate %s: %w", certPath, err)
		}
		return cert, certPath, nil
	}

	stored, err := awconfig.ListTeamCertificates(workingDir)
	if err != nil {
		return nil, "", err
	}
	if len(stored) == 0 {
		return nil, "", fmt.Errorf("no team certificate found under %s", awconfig.TeamCertificatesDir(workingDir))
	}
	if len(stored) > 1 {
		return nil, "", fmt.Errorf("multiple team certificates found under %s; set an active team first", awconfig.TeamCertificatesDir(workingDir))
	}
	return stored[0].Certificate, filepath.Join(workingDir, ".aw", filepath.FromSlash(stored[0].CertPath)), nil
}

func requireTeamStateForMembership(workingDir string) (*awconfig.TeamState, error) {
	teamState, err := awconfig.LoadTeamState(workingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, usageError("current identity is missing .aw/teams.yaml; join a team first")
		}
		return nil, err
	}
	return teamState, nil
}

func rollbackAddedTeamCertificate(workingDir string, accepted *acceptedTeamInvite, cause error) error {
	revokeErr := revokeAcceptedTeamCertificate(accepted)
	if accepted != nil && accepted.Output != nil && strings.TrimSpace(accepted.Output.CertPath) != "" {
		_ = os.Remove(filepath.Join(workingDir, ".aw", filepath.FromSlash(strings.TrimSpace(accepted.Output.CertPath))))
	}
	if revokeErr != nil {
		return fmt.Errorf("%w (rollback revoke failed: %v)", cause, revokeErr)
	}
	return cause
}

func upsertAcceptedTeamMembershipState(workingDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, setActive bool) error {
	if output == nil || cert == nil {
		return fmt.Errorf("accepted team membership is required")
	}
	teamState, err := loadOptionalTeamState(workingDir)
	if err != nil {
		return err
	}
	if teamState == nil {
		teamState = &awconfig.TeamState{}
	}
	teamState.AddMembership(awconfig.TeamMembership{
		TeamID:   strings.TrimSpace(output.TeamID),
		Alias:    strings.TrimSpace(output.Alias),
		CertPath: filepath.ToSlash(strings.TrimSpace(output.CertPath)),
		JoinedAt: strings.TrimSpace(cert.IssuedAt),
	})
	if setActive || strings.TrimSpace(teamState.ActiveTeam) == "" {
		teamState.ActiveTeam = strings.TrimSpace(output.TeamID)
	}
	return awconfig.SaveTeamState(workingDir, teamState)
}

func loadOptionalTeamState(workingDir string) (*awconfig.TeamState, error) {
	teamState, err := awconfig.LoadTeamState(workingDir)
	if err == nil {
		return teamState, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}

func applyTeamStateToWorkspaceCache(workspace *awconfig.WorktreeWorkspace, teamState *awconfig.TeamState) {
	if workspace == nil {
		return
	}
	workspace.ActiveTeam = strings.TrimSpace(teamState.ActiveTeam)
	if teamState == nil || len(teamState.Memberships) == 0 {
		workspace.Memberships = nil
		return
	}
	memberships := make([]awconfig.WorktreeMembership, 0, len(teamState.Memberships))
	for _, membership := range teamState.Memberships {
		cached := awconfig.WorktreeMembership{
			TeamID:   strings.TrimSpace(membership.TeamID),
			Alias:    strings.TrimSpace(membership.Alias),
			CertPath: filepath.ToSlash(strings.TrimSpace(membership.CertPath)),
			JoinedAt: strings.TrimSpace(membership.JoinedAt),
		}
		if existing := workspace.Membership(membership.TeamID); existing != nil {
			cached.RoleName = strings.TrimSpace(existing.RoleName)
			cached.WorkspaceID = strings.TrimSpace(existing.WorkspaceID)
		}
		memberships = append(memberships, cached)
	}
	workspace.Memberships = memberships
}

func upsertWorkspaceMembershipCache(workspace *awconfig.WorktreeWorkspace, membership awconfig.WorktreeMembership) {
	if workspace == nil {
		return
	}
	membership.TeamID = strings.TrimSpace(membership.TeamID)
	membership.Alias = strings.TrimSpace(membership.Alias)
	membership.RoleName = strings.TrimSpace(membership.RoleName)
	membership.WorkspaceID = strings.TrimSpace(membership.WorkspaceID)
	membership.CertPath = filepath.ToSlash(strings.TrimSpace(membership.CertPath))
	membership.JoinedAt = strings.TrimSpace(membership.JoinedAt)
	if membership.TeamID == "" {
		return
	}
	if existing := workspace.Membership(membership.TeamID); existing != nil {
		if strings.TrimSpace(existing.RoleName) != "" && strings.TrimSpace(membership.RoleName) == "" {
			membership.RoleName = strings.TrimSpace(existing.RoleName)
		}
		if strings.TrimSpace(existing.WorkspaceID) != "" && strings.TrimSpace(membership.WorkspaceID) == "" {
			membership.WorkspaceID = strings.TrimSpace(existing.WorkspaceID)
		}
		*existing = membership
		return
	}
	workspace.Memberships = append(workspace.Memberships, membership)
}

// --- helpers ---

func ensureLocalTeamRegistered(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, name, displayName string,
	controllerKey ed25519.PrivateKey,
) (*localTeamRegistration, error) {
	domain = awconfig.NormalizeDomain(domain)
	name = strings.ToLower(strings.TrimSpace(name))
	registryURL = strings.TrimSpace(registryURL)
	if registry == nil {
		return nil, fmt.Errorf("registry client is required")
	}
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("team name is required")
	}
	if controllerKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}

	var teamPriv ed25519.PrivateKey
	exists, err := awconfig.TeamKeyExists(domain, name)
	if err != nil {
		return nil, err
	}
	if exists {
		teamPriv, err = awconfig.LoadTeamKey(domain, name)
		if err != nil {
			return nil, err
		}
	} else {
		_, teamPriv, err = awid.GenerateKeypair()
		if err != nil {
			return nil, err
		}
	}
	teamDIDKey := awid.ComputeDIDKey(teamPriv.Public().(ed25519.PublicKey))

	_, err = registry.CreateTeam(ctx, registryURL, domain, name, strings.TrimSpace(displayName), teamDIDKey, controllerKey)
	if err != nil {
		if code, ok := registryStatusCode(err); !ok || code != http.StatusConflict {
			return nil, fmt.Errorf("create team at registry: %w", err)
		}
		existingTeam, getErr := registry.GetTeam(ctx, registryURL, domain, name)
		if getErr != nil {
			return nil, fmt.Errorf("create team at registry: %w", err)
		}
		if strings.TrimSpace(existingTeam.TeamDIDKey) != teamDIDKey {
			return nil, fmt.Errorf("team %s/%s is already pinned to %s", domain, name, existingTeam.TeamDIDKey)
		}
	}

	if !exists {
		if err := awconfig.SaveTeamKey(domain, name, teamPriv); err != nil {
			return nil, err
		}
	}
	teamKeyPath, err := awconfig.TeamKeyPath(domain, name)
	if err != nil {
		return nil, err
	}
	return &localTeamRegistration{
		TeamID:      awid.BuildTeamID(domain, name),
		TeamDIDKey:  teamDIDKey,
		TeamKey:     teamPriv,
		TeamKeyPath: teamKeyPath,
	}, nil
}

func bootstrapFirstLocalTeamMember(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, teamName, displayName string,
	controllerKey, memberKey ed25519.PrivateKey,
	memberDIDAW, memberAddress, alias string,
) (*localTeamBootstrapResult, error) {
	return bootstrapLocalTeamMemberWithLifetime(
		ctx,
		registry,
		registryURL,
		domain,
		teamName,
		displayName,
		controllerKey,
		memberKey,
		memberDIDAW,
		memberAddress,
		alias,
		awid.LifetimePersistent,
	)
}

func bootstrapLocalTeamMemberWithLifetime(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, teamName, displayName string,
	controllerKey, memberKey ed25519.PrivateKey,
	memberDIDAW, memberAddress, alias, lifetime string,
) (*localTeamBootstrapResult, error) {
	if memberKey == nil {
		return nil, fmt.Errorf("member signing key is required")
	}
	resolvedRegistryURL := strings.TrimSpace(registryURL)
	if resolvedRegistryURL == "" && registry != nil {
		resolvedRegistryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	lifetime = strings.TrimSpace(lifetime)
	if lifetime == "" {
		lifetime = awid.LifetimePersistent
	}
	registration, err := ensureLocalTeamRegistered(ctx, registry, resolvedRegistryURL, domain, teamName, displayName, controllerKey)
	if err != nil {
		return nil, err
	}
	memberDIDKey := awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey))
	cert, err := awid.SignTeamCertificate(registration.TeamKey, awid.TeamCertificateFields{
		Team:          registration.TeamID,
		MemberDIDKey:  memberDIDKey,
		MemberDIDAW:   strings.TrimSpace(memberDIDAW),
		MemberAddress: strings.TrimSpace(memberAddress),
		Alias:         strings.TrimSpace(alias),
		Lifetime:      strings.TrimSpace(lifetime),
	})
	if err != nil {
		return nil, err
	}
	if err := registry.RegisterCertificate(ctx, resolvedRegistryURL, awconfig.NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(teamName)), cert, registration.TeamKey); err != nil {
		return nil, fmt.Errorf("register certificate at registry: %w", err)
	}
	return &localTeamBootstrapResult{
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		Certificate: cert,
	}, nil
}

func resolveOrGenerateMemberDIDKey(workingDir string, ephemeral bool) (string, error) {
	// Try to load existing identity
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err == nil && strings.TrimSpace(identity.DID) != "" {
		return strings.TrimSpace(identity.DID), nil
	}

	// Try to load existing signing key
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err == nil {
		return awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)), nil
	}

	if !ephemeral {
		return "", usageError("no identity found; run `aw id create` first, or use --ephemeral invite")
	}

	// Generate ephemeral keypair
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return "", err
	}
	if err := awid.SaveSigningKey(signingKeyPath, priv); err != nil {
		return "", err
	}
	return awid.ComputeDIDKey(pub), nil
}

// resolveIdentityFieldsForCert reads stable identity fields from .aw/identity.yaml.
// Returns empty strings for ephemeral agents that have no identity.yaml.
func resolveIdentityFieldsForCert(workingDir string) (didAW, address string) {
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		return "", ""
	}
	return strings.TrimSpace(identity.StableID), strings.TrimSpace(identity.Address)
}

func resolveAliasFromIdentity(workingDir string) string {
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil || strings.TrimSpace(identity.Address) == "" {
		return ""
	}
	// Address is domain/name — extract name
	parts := strings.SplitN(identity.Address, "/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func parseAddress(address string) (domain, name string, err error) {
	parts := strings.SplitN(strings.TrimSpace(address), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", usageError("invalid address %q (expected domain/name)", address)
	}
	return awconfig.NormalizeDomain(parts[0]), strings.ToLower(strings.TrimSpace(parts[1])), nil
}
