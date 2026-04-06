package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
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
	TeamAddress string `json:"team_address"`
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
	Status      string `json:"status"`
	TeamAddress string `json:"team_address"`
	Alias       string `json:"alias"`
	CertPath    string `json:"cert_path"`
}

type teamAddMemberOutput struct {
	Status        string `json:"status"`
	TeamAddress   string `json:"team_address"`
	MemberAddress string `json:"member_address"`
	CertificateID string `json:"certificate_id"`
}

type teamRemoveMemberOutput struct {
	Status        string `json:"status"`
	TeamAddress   string `json:"team_address"`
	MemberAddress string `json:"member_address"`
}

type certShowOutput struct {
	TeamAddress   string `json:"team_address"`
	Alias         string `json:"alias"`
	MemberDIDKey  string `json:"member_did_key"`
	TeamDIDKey    string `json:"team_did_key"`
	Lifetime      string `json:"lifetime"`
	IssuedAt      string `json:"issued_at"`
	CertificateID string `json:"certificate_id"`
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

	teamAddTeam      string
	teamAddNamespace string
	teamAddMember    string

	teamRemoveTeam      string
	teamRemoveNamespace string
	teamRemoveMember    string
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

	teamAddMemberCmd.Flags().StringVar(&teamAddTeam, "team", "", "Team name")
	teamAddMemberCmd.Flags().StringVar(&teamAddNamespace, "namespace", "", "Namespace domain")
	teamAddMemberCmd.Flags().StringVar(&teamAddMember, "member", "", "Member address (e.g. acme.com/alice)")
	teamCmd.AddCommand(teamAddMemberCmd)

	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveTeam, "team", "", "Team name")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveNamespace, "namespace", "", "Namespace domain")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveMember, "member", "", "Member address (e.g. acme.com/alice)")
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

	// Reuse existing team key or generate a fresh one
	var teamPriv ed25519.PrivateKey
	exists, err := awconfig.TeamKeyExists(domain, name)
	if err != nil {
		return err
	}
	if exists {
		teamPriv, err = awconfig.LoadTeamKey(domain, name)
		if err != nil {
			return err
		}
	} else {
		_, teamPriv, err = awid.GenerateKeypair()
		if err != nil {
			return err
		}
	}
	teamDIDKey := awid.ComputeDIDKey(teamPriv.Public().(ed25519.PublicKey))

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

	_, err = registry.CreateTeam(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, name, strings.TrimSpace(teamCreateDisplayName), teamDIDKey, controllerKey)
	if err != nil {
		return fmt.Errorf("create team at registry: %w", err)
	}

	// Save the key only after registry confirms success
	if !exists {
		if err := awconfig.SaveTeamKey(domain, name, teamPriv); err != nil {
			return err
		}
	}

	teamKeyPath, _ := awconfig.TeamKeyPath(domain, name)
	printOutput(teamCreateOutput{
		Status:      "created",
		TeamAddress: domain + "/" + name,
		TeamDIDKey:  teamDIDKey,
		TeamKeyPath: teamKeyPath,
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

	// Verify team key exists locally
	exists, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return err
	}
	if !exists {
		return usageError("no team key for %s/%s; run `aw id team create` first", domain, team)
	}

	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		return err
	}

	invite := &awconfig.TeamInvite{
		InviteID:  inviteID,
		Domain:    domain,
		TeamName:  team,
		Ephemeral: teamInviteEphemeral,
		Secret:    secret,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if err := awconfig.SaveTeamInvite(invite); err != nil {
		return err
	}

	token, err := awconfig.EncodeInviteToken(invite)
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
	decoded, err := awconfig.DecodeInviteToken(args[0])
	if err != nil {
		return err
	}

	// Load the stored invite to verify the secret and get ephemeral flag
	invite, err := awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil {
		return fmt.Errorf("invite not found (token may be invalid or expired): %w", err)
	}
	if invite.Secret != decoded.Secret {
		return fmt.Errorf("invalid invite token: secret mismatch")
	}

	teamAddress := invite.Domain + "/" + invite.TeamName

	// Load the team key (requires the team controller to be on this machine)
	teamKey, err := awconfig.LoadTeamKey(invite.Domain, invite.TeamName)
	if err != nil {
		return fmt.Errorf("team key for %s not found: %w (accept-invite must run on the machine that created the team)", teamAddress, err)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	// Resolve the agent's did:key — either from existing identity or generate one
	memberDIDKey, err := resolveOrGenerateMemberDIDKey(workingDir, invite.Ephemeral)
	if err != nil {
		return err
	}

	// Determine alias
	alias := strings.TrimSpace(teamAcceptAlias)
	if alias == "" {
		alias = resolveAliasFromIdentity(workingDir)
	}
	if alias == "" {
		return usageError("--alias is required (no identity found to derive alias from)")
	}

	lifetime := awid.LifetimePersistent
	if invite.Ephemeral {
		lifetime = awid.LifetimeEphemeral
	}

	// Sign certificate
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		TeamAddress:  teamAddress,
		MemberDIDKey: memberDIDKey,
		Alias:        alias,
		Lifetime:     lifetime,
	})
	if err != nil {
		return err
	}

	// Register certificate at awid
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registry.RegisterCertificate(ctx, strings.TrimSpace(registry.DefaultRegistryURL), invite.Domain, invite.TeamName, cert, teamKey); err != nil {
		return fmt.Errorf("register certificate at registry: %w", err)
	}

	// Save certificate to .aw/team-cert.pem
	certPath := filepath.Join(workingDir, ".aw", "team-cert.pem")
	if err := awid.SaveTeamCertificate(certPath, cert); err != nil {
		return err
	}

	// Clean up consumed invite
	if err := awconfig.DeleteTeamInvite(invite.InviteID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to delete consumed invite %s: %v\n", invite.InviteID, err)
	}

	printOutput(teamAcceptInviteOutput{
		Status:      "accepted",
		TeamAddress: teamAddress,
		Alias:       alias,
		CertPath:    certPath,
	}, formatTeamAcceptInvite)
	return nil
}

func runTeamAddMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamAddTeam))
	domain := awconfig.NormalizeDomain(teamAddNamespace)
	member := strings.TrimSpace(teamAddMember)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if member == "" {
		return usageError("--member is required")
	}

	teamAddress := domain + "/" + team

	// Load team key
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return fmt.Errorf("load team key for %s: %w", teamAddress, err)
	}

	// Resolve member's did:key from their address via awid
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	memberDomain, memberName, err := parseAddress(member)
	if err != nil {
		return err
	}

	address, _, err := registry.GetNamespaceAddressAt(ctx, strings.TrimSpace(registry.DefaultRegistryURL), memberDomain, memberName)
	if err != nil {
		return fmt.Errorf("resolve member address %s: %w", member, err)
	}

	// Sign certificate
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		TeamAddress:  teamAddress,
		MemberDIDKey: address.CurrentDIDKey,
		Alias:        memberName,
		Lifetime:     awid.LifetimePersistent,
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
		TeamAddress:   teamAddress,
		MemberAddress: member,
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

	teamAddress := domain + "/" + team

	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return fmt.Errorf("load team key for %s: %w", teamAddress, err)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// List active certificates to find the member's certificate_id
	certs, err := registry.ListCertificates(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, team, true)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	memberDomain, memberName, err := parseAddress(member)
	if err != nil {
		return err
	}

	// Try to resolve the member's did:key for precise matching
	var memberDIDKey string
	address, _, addrErr := registry.GetNamespaceAddressAt(ctx, strings.TrimSpace(registry.DefaultRegistryURL), memberDomain, memberName)
	if addrErr == nil {
		memberDIDKey = address.CurrentDIDKey
	}

	certID, err := findCertificateForMember(certs, memberName, memberDIDKey)
	if err != nil {
		return fmt.Errorf("in team %s: %w", teamAddress, err)
	}

	if err := registry.RevokeCertificate(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, team, certID, teamKey); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}

	printOutput(teamRemoveMemberOutput{
		Status:        "removed",
		TeamAddress:   teamAddress,
		MemberAddress: member,
	}, formatTeamRemoveMember)
	return nil
}

func runCertShow(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	certPath := filepath.Join(workingDir, ".aw", "team-cert.pem")
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return fmt.Errorf("load certificate: %w (no team certificate at %s)", err, certPath)
	}

	printOutput(certShowOutput{
		TeamAddress:   cert.TeamAddress,
		Alias:         cert.Alias,
		MemberDIDKey:  cert.MemberDIDKey,
		TeamDIDKey:    cert.TeamDIDKey,
		Lifetime:      cert.Lifetime,
		IssuedAt:      cert.IssuedAt,
		CertificateID: cert.CertificateID,
	}, formatCertShow)
	return nil
}

// --- helpers ---

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

// findCertificateForMember finds a certificate by DID key (preferred) or alias.
// Returns an error if alias-based matching finds multiple certificates.
func findCertificateForMember(certs []awid.RegistryCertificate, alias, memberDIDKey string) (string, error) {
	// Prefer exact did:key match
	if strings.TrimSpace(memberDIDKey) != "" {
		for _, c := range certs {
			if c.MemberDIDKey == memberDIDKey {
				return c.CertificateID, nil
			}
		}
	}

	// Fall back to alias match with ambiguity detection
	var matches []string
	for _, c := range certs {
		if c.Alias == alias {
			matches = append(matches, c.CertificateID)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no active certificate found for member %s", alias)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("multiple active certificates found for alias %s; resolve the member's address to disambiguate", alias)
	}
}
