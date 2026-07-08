package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	FetchCommand  string `json:"fetch_command,omitempty"`
}

type teamFetchCertOutput struct {
	Status        string `json:"status"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	CertificateID string `json:"certificate_id"`
	CertPath      string `json:"cert_path"`
}

type teamRemoveMemberOutput struct {
	Status        string `json:"status"`
	TeamID        string `json:"team_id"`
	MemberAddress string `json:"member_address,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	AgentID       string `json:"agent_id,omitempty"`
	WorkspaceID   string `json:"workspace_id,omitempty"`
}

type hostedTeamRemoveMemberRequest struct {
	MemberAddress string `json:"member_address,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
}

type hostedTeamRemoveMemberResponse struct {
	Status          string `json:"status"`
	TeamID          string `json:"team_id,omitempty"`
	CanonicalTeamID string `json:"canonical_team_id,omitempty"`
	MemberAddress   string `json:"member_address,omitempty"`
	CertificateID   string `json:"certificate_id,omitempty"`
	AgentID         string `json:"agent_id,omitempty"`
	WorkspaceID     string `json:"workspace_id,omitempty"`
	AuditID         string `json:"audit_id,omitempty"`
}

type teamMemberItem struct {
	CertificateID string `json:"certificate_id"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	MemberAddress string `json:"member_address,omitempty"`
	MemberDIDKey  string `json:"member_did_key"`
	MemberDIDAW   string `json:"member_did_aw,omitempty"`
	IdentityScope string `json:"identity_scope"`
	IssuedAt      string `json:"issued_at"`
	RevokedAt     string `json:"revoked_at,omitempty"`
}

type teamMembersOutput struct {
	TeamID  string           `json:"team_id"`
	Members []teamMemberItem `json:"members"`
}

type teamImportRequestOutput struct {
	Status              string         `json:"status"`
	AWIDTeamID          string         `json:"awid_team_id"`
	DryRun              bool           `json:"dry_run"`
	Timestamp           string         `json:"timestamp"`
	ControllerDID       string         `json:"controller_did"`
	ControllerSignature string         `json:"controller_signature"`
	CanonicalPayload    string         `json:"canonical_payload"`
	RequestBody         map[string]any `json:"request_body"`
}

type teamRegisterNextStep struct {
	Label       string `json:"label,omitempty"`
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	CWD         string `json:"cwd,omitempty"`
}

type teamRegisterOutput struct {
	Status              string                 `json:"status"`
	AWIDTeamID          string                 `json:"awid_team_id"`
	ServiceURL          string                 `json:"service_url"`
	DryRun              bool                   `json:"dry_run"`
	Timestamp           string                 `json:"timestamp"`
	ControllerDID       string                 `json:"controller_did"`
	ControllerSignature string                 `json:"controller_signature,omitempty"`
	CanonicalPayload    string                 `json:"canonical_payload,omitempty"`
	TeamDIDKey          string                 `json:"team_did_key,omitempty"`
	DashboardURL        string                 `json:"dashboard_url,omitempty"`
	NextSteps           []teamRegisterNextStep `json:"next_steps,omitempty"`
}

type teamCleanupCloudOutput struct {
	Status                        string `json:"status"`
	TeamID                        string `json:"team_id"`
	DryRun                        bool   `json:"dry_run"`
	ControllerDID                 string `json:"controller_did"`
	ControllerScope               string `json:"controller_scope"`
	CloudURL                      string `json:"cloud_url"`
	AgentsDeleted                 int    `json:"agents_deleted"`
	WorkspacesDeleted             int    `json:"workspaces_deleted"`
	CloudWorkspaceMetadataDeleted int    `json:"cloud_workspace_metadata_deleted"`
	TeamMembersDeleted            int    `json:"team_members_deleted"`
	BYOTAuthorizationsDeleted     int    `json:"byot_authorizations_deleted"`
	TeamDeleted                   bool   `json:"team_deleted"`
	AuditID                       string `json:"audit_id,omitempty"`
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
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
	Active        bool   `json:"active"`
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
	IdentityScope string `json:"identity_scope"`
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
	AwebURL     string
	Domain      string
	TeamName    string
}

type teamAcceptInviteOptions struct {
	Name      string
	Address   string
	Scope     string
	NoAddress bool
}

type teamMemberEnrollmentResolveOptions struct {
	WorkingDir        string
	TeamDomain        string
	Name              string
	Address           string
	Scope             string
	NoAddress         bool
	RegistryURL       string
	Registry          *awid.RegistryClient
	AllowLocalMint    bool
	AllowDefaultClaim bool
}

type teamMemberEnrollmentPlan struct {
	Name               string
	Scope              string
	Lifetime           string
	MemberDIDKey       string
	MemberDIDAW        string
	MemberAddress      string
	IdentitySigningKey ed25519.PrivateKey
	DefaultClaim       *awid.AtomicAddressClaimParams
}

// --- flags ---

var (
	teamCreateName        string
	teamCreateNamespace   string
	teamCreateDisplayName string
	teamCreateRegistryURL string

	teamInviteTeam         string
	teamInviteNamespace    string
	teamInviteEphemeral    bool
	teamInvitePersistent   bool
	teamInviteLocal        bool
	teamInviteGlobal       bool
	teamInviteMemberLocal  bool
	teamInviteMemberGlobal bool

	teamAcceptAlias     string
	teamAcceptAddress   string
	teamAcceptLocal     bool
	teamAcceptGlobal    bool
	teamAcceptNoAddress bool
	teamAddAlias        string
	teamAddAddress      string

	teamAddTeam           string
	teamAddNamespace      string
	teamAddMember         string
	teamAddMemberDID      string
	teamAddMemberAlias    string
	teamAddMemberLifetime string
	teamAddMemberLocal    bool
	teamAddMemberGlobal   bool
	teamAddMemberDIDAW    string
	teamAddMemberAddress  string

	teamFetchCertTeam      string
	teamFetchCertNamespace string
	teamFetchCertID        string
	teamFetchCertRegistry  string
	teamFetchCertForce     bool

	teamRemoveTeam        string
	teamRemoveNamespace   string
	teamRemoveMember      string
	teamRemoveCertID      string
	teamRemoveRegistryURL string
	teamRemoveAwebURL     string
	teamRemoveAPIKey      string

	teamMembersTeam           string
	teamMembersNamespace      string
	teamMembersTeamID         string
	teamMembersRegistryURL    string
	teamMembersIncludeRevoked bool

	teamImportRequestTeam           string
	teamImportRequestNamespace      string
	teamImportRequestOrganizationID string
	teamImportRequestCloudTeamID    string
	teamImportRequestTimestamp      string
	teamImportRequestApply          bool

	teamRegisterTeam        string
	teamRegisterServiceURL  string
	teamRegisterRegistryURL string
	teamRegisterTimestamp   string
	teamRegisterDryRun      bool

	teamCleanupCloudTeam                string
	teamCleanupCloudNamespace           string
	teamCleanupCloudURL                 string
	teamCleanupCloudTeamKeyPath         string
	teamCleanupCloudNamespaceKeyPath    string
	teamCleanupCloudTimestamp           string
	teamCleanupCloudApply               bool
	teamCleanupCloudNamespaceController bool
)

var teamCleanupCloudTXTResolver awid.TXTResolver

// --- commands ---

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Team membership plus protocol/admin certificate operations",
	Long: "Team membership plus protocol/admin certificate operations.\n\n" +
		"Everyday hosted setup normally uses invite and accept-invite. Controller-backed\n" +
		"commands such as create, add-member, remove-member, register, import-request,\n" +
		"cleanup-cloud, and delete are protocol/admin primitives for BYOT, controller\n" +
		"holders, service projection, or diagnostics.",
}

var teamCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Protocol/admin: create a customer-controlled AWID team",
	RunE:  runTeamCreate,
}

var teamInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Generate an invite token for a team",
	Long: "Generate an invite token for a team.\n\n" +
		"Defaults to the active local team when --team and --namespace are omitted.\n" +
		"Invites create local workspace members unless --member-global is set. Hosted teams use cloud\n" +
		"invite authority; local-controller teams use the local team controller key.",
	RunE: runTeamInvite,
}

var teamAcceptInviteCmd = &cobra.Command{
	Use:   "accept-invite <token>",
	Short: "Accept a team invite and receive a membership certificate",
	Long: "Accept a team invite and receive a membership certificate.\n\n" +
		"Scope is explicit: --local is the default, and --global reuses the existing\n" +
		"self-custodial global identity in this workspace. --address never selects\n" +
		"global scope; pass --global when presenting an existing owned address.\n\n" +
		"Hosted aw_inv_ tokens are redeemed through the cloud. Local hosted accepts\n" +
		"create a fresh local signing key and refuse to overwrite completed local\n" +
		"state. Global hosted accepts reuse identity.yaml's stored did:aw and signing\n" +
		"key; they do not mint a new did:aw just because this identity joins another\n" +
		"team. Hosted --global accepts may use --address for an owned address or\n" +
		"--no-address for did:aw-only membership.\n" +
		"After accepting, run `aw init` in that directory to connect the\n" +
		"workspace.\n\n" +
		"Local-controller invite tokens are same-machine helpers: they require the\n" +
		"local invite record and local team controller key. Local-controller global\n" +
		"accepts default-claim team-domain/name only when the local namespace\n" +
		"controller key is also present; otherwise use --address for an owned address\n" +
		"or --no-address for did:aw-only membership. For cross-machine BYOT joins, use\n" +
		"`aw id team request`, have the controller run `aw id team add-member`, then\n" +
		"install with `aw id team fetch-cert` on the joining machine.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamAcceptInvite,
}

var teamAddCmd = &cobra.Command{
	Use:        "add <invite-token>",
	Short:      "Deprecated alias for accept-invite with a global identity",
	Deprecated: "use `aw id team accept-invite --global <token>` or `aw team join --global <token>`",
	Args:       cobra.ExactArgs(1),
	RunE:       runTeamAdd,
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
	Short: "Protocol/admin: add a member by signing a team certificate",
	RunE:  runTeamAddMember,
}

var teamFetchCertCmd = &cobra.Command{
	Use:   "fetch-cert",
	Short: "Protocol/admin bridge: fetch and install an approved team certificate",
	RunE:  runTeamFetchCert,
}

var teamRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Protocol/admin: remove a member by revoking a team certificate",
	RunE:  runTeamRemoveMember,
}

var teamMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List a team's members from AWID certificates",
	Long: "List a team's members from AWID certificates.\n\n" +
		"Membership is represented by team certificates, so this identity-level\n" +
		"command lists the certificate roster for the selected team. By default it\n" +
		"shows active certificates; pass --include-revoked to include revoked rows.",
	RunE: runTeamMembers,
}

var teamImportRequestCmd = &cobra.Command{
	Use:   "import-request",
	Short: "Protocol/admin: create a signed BYOT import request for aweb cloud",
	Long: "Create a signed BYOT import request for aweb cloud.\n\n" +
		"This command signs the canonical import payload with your local BYOT team\n" +
		"controller key. It prints the request body expected by\n" +
		"POST /api/v1/teams/byoidt/import. It never uploads or prints namespace or\n" +
		"team controller private keys. The cloud import endpoint accepts the signed\n" +
		"timestamp for five minutes; regenerate the request body after it expires.",
	RunE: runTeamImportRequest,
}

var teamRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Protocol/admin: register or sync a customer-controlled team with a service",
	Long: "Register or sync a customer-controlled AWID team with an aw-compatible service.\n\n" +
		"This command is service-generic: it signs a registration request with the\n" +
		"local team controller key and sends only public/signed team facts to the\n" +
		"service. It never uploads namespace or team controller private keys and does\n" +
		"not initialize any agent workspace. Services may return their own next steps,\n" +
		"such as `aw service init` or `aw claim-human`.",
	RunE: runTeamRegister,
}

var teamCleanupCloudCmd = &cobra.Command{
	Use:   "cleanup-cloud",
	Short: "Protocol/admin: delete aweb Cloud's BYOT projection after registry team deletion",
	Long: "Delete aweb Cloud's imported BYOT team projection using customer-held controller authority.\n\n" +
		"This command does not mutate AWID. In the normal path it signs the cleanup\n" +
		"request with ~/.awid/team-keys/<namespace>/<team>.key so aweb Cloud can\n" +
		"verify that the customer-controlled team controller authorized the projection\n" +
		"delete. If the team controller key has already been retired, use\n" +
		"--namespace-controller to sign with the namespace controller key; aweb Cloud\n" +
		"will verify that key against the _awid.<domain> DNS TXT controller for the\n" +
		"team's domain, with AWID registry lookup as a fallback when DNS is absent.",
	RunE: runTeamCleanupCloud,
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
	teamInviteCmd.Flags().BoolVar(&teamInviteMemberLocal, "member-local", false, "Create local workspace member invite (default)")
	teamInviteCmd.Flags().BoolVar(&teamInviteMemberGlobal, "member-global", false, "Create global member invite")
	teamInviteCmd.Flags().BoolVar(&teamInviteLocal, "local", false, "Deprecated alias for --member-local")
	teamInviteCmd.Flags().BoolVar(&teamInviteGlobal, "global", false, "Deprecated alias for --member-global")
	teamInviteCmd.Flags().BoolVar(&teamInviteEphemeral, "ephemeral", false, "Deprecated alias for --member-local")
	teamInviteCmd.Flags().BoolVar(&teamInvitePersistent, "persistent", false, "Deprecated alias for --member-global")
	markDeprecatedHiddenFlag(teamInviteCmd, "local", "member-local")
	markDeprecatedHiddenFlag(teamInviteCmd, "global", "member-global")
	markDeprecatedHiddenFlag(teamInviteCmd, "ephemeral", "member-local")
	markDeprecatedHiddenFlag(teamInviteCmd, "persistent", "member-global")
	teamCmd.AddCommand(teamInviteCmd)

	teamAcceptInviteCmd.Flags().StringVar(&teamAcceptAlias, "name", "", "Member name for the accepting agent (defaults to identity name)")
	teamAcceptInviteCmd.Flags().StringVar(&teamAcceptAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(teamAcceptInviteCmd, "alias", "name")
	teamAcceptInviteCmd.Flags().BoolVar(&teamAcceptLocal, "local", false, "Join with a local workspace identity (default)")
	teamAcceptInviteCmd.Flags().BoolVar(&teamAcceptGlobal, "global", false, "Join by reusing the existing global identity in this workspace")
	teamAcceptInviteCmd.Flags().BoolVar(&teamAcceptNoAddress, "no-address", false, "For --global, join with did:aw continuity but no member address")
	teamAcceptInviteCmd.Flags().StringVar(&teamAcceptAddress, "address", "", "Advanced: existing owned address to place in the global member certificate")
	teamCmd.AddCommand(teamAcceptInviteCmd)

	teamAddCmd.Flags().StringVar(&teamAddAlias, "name", "", "Member name for the added team membership (defaults to the current identity name)")
	teamAddCmd.Flags().StringVar(&teamAddAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(teamAddCmd, "alias", "name")
	teamAddCmd.Flags().StringVar(&teamAddAddress, "address", "", "Registered address to place in the global member certificate")
	teamAddCmd.Flags().BoolVar(&teamAcceptNoAddress, "no-address", false, "Join with did:aw continuity but no member address")
	teamCmd.AddCommand(teamAddCmd)
	teamCmd.AddCommand(teamSwitchCmd)
	teamCmd.AddCommand(teamListCmd)
	teamCmd.AddCommand(teamLeaveCmd)

	teamAddMemberCmd.Flags().StringVar(&teamAddTeam, "team", "", "Team name")
	teamAddMemberCmd.Flags().StringVar(&teamAddNamespace, "namespace", "", "Namespace domain")
	teamAddMemberCmd.Flags().StringVar(&teamAddMember, "member", "", "Member address (e.g. acme.com/alice)")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberDID, "did", "", "Member did:key for direct certificate issuance")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberAlias, "name", "", "Member name to use with --did")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(teamAddMemberCmd, "alias", "name")
	teamAddMemberCmd.Flags().BoolVar(&teamAddMemberLocal, "local", false, "Issue a local workspace member certificate for --did (default)")
	teamAddMemberCmd.Flags().BoolVar(&teamAddMemberGlobal, "global", false, "Issue a global member certificate for --did")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberLifetime, "lifetime", awid.LifetimeEphemeral, "Deprecated compatibility scope for --did; use --local or --global")
	markDeprecatedHiddenFlag(teamAddMemberCmd, "lifetime", "local/--global")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberDIDAW, "did-aw", "", "Optional stable did:aw when using --did")
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberAddress, "address", "", "Global member address when using --did; must resolve to --did-aw")
	teamCmd.AddCommand(teamAddMemberCmd)

	teamFetchCertCmd.Flags().StringVar(&teamFetchCertTeam, "team", "", "Team name")
	teamFetchCertCmd.Flags().StringVar(&teamFetchCertNamespace, "namespace", "", "Namespace domain")
	teamFetchCertCmd.Flags().StringVar(&teamFetchCertID, "cert-id", "", "Certificate id")
	teamFetchCertCmd.Flags().StringVar(&teamFetchCertRegistry, "registry", "", "Registry origin override")
	teamFetchCertCmd.Flags().BoolVar(&teamFetchCertForce, "force", false, "Overwrite an existing local certificate for the team")
	teamCmd.AddCommand(teamFetchCertCmd)

	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveTeam, "team", "", "Team name")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveNamespace, "namespace", "", "Namespace domain")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveMember, "member", "", "Member address (e.g. acme.com/alice)")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveCertID, "cert-id", "", "Certificate id to revoke (hosted remove accepts --member or --cert-id)")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveRegistryURL, "registry", "", "Registry origin override")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveAwebURL, "aweb-url", "", "Hosted aweb API URL override for cloud-mediated removal")
	teamRemoveMemberCmd.Flags().StringVar(&teamRemoveAPIKey, "api-key", "", "Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)")
	teamCmd.AddCommand(teamRemoveMemberCmd)

	teamMembersCmd.Flags().StringVar(&teamMembersTeamID, "team-id", "", "Canonical team id (<team>:<namespace>); defaults to active team")
	teamMembersCmd.Flags().StringVar(&teamMembersTeam, "team", "", "Team name; defaults to active team name")
	teamMembersCmd.Flags().StringVar(&teamMembersNamespace, "namespace", "", "Namespace domain; defaults to active team namespace")
	teamMembersCmd.Flags().StringVar(&teamMembersRegistryURL, "registry", "", "Registry origin override")
	teamMembersCmd.Flags().BoolVar(&teamMembersIncludeRevoked, "include-revoked", false, "Include revoked membership certificates")
	teamCmd.AddCommand(teamMembersCmd)

	teamImportRequestCmd.Flags().StringVar(&teamImportRequestTeam, "team", "", "Team name")
	teamImportRequestCmd.Flags().StringVar(&teamImportRequestNamespace, "namespace", "", "Namespace domain")
	teamImportRequestCmd.Flags().StringVar(&teamImportRequestOrganizationID, "organization-id", "", "AC organization id for a new imported team")
	teamImportRequestCmd.Flags().StringVar(&teamImportRequestCloudTeamID, "cloud-team-id", "", "Existing AC team id to sync")
	teamImportRequestCmd.Flags().StringVar(&teamImportRequestTimestamp, "timestamp", "", "RFC3339 timestamp to sign (defaults to now; accepted for five minutes by cloud)")
	teamImportRequestCmd.Flags().BoolVar(&teamImportRequestApply, "apply", false, "Create an apply request instead of the default dry-run request")
	teamCmd.AddCommand(teamImportRequestCmd)

	teamRegisterCmd.Flags().StringVar(&teamRegisterTeam, "team", "", "Canonical AWID team id (<team>:<namespace>)")
	teamRegisterCmd.Flags().StringVar(&teamRegisterServiceURL, "service", "", "Service URL to register with")
	teamRegisterCmd.Flags().StringVar(&teamRegisterRegistryURL, "registry", "", "Registry origin override")
	teamRegisterCmd.Flags().StringVar(&teamRegisterTimestamp, "timestamp", "", "RFC3339 timestamp to sign (defaults to now; accepted for five minutes by service)")
	teamRegisterCmd.Flags().BoolVar(&teamRegisterDryRun, "dry-run", false, "Preview registration without mutating the service projection")
	teamCmd.AddCommand(teamRegisterCmd)

	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudTeam, "team", "", "Team name")
	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudNamespace, "namespace", "", "Namespace domain")
	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudURL, "aweb-url", DefaultAwebURL, "aweb Cloud URL")
	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudTeamKeyPath, "team-key", "", "Team controller key path override")
	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudNamespaceKeyPath, "namespace-key", "", "Namespace controller key path override for --namespace-controller")
	teamCleanupCloudCmd.Flags().BoolVar(&teamCleanupCloudNamespaceController, "namespace-controller", false, "Authorize cleanup with the namespace controller key instead of the team controller key")
	teamCleanupCloudCmd.Flags().StringVar(&teamCleanupCloudTimestamp, "timestamp", "", "RFC3339 timestamp to sign (defaults to now; accepted for five minutes by cloud)")
	teamCleanupCloudCmd.Flags().BoolVar(&teamCleanupCloudApply, "apply", false, "Apply the cleanup instead of dry-run")
	teamCmd.AddCommand(teamCleanupCloudCmd)

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
		return fmt.Errorf("load controller key for %s: %w (run `aw id namespace prepare-controller --domain %s` first)", domain, err, domain)
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
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	global := teamInviteMemberGlobal || teamInviteGlobal || teamInvitePersistent
	local := teamInviteMemberLocal || teamInviteLocal || teamInviteEphemeral
	if global && local {
		return usageError("--member-global and --member-local cannot be used together")
	}
	team, domain, registryURL, awebURL, err := resolveTeamInviteTarget(workingDir)
	if err != nil {
		return err
	}

	localInvite := !global
	hasTeamKey, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return err
	}
	var inviteID, token string
	if hasTeamKey {
		inviteID, token, err = createTeamInviteToken(domain, team, registryURL, awebURL, localInvite)
		if err != nil {
			return err
		}
	} else if strings.TrimSpace(awebURL) != "" {
		inviteID, token, err = createHostedTeamInviteToken(workingDir, awid.BuildTeamID(domain, team), localInvite)
		if err != nil {
			return err
		}
	} else {
		inviteID, token, err = createTeamInviteToken(domain, team, registryURL, awebURL, localInvite)
		if err != nil {
			return err
		}
	}

	printOutput(teamInviteOutput{
		Status:   "created",
		InviteID: inviteID,
		Token:    token,
	}, formatTeamInvite)
	return nil
}

func resolveTeamInviteTarget(workingDir string) (team, domain, registryURL, awebURL string, err error) {
	team = strings.ToLower(strings.TrimSpace(teamInviteTeam))
	domain = awconfig.NormalizeDomain(teamInviteNamespace)

	rootDir := strings.TrimSpace(workingDir)
	if team == "" || domain == "" {
		teamState, loadedRoot, loadErr := loadTeamStateForInvite(workingDir)
		if loadErr != nil {
			missing := "--team and --namespace"
			if team != "" {
				missing = "--namespace"
			} else if domain != "" {
				missing = "--team"
			}
			return "", "", "", "", usageError("%s required when no active team can be inferred from this workspace: %v", missing, loadErr)
		}
		rootDir = loadedRoot
		activeDomain, activeTeam, parseErr := awid.ParseTeamID(strings.TrimSpace(teamState.ActiveTeam))
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("invalid active team %q: %w", teamState.ActiveTeam, parseErr)
		}
		if team == "" {
			team = activeTeam
		}
		if domain == "" {
			domain = activeDomain
		}
	}
	if team == "" {
		return "", "", "", "", usageError("--team is required")
	}
	if domain == "" {
		return "", "", "", "", usageError("--namespace is required")
	}
	awebURL = awebURLForTeamInvite(rootDir, awid.BuildTeamID(domain, team))
	registryURL = registryURLForTeamInvite(rootDir, domain, awebURL)
	return team, domain, registryURL, awebURL, nil
}

func loadTeamStateForInvite(workingDir string) (*awconfig.TeamState, string, error) {
	_, teamState, rootDir, err := awconfig.LoadWorkspaceAndTeamState(workingDir)
	if err == nil {
		return teamState, rootDir, nil
	}
	teamState, stateErr := awconfig.LoadTeamState(workingDir)
	if stateErr == nil {
		return teamState, workingDir, nil
	}
	return nil, "", err
}

func registryURLForTeamInvite(workingDir, domain, awebURL string) string {
	if meta, err := awconfig.LoadControllerMeta(domain); err == nil && meta != nil {
		if registryURL := strings.TrimSpace(meta.RegistryURL); registryURL != "" {
			return registryURL
		}
	}
	if identity, _, err := awconfig.LoadWorktreeIdentityFromDir(workingDir); err == nil && identity != nil {
		if registryURL := strings.TrimSpace(identity.RegistryURL); registryURL != "" {
			return registryURL
		}
	}
	if strings.TrimSpace(awebURL) != "" {
		if discovered, err := discoverOnboardingServiceURLs(awebURL); err == nil {
			if registryURL := strings.TrimSpace(discovered.RegistryURL); registryURL != "" {
				return registryURL
			}
		}
	}
	// A hosted aweb.ai team resolves to our registry when nothing else is on
	// record; BYOT and local namespaces fail closed rather than assume it.
	if isAwebHostedNamespace(domain) {
		return awid.DefaultAWIDRegistryURL
	}
	return ""
}

// awebURLForTeamInvite resolves the aweb server hosting teamID so an invite can
// be minted for it. Precedence: the live worktree binding (workspace.yaml,
// written by `aw init`), then the team roster (teams.yaml, which `aw team join`
// populates before `aw init` writes workspace.yaml), then the hosted default
// for aweb.ai namespaces. It must not return "" for a hosted team: an empty
// result makes the invite mint fall through to the local team-key branch, so a
// member entitled to mint via their hosted cert fails with "no team key". BYOT
// and local namespaces have no hosted default and correctly resolve to "" when
// no URL is on record, so they fail closed rather than assume our server.
func awebURLForTeamInvite(workingDir, teamID string) string {
	teamID = strings.TrimSpace(teamID)
	if workspace, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(workingDir); err == nil && workspace != nil {
		if awebURL := strings.TrimSpace(workspace.AwebURL); awebURL != "" {
			if teamID == "" {
				if awconfig.ActiveMembershipFor(workspace, teamState) != nil {
					return awebURL
				}
			} else if workspace.Membership(teamID) != nil {
				return awebURL
			}
		}
	}
	if teamState, err := awconfig.LoadTeamState(workingDir); err == nil && teamState != nil {
		membership := teamState.Membership(teamID)
		if membership == nil && teamID == "" {
			membership = teamState.ActiveMembership()
		}
		if membership != nil {
			if awebURL := strings.TrimSpace(membership.AwebURL); awebURL != "" {
				return awebURL
			}
		}
	}
	if domain, _, err := awid.ParseTeamID(teamID); err == nil && isAwebHostedNamespace(domain) {
		return awebURLOrDefault("")
	}
	return ""
}

func runTeamAcceptInvite(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	acceptScope, err := resolveTeamAcceptInviteScope(cmd)
	if err != nil {
		return err
	}
	accepted, err := acceptAndStoreTeamInvite(workingDir, args[0], teamAcceptInviteOptions{
		Name:      teamAcceptAlias,
		Address:   teamAcceptAddress,
		Scope:     acceptScope,
		NoAddress: teamAcceptNoAddress,
	}, teamInviteStoreOptions{SetActive: true})
	if err != nil {
		return err
	}
	printOutput(*accepted.Output, formatTeamAcceptInvite)
	return nil
}

func resolveTeamAcceptInviteScope(cmd *cobra.Command) (string, error) {
	local := teamAcceptLocal
	global := teamAcceptGlobal
	if local && global {
		return "", usageError("--local and --global cannot be used together")
	}
	if global {
		return awid.IdentityModeGlobal, nil
	}
	return awid.IdentityModeLocal, nil
}

func teamAcceptScopeForAddress(address string) string {
	if strings.TrimSpace(address) != "" {
		return awid.IdentityModeGlobal
	}
	return awid.IdentityModeLocal
}

func teamAcceptScopeFromGlobal(global bool) string {
	if global {
		return awid.IdentityModeGlobal
	}
	return awid.IdentityModeLocal
}

type teamInviteStoreOptions struct {
	SetActive       bool
	RejectDuplicate bool
}

func acceptAndStoreTeamInvite(workingDir, token string, opts teamAcceptInviteOptions, store teamInviteStoreOptions) (*acceptedTeamInvite, error) {
	var teamState *awconfig.TeamState
	if store.RejectDuplicate {
		loaded, err := requireTeamStateForMembership(workingDir)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			loaded = &awconfig.TeamState{}
		}
		teamState = loaded
	}
	accepted, err := acceptTeamInviteWithDetails(workingDir, token, opts)
	if err != nil {
		return nil, err
	}
	if teamState != nil && teamState.Membership(accepted.Output.TeamID) != nil {
		return nil, rollbackAddedTeamCertificate(workingDir, accepted, usageError("team %q is already present in local team memberships", accepted.Output.TeamID))
	}
	// Join deliberately leaves the worktree binding for `aw init`; only the
	// teams.yaml membership and the encryption key are recorded here.
	if err := recordAcceptedTeamMembership(workingDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, accepted.AwebURL, recordMembershipOptions{SetActive: store.SetActive}); err != nil {
		if store.RejectDuplicate {
			return nil, rollbackAddedTeamCertificate(workingDir, accepted, err)
		}
		return nil, err
	}
	return accepted, nil
}

func runTeamAdd(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	teamAddMemberAddress := strings.TrimSpace(teamAddAddress)
	if teamAddMemberAddress == "" && !teamAcceptNoAddress {
		_, teamAddMemberAddress = resolveIdentityFieldsForCert(workingDir)
	}
	accepted, err := acceptAndStoreTeamInvite(workingDir, args[0], teamAcceptInviteOptions{
		Name:      teamAddAlias,
		Address:   teamAddMemberAddress,
		Scope:     awid.IdentityModeGlobal,
		NoAddress: teamAcceptNoAddress,
	}, teamInviteStoreOptions{SetActive: false, RejectDuplicate: true})
	if err != nil {
		return err
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
			item.IdentityScope = awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime))
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

func runTeamMembers(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	domain, team, teamID, registryURL, err := resolveTeamMembersTarget(workingDir)
	if err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	certs, err := registry.ListCertificates(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, team, !teamMembersIncludeRevoked)
	if err != nil {
		return fmt.Errorf("list team members for %s: %w", teamID, err)
	}
	items := make([]teamMemberItem, 0, len(certs))
	for _, cert := range certs {
		items = append(items, teamMemberItem{
			CertificateID: strings.TrimSpace(cert.CertificateID),
			TeamID:        strings.TrimSpace(cert.TeamID),
			Alias:         strings.TrimSpace(cert.Alias),
			MemberAddress: strings.TrimSpace(cert.MemberAddress),
			MemberDIDKey:  strings.TrimSpace(cert.MemberDIDKey),
			MemberDIDAW:   strings.TrimSpace(cert.MemberDIDAW),
			IdentityScope: awid.NormalizeIdentityScope(cert.IdentityScope),
			IssuedAt:      strings.TrimSpace(cert.IssuedAt),
			RevokedAt:     strings.TrimSpace(cert.RevokedAt),
		})
	}
	sort.SliceStable(items, func(i, j int) bool {
		left := strings.ToLower(firstNonEmpty(items[i].Alias, items[i].MemberAddress, items[i].MemberDIDAW, items[i].MemberDIDKey, items[i].CertificateID))
		right := strings.ToLower(firstNonEmpty(items[j].Alias, items[j].MemberAddress, items[j].MemberDIDAW, items[j].MemberDIDKey, items[j].CertificateID))
		return left < right
	})
	printOutput(teamMembersOutput{TeamID: teamID, Members: items}, formatTeamMembers)
	return nil
}

func resolveTeamMembersTarget(workingDir string) (domain, team, teamID, registryURL string, err error) {
	if strings.TrimSpace(teamMembersTeamID) != "" {
		if strings.TrimSpace(teamMembersTeam) != "" || strings.TrimSpace(teamMembersNamespace) != "" {
			return "", "", "", "", usageError("--team-id cannot be combined with --team or --namespace")
		}
		domain, team, err = awid.ParseTeamID(strings.TrimSpace(teamMembersTeamID))
		if err != nil {
			return "", "", "", "", err
		}
		teamID = awid.BuildTeamID(domain, team)
		registryURL = strings.TrimSpace(teamMembersRegistryURL)
		if registryURL == "" {
			if state, stateErr := awconfig.LoadTeamState(workingDir); stateErr == nil && state != nil {
				if membership := state.Membership(teamID); membership != nil {
					registryURL = registryURLForTeamMembersMembership(membership)
				}
			}
		}
		return domain, team, teamID, registryURL, nil
	}
	team = strings.ToLower(strings.TrimSpace(teamMembersTeam))
	domain = awconfig.NormalizeDomain(teamMembersNamespace)
	var state *awconfig.TeamState
	if team == "" || domain == "" || strings.TrimSpace(teamMembersRegistryURL) == "" {
		if loaded, stateErr := awconfig.LoadTeamState(workingDir); stateErr == nil {
			state = loaded
		} else if team == "" || domain == "" {
			return "", "", "", "", usageError("--team-id or both --team and --namespace are required when no active team can be inferred from this workspace: %v", stateErr)
		}
	}
	if team == "" || domain == "" {
		active := ""
		if state != nil {
			active = strings.TrimSpace(state.ActiveTeam)
		}
		activeDomain, activeTeam, parseErr := awid.ParseTeamID(active)
		if parseErr != nil {
			return "", "", "", "", fmt.Errorf("invalid active team %q: %w", active, parseErr)
		}
		if team == "" {
			team = activeTeam
		}
		if domain == "" {
			domain = activeDomain
		}
	}
	if team == "" {
		return "", "", "", "", usageError("--team is required")
	}
	if domain == "" {
		return "", "", "", "", usageError("--namespace is required")
	}
	teamID = awid.BuildTeamID(domain, team)
	registryURL = strings.TrimSpace(teamMembersRegistryURL)
	if registryURL == "" && state != nil {
		if membership := state.Membership(teamID); membership != nil {
			registryURL = registryURLForTeamMembersMembership(membership)
		}
	}
	return domain, team, teamID, registryURL, nil
}

func registryURLForTeamMembersMembership(membership *awconfig.TeamMembership) string {
	if membership == nil {
		return ""
	}
	if registryURL := strings.TrimSpace(membership.RegistryURL); registryURL != "" {
		return registryURL
	}
	if awebURL := strings.TrimSpace(membership.AwebURL); awebURL != "" {
		if discovered, err := discoverOnboardingServiceURLs(awebURL); err == nil {
			return strings.TrimSpace(discovered.RegistryURL)
		}
	}
	return ""
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

func createTeamInviteToken(domain, team, registryURL, awebURL string, ephemeral bool) (string, string, error) {
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
		AwebURL:     awebURL,
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

func createHostedTeamInviteToken(workingDir, teamID string, ephemeral bool) (string, string, error) {
	if !ephemeral {
		return "", "", usageError("--member-global is not supported for hosted team invites")
	}
	client, _, err := resolveClientSelectionForDirWithTeamOverride(workingDir, teamID)
	if err != nil {
		return "", "", fmt.Errorf(
			"no local team controller key for %s and cloud-hosted invite authority is unavailable: %w",
			teamID,
			err,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := client.CreateSpawnInvite(ctx, &awid.SpawnCreateInviteRequest{
		AccessMode: "open",
		MaxUses:    1,
	})
	if err != nil {
		return "", "", fmt.Errorf("create hosted team invite: %w", err)
	}
	if strings.TrimSpace(created.Token) == "" {
		return "", "", fmt.Errorf("hosted team invite response is missing token")
	}
	return strings.TrimSpace(created.InviteID), strings.TrimSpace(created.Token), nil
}

func acceptTeamInviteWithDetails(workingDir, token string, opts teamAcceptInviteOptions) (*acceptedTeamInvite, error) {
	if awid.IsHostedSpawnInviteToken(token) {
		return acceptHostedTeamInviteWithDetails(workingDir, token, opts)
	}

	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = awid.IdentityModeLocal
	}
	if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
		return nil, usageError("identity scope must be --local or --global")
	}
	if scope == awid.IdentityModeLocal {
		if strings.TrimSpace(opts.Address) != "" {
			return nil, usageError("--address requires --global")
		}
		if opts.NoAddress {
			return nil, usageError("--no-address requires --global")
		}
	}
	if opts.NoAddress && strings.TrimSpace(opts.Address) != "" {
		return nil, usageError("--address and --no-address cannot be used together")
	}
	if err := ensureTeamAcceptScopeAllowed(workingDir, scope); err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("local team controller key for %s not found: %w (cross-machine joins should use `aw id team request`, controller-side `aw id team add-member`, then invitee-side `aw id team fetch-cert`)", teamID, err)
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

	plan, err := resolveTeamMemberEnrollment(ctx, teamMemberEnrollmentResolveOptions{
		WorkingDir:        workingDir,
		TeamDomain:        invite.Domain,
		Name:              opts.Name,
		Address:           opts.Address,
		Scope:             scope,
		NoAddress:         opts.NoAddress,
		RegistryURL:       registryURL,
		Registry:          registry,
		AllowLocalMint:    true,
		AllowDefaultClaim: true,
	})
	if err != nil {
		return nil, err
	}
	if plan.DefaultClaim != nil {
		if _, err := registry.ClaimIdentityAddressAt(ctx, registryURL, *plan.DefaultClaim); err != nil {
			return nil, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err)
		}
		plan.DefaultClaim.DryRun = false
	}

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  plan.MemberDIDKey,
		MemberDIDAW:   plan.MemberDIDAW,
		MemberAddress: plan.MemberAddress,
		Alias:         plan.Name,
		Lifetime:      plan.Lifetime,
	})
	if err != nil {
		return nil, err
	}

	if err := registry.RegisterCertificate(ctx, registryURL, invite.Domain, invite.TeamName, cert, teamKey); err != nil {
		return nil, fmt.Errorf("register certificate at registry: %w", err)
	}
	if plan.DefaultClaim != nil {
		if _, err := registry.ClaimIdentityAddressAt(ctx, registryURL, *plan.DefaultClaim); err != nil {
			accepted := &acceptedTeamInvite{Certificate: cert, RegistryURL: registryURL, Domain: invite.Domain, TeamName: invite.TeamName}
			return nil, rollbackAddedTeamCertificate(workingDir, accepted, idAddressClaimAtomicError(plan.MemberAddress, registryURL, err))
		}
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
			Alias:    plan.Name,
			CertPath: certPath,
		},
		Certificate: cert,
		RegistryURL: registryURL,
		AwebURL:     strings.TrimSpace(decoded.AwebURL),
		Domain:      invite.Domain,
		TeamName:    invite.TeamName,
	}, nil
}

func acceptHostedTeamInviteWithDetails(workingDir, token string, opts teamAcceptInviteOptions) (*acceptedTeamInvite, error) {
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = awid.IdentityModeLocal
	}
	if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
		return nil, usageError("identity scope must be --local or --global")
	}
	if scope == awid.IdentityModeLocal {
		if strings.TrimSpace(opts.Address) != "" {
			return nil, usageError("--address requires --global")
		}
		if opts.NoAddress {
			return nil, usageError("--no-address requires --global")
		}
	}
	if opts.NoAddress && strings.TrimSpace(opts.Address) != "" {
		return nil, usageError("--address and --no-address cannot be used together")
	}
	if err := ensureTeamAcceptScopeAllowed(workingDir, scope); err != nil {
		return nil, err
	}

	alias := strings.TrimSpace(opts.Name)
	memberAddress := strings.TrimSpace(opts.Address)
	addressName := ""
	if memberAddress != "" {
		_, name, err := parseAddress(memberAddress)
		if err != nil {
			return nil, err
		}
		addressName = name
	}
	if alias == "" {
		alias = resolveAliasFromIdentity(workingDir)
	}
	if alias == "" && addressName != "" {
		alias = addressName
	}
	if alias == "" {
		return nil, usageError("--name is required for hosted team invites")
	}
	var err error
	alias, err = normalizeIDCreateName(alias)
	if err != nil {
		return nil, err
	}

	var pub ed25519.PublicKey
	var signingKey ed25519.PrivateKey
	var didKey string
	stableID := ""
	if scope == awid.IdentityModeGlobal {
		identity, globalSigningKey, err := resolveGlobalIdentityForTeamAccept(workingDir)
		if err != nil {
			return nil, err
		}
		signingKey = globalSigningKey
		pub = signingKey.Public().(ed25519.PublicKey)
		didKey = strings.TrimSpace(identity.DID)
		stableID = strings.TrimSpace(identity.StableID)
	} else {
		// Persist the generated signing key to the home BEFORE calling AC, so a retry
		// after AC has committed presents the SAME key and hits AC's idempotent
		// re-mint instead of generating a new key (which AC 409s as a mismatch).
		pub, signingKey, err = hostedAcceptSigningKey(workingDir)
		if err != nil {
			return nil, err
		}
		didKey = awid.ComputeDIDKey(pub)
	}
	awebURL := awebURLOrDefault(resolveInitAwebURLOverride())
	awebURL, err = normalizeAwebBaseURL(awebURL)
	if err != nil {
		return nil, err
	}
	client, err := awid.NewWithIdentity(awebURL, signingKey, didKey)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	registryURL := ""
	var atomicAddressClaim *awid.AtomicAddressClaimIdentityProof
	if scope == awid.IdentityModeGlobal && memberAddress != "" {
		registry, err := newConfiguredRegistryClient(nil, awebURL)
		if err != nil {
			return nil, err
		}
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
		domain, name, err := parseAddress(memberAddress)
		if err != nil {
			return nil, err
		}
		var logProof *awid.DidKeyEvidence
		if awid.ComputeStableID(pub) != stableID {
			resolution, err := registry.ResolveKeyAt(ctx, registryURL, stableID)
			if err != nil {
				return nil, fmt.Errorf("resolve did log head for hosted global identity %s: %w", stableID, err)
			}
			if strings.TrimSpace(resolution.CurrentDIDKey) != didKey {
				return nil, fmt.Errorf("registry current did:key for %s is %s, not %s", stableID, resolution.CurrentDIDKey, didKey)
			}
			logProof = resolution.LogHead
			if logProof == nil {
				return nil, fmt.Errorf("registry did log for hosted global identity %s has no log head", stableID)
			}
		}
		atomicAddressClaim, err = awid.BuildAtomicAddressClaimIdentityProof(awid.AtomicAddressClaimFields{
			Operation:        awid.AtomicAddressClaimOperation,
			Domain:           domain,
			AddressName:      name,
			DIDAW:            stableID,
			CurrentDIDKey:    didKey,
			RegistryURL:      registryURL,
			DryRun:           false,
			IdentityCustody:  string(awid.AddressClaimCustodySelf),
			NamespaceCustody: string(awid.AddressClaimCustodyHostedCustodial),
			DIDLogProof:      logProof,
		}, signingKey)
		if err != nil {
			return nil, fmt.Errorf("build hosted invite atomic address claim proof: %w", err)
		}
	}

	req := &awid.SpawnAcceptInviteRequest{
		Token:         strings.TrimSpace(token),
		DID:           didKey,
		PublicKey:     base64.StdEncoding.EncodeToString(pub),
		Custody:       awid.CustodySelf,
		Lifetime:      awid.LifetimeEphemeral,
		IdentityScope: awid.IdentityModeLocal,
	}
	if scope == awid.IdentityModeGlobal {
		req.Name = alias
		req.StableID = stableID
		req.Lifetime = awid.LifetimePersistent
		req.IdentityScope = awid.IdentityModeGlobal
		req.AtomicAddressClaim = atomicAddressClaim
	} else {
		req.Alias = alias
	}
	resp, err := client.AcceptSpawnInvite(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("accept hosted team invite: %w", err)
	}
	cert, serverURL, err := validateHostedTeamInviteAcceptResponse(resp, didKey, alias, stableID, memberAddress, scope, opts.NoAddress)
	if err != nil {
		return nil, err
	}
	if scope == awid.IdentityModeGlobal {
		if err := persistLocalSigningKeyAndCertificate(workingDir, signingKey, cert); err != nil {
			return nil, err
		}
	} else if err := persistGuidedHostedState(workingDir, registryURL, signingKey, cert, didKey, stableID, memberAddress, false); err != nil {
		return nil, err
	}
	// Accept completed: clear the pending marker so the home is no longer in
	// pending-accept state. (The completed-identity guard already protects it.)
	_ = os.Remove(hostedAcceptPendingMarkerPath(workingDir))

	return &acceptedTeamInvite{
		Output: &teamAcceptInviteOutput{
			Status:   "accepted",
			TeamID:   cert.Team,
			Alias:    strings.TrimSpace(cert.Alias),
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
		},
		Certificate: cert,
		AwebURL:     serverURL,
		Domain:      strings.TrimSpace(resp.Namespace),
		TeamName:    strings.TrimSpace(resp.TeamSlug),
	}, nil
}

// hostedAcceptSigningKey returns the signing key for a hosted accept-invite,
// generating and persisting it before the AC call so a retry reuses the same
// key. A pending key with no completed identity/cert/workspace is reloaded (a
// retry); an already-completed accept is refused rather than overwritten.
func hostedAcceptSigningKey(workingDir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return nil, nil, err
	}
	keyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	markerPath := hostedAcceptPendingMarkerPath(workingDir)
	if _, err := os.Stat(keyPath); err == nil {
		completedPaths := []string{
			filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
			filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()),
		}
		for _, path := range completedPaths {
			if _, err := os.Stat(path); err == nil {
				return nil, nil, usageError("refusing to overwrite existing %s", path)
			} else if !os.IsNotExist(err) {
				return nil, nil, err
			}
		}
		markerErr := statHostedAcceptPendingMarker(markerPath, keyPath)
		if markerErr != nil {
			return nil, nil, markerErr
		}
		certsPath := awconfig.TeamCertificatesDir(workingDir)
		if _, err := os.Stat(certsPath); err == nil {
			// A previous hosted accept can fail after writing the certificate but
			// before writing identity.yaml. The pending marker proves this is the
			// same in-flight hosted accept, so retry with the saved key instead of
			// trapping the user in key+cert+no-identity partial state.
		} else if !os.IsNotExist(err) {
			return nil, nil, err
		}
		signingKey, err := awid.LoadSigningKey(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load pending hosted accept signing key: %w", err)
		}
		pub, ok := signingKey.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("pending hosted accept signing key has invalid public key")
		}
		return pub, signingKey, nil
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if err := ensureConnectTargetClean(workingDir); err != nil {
		return nil, nil, err
	}
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	if err := awid.SaveSigningKey(keyPath, signingKey); err != nil {
		return nil, nil, fmt.Errorf("save pending hosted accept signing key: %w", err)
	}
	if err := os.WriteFile(markerPath, []byte("pending hosted accept\n"), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write pending hosted accept marker: %w", err)
	}
	return pub, signingKey, nil
}

// hostedAcceptPendingMarkerPath is the marker written next to the signing key
// while a hosted accept is pending, so a retry reuses the key while a stray
// leftover key (no marker) is refused.
func hostedAcceptPendingMarkerPath(workingDir string) string {
	return filepath.Join(filepath.Dir(awconfig.WorktreeSigningKeyPath(workingDir)), "pending-hosted-accept")
}

func validateHostedTeamInviteAcceptResponse(resp *awid.SpawnAcceptInviteResponse, didKey, requestedAlias, expectedStableID, expectedAddress, expectedScope string, expectedNoAddress bool) (*awid.TeamCertificate, string, error) {
	if resp == nil {
		return nil, "", fmt.Errorf("missing hosted team invite response")
	}
	serverURL, err := normalizeBootstrapServerURL(strings.TrimSpace(resp.ServerURL))
	if err != nil {
		return nil, "", fmt.Errorf("invalid hosted team invite server_url: %w", err)
	}
	encodedCert := strings.TrimSpace(resp.TeamCert)
	if encodedCert == "" {
		return nil, "", fmt.Errorf("hosted team invite response is missing team_cert")
	}
	cert, err := awid.DecodeTeamCertificateHeader(encodedCert)
	if err != nil {
		return nil, "", fmt.Errorf("decode hosted team invite certificate: %w", err)
	}
	teamPub, err := awid.ExtractPublicKey(strings.TrimSpace(cert.TeamDIDKey))
	if err != nil {
		return nil, "", fmt.Errorf("hosted team invite certificate has invalid team_did_key %q: %w", cert.TeamDIDKey, err)
	}
	if err := awid.VerifyTeamCertificate(cert, teamPub); err != nil {
		return nil, "", fmt.Errorf("hosted team invite certificate signature verification failed: %w", err)
	}
	if strings.TrimSpace(cert.MemberDIDKey) != strings.TrimSpace(didKey) {
		return nil, "", fmt.Errorf("hosted team invite certificate member_did_key %q does not match generated did:key %q", cert.MemberDIDKey, didKey)
	}
	if strings.TrimSpace(cert.Alias) != strings.TrimSpace(requestedAlias) {
		return nil, "", fmt.Errorf("hosted team invite certificate member name %q does not match requested name %q", cert.Alias, requestedAlias)
	}
	expectedScope = strings.TrimSpace(expectedScope)
	if expectedScope == "" {
		expectedScope = awid.IdentityModeLocal
	}
	actualScope := awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime))
	if actualScope != expectedScope {
		return nil, "", fmt.Errorf("hosted team invite certificate identity_scope %q does not match %q", actualScope, expectedScope)
	}
	if expectedScope == awid.IdentityModeLocal && (strings.TrimSpace(cert.MemberDIDAW) != "" || strings.TrimSpace(cert.MemberAddress) != "") {
		return nil, "", fmt.Errorf("hosted local team invite certificate unexpectedly contains global identity fields")
	}
	if expectedScope == awid.IdentityModeGlobal {
		if strings.TrimSpace(resp.StableID) != strings.TrimSpace(expectedStableID) {
			return nil, "", fmt.Errorf("hosted team invite response stable_id %q does not match generated did:aw %q", resp.StableID, expectedStableID)
		}
		if expectedNoAddress && strings.TrimSpace(resp.Address) != "" {
			return nil, "", fmt.Errorf("hosted team invite response address %q was returned for --no-address", resp.Address)
		}
		if strings.TrimSpace(expectedAddress) != "" && strings.TrimSpace(resp.Address) != strings.TrimSpace(expectedAddress) {
			return nil, "", fmt.Errorf("hosted team invite response address %q does not match requested address %q", resp.Address, expectedAddress)
		}
		if strings.TrimSpace(cert.MemberDIDAW) != strings.TrimSpace(expectedStableID) {
			return nil, "", fmt.Errorf("hosted team invite certificate member_did_aw %q does not match generated did:aw %q", cert.MemberDIDAW, expectedStableID)
		}
		if expectedNoAddress && strings.TrimSpace(cert.MemberAddress) != "" {
			return nil, "", fmt.Errorf("hosted team invite certificate member_address %q was returned for --no-address", cert.MemberAddress)
		}
		if strings.TrimSpace(expectedAddress) != "" && strings.TrimSpace(cert.MemberAddress) != strings.TrimSpace(expectedAddress) {
			return nil, "", fmt.Errorf("hosted team invite certificate member_address %q does not match requested address %q", cert.MemberAddress, expectedAddress)
		}
	}
	return cert, serverURL, nil
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

func statHostedAcceptPendingMarker(markerPath, keyPath string) error {
	if _, err := os.Stat(markerPath); err != nil {
		if os.IsNotExist(err) {
			return usageError(
				"refusing to reuse existing %s: not a pending hosted accept (no %s marker); remove it if it is stale. If this directory has .aw/team-certs but no .aw/identity.yaml after a failed hosted global accept, rerun the same accept-invite command only when the marker is present; otherwise back up/remove the partial .aw/signing.key and .aw/team-certs state before retrying",
				keyPath,
				filepath.Base(markerPath),
			)
		}
		return err
	}
	return nil
}

func isAwebHostedNamespace(domain string) bool {
	normalized := awconfig.NormalizeDomain(domain)
	// Hosted team authority is reserved for the exact aweb.ai zone and valid
	// DNS-label subdomains below it. The leading dot in the suffix is the
	// boundary; lookalikes such as evil-aweb.ai or aweb.ai.example.com must not
	// route to hosted cloud signing.
	if normalized == "aweb.ai" {
		return true
	}
	if strings.HasPrefix(normalized, ".") || strings.Contains(normalized, "..") {
		return false
	}
	return strings.HasSuffix(normalized, ".aweb.ai")
}

func teamKeyLoadError(teamID, domain string, err error) error {
	if isAwebHostedNamespace(domain) {
		return fmt.Errorf(
			"local team controller key for %s was not found: %w\n\nThis looks like an aweb.ai hosted namespace. Hosted teams keep the team controller key in cloud, so this raw AWID command cannot sign the add-member operation locally. Use the hosted dashboard Add existing agent action for hosted teams. Use `aw id team add-member` only for BYOIDT/BYOD teams where you hold ~/.awid/team-keys/<namespace>/<team>.key",
			teamID,
			err,
		)
	}
	return fmt.Errorf(
		"local team controller key for %s was not found: %w (this command is for BYOIDT/BYOD teams where you hold ~/.awid/team-keys/<namespace>/<team>.key; hosted aweb.ai teams should use the dashboard Add existing agent action)",
		teamID,
		err,
	)
}

func resolveTeamAddMemberLifetime(cmd *cobra.Command) (string, error) {
	global := teamAddMemberGlobal
	local := teamAddMemberLocal
	if global && local {
		return "", usageError("--global and --local cannot be used together")
	}
	if global {
		return awid.LifetimePersistent, nil
	}
	if local {
		return awid.LifetimeEphemeral, nil
	}
	if cmd != nil && cmd.Flags().Changed("lifetime") {
		switch awid.NormalizeLifetime(teamAddMemberLifetime) {
		case awid.LifetimePersistent:
			return awid.LifetimePersistent, nil
		case awid.LifetimeEphemeral:
			return awid.LifetimeEphemeral, nil
		default:
			return "", usageError("invalid deprecated --lifetime value %q; use --global or --local", teamAddMemberLifetime)
		}
	}
	return awid.LifetimeEphemeral, nil
}

func runTeamAddMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamAddTeam))
	domain := awconfig.NormalizeDomain(teamAddNamespace)
	member := strings.TrimSpace(teamAddMember)
	memberDID := strings.TrimSpace(teamAddMemberDID)
	memberAlias := strings.TrimSpace(teamAddMemberAlias)
	lifetime, err := resolveTeamAddMemberLifetime(cmd)
	if err != nil {
		return err
	}
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
			return usageError("--name is required when using --did")
		}
		if memberAddress != "" {
			if lifetime != awid.LifetimePersistent {
				return usageError("--address requires --global when using --did")
			}
			if memberDIDAW == "" {
				return usageError("--did-aw is required when --address is set")
			}
		}
	}

	teamID := awid.BuildTeamID(domain, team)

	// Load team key
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return teamKeyLoadError(teamID, domain, err)
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
		// Local/global flags only apply to the direct --did path; address-backed members are always global.
		lifetime = awid.LifetimePersistent
	}

	if member == "" && memberDID != "" && memberAddress != "" {
		workingDir, err := os.Getwd()
		if err != nil {
			return err
		}
		lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
		if err != nil {
			return err
		}
		if err := validateMemberAddressForCertificate(ctx, registry, strings.TrimSpace(registry.DefaultRegistryURL), memberAddress, memberDIDAW, memberDID, lookupSigningKey); err != nil {
			return err
		}
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

	fetchCommand := teamFetchCertificateCommand(domain, team, cert.CertificateID, "")
	printOutput(teamAddMemberOutput{
		Status:        "added",
		Member:        firstNonEmpty(memberAddress, memberDID),
		TeamID:        teamID,
		MemberAddress: memberAddress,
		CertificateID: cert.CertificateID,
		FetchCommand:  fetchCommand,
	}, formatTeamAddMember)
	return nil
}

func runTeamFetchCert(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamFetchCertTeam))
	domain := awconfig.NormalizeDomain(teamFetchCertNamespace)
	certificateID := strings.TrimSpace(teamFetchCertID)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if certificateID == "" {
		return usageError("--cert-id is required")
	}
	teamID := awid.BuildTeamID(domain, team)

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	certPathAbs := awconfig.TeamCertificatePath(workingDir, teamID)
	existingCert, existingErr := awconfig.LoadTeamCertificateForTeam(workingDir, teamID)
	if existingErr == nil && existingCert != nil {
		if strings.TrimSpace(existingCert.CertificateID) == certificateID {
			certPath := awconfig.TeamCertificateRelativePath(teamID)
			if err := upsertAcceptedTeamMembershipState(workingDir, &teamAcceptInviteOutput{
				Status:   "already_installed",
				TeamID:   teamID,
				Alias:    strings.TrimSpace(existingCert.Alias),
				CertPath: certPath,
			}, existingCert, "", "", false); err != nil {
				return err
			}
			if err := ensureLocalIdentityEncryptionKeyForDir(workingDir); err != nil {
				return err
			}
			printOutput(teamFetchCertOutput{
				Status:        "already_installed",
				TeamID:        teamID,
				Alias:         strings.TrimSpace(existingCert.Alias),
				CertificateID: strings.TrimSpace(existingCert.CertificateID),
				CertPath:      certPath,
			}, formatTeamFetchCert)
			return nil
		}
		if !teamFetchCertForce {
			return usageError("team certificate already exists at %s with certificate_id %s; use --force to overwrite", certPathAbs, existingCert.CertificateID)
		}
	} else if !os.IsNotExist(existingErr) {
		if !teamFetchCertForce {
			return fmt.Errorf("existing team certificate at %s could not be read: %w (use --force to overwrite)", certPathAbs, existingErr)
		}
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(workingDir))
	if err != nil {
		return fmt.Errorf("load local signing key: %w (run `aw id create` first on this machine)", err)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(teamFetchCertRegistry)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	} else {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cert, err := registry.FetchTeamCertificate(ctx, registryURL, domain, team, certificateID, signingKey)
	if err != nil {
		return fmt.Errorf("fetch certificate: %w", err)
	}
	if strings.TrimSpace(cert.Team) != teamID {
		return fmt.Errorf("fetched certificate team_id %q does not match requested %q", cert.Team, teamID)
	}

	certPath, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert)
	if err != nil {
		return err
	}
	if err := upsertAcceptedTeamMembershipState(workingDir, &teamAcceptInviteOutput{
		Status:   "installed",
		TeamID:   teamID,
		Alias:    strings.TrimSpace(cert.Alias),
		CertPath: certPath,
	}, cert, registryURL, "", false); err != nil {
		return err
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(workingDir); err != nil {
		return err
	}

	printOutput(teamFetchCertOutput{
		Status:        "installed",
		TeamID:        teamID,
		Alias:         strings.TrimSpace(cert.Alias),
		CertificateID: strings.TrimSpace(cert.CertificateID),
		CertPath:      certPath,
	}, formatTeamFetchCert)
	return nil
}

func runTeamRemoveMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamRemoveTeam))
	domain := awconfig.NormalizeDomain(teamRemoveNamespace)
	member := strings.TrimSpace(teamRemoveMember)
	certificateID := strings.TrimSpace(teamRemoveCertID)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if member == "" && certificateID == "" {
		return usageError("--member or --cert-id is required")
	}
	if member != "" && certificateID != "" {
		return usageError("--member and --cert-id are mutually exclusive")
	}

	teamID := awid.BuildTeamID(domain, team)
	if isAwebHostedNamespace(domain) {
		return runHostedTeamRemoveMember(teamID, member, certificateID)
	}

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

	if certificateID == "" {
		_, memberName, err := parseAddress(member)
		if err != nil {
			return err
		}
		memberRef, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, memberName)
		if err != nil {
			return fmt.Errorf("resolve team member %s in %s: %w", memberName, teamID, err)
		}
		certificateID = strings.TrimSpace(memberRef.CertificateID)
	}

	if err := registry.RevokeCertificate(ctx, registryURL, domain, team, certificateID, teamKey); err != nil {
		return fmt.Errorf("revoke certificate: %w", err)
	}

	printOutput(teamRemoveMemberOutput{
		Status:        "removed",
		TeamID:        teamID,
		MemberAddress: member,
		CertificateID: certificateID,
	}, formatTeamRemoveMember)
	return nil
}

func runHostedTeamRemoveMember(teamID, memberAddress, certificateID string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	awebURL, apiKey, err := resolveHostedTeamRemoveAuth(workingDir, teamID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := postHostedTeamRemoveMember(ctx, awebURL, apiKey, teamID, hostedTeamRemoveMemberRequest{
		MemberAddress: strings.TrimSpace(memberAddress),
		CertificateID: strings.TrimSpace(certificateID),
	})
	if err != nil {
		return err
	}
	status := strings.TrimSpace(resp.Status)
	if status == "" {
		status = "removed"
	}
	printOutput(teamRemoveMemberOutput{
		Status:        status,
		TeamID:        firstNonEmpty(resp.CanonicalTeamID, resp.TeamID, teamID),
		MemberAddress: firstNonEmpty(resp.MemberAddress, memberAddress),
		CertificateID: firstNonEmpty(resp.CertificateID, certificateID),
		AgentID:       strings.TrimSpace(resp.AgentID),
		WorkspaceID:   strings.TrimSpace(resp.WorkspaceID),
	}, formatTeamRemoveMember)
	return nil
}

func resolveHostedTeamRemoveAuth(workingDir, teamID string) (awebURL, apiKey string, err error) {
	return resolveHostedTeamRemoveAuthWithAwebURL(workingDir, teamID, teamRemoveAwebURL, teamRemoveAPIKey)
}

func resolveHostedTeamRemoveAuthWithAwebURL(workingDir, teamID, explicitAwebURL, explicitAPIKey string) (awebURL, apiKey string, err error) {
	awebURL = strings.TrimSpace(explicitAwebURL)
	apiKey = firstNonEmptyLibraryValue(explicitAPIKey, os.Getenv(initAPIKeyEnvVar))
	workspace, teamState, _, loadErr := awconfig.LoadWorkspaceAndTeamState(workingDir)
	if loadErr == nil && workspace != nil {
		if awebURL == "" {
			awebURL = strings.TrimSpace(workspace.AwebURL)
		}
		if teamState != nil {
			if membership := teamState.Membership(teamID); membership != nil {
				if awebURL == "" {
					awebURL = strings.TrimSpace(membership.AwebURL)
				}
			}
		}
	}
	if strings.TrimSpace(awebURL) == "" {
		if loadErr != nil {
			return "", "", usageError("hosted remove for %s requires --aweb-url or a workspace with aweb_url: %v", teamID, loadErr)
		}
		return "", "", usageError("hosted remove for %s requires --aweb-url or a workspace with aweb_url", teamID)
	}
	if strings.TrimSpace(apiKey) == "" {
		return "", "", usageError("hosted remove for %s requires --api-key or %s with a team-scoped owner/admin API key; workspace-bound API keys cannot remove hosted team members", teamID, initAPIKeyEnvVar)
	}
	return awebURL, strings.TrimSpace(apiKey), nil
}

func postHostedTeamRemoveMember(ctx context.Context, awebURL, apiKey, teamID string, payload hostedTeamRemoveMemberRequest) (*hostedTeamRemoveMemberResponse, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := "/api/v1/teams/" + urlPathSegmentEscape(teamID) + "/agents/remove-member"
	base := strings.TrimRight(strings.TrimSpace(awebURL), "/")
	if strings.HasSuffix(base, "/api") {
		path = strings.TrimPrefix(path, "/api")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var detail struct {
			Detail any `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		if detail.Detail != nil {
			encoded, _ := json.Marshal(detail.Detail)
			return nil, fmt.Errorf("hosted remove-member returned %d: %s", resp.StatusCode, strings.TrimSpace(string(encoded)))
		}
		return nil, fmt.Errorf("hosted remove-member returned %d", resp.StatusCode)
	}
	var out hostedTeamRemoveMemberResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode hosted remove-member response: %w", err)
	}
	if strings.EqualFold(strings.TrimSpace(out.Status), "not_found") {
		out.Status = "already_removed"
	}
	return &out, nil
}

func urlPathSegmentEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(strings.TrimSpace(value)), "+", "%20")
}

func runTeamImportRequest(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamImportRequestTeam))
	domain := awconfig.NormalizeDomain(teamImportRequestNamespace)
	organizationID := strings.TrimSpace(teamImportRequestOrganizationID)
	cloudTeamID := strings.TrimSpace(teamImportRequestCloudTeamID)
	timestamp := strings.TrimSpace(teamImportRequestTimestamp)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if isAwebHostedNamespace(domain) {
		return usageError("namespace %s is hosted by aweb.ai; use the hosted dashboard flow instead of BYOT import-request", domain)
	}
	if organizationID != "" && cloudTeamID != "" {
		return usageError("--organization-id and --cloud-team-id are mutually exclusive")
	}
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	teamID := awid.BuildTeamID(domain, team)
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return teamKeyLoadError(teamID, domain, err)
	}
	output, err := buildTeamImportRequestOutput(
		teamKey,
		teamID,
		organizationID,
		cloudTeamID,
		!teamImportRequestApply,
		timestamp,
	)
	if err != nil {
		return err
	}
	printOutput(output, formatTeamImportRequest)
	return nil
}

func runTeamRegister(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	teamID := strings.TrimSpace(teamRegisterTeam)
	if teamID == "" {
		return usageError("--team is required")
	}
	domain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return fmt.Errorf("invalid --team %q: %w", teamID, err)
	}
	if strings.TrimSpace(teamRegisterServiceURL) == "" {
		return usageError("--service is required")
	}
	timestamp := strings.TrimSpace(teamRegisterTimestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	target, err := resolveTeamRegistrationEndpoint(strings.TrimSpace(teamRegisterServiceURL))
	if err != nil {
		return err
	}

	teamKey, err := awconfig.LoadTeamKey(domain, teamName)
	if err != nil {
		return teamKeyLoadError(teamID, domain, err)
	}
	verificationRegistry := firstNonEmpty(strings.TrimSpace(teamRegisterRegistryURL), target.RegistryURL)
	if err := verifyTeamRegisterLocalKey(ctx, teamKey, domain, teamName, verificationRegistry); err != nil {
		return err
	}
	out, err := executeTeamRegisterWithTarget(ctx, teamKey, teamID, target, teamRegisterDryRun, timestamp)
	if err != nil {
		return err
	}
	printOutput(out, formatTeamRegister)
	return nil
}

func runTeamCleanupCloud(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	team := strings.ToLower(strings.TrimSpace(teamCleanupCloudTeam))
	domain := awconfig.NormalizeDomain(teamCleanupCloudNamespace)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	timestamp := strings.TrimSpace(teamCleanupCloudTimestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if !teamCleanupCloudNamespaceController && strings.TrimSpace(teamCleanupCloudNamespaceKeyPath) != "" {
		return usageError("--namespace-key requires --namespace-controller")
	}
	if teamCleanupCloudNamespaceController && strings.TrimSpace(teamCleanupCloudTeamKeyPath) != "" {
		return usageError("--team-key cannot be combined with --namespace-controller")
	}
	teamID := awid.BuildTeamID(domain, team)
	controllerScope := "team"
	var controllerKey ed25519.PrivateKey
	var err error
	if teamCleanupCloudNamespaceController {
		controllerScope = "namespace"
		controllerKey, err = loadTeamCleanupCloudNamespaceKey(ctx, domain, teamCleanupCloudNamespaceKeyPath)
		if err != nil {
			return fmt.Errorf("load namespace controller key for %s: %w", domain, err)
		}
	} else {
		controllerKey, err = loadTeamCleanupCloudKey(domain, team, teamCleanupCloudTeamKeyPath)
		if err != nil {
			return teamKeyLoadError(teamID, domain, err)
		}
	}
	out, err := executeTeamCleanupCloud(ctx, controllerKey, controllerScope, teamID, !teamCleanupCloudApply, timestamp, teamCleanupCloudURL)
	if err != nil {
		return err
	}
	printOutput(out, formatTeamCleanupCloud)
	return nil
}

func executeTeamRegister(
	ctx context.Context,
	teamKey ed25519.PrivateKey,
	awidTeamID string,
	serviceURL string,
	dryRun bool,
	timestamp string,
) (teamRegisterOutput, error) {
	target, err := resolveTeamRegistrationEndpoint(serviceURL)
	if err != nil {
		return teamRegisterOutput{}, err
	}
	return executeTeamRegisterWithTarget(ctx, teamKey, awidTeamID, target, dryRun, timestamp)
}

type teamRegistrationEndpoint struct {
	ServiceURL  string
	EndpointURL string
	RegistryURL string
}

func executeTeamRegisterWithTarget(
	ctx context.Context,
	teamKey ed25519.PrivateKey,
	awidTeamID string,
	target teamRegistrationEndpoint,
	dryRun bool,
	timestamp string,
) (teamRegisterOutput, error) {
	if strings.TrimSpace(awidTeamID) == "" {
		return teamRegisterOutput{}, usageError("team id is required")
	}
	if strings.TrimSpace(target.ServiceURL) == "" {
		return teamRegisterOutput{}, usageError("service URL is required")
	}
	if strings.TrimSpace(target.EndpointURL) == "" {
		return teamRegisterOutput{}, usageError("service registration endpoint is required")
	}
	if strings.TrimSpace(timestamp) == "" {
		return teamRegisterOutput{}, usageError("timestamp is required")
	}
	teamControllerDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	payload := map[string]any{
		"operation":    "team_service_register",
		"awid_team_id": strings.TrimSpace(awidTeamID),
		"service_url":  strings.TrimSpace(target.ServiceURL),
		"dry_run":      dryRun,
		"timestamp":    strings.TrimSpace(timestamp),
	}
	canonical, err := awid.CanonicalJSONValue(payload)
	if err != nil {
		return teamRegisterOutput{}, err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte(canonical)))
	body := map[string]any{
		"awid_team_id":         strings.TrimSpace(awidTeamID),
		"service_url":          strings.TrimSpace(target.ServiceURL),
		"dry_run":              dryRun,
		"timestamp":            strings.TrimSpace(timestamp),
		"controller_signature": signature,
	}

	var response struct {
		DryRun       bool                   `json:"dry_run"`
		Status       string                 `json:"status"`
		AWIDTeamID   string                 `json:"awid_team_id"`
		TeamDIDKey   string                 `json:"team_did_key"`
		DashboardURL string                 `json:"dashboard_url"`
		NextSteps    []teamRegisterNextStep `json:"next_steps"`
	}
	if err := postTeamRegister(ctx, strings.TrimSpace(target.EndpointURL), body, &response); err != nil {
		return teamRegisterOutput{}, err
	}
	status := strings.TrimSpace(response.Status)
	if status == "" {
		if response.DryRun {
			status = "dry-run"
		} else {
			status = "registered"
		}
	}
	return teamRegisterOutput{
		Status:              status,
		AWIDTeamID:          firstNonEmpty(strings.TrimSpace(response.AWIDTeamID), strings.TrimSpace(awidTeamID)),
		ServiceURL:          strings.TrimSpace(target.ServiceURL),
		DryRun:              response.DryRun,
		Timestamp:           strings.TrimSpace(timestamp),
		ControllerDID:       teamControllerDID,
		ControllerSignature: signature,
		CanonicalPayload:    canonical,
		TeamDIDKey:          strings.TrimSpace(response.TeamDIDKey),
		DashboardURL:        strings.TrimSpace(response.DashboardURL),
		NextSteps:           response.NextSteps,
	}, nil
}

func resolveTeamRegistrationEndpoint(serviceURL string) (teamRegistrationEndpoint, error) {
	urls, discoverErr := discoverOnboardingServiceURLs(serviceURL)
	if discoverErr == nil {
		normalizedServiceURL := strings.TrimSpace(urls.OnboardingURL)
		if normalizedServiceURL == "" {
			normalizedServiceURL = strings.TrimSpace(urls.AwebURL)
		}
		if strings.TrimSpace(urls.TeamRegistrationURL) != "" {
			if normalizedServiceURL == "" {
				var err error
				normalizedServiceURL, err = cleanBaseURL(serviceURL)
				if err != nil {
					return teamRegistrationEndpoint{}, err
				}
			}
			return teamRegistrationEndpoint{
				ServiceURL:  normalizedServiceURL,
				EndpointURL: strings.TrimSpace(urls.TeamRegistrationURL),
				RegistryURL: strings.TrimSpace(urls.RegistryURL),
			}, nil
		}
	}
	normalizedServiceURL, err := cleanBaseURL(serviceURL)
	if err != nil {
		return teamRegistrationEndpoint{}, err
	}
	if discoverErr == nil {
		urls, err = normalizeOnboardingServiceURLs(urls)
		if err != nil {
			return teamRegistrationEndpoint{}, err
		}
		normalizedServiceURL = firstNonEmpty(strings.TrimSpace(urls.OnboardingURL), strings.TrimSpace(urls.AwebURL), normalizedServiceURL)
	}
	base := strings.TrimRight(normalizedServiceURL, "/")
	path := "/api/v1/teams/service-register"
	if strings.HasSuffix(base, "/api") {
		path = strings.TrimPrefix(path, "/api")
	}
	return teamRegistrationEndpoint{
		ServiceURL:  normalizedServiceURL,
		EndpointURL: base + path,
		RegistryURL: strings.TrimSpace(urls.RegistryURL),
	}, nil
}

func postTeamRegister(ctx context.Context, endpoint string, body map[string]any, out any) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := newTeamCloudHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var detail struct {
			Detail any `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		if detail.Detail != nil {
			encoded, _ := json.Marshal(detail.Detail)
			return fmt.Errorf("service register: http %d: %s", resp.StatusCode, strings.TrimSpace(string(encoded)))
		}
		return fmt.Errorf("service register: http %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

func newTeamCloudHTTPClient() *http.Client {
	return &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}
}

func verifyTeamRegisterLocalKey(ctx context.Context, teamKey ed25519.PrivateKey, domain, teamName, registryURL string) error {
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	}
	team, err := registry.GetTeam(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, teamName)
	if err != nil {
		return fmt.Errorf("load AWID team %s: %w", awid.BuildTeamID(domain, teamName), err)
	}
	localDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	registryDID := strings.TrimSpace(team.TeamDIDKey)
	if registryDID == "" {
		return fmt.Errorf("AWID team %s is missing team_did_key", awid.BuildTeamID(domain, teamName))
	}
	if registryDID != localDID {
		return fmt.Errorf("local team controller key does not match AWID team controller for %s (local=%s, awid=%s)", awid.BuildTeamID(domain, teamName), localDID, registryDID)
	}
	return nil
}

func buildTeamImportRequestOutput(
	teamKey ed25519.PrivateKey,
	awidTeamID string,
	organizationID string,
	cloudTeamID string,
	dryRun bool,
	timestamp string,
) (teamImportRequestOutput, error) {
	payload := map[string]any{
		"operation":       "byoidt_import",
		"awid_team_id":    strings.TrimSpace(awidTeamID),
		"organization_id": strings.TrimSpace(organizationID),
		"team_id":         strings.TrimSpace(cloudTeamID),
		"dry_run":         dryRun,
		"timestamp":       strings.TrimSpace(timestamp),
	}
	canonical, err := awid.CanonicalJSONValue(payload)
	if err != nil {
		return teamImportRequestOutput{}, err
	}
	controllerDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte(canonical)))
	body := map[string]any{
		"awid_team_id":         strings.TrimSpace(awidTeamID),
		"organization_id":      nullableString(strings.TrimSpace(organizationID)),
		"team_id":              nullableString(strings.TrimSpace(cloudTeamID)),
		"dry_run":              dryRun,
		"timestamp":            strings.TrimSpace(timestamp),
		"controller_signature": signature,
	}
	return teamImportRequestOutput{
		Status:              "signed",
		AWIDTeamID:          strings.TrimSpace(awidTeamID),
		DryRun:              dryRun,
		Timestamp:           strings.TrimSpace(timestamp),
		ControllerDID:       controllerDID,
		ControllerSignature: signature,
		CanonicalPayload:    canonical,
		RequestBody:         body,
	}, nil
}

func loadTeamCleanupCloudKey(domain, team, path string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(path) != "" {
		return awid.LoadSigningKey(strings.TrimSpace(path))
	}
	return awconfig.LoadTeamKey(domain, team)
}

func loadTeamCleanupCloudNamespaceKey(ctx context.Context, domain, path string) (ed25519.PrivateKey, error) {
	var key ed25519.PrivateKey
	var err error
	if strings.TrimSpace(path) != "" {
		key, err = awid.LoadSigningKey(strings.TrimSpace(path))
	} else {
		key, err = awconfig.LoadControllerKey(domain)
	}
	if err != nil {
		return nil, err
	}
	controllerDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	authority, err := awid.VerifyExactDomainAuthority(ctx, teamCleanupCloudTXTResolver, domain)
	if err != nil {
		return nil, fmt.Errorf("verify DNS authority for %s: %w", domain, err)
	}
	if strings.TrimSpace(authority.ControllerDID) != controllerDID {
		return nil, fmt.Errorf("local namespace controller key for %s does not match DNS controller (local=%s, dns=%s)", domain, controllerDID, strings.TrimSpace(authority.ControllerDID))
	}
	return key, nil
}

func executeTeamCleanupCloud(
	ctx context.Context,
	controllerKey ed25519.PrivateKey,
	controllerScope string,
	awidTeamID string,
	dryRun bool,
	timestamp string,
	awebURL string,
) (teamCleanupCloudOutput, error) {
	if strings.TrimSpace(awidTeamID) == "" {
		return teamCleanupCloudOutput{}, usageError("team id is required")
	}
	if strings.TrimSpace(timestamp) == "" {
		return teamCleanupCloudOutput{}, usageError("timestamp is required")
	}
	awebURL = awebURLOrDefault(awebURL)
	controllerScope = strings.ToLower(strings.TrimSpace(controllerScope))
	if controllerScope == "" {
		controllerScope = "team"
	}
	if controllerScope != "team" && controllerScope != "namespace" {
		return teamCleanupCloudOutput{}, usageError("controller scope must be team or namespace")
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	signPayload := map[string]any{
		"operation":    "byoidt_projection_delete",
		"awid_team_id": strings.TrimSpace(awidTeamID),
		"dry_run":      dryRun,
		"timestamp":    strings.TrimSpace(timestamp),
	}
	if controllerScope != "team" {
		signPayload["controller_scope"] = controllerScope
	}
	canonical, err := awid.CanonicalJSONValue(signPayload)
	if err != nil {
		return teamCleanupCloudOutput{}, err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(controllerKey, []byte(canonical)))
	body := map[string]any{
		"awid_team_id":         strings.TrimSpace(awidTeamID),
		"dry_run":              dryRun,
		"timestamp":            strings.TrimSpace(timestamp),
		"controller_signature": signature,
	}
	if controllerScope != "team" {
		body["controller_scope"] = controllerScope
	}
	var response struct {
		DryRun                        bool   `json:"dry_run"`
		CanonicalTeamID               string `json:"canonical_team_id"`
		TeamID                        string `json:"team_id"`
		AgentsDeleted                 int    `json:"agents_deleted"`
		WorkspacesDeleted             int    `json:"workspaces_deleted"`
		CloudWorkspaceMetadataDeleted int    `json:"cloud_workspace_metadata_deleted"`
		TeamMembersDeleted            int    `json:"team_members_deleted"`
		BYOTAuthorizationsDeleted     int    `json:"byot_authorizations_deleted"`
		TeamDeleted                   bool   `json:"team_deleted"`
		AuditID                       string `json:"audit_id"`
	}
	if err := postTeamCleanupCloud(ctx, awebURL, body, &response); err != nil {
		return teamCleanupCloudOutput{}, err
	}
	status := "dry-run"
	if !response.DryRun {
		status = "deleted"
	}
	return teamCleanupCloudOutput{
		Status:                        status,
		TeamID:                        response.CanonicalTeamID,
		DryRun:                        response.DryRun,
		ControllerDID:                 controllerDID,
		ControllerScope:               controllerScope,
		CloudURL:                      strings.TrimRight(awebURL, "/"),
		AgentsDeleted:                 response.AgentsDeleted,
		WorkspacesDeleted:             response.WorkspacesDeleted,
		CloudWorkspaceMetadataDeleted: response.CloudWorkspaceMetadataDeleted,
		TeamMembersDeleted:            response.TeamMembersDeleted,
		BYOTAuthorizationsDeleted:     response.BYOTAuthorizationsDeleted,
		TeamDeleted:                   response.TeamDeleted,
		AuditID:                       response.AuditID,
	}, nil
}

func postTeamCleanupCloud(ctx context.Context, awebURL string, body map[string]any, out any) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}
	path := "/api/v1/teams/byoidt/projection-delete"
	base := strings.TrimRight(strings.TrimSpace(awebURL), "/")
	if strings.HasSuffix(base, "/api") {
		path = strings.TrimPrefix(path, "/api")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := newTeamCloudHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var detail struct {
			Detail any `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&detail)
		if detail.Detail != nil {
			encoded, _ := json.Marshal(detail.Detail)
			return fmt.Errorf("aweb: http %d: %s", resp.StatusCode, strings.TrimSpace(string(encoded)))
		}
		return fmt.Errorf("aweb: http %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return err
		}
	}
	return nil
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
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
		IdentityScope: awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime)),
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

// recordMembershipOptions controls the two steps that legitimately differ across
// accept/enroll paths. WriteWorkspaceBinding is the intended join-vs-provision
// boundary: agent-provisioning paths write the worktree binding immediately so the
// agent is ready to run, while `aw team join`/`aw team accept-invite` leave it unset
// and defer it to `aw init`.
type recordMembershipOptions struct {
	SetActive             bool
	WriteWorkspaceBinding bool
}

// recordAcceptedTeamMembership finalizes an accepted team membership: the steps
// every accept/enroll path shares once the certificate is in hand. It records the
// teams.yaml membership, optionally writes the worktree binding, and ensures the
// local identity encryption key so the member can do E2E messaging. How the
// certificate was obtained (local mint / hosted accept / cross-machine fetch) stays
// with each caller; only these shared steps live here.
func recordAcceptedTeamMembership(workingDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, registryURL, awebURL string, opts recordMembershipOptions) error {
	if err := upsertAcceptedTeamMembershipState(workingDir, output, cert, registryURL, awebURL, opts.SetActive); err != nil {
		return err
	}
	if opts.WriteWorkspaceBinding {
		if err := ensureAcceptedTeamWorkspaceBinding(workingDir, output, cert, awebURL); err != nil {
			return err
		}
	}
	return ensureLocalIdentityEncryptionKeyForDir(workingDir)
}

func upsertAcceptedTeamMembershipState(workingDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, registryURL, awebURL string, setActive bool) error {
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
	joinedAt := strings.TrimSpace(cert.IssuedAt)
	if existing := teamState.Membership(strings.TrimSpace(output.TeamID)); existing != nil {
		if strings.TrimSpace(registryURL) == "" {
			registryURL = strings.TrimSpace(existing.RegistryURL)
		}
		if strings.TrimSpace(awebURL) == "" {
			awebURL = strings.TrimSpace(existing.AwebURL)
		}
		// JoinedAt is the original join time; a re-accept or certificate
		// rotation must not overwrite it with the newer cert.IssuedAt.
		if strings.TrimSpace(existing.JoinedAt) != "" {
			joinedAt = strings.TrimSpace(existing.JoinedAt)
		}
	}
	teamState.AddMembership(awconfig.TeamMembership{
		TeamID:      strings.TrimSpace(output.TeamID),
		Alias:       strings.TrimSpace(output.Alias),
		CertPath:    filepath.ToSlash(strings.TrimSpace(output.CertPath)),
		JoinedAt:    joinedAt,
		RegistryURL: strings.TrimSpace(registryURL),
		AwebURL:     strings.TrimSpace(awebURL),
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
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	if err := ensureStandaloneNamespace(ctx, registry, &idCreatePlan{
		Domain:        domain,
		RegistryURL:   registryURL,
		ControllerDID: controllerDID,
	}, controllerKey); err != nil {
		return nil, fmt.Errorf("ensure namespace at registry: %w", err)
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

func resolveTeamMemberEnrollment(ctx context.Context, opts teamMemberEnrollmentResolveOptions) (teamMemberEnrollmentPlan, error) {
	scope := strings.TrimSpace(opts.Scope)
	if scope == "" {
		scope = awid.IdentityModeLocal
	}
	if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
		return teamMemberEnrollmentPlan{}, usageError("identity scope must be --local or --global")
	}
	alias := strings.TrimSpace(opts.Name)
	if alias == "" {
		alias = resolveAliasFromIdentity(opts.WorkingDir)
	}
	if alias == "" {
		return teamMemberEnrollmentPlan{}, usageError("--name is required (no identity found to derive name from)")
	}
	var err error
	alias, err = normalizeIDCreateName(alias)
	if err != nil {
		return teamMemberEnrollmentPlan{}, err
	}
	plan := teamMemberEnrollmentPlan{Name: alias, Scope: scope, Lifetime: awid.LifetimeEphemeral}
	if scope == awid.IdentityModeLocal {
		if strings.TrimSpace(opts.Address) != "" {
			return teamMemberEnrollmentPlan{}, usageError("--address requires --global")
		}
		if opts.NoAddress {
			return teamMemberEnrollmentPlan{}, usageError("--no-address requires --global")
		}
		teamState, err := loadOptionalTeamState(opts.WorkingDir)
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		if teamState != nil && len(teamState.Memberships) > 0 {
			return teamMemberEnrollmentPlan{}, usageError("local identities can only enroll in one team; use --first-agent-global/--global to reuse a global identity across teams, or use a fresh workspace for local")
		}
		if identity, err := awconfig.ResolveIdentity(opts.WorkingDir); err == nil && strings.TrimSpace(identity.IdentityScope) == awid.IdentityModeGlobal {
			return teamMemberEnrollmentPlan{}, usageError("this workspace already has a global identity; use --global/--first-agent-global to reuse it, or use a fresh workspace for local")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return teamMemberEnrollmentPlan{}, err
		}
		memberDIDKey, err := resolveOrGenerateMemberDIDKey(opts.WorkingDir, opts.AllowLocalMint)
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		plan.MemberDIDKey = memberDIDKey
		return plan, nil
	}

	plan.Lifetime = awid.LifetimePersistent
	identity, signingKey, err := resolveGlobalIdentityForTeamAccept(opts.WorkingDir)
	if err != nil {
		return teamMemberEnrollmentPlan{}, err
	}
	plan.IdentitySigningKey = signingKey
	plan.MemberDIDKey = strings.TrimSpace(identity.DID)
	plan.MemberDIDAW = strings.TrimSpace(identity.StableID)
	plan.MemberAddress = strings.TrimSpace(opts.Address)
	if opts.NoAddress && plan.MemberAddress != "" {
		return teamMemberEnrollmentPlan{}, usageError("--address and --no-address cannot be used together")
	}
	if plan.MemberAddress != "" {
		lookupSigningKey, err := loadOptionalWorktreeSigningKey(opts.WorkingDir)
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		if err := validateMemberAddressForCertificate(ctx, opts.Registry, opts.RegistryURL, plan.MemberAddress, plan.MemberDIDAW, plan.MemberDIDKey, lookupSigningKey); err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
	} else if !opts.NoAddress {
		if !opts.AllowDefaultClaim {
			return teamMemberEnrollmentPlan{}, usageError("cannot default-claim %s/%s: no namespace authority for %s; use --address with an address this identity already owns, or --no-address", awconfig.NormalizeDomain(opts.TeamDomain), alias, awconfig.NormalizeDomain(opts.TeamDomain))
		}
		controllerKey, ok, err := loadOptionalNamespaceControllerKey(opts.TeamDomain)
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		if !ok {
			return teamMemberEnrollmentPlan{}, usageError("cannot default-claim %s/%s: no namespace authority for %s; use --address with an address this identity already owns, or --no-address", awconfig.NormalizeDomain(opts.TeamDomain), alias, awconfig.NormalizeDomain(opts.TeamDomain))
		}
		plan.MemberAddress = awconfig.NormalizeDomain(opts.TeamDomain) + "/" + alias
		claim := awid.AtomicAddressClaimParams{
			Domain:                        awconfig.NormalizeDomain(opts.TeamDomain),
			AddressName:                   alias,
			DIDAW:                         plan.MemberDIDAW,
			CurrentDIDKey:                 plan.MemberDIDKey,
			IdentitySigningKey:            signingKey,
			NamespaceControllerSigningKey: controllerKey,
			DryRun:                        true,
			IdentityCustody:               string(awid.AddressClaimCustodySelf),
			NamespaceCustody:              string(awid.AddressClaimCustodySelf),
		}
		plan.DefaultClaim = &claim
	}
	if strings.TrimSpace(plan.MemberDIDAW) == "" {
		return teamMemberEnrollmentPlan{}, usageError("--global/--first-agent-global requires an existing did:aw; run `aw id create` first")
	}
	return plan, nil
}

func ensureTeamAcceptScopeAllowed(workingDir, scope string) error {
	teamState, err := loadOptionalTeamState(workingDir)
	if err != nil {
		return err
	}
	if scope == awid.IdentityModeLocal && teamState != nil && len(teamState.Memberships) > 0 {
		return usageError("local identities can only join one team; use --global to reuse a global identity across teams, or accept this local invite in a fresh workspace")
	}
	identity, err := awconfig.ResolveIdentity(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if scope == awid.IdentityModeLocal && strings.TrimSpace(identity.IdentityScope) == awid.IdentityModeGlobal {
		return usageError("this workspace already has a global identity; use --global to reuse it, or accept --local in a fresh workspace")
	}
	return nil
}

func resolveGlobalIdentityForTeamAccept(workingDir string) (*awconfig.ResolvedIdentity, ed25519.PrivateKey, error) {
	identity, err := awconfig.ResolveIdentity(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, usageError("--global/--first-agent-global requires an existing global identity; run `aw id create` first")
		}
		return nil, nil, err
	}
	if strings.TrimSpace(identity.IdentityScope) != awid.IdentityModeGlobal || strings.TrimSpace(identity.StableID) == "" {
		return nil, nil, usageError("--global/--first-agent-global requires an existing global identity; run `aw id create` first")
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return nil, nil, usageError("--global/--first-agent-global requires a self-custodial global identity")
	}
	signingKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load global identity signing key: %w", err)
	}
	currentDID := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if currentDID != strings.TrimSpace(identity.DID) {
		return nil, nil, usageError("current signing key did:key %s does not match identity.yaml did %s", currentDID, identity.DID)
	}
	return identity, signingKey, nil
}

func loadOptionalNamespaceControllerKey(domain string) (ed25519.PrivateKey, bool, error) {
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}
	key, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, false, fmt.Errorf("load namespace controller key for %s: %w", awconfig.NormalizeDomain(domain), err)
	}
	return key, true, nil
}

func validateMemberAddressForCertificate(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, memberAddress, memberDIDAW, memberDIDKey string,
	signingKey ed25519.PrivateKey,
) error {
	memberAddress = strings.TrimSpace(memberAddress)
	if memberAddress == "" {
		return nil
	}
	memberDIDAW = strings.TrimSpace(memberDIDAW)
	memberDIDKey = strings.TrimSpace(memberDIDKey)
	if memberDIDAW == "" {
		return usageError("member address %q requires member_did_aw", memberAddress)
	}
	if memberDIDKey == "" {
		return usageError("member address %q requires member_did_key", memberAddress)
	}
	if registry == nil {
		return fmt.Errorf("registry client is required")
	}
	registryURL = strings.TrimSpace(registryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	domain, name, err := parseAddress(memberAddress)
	if err != nil {
		return err
	}
	var address *awid.RegistryAddress
	if signingKey != nil {
		address, _, err = registry.GetNamespaceAddressAtSigned(ctx, registryURL, domain, name, signingKey)
	} else {
		address, _, err = registry.GetNamespaceAddressAt(ctx, registryURL, domain, name)
	}
	if err != nil {
		return fmt.Errorf("validate member address %s: %w", memberAddress, err)
	}
	resolvedDIDAW := strings.TrimSpace(address.DIDAW)
	if resolvedDIDAW != memberDIDAW {
		return fmt.Errorf("member address %s belongs to %s, not %s", memberAddress, resolvedDIDAW, memberDIDAW)
	}
	resolvedDIDKey := strings.TrimSpace(address.CurrentDIDKey)
	if resolvedDIDKey == "" {
		return fmt.Errorf("member address %s registry record is missing current_did_key", memberAddress)
	}
	if resolvedDIDKey != memberDIDKey {
		return fmt.Errorf("member address %s resolves to did:key %s, not %s", memberAddress, resolvedDIDKey, memberDIDKey)
	}
	return nil
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
		return "", usageError("no identity found; run `aw id create` first, or use --local invite")
	}

	// Generate local keypair
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return "", err
	}
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return "", err
	}
	if err := awid.SaveSigningKey(signingKeyPath, priv); err != nil {
		return "", err
	}
	return awid.ComputeDIDKey(pub), nil
}

// resolveIdentityFieldsForCert reads stable identity fields from .aw/identity.yaml.
// Returns empty strings for local agents that have no identity.yaml.
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

func teamFetchCertificateCommand(domain, team, certificateID, registryURL string) string {
	parts := []string{
		"aw", "id", "team", "fetch-cert",
		"--namespace", awconfig.NormalizeDomain(domain),
		"--team", strings.ToLower(strings.TrimSpace(team)),
		"--cert-id", strings.TrimSpace(certificateID),
	}
	if strings.TrimSpace(registryURL) != "" {
		parts = append(parts, "--registry", strings.TrimSpace(registryURL))
	}
	return strings.Join(parts, " ")
}
