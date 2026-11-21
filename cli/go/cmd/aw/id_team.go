package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/awebai/aw/signaturewire"
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
	ForHuman      *string `json:"for_human"`
	Status        string  `json:"status"`
	InviteID      string  `json:"invite_id"`
	Token         string  `json:"token"`
	ExpiresAt     string  `json:"expires_at,omitempty"`
	PorcelainJoin bool    `json:"-"`
}

type teamAcceptInviteOutput struct {
	TeamKey        *awid.TeamKeyEvidence `json:"team_key,omitempty"`
	IDRegistration string                `json:"id_registration,omitempty"`
	Responsibility *awid.IDChainResult   `json:"responsibility,omitempty"`
	HarnessSetup   *joinHarnessResult    `json:"harness_setup,omitempty"`
	Status         string                `json:"status"`
	TeamID         string                `json:"team_id"`
	Alias          string                `json:"alias"`
	CertPath       string                `json:"cert_path"`
	Connected      *bool                 `json:"connected,omitempty"`
	AwebURL        string                `json:"aweb_url,omitempty"`
	ConnectCommand string                `json:"connect_command,omitempty"`
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
	TeamID      string           `json:"team_id"`
	Members     []teamMemberItem `json:"members"`
	Source      string           `json:"source,omitempty"`
	Limitations string           `json:"limitations,omitempty"`
}

const grantRosterLimitations = "agents only (people are not included); no certificate IDs or issued/revoked metadata"

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
	RegistryURL   string `json:"registry_url"`
	AwebURL       string `json:"aweb_url"`
	CertificateID string `json:"certificate_id"`
	WorkspaceID   string `json:"workspace_id"`
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
	// The key check's origin is retained for immediate rollback only.
	observedRegistryURL string
	AwebURL             string
	Domain              string
	TeamName            string
}

type teamAcceptInviteOptions struct {
	ParentFromSource bool
	ParentHome       string
	Registry         *awid.RegistryClient
	TXTResolver      awid.TXTResolver
	IdentityHome     string
	Name             string
	Address          string
	Scope            string
	NoAddress        bool
	AwebURL          string
	RegistryURL      string
}

type teamMemberEnrollmentResolveOptions struct {
	WorkingDir        string
	IdentityHome      string
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
	teamCreateHosted      bool
	teamCreateRequestID   string
	teamCreateShowToken   bool

	teamInviteTeam                  string
	teamInviteNamespace             string
	teamInviteLocal                 bool
	teamInviteGlobal                bool
	teamInviteMemberLocal           bool
	teamInviteMemberGlobal          bool
	teamInviteDeprecatedLocalScope  bool
	teamInviteDeprecatedGlobalScope bool

	teamAcceptAlias     string
	teamAcceptAddress   string
	teamAcceptLocal     bool
	teamAcceptGlobal    bool
	teamAcceptNoAddress bool
	teamAddAlias        string
	teamAddAddress      string

	teamAddTeam                       string
	teamAddNamespace                  string
	teamAddMember                     string
	teamAddMemberDID                  string
	teamAddMemberAlias                string
	teamAddMemberLocal                bool
	teamAddMemberGlobal               bool
	teamAddMemberDeprecatedScopeValue string
	teamAddMemberDIDAW                string
	teamAddMemberAddress              string

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
		"commands such as add-member, remove-member, register, import-request,\n" +
		"cleanup-cloud, and delete are protocol/admin primitives for BYOT, controller\n" +
		"holders, service projection, or diagnostics.",
}

var teamCreateCmd = &cobra.Command{
	Args: cobra.NoArgs,
	Long: `Create a hosted sibling team using the selected team certificate, or create
a customer-controlled AWID team using a local namespace controller key.

Without --namespace, creation is hosted. An explicit --namespace selects BYOT
and requires a local controller key and a native identity home. BYOT refuses
--team. --hosted explicitly selects hosted creation; a namespace supplied in
that mode must match the selected source team. The hosted service URL is printed
to stderr before the request.
Hosted authorization is decided by the service; no human login is performed.

Hosted creation generates a request UUID. Replay with the same --request-id and
parameters after an uncertain result; there are no automatic retries. A replay
returns the same team and replaces its unused invite. JSON includes the secret
invite token; text hides it unless --show-token is set. The caller is not joined.
Accept into <fresh-directory>/.aw, then run aw init from that directory with
AWEB_IDENTITY_HOME unset.`,
	Use:   "create",
	Short: "Create a hosted sibling team or a customer-controlled AWID team",
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
	Annotations: map[string]string{identityCreationTargetAnnotation: "true"},
	Use:         "accept-invite [token]",
	Short:       "Accept a team invite and receive a membership certificate",
	Long: "Accept a team invite and receive a membership certificate.\n\n" +
		"Pass the token positionally, or read it with --token-file or --token-stdin\n" +
		"(only one). The file or stdin is read to EOF, up to 65536 bytes, and must\n" +
		"contain one token line; surrounding whitespace is trimmed. Close the pipe\n" +
		"after writing the token.\n\n" +
		"Scope is explicit: --local is the default, and --global reuses the existing\n" +
		"self-custodial global identity in this workspace. --address never selects\n" +
		"global scope; pass --global when presenting an existing owned address.\n\n" +
		"Hosted aw_inv_ tokens are redeemed through the cloud. Local hosted accepts\n" +
		"create a fresh local signing key and refuse to overwrite completed local\n" +
		"state. Global hosted accepts reuse identity.yaml's stored did:aw and signing\n" +
		"key; they do not mint a new did:aw just because this identity joins another\n" +
		"team. Hosted --global accepts may use --address for an owned address or\n" +
		"--no-address for did:aw-only membership. External --identity-home hosted\n" +
		"local accepts connect that root to the issuing service when the invite names\n" +
		"one; if connection fails, rerun the printed `aw --identity-home <root>\n" +
		"workspace connect --service <url>` recovery command without reusing the\n" +
		"invite. Other membership-only accepts can be connected later with `aw init`\n" +
		"or `aw workspace connect`.\n\n" +
		"Local-controller invite tokens are same-machine helpers: they require the\n" +
		"local invite record and local team controller key. Local-controller global\n" +
		"accepts default-claim team-domain/name only when the local namespace\n" +
		"controller key is also present; otherwise use --address for an owned address\n" +
		"or --no-address for did:aw-only membership. For cross-machine BYOT joins, use\n" +
		"`aw id team request`, have the controller run `aw id team add-member`, then\n" +
		"install with `aw id team fetch-cert` on the joining machine.",
	Args: func(cmd *cobra.Command, args []string) error {
		if teamJoinTokenFromFlags(cmd) {
			if len(args) != 0 {
				return usageError("give the invite token as an argument or through --token-file or --token-stdin, not both")
			}
			return nil
		}
		return cobra.ExactArgs(1)(cmd, args)
	},
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
	Annotations: map[string]string{identityKeyOnlyTargetAnnotation: "true"},
	Use:         "fetch-cert",
	Short:       "Protocol/admin bridge: fetch and install an approved team certificate",
	RunE:        runTeamFetchCert,
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
		"shows active certificates; pass --include-revoked to include revoked rows.\n\n" +
		"Grant homes read their bound team's service roster: agents only (people are not included),\n" +
		"without certificate IDs or issued/revoked metadata. --include-revoked and\n" +
		"--registry are not supported in grant homes.",
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
	bindTeamSelector(teamCreateCmd)
	teamCreateCmd.Annotations = map[string]string{hostHumanOrgAnnotation: "true"}
	teamCreateCmd.Flags().String("org", "", "Hosted organization slug or ID (requires aw auth login)")
	teamCreateCmd.Flags().StringVar(&teamCreateName, "name", "", "Team name")
	teamCreateCmd.Flags().StringVar(&teamCreateNamespace, "namespace", "", "Namespace domain")
	teamCreateCmd.Flags().StringVar(&teamCreateDisplayName, "display-name", "", "Team display name")
	teamCreateCmd.Flags().StringVar(&teamCreateRegistryURL, "registry", "", "Registry origin override")
	teamCreateCmd.Flags().BoolVar(&teamCreateHosted, "hosted", false, "Create a hosted sibling using the selected team certificate")
	teamCreateCmd.Flags().StringVar(&teamCreateRequestID, "request-id", "", "Hosted create UUID (reuse the same UUID and parameters to replay)")
	teamCreateCmd.Flags().BoolVar(&teamCreateShowToken, "show-token", false, "Print the hosted invite token in text output (JSON includes it)")
	teamCmd.AddCommand(teamCreateCmd)

	teamInviteCmd.Flags().String("for-human", "", "Admit agents whose verified nearest human is this did:aw person")
	teamInviteCmd.Flags().StringVar(&teamInviteTeam, "team", "", "Team name")
	teamInviteCmd.Flags().StringVar(&teamInviteNamespace, "namespace", "", "Namespace domain")
	teamInviteCmd.Flags().BoolVar(&teamInviteMemberLocal, "member-local", false, "Create local workspace member invite (default)")
	teamInviteCmd.Flags().BoolVar(&teamInviteMemberGlobal, "member-global", false, "Create global member invite")
	teamInviteCmd.Flags().BoolVar(&teamInviteLocal, "local", false, "Deprecated alias for --member-local")
	teamInviteCmd.Flags().BoolVar(&teamInviteGlobal, "global", false, "Deprecated alias for --member-global")
	teamInviteCmd.Flags().BoolVar(&teamInviteDeprecatedLocalScope, "ephemeral", false, "Deprecated alias for --member-local")
	teamInviteCmd.Flags().BoolVar(&teamInviteDeprecatedGlobalScope, "persistent", false, "Deprecated alias for --member-global")
	markDeprecatedHiddenFlag(teamInviteCmd, "local", "member-local")
	markDeprecatedHiddenFlag(teamInviteCmd, "global", "member-global")
	markDeprecatedHiddenFlag(teamInviteCmd, "ephemeral", "member-local")
	markDeprecatedHiddenFlag(teamInviteCmd, "persistent", "member-global")
	teamCmd.AddCommand(teamInviteCmd)

	teamAcceptInviteCmd.Flags().String("token-file", "", "Read the invite token from this file instead of an argument")
	teamAcceptInviteCmd.Flags().String("parent", "", "Same-machine creator home for a fresh child, independent of the invite")
	teamAcceptInviteCmd.Flags().Bool("token-stdin", false, "Read one invite token from stdin through EOF (max 65536 bytes)")
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
	teamAddMemberCmd.Flags().StringVar(&teamAddMemberDeprecatedScopeValue, "lifetime", "", "Deprecated identity scope selector")
	markDeprecatedHiddenFlag(teamAddMemberCmd, "lifetime", "global or --local")
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
	teamCmd.AddCommand(teamImportRequestCmd, teamClaimHumanRequestCmd)

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

	bindTeamSelector(certShowCmd)
	certCmd.AddCommand(certShowCmd)
	identityCmd.AddCommand(certCmd)
}

// --- implementations ---

func runTeamCreate(cmd *cobra.Command, args []string) error {
	if cmd != nil && cmd.Flags().Changed("org") {
		return runOrgTeamCreate(cmd, teamCreateName)
	}
	name := strings.ToLower(strings.TrimSpace(teamCreateName))
	domain := awconfig.NormalizeDomain(teamCreateNamespace)
	if name == "" {
		return usageError("--name is required")
	}
	if teamCreateHosted || domain == "" {
		return runHostedTeamCreate(cmd, name, domain)
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if home.External() {
		return usageError("BYOT team creation does not support an external identity home; use --hosted for a hosted sibling, or run BYOT from a native home with the namespace controller key")
	}
	if cmd.Flags().Changed("team") {
		return usageError("--team is only supported for hosted creation; pass --hosted or remove --team for BYOT")
	}

	// An explicit namespace selects controller authority unless --hosted was
	// also explicit. A missing controller must not silently switch authority.
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if errors.Is(err, os.ErrNotExist) {
		return withErrorCode(codeControllerKeyMissing, usageError("no local controller key for --namespace %s; pass --hosted for a hosted sibling, or install the namespace controller key for BYOT (aw id namespace prepare-controller --domain %s)", domain, domain))
	}
	if err != nil {
		return withErrorCode(codeControllerKeyMissing, fmt.Errorf("load controller key for %s: %w (run `aw id namespace prepare-controller --domain %s` first)", domain, err, domain))
	}
	if cmd.Flags().Changed("request-id") || teamCreateShowToken {
		return usageError("--request-id and --show-token require hosted creation; use --hosted")
	}

	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	registryURL, err := resolveTeamCommandRegistry(ctx, registry, wd, domain, awid.BuildTeamID(domain, name), teamCreateRegistryURL)
	if err != nil {
		return err
	}

	registration, err := ensureLocalTeamRegistered(
		ctx,
		registry,
		registryURL,
		domain,
		name,
		strings.TrimSpace(teamCreateDisplayName),
		controllerKey,
	)
	if err != nil {
		return err
	}
	return printOutput(teamCreateOutput{
		Status:      "created",
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		RegistryURL: strings.TrimSpace(registry.DefaultRegistryURL),
	}, formatTeamCreate)
}

func runTeamInvite(cmd *cobra.Command, args []string) error {
	if cmd.Flags().Changed("team-id") {
		if err := applyHumanTeamIDToInvite(teamHumanInviteTeamID); err != nil {
			return err
		}
	}
	return runTeamInviteWithOutput(cmd, args, inviteOutputProtocol)
}

func runTeamHumanInvite(cmd *cobra.Command, args []string) error {
	if err := applyHumanTeamIDToInvite(teamHumanInviteTeamID); err != nil {
		return err
	}
	return runTeamInviteWithOutput(cmd, args, inviteOutputJoin)
}

func runTeamInviteWithOutput(cmd *cobra.Command, args []string, style teamInviteOutputStyle) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	global := teamInviteMemberGlobal || teamInviteGlobal || teamInviteDeprecatedGlobalScope
	local := teamInviteMemberLocal || teamInviteLocal || teamInviteDeprecatedLocalScope
	if global && local {
		return usageError("--member-global and --member-local cannot be used together")
	}
	team, domain, registryURL, awebURL, err := resolveTeamInviteTargetAt(workingDir, externalIdentityHomeRoot(home))
	if err != nil {
		return err
	}

	var humanCondition *string
	if cmd.Flags().Changed("for-human") {
		value, err := cmd.Flags().GetString("for-human")
		if err != nil {
			return err
		}
		if err := validateInviteHuman(value); err != nil {
			return err
		}
		humanCondition = &value
	}
	plan, err := planTeamInvite(teamInviteSource{WorkingDir: workingDir, Home: home, Domain: domain, Team: team, RegistryURL: registryURL, AwebURL: awebURL})
	if err != nil {
		return err
	}
	scope := inviteMemberScopeFromFlags(inviteMemberScopeFlags{Global: global})
	request := teamInviteMintRequest{Plan: plan, Scope: scope, ForHuman: humanCondition, ExpiresAfter: teamInviteExpiresAfter}
	if plan.Kind == inviteAuthorityHosted && cmd.Flags().Changed("expires") {
		return usageError("--expires selects a local controller invite lifetime; the hosted service sets its own expiry")
	}
	if teamInvitePreflight {
		preview, err := preflightTeamInviteMint(request)
		if err != nil {
			return err
		}
		return printJSON(preview)
	}
	created, err := mintPlannedTeamInvite(request)
	if err != nil {
		return err
	}

	if !jsonFlag {
		fmt.Fprintln(cmd.ErrOrStderr(), teamInviteTokenWarning(created.ExpiresAt))
	}
	return printOutput(teamInviteOutput{
		ForHuman:      created.ForHuman,
		Status:        "created",
		InviteID:      created.InviteID,
		Token:         created.Token,
		ExpiresAt:     created.ExpiresAt,
		PorcelainJoin: style == inviteOutputJoin,
	}, formatTeamInvite)
}

// teamInviteTokenWarning goes to stderr with the human output, so the
// invite's output is unchanged; --json output carries expires_at and writes
// nothing to stderr.
// It names only the flags that the printed join command has, and the expiry
// when the issuer reports one; an absent expiry never implies unlimited life.
func teamInviteTokenWarning(expiresAt string) string {
	validity := "while the invitation remains valid"
	if expiresAt = strings.TrimSpace(expiresAt); expiresAt != "" {
		validity = "until it is used or until " + expiresAt
	}
	return "Warning: the invite token below is a credential: whoever holds it can join the team " + validity + ". " +
		"Share it privately. On the joining side, save it to a file and run the command below with --token-file, or pipe it to --token-stdin, so it stays out of shell history."
}

var errTeamInviteTargetHasNoActiveTeam = errors.New("team invite target has no active team")

type noActiveTeamInviteTargetError struct {
	message string
	cause   error
}

func (e *noActiveTeamInviteTargetError) Error() string { return e.message }
func (e *noActiveTeamInviteTargetError) ExitCode() int { return 2 }
func (e *noActiveTeamInviteTargetError) Unwrap() error { return e.cause }
func (e *noActiveTeamInviteTargetError) Is(target error) bool {
	return target == errTeamInviteTargetHasNoActiveTeam
}

func resolveTeamInviteTarget(workingDir string) (team, domain, registryURL, awebURL string, err error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return "", "", "", "", err
	}
	return resolveTeamInviteTargetAt(workingDir, externalIdentityHomeRoot(home))
}

func resolveTeamInviteTargetAt(workingDir, identityHome string) (team, domain, registryURL, awebURL string, err error) {
	team = strings.ToLower(strings.TrimSpace(teamInviteTeam))
	domain = awconfig.NormalizeDomain(teamInviteNamespace)
	if awconfig.IsGrantHome(identityHome) {
		grant, loadErr := awconfig.LoadGrantHome(identityHome)
		if loadErr != nil {
			return "", "", "", "", loadErr
		}
		grantDomain, grantTeam, parseErr := awid.ParseTeamID(grant.TeamID)
		if parseErr != nil {
			return "", "", "", "", parseErr
		}
		if (team != "" && team != grantTeam) || (domain != "" && domain != grantDomain) {
			return "", "", "", "", usageError("grant home %s is bound to team %s", identityHome, grant.TeamID)
		}
		return grantTeam, grantDomain, "", grant.AwebURL, nil
	}

	rootDir := strings.TrimSpace(workingDir)
	if team == "" || domain == "" {
		teamState, loadedRoot, loadErr := loadTeamStateForInviteAt(workingDir, identityHome)
		if loadErr != nil {
			missing := "--team and --namespace"
			if team != "" {
				missing = "--namespace"
			} else if domain != "" {
				missing = "--team"
			}
			message := fmt.Sprintf("%s required when no active team can be inferred from this workspace: %v", missing, loadErr)
			if os.IsNotExist(loadErr) {
				return "", "", "", "", &noActiveTeamInviteTargetError{message: message, cause: loadErr}
			}
			return "", "", "", "", usageError("%s", message)
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
	teamID := awid.BuildTeamID(domain, team)
	awebURL = awebURLForTeamInviteAt(rootDir, identityHome, teamID)
	registryURL, err = resolveRegistryAuthority(context.Background(), registryAuthorityRequest{
		Kind: registryTeamRoute, Domain: domain, TeamID: teamID, WorkingDir: rootDir, IdentityHome: identityHome, AwebURL: awebURL,
	})
	return team, domain, registryURL, awebURL, err
}

func loadTeamStateForInvite(workingDir string) (*awconfig.TeamState, string, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return nil, "", err
	}
	return loadTeamStateForInviteAt(workingDir, externalIdentityHomeRoot(home))
}

func loadTeamStateForInviteAt(workingDir, identityHome string) (*awconfig.TeamState, string, error) {
	if strings.TrimSpace(identityHome) != "" {
		state, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
		return state, workingDir, err
	}
	_, teamState, rootDir, workspaceErr := awconfig.LoadWorkspaceAndTeamState(workingDir)
	if workspaceErr == nil {
		return teamState, rootDir, nil
	}
	teamState, stateErr := awconfig.LoadTeamState(workingDir)
	if stateErr == nil {
		return teamState, workingDir, nil
	}
	if !os.IsNotExist(workspaceErr) {
		return nil, "", workspaceErr
	}
	return nil, "", stateErr
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
	return awebURLForTeamInviteAt(workingDir, "", teamID)
}

func awebURLForTeamInviteAt(workingDir, identityHome, teamID string) string {
	teamID = strings.TrimSpace(teamID)
	if workspace, teamState, _, err := loadCurrentWorkspaceAndTeamState(workingDir, identityHome); err == nil {
		if awebURL := workspaceAwebURLForTeam(workspace, teamState, teamID); awebURL != "" {
			return awebURL
		}
	}
	var teamState *awconfig.TeamState
	var err error
	if strings.TrimSpace(identityHome) != "" {
		teamState, err = awconfig.LoadTeamStateFromIdentityHome(identityHome)
	} else {
		teamState, err = awconfig.LoadTeamState(workingDir)
	}
	if err == nil && teamState != nil {
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

const inviteTokenStdinLimit = 64 * 1024

// readInviteToken reads one invite token from source. Its refusals never
// repeat what was read, which may be a credential.
func readInviteToken(reader io.Reader, source string) (string, error) {
	data, err := io.ReadAll(io.LimitReader(reader, inviteTokenStdinLimit+1))
	if err != nil {
		return "", usageError("cannot read invite token from %s", source)
	}
	if len(data) > inviteTokenStdinLimit {
		return "", usageError("invite token %s exceeds 65536 bytes", source)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", usageError("invite token %s is empty", source)
	}
	if strings.ContainsAny(token, "\r\n") {
		return "", usageError("%s must contain one token line", source)
	}
	// All supported wire formats are unpadded base64url or aw_inv_ tokens.
	// Validate before the acceptance path can write identity state. Never expose
	// decoder errors, which can include bytes from the supplied secret.
	for _, c := range token {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", usageError("invalid invite token on %s", source)
		}
	}
	if awid.IsHostedSpawnInviteToken(token) {
		if len(token) <= len("aw_inv_") {
			return "", usageError("invalid invite token on %s", source)
		}
	} else if _, err := awconfig.DecodeInviteToken(token); err != nil {
		return "", usageError("invalid invite token on %s", source)
	}
	if _, _, err := decodeJoinToken(token); err != nil {
		return "", usageError("invalid invite token on %s", source)
	}
	return token, nil
}

// teamJoinTokenArgs returns the invite token argument for aw team join: the
// positional token, or one read from --token-file or --token-stdin.
func teamJoinTokenArgs(cmd *cobra.Command, args []string) ([]string, error) {
	var path string
	var fromStdin bool
	var err error
	// Shared callers may expose just one token source. A missing flag is absent;
	// a present flag with an invalid type remains an error.
	if cmd.Flags().Lookup("token-file") != nil {
		path, err = cmd.Flags().GetString("token-file")
		if err != nil {
			return nil, fmt.Errorf("read --token-file: %w", err)
		}
	}
	if cmd.Flags().Lookup("token-stdin") != nil {
		fromStdin, err = cmd.Flags().GetBool("token-stdin")
		if err != nil {
			return nil, fmt.Errorf("read --token-stdin: %w", err)
		}
	}

	path = strings.TrimSpace(path)
	if path == "" && !fromStdin {
		return args, nil
	}
	if path != "" && fromStdin {
		return nil, usageError("--token-file and --token-stdin cannot be used together")
	}
	if len(args) != 0 {
		return nil, usageError("give the invite token as an argument or through --token-file or --token-stdin, not both")
	}
	if fromStdin {
		token, err := readInviteToken(cmd.InOrStdin(), "stdin")
		if err != nil {
			return nil, err
		}
		return []string{token}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, usageError("cannot open --token-file %s", path)
	}
	token, err := readInviteToken(file, "--token-file")
	closeErr := file.Close()
	if err != nil {
		return nil, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close --token-file: %w; close the file and retry the same invite", closeErr)
	}
	return []string{token}, nil
}

func runTeamAcceptInvite(cmd *cobra.Command, args []string) error {
	// Keep the token in process memory; never construct a child command argv.
	args, err := teamJoinTokenArgs(cmd, args)
	if err != nil {
		return err
	}
	return runTeamInviteAcceptance(cmd, args, teamInviteInstallMembership)
}

func runTeamHumanJoin(cmd *cobra.Command, args []string) error {
	args, err := teamJoinTokenArgs(cmd, args)
	if err != nil {
		return err
	}
	if err := validateTeamJoinArgs(cmd, args); err != nil {
		return err
	}
	if teamHumanJoinSetupOnly {
		return runJoinHarnessSetupOnly(cmd)
	}
	return runTeamInviteAcceptance(cmd, args, teamInviteConnectWorkspace)
}

func runTeamInviteAcceptance(cmd *cobra.Command, args []string, completion teamInviteCompletionMode) error {
	if completion != teamInviteInstallMembership && completion != teamInviteConnectWorkspace {
		return usageError("unknown invite completion; use id team accept-invite to install membership, or team join to connect it")
	}
	connectWorkspace := completion == teamInviteConnectWorkspace
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	acceptScope, err := resolveTeamAcceptInviteScope(cmd)
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if home.Source == awconfig.IdentityHomeEnvVar && acceptScope == awid.IdentityModeLocal {
		return usageError("local identity creation requires an explicit fresh --identity-home target; refusing to change inherited identity home %s", home.Root)
	}
	rawToken, inviteAwebURL, err := decodeJoinToken(args[0])
	if err != nil {
		return err
	}
	if home.External() && acceptScope == awid.IdentityModeLocal && !canResumeNativeInviteIssuance(rawToken, home.Root) && !canResumeTeamInviteIDChild(rawToken, home.Root) && !canResumeHostedInvite(rawToken, home.Root) {
		if err := ensureExternalLocalAcceptHomeAvailable(home.Root); err != nil {
			return err
		}
	}
	accepted, err := acceptAndStoreTeamInvite(teamInviteStoreRequest{
		Acceptance: teamInviteAcceptanceRequest{
			WorkingDir: workingDir,
			Token:      rawToken,
			Options: teamAcceptInviteOptions{
				IdentityHome: externalIdentityHomeRoot(home),
				Name:         teamAcceptAlias,
				Address:      teamAcceptAddress,
				Scope:        acceptScope,
				NoAddress:    teamAcceptNoAddress,
				AwebURL:      inviteAwebURL,
				ParentHome:   inviteParentFlag(cmd),
			},
		},
		Store: teamInviteStoreOptions{IdentityHome: resolvedEncryptionKeyIdentityHome(home), Activation: membershipMakeActive},
	})
	if err != nil {
		return err
	}
	connectionFailure := func(cause error) error {
		if connectWorkspace && teamHumanJoinHarness != "" {
			connected := false
			accepted.Output.Connected = &connected
			accepted.Output.HarnessSetup = &joinHarnessResult{
				Harness: teamHumanJoinHarness, Status: "not_started",
				RetryCommand: joinHarnessRetryCommand(home, teamHumanJoinHarness),
			}
			outputErr := printOutput(*accepted.Output, formatTeamAcceptInvite)
			return errors.Join(fmt.Errorf("%w\nAfter connecting, run `%s` here without reusing the invite", cause, accepted.Output.HarnessSetup.RetryCommand), outputErr)
		}
		return cause
	}
	externalHostedLocalAccept := false
	if home.External() && acceptScope == awid.IdentityModeLocal {
		if domain, _, parseErr := awid.ParseTeamID(accepted.Output.TeamID); parseErr == nil && isAwebHostedNamespace(domain) {
			externalHostedLocalAccept = true
		}
	}
	if connectWorkspace || externalHostedLocalAccept {
		connectURL := acceptedInviteServiceURL(teamInviteConnectionTarget{Token: rawToken, PreferredURL: inviteAwebURL, Accepted: accepted})
		if connectURL == "" {
			connectURL = awebURLForTeamInviteAt(workingDir, externalIdentityHomeRoot(home), accepted.Output.TeamID)
		}
		if connectWorkspace && teamHumanJoinNoConnect {
			connected := false
			accepted.Output.Connected = &connected
			if normalized, normalizeErr := validateInviteAwebURL(connectURL); normalizeErr == nil {
				accepted.Output.AwebURL = normalized
				accepted.Output.ConnectCommand = workspaceConnectCommandForIdentityHome(normalized, externalIdentityHomeRoot(home))
			}
			return printOutput(*accepted.Output, formatTeamAcceptInvite)
		}
		if connectURL == "" {
			return connectionFailure(usageError("team membership was installed, but this legacy invite does not identify its aweb service; run `%s` after choosing the service", workspaceConnectCommandForIdentityHome("<url>", externalIdentityHomeRoot(home))))
		}
		connectURL, err = validateInviteAwebURL(connectURL)
		if err != nil {
			return connectionFailure(fmt.Errorf("team membership was installed, but its aweb service URL is invalid: %w", err))
		}
		accepted.Output.AwebURL = connectURL
		accepted.Output.ConnectCommand = workspaceConnectCommandForIdentityHome(connectURL, externalIdentityHomeRoot(home))
		connectOpts := certificateConnectOptions{IdentityHome: home.Root}
		if home.External() {
			connectOpts.BindingWorkspacePath = home.Root
		}
		connected, connectErr := initCertificateConnectWithOptions(workingDir, connectURL, connectOpts)
		if connectErr != nil {
			return connectionFailure(fmt.Errorf("team membership was installed, but workspace connection failed: %w\nRun `%s` to retry without reusing the invite", connectErr, accepted.Output.ConnectCommand))
		}
		connectionComplete := true
		accepted.Output.Connected = &connectionComplete
		accepted.Output.ConnectCommand = ""
		if strings.TrimSpace(connected.Alias) != "" {
			accepted.Output.Alias = strings.TrimSpace(connected.Alias)
		}
	}
	if connectWorkspace && teamHumanJoinHarness != "" {
		setup, setupErr := setupJoinHarness(workingDir, home, teamHumanJoinHarness)
		accepted.Output.HarnessSetup = setup
		outputErr := printOutput(*accepted.Output, formatTeamAcceptInvite)
		if setupErr != nil {
			return errors.Join(fmt.Errorf("team membership and workspace connection completed, but harness setup failed: %w\nRun `%s` here to retry setup without reusing the invite", setupErr, setup.RetryCommand), outputErr)
		}
		return outputErr
	}
	return printOutput(*accepted.Output, formatTeamAcceptInvite)
}

func resolveTeamAcceptInviteScope(cmd *cobra.Command) (string, error) {
	local := teamAcceptLocal
	global := teamAcceptGlobal
	if local && global {
		return "", usageError("--local and --global cannot be used together")
	}
	return string(inviteMemberScopeFromFlags(inviteMemberScopeFlags{Global: global})), nil
}

type teamInviteStoreRequest struct {
	Acceptance teamInviteAcceptanceRequest
	Store      teamInviteStoreOptions
}

type teamInviteStoreOptions struct {
	IdentityHome encryptionKeyIdentityHomeIntent
	Activation   membershipActivation
	Duplicates   membershipDuplicatePolicy
}

func acceptAndStoreTeamInvite(request teamInviteStoreRequest) (*acceptedTeamInvite, error) {
	workingDir, token, opts := request.Acceptance.WorkingDir, request.Acceptance.Token, request.Acceptance.Options
	store := request.Store
	identityHomeRoot, explicitIdentityHome, err := store.IdentityHome.resolve()
	if err != nil {
		return nil, err
	}
	if explicitIdentityHome {
		opts.IdentityHome = identityHomeRoot
	}
	var teamState *awconfig.TeamState
	if store.Duplicates == membershipRejectDuplicate {
		loaded, err := requireTeamStateForMembershipAt(workingDir, identityHomeRoot)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			loaded = &awconfig.TeamState{}
		}
		teamState = loaded
	}
	accepted, err := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: workingDir,
		Token:      token,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}
	if teamState != nil && teamState.Membership(accepted.Output.TeamID) != nil {
		return nil, rollbackAddedTeamCertificate(workingDir, identityHomeRoot, accepted, usageError("team %q is already present in local team memberships", accepted.Output.TeamID))
	}
	// Membership recording prepares teams.yaml and encryption. The caller
	// connects the workspace separately when its join mode requires it.
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{
		WorkingDir:   workingDir,
		Output:       accepted.Output,
		Certificate:  accepted.Certificate,
		RegistryURL:  accepted.RegistryURL,
		AwebURL:      accepted.AwebURL,
		IdentityHome: store.IdentityHome,
		Activation:   store.Activation,
	}); err != nil {
		if store.Duplicates == membershipRejectDuplicate {
			return nil, rollbackAddedTeamCertificate(workingDir, identityHomeRoot, accepted, err)
		}
		return nil, retainIdentityForRecovery(err)
	}
	if explicitIdentityHome {
		if err := writeExternalLocalIdentityStateIfNeeded(identityHomeRoot, accepted.Certificate); err != nil {
			return nil, retainedIssuedIdentityStateFailure(accepted.Certificate, err)
		}
	}
	return accepted, nil
}

func ensureExternalLocalAcceptHomeAvailable(identityHome string) error {
	if key, err := unjoinedChainSigningKey(identityHome); err != nil {
		return err
	} else if key != nil {
		return nil
	}

	home := awconfig.IdentityHome{Root: strings.TrimSpace(identityHome)}
	for _, rel := range []string{"grant.yaml", "identity.yaml", "workspace.yaml", "teams.yaml"} {
		path, err := awconfig.IdentityHomePath(home, rel)
		if err != nil {
			return err
		}
		if _, err := os.Stat(path); err == nil {
			return usageError("refusing to overwrite existing %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func writeExternalLocalIdentityStateIfNeeded(identityHome string, cert *awid.TeamCertificate) error {
	if cert == nil || awid.NormalizeIdentityScope(cert.IdentityScope) != awid.IdentityModeLocal {
		return nil
	}
	if strings.TrimSpace(cert.MemberDIDKey) == "" {
		return fmt.Errorf("accepted local team certificate is missing member_did_key")
	}
	home := awconfig.IdentityHome{Root: strings.TrimSpace(identityHome)}
	identityPath, err := awconfig.IdentityHomePath(home, "identity.yaml")
	if err != nil {
		return err
	}
	if existing, err := awconfig.LoadWorktreeIdentityFrom(identityPath); err == nil {
		if awid.NormalizeIdentityScope(existing.IdentityScope) == awid.IdentityModeLocal && strings.TrimSpace(existing.DID) == strings.TrimSpace(cert.MemberDIDKey) {
			return nil
		}
		return usageError("refusing to overwrite existing %s", identityPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	createdAt := strings.TrimSpace(cert.IssuedAt)
	if createdAt == "" {
		createdAt = time.Now().UTC().Format(time.RFC3339)
	}
	return awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:           strings.TrimSpace(cert.MemberDIDKey),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     createdAt,
	})
}

func runTeamAdd(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	teamAddMemberAddress := strings.TrimSpace(teamAddAddress)
	if teamAddMemberAddress == "" && !teamAcceptNoAddress {
		identity, readErr := loadOptionalInviteIdentity(teamMembershipLocation{WorkingDir: workingDir, IdentityHome: home.Root})
		if readErr != nil {
			return readErr
		}
		if identity != nil {
			teamAddMemberAddress = strings.TrimSpace(identity.Address)
		}
	}
	accepted, err := acceptAndStoreTeamInvite(teamInviteStoreRequest{
		Acceptance: teamInviteAcceptanceRequest{
			WorkingDir: workingDir,
			Token:      args[0],
			Options: teamAcceptInviteOptions{
				IdentityHome: externalIdentityHomeRoot(home),
				Name:         teamAddAlias,
				Address:      teamAddMemberAddress,
				Scope:        awid.IdentityModeGlobal,
				NoAddress:    teamAcceptNoAddress,
			},
		},
		Store: teamInviteStoreOptions{IdentityHome: resolvedEncryptionKeyIdentityHome(home), Activation: membershipPreserveActive, Duplicates: membershipRejectDuplicate},
	})
	if err != nil {
		return err
	}
	return printOutput(teamAddOutput{
		Status:   "added",
		TeamID:   accepted.Output.TeamID,
		Alias:    accepted.Output.Alias,
		CertPath: accepted.Output.CertPath,
	}, formatTeamAdd)
}

func runTeamSwitch(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembershipAt(workingDir, externalIdentityHomeRoot(home))
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(args[0])
	if teamState.Membership(teamID) == nil {
		return usageError("team %q is not present in local team memberships; available: %s", teamID, strings.Join(teamState.AvailableTeamIDs(), ", "))
	}
	if strings.EqualFold(strings.TrimSpace(teamState.ActiveTeam), teamID) {
		return printOutput(teamSwitchOutput{
			Status:     "already_active",
			ActiveTeam: strings.TrimSpace(teamState.ActiveTeam),
		}, formatTeamSwitch)
	}
	teamState.ActiveTeam = teamID
	if err := saveCurrentTeamState(workingDir, externalIdentityHomeRoot(home), teamState); err != nil {
		return err
	}
	return printOutput(teamSwitchOutput{
		Status:     "switched",
		ActiveTeam: teamState.ActiveTeam,
	}, formatTeamSwitch)
}

func runTeamList(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	teamState, err := requireTeamStateForMembershipAt(workingDir, externalIdentityHomeRoot(home))
	if err != nil {
		return err
	}

	workspacePath, err := awconfig.IdentityHomePath(home, "workspace.yaml")
	if err != nil {
		return err
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read workspace binding: %w; repair the selected home's workspace.yaml before listing its bindings", err)
	}

	items := make([]teamListItem, 0, len(teamState.Memberships))
	for _, membership := range teamState.Memberships {
		item := teamListItem{
			TeamID:      strings.TrimSpace(membership.TeamID),
			Alias:       strings.TrimSpace(membership.Alias),
			Active:      strings.EqualFold(strings.TrimSpace(membership.TeamID), strings.TrimSpace(teamState.ActiveTeam)),
			RegistryURL: strings.TrimSpace(membership.RegistryURL),
			AwebURL:     strings.TrimSpace(membership.AwebURL),
		}
		cert, err := loadTeamCertificateAt(workingDir, externalIdentityHomeRoot(home), membership.TeamID)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read certificate for %s: %w; restore that team's certificate before listing its membership", membership.TeamID, err)
		}
		if cert != nil {
			item.IdentityScope = awid.NormalizeIdentityScope(cert.IdentityScope)
			item.IssuedAt = strings.TrimSpace(cert.IssuedAt)
			item.CertificateID = strings.TrimSpace(cert.CertificateID)
		}
		if workspace != nil {
			if bound := workspace.Membership(membership.TeamID); bound != nil {
				item.WorkspaceID = strings.TrimSpace(bound.WorkspaceID)
				if item.AwebURL == "" {
					item.AwebURL = strings.TrimSpace(workspace.AwebURL)
				}
			}
		}
		items = append(items, item)
	}
	return printOutput(teamListOutput{
		ActiveTeam:  strings.TrimSpace(teamState.ActiveTeam),
		Memberships: items,
	}, formatTeamList)
}

func runTeamMembers(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if awconfig.IsGrantHome(home.Root) {
		return runGrantTeamMembers(cmd, workingDir, home)
	}
	domain, team, teamID, err := resolveTeamMembersTarget(workingDir, home)
	if err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	registryURL, err := resolveTeamCommandRegistry(ctx, registry, workingDir, domain, teamID, teamMembersRegistryURL)
	if err != nil {
		return err
	}
	signers, err := teamReadSigners(workingDir, domain, team)
	if err != nil {
		return err
	}
	var certs []awid.RegistryCertificate
	if _, err := readSignedTeamState(signers, func(key ed25519.PrivateKey) error {
		var listErr error
		certs, listErr = registry.ListCertificates(ctx, registryURL, domain, team, !teamMembersIncludeRevoked, key)
		return listErr
	}); err != nil {
		if friendly := friendlyTeamReadError(err, teamID, len(signers) > 0); friendly != err {
			return friendly
		}
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
	return printTeamMembers(teamMembersOutput{TeamID: teamID, Members: items})
}

func runGrantTeamMembers(cmd *cobra.Command, workingDir string, home awconfig.IdentityHome) error {
	if teamMembersIncludeRevoked || cmd.Flags().Changed("include-revoked") {
		return usageError("--include-revoked is not supported in a grant home: the service roster has no revoked-certificate records")
	}
	if strings.TrimSpace(teamMembersRegistryURL) != "" || cmd.Flags().Changed("registry") {
		return usageError("--registry is not supported in a grant home: the roster is read from the grant's bound service")
	}
	if strings.TrimSpace(teamMembersTeamID) != "" && (strings.TrimSpace(teamMembersTeam) != "" || strings.TrimSpace(teamMembersNamespace) != "") {
		return usageError("--team-id cannot be combined with --team or --namespace")
	}
	client, selection, err := resolveGrantClientSelection(workingDir, home)
	if err != nil {
		return err
	}
	domain, team, err := awid.ParseTeamID(selection.TeamID)
	if err != nil {
		return err
	}
	requested := selection.TeamID
	if strings.TrimSpace(teamMembersTeamID) != "" {
		requestedDomain, requestedTeam, err := awid.ParseTeamID(strings.TrimSpace(teamMembersTeamID))
		if err != nil {
			return err
		}
		requested = awid.BuildTeamID(requestedDomain, requestedTeam)
	} else {
		if strings.TrimSpace(teamMembersTeam) != "" {
			team = strings.ToLower(strings.TrimSpace(teamMembersTeam))
		}
		if strings.TrimSpace(teamMembersNamespace) != "" {
			domain = awconfig.NormalizeDomain(teamMembersNamespace)
		}
		requested = awid.BuildTeamID(domain, team)
	}
	if requested != selection.TeamID {
		return usageError("grant home is bound to team %s; requested team %s conflicts", selection.TeamID, requested)
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	// Use the existing grant-authorized roster. A session key is not an AWID
	// member key; never fall back to root/controller credentials on a refusal.
	roster, err := client.ListAgents(ctx)
	if err != nil {
		return fmt.Errorf("list service roster for %s: %w", selection.TeamID, err)
	}
	if strings.TrimSpace(roster.TeamID) != selection.TeamID {
		return fmt.Errorf("roster response does not match the grant's bound team %s (got %q)", selection.TeamID, roster.TeamID)
	}
	items := make([]teamMemberItem, 0, len(roster.Agents))
	for _, agent := range roster.Agents {
		items = append(items, teamMemberItem{
			TeamID:        selection.TeamID,
			Alias:         strings.TrimSpace(agent.Alias),
			MemberAddress: strings.TrimSpace(agent.Address),
			MemberDIDKey:  strings.TrimSpace(agent.DIDKey),
			MemberDIDAW:   strings.TrimSpace(agent.DIDAW),
			IdentityScope: awid.NormalizeIdentityScope(agent.IdentityScope),
		})
	}
	return printTeamMembers(teamMembersOutput{TeamID: selection.TeamID, Members: items, Source: "service-roster", Limitations: grantRosterLimitations})
}

func printTeamMembers(out teamMembersOutput) error {
	items := out.Members
	sort.SliceStable(items, func(i, j int) bool {
		left := strings.ToLower(firstNonEmpty(items[i].Alias, items[i].MemberAddress, items[i].MemberDIDAW, items[i].MemberDIDKey, items[i].CertificateID))
		right := strings.ToLower(firstNonEmpty(items[j].Alias, items[j].MemberAddress, items[j].MemberDIDAW, items[j].MemberDIDKey, items[j].CertificateID))
		return left < right
	})
	return printOutput(out, formatTeamMembers)
}

func resolveTeamMembersTarget(workingDir string, home awconfig.IdentityHome) (domain, team, teamID string, err error) {
	if requested := strings.TrimSpace(teamMembersTeamID); requested != "" {
		if strings.TrimSpace(teamMembersTeam) != "" || strings.TrimSpace(teamMembersNamespace) != "" {
			return "", "", "", usageError("--team-id cannot be combined with --team or --namespace")
		}
		domain, team, err = awid.ParseTeamID(requested)
		if err != nil {
			return "", "", "", err
		}
		return domain, team, awid.BuildTeamID(domain, team), nil
	}
	team = strings.ToLower(strings.TrimSpace(teamMembersTeam))
	domain = awconfig.NormalizeDomain(teamMembersNamespace)
	if team == "" || domain == "" {
		state, err := loadSelectedTeamState(workingDir, home)
		if err != nil {
			return "", "", "", usageError("--team-id or both --team and --namespace are required when no active team can be inferred from this workspace: %v", err)
		}
		active := strings.TrimSpace(state.ActiveTeam)
		activeDomain, activeTeam, parseErr := awid.ParseTeamID(active)
		if parseErr != nil {
			return "", "", "", fmt.Errorf("invalid active team %q: %w", active, parseErr)
		}
		if team == "" {
			team = activeTeam
		}
		if domain == "" {
			domain = activeDomain
		}
	}
	return domain, team, awid.BuildTeamID(domain, team), nil
}

func runTeamLeave(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	identityHome := externalIdentityHomeRoot(home)
	teamState, err := requireTeamStateForMembershipAt(workingDir, identityHome)
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
	if err := saveCurrentTeamState(workingDir, identityHome, teamState); err != nil {
		return err
	}
	certPath := awconfig.TeamCertificatePath(workingDir, teamID)
	if strings.TrimSpace(identityHome) != "" {
		certPath, err = awconfig.TeamCertificatePathFromIdentityHome(identityHome, teamID)
		if err != nil {
			return err
		}
	}
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return printOutput(teamLeaveOutput{
		Status:     "left",
		TeamID:     teamID,
		ActiveTeam: strings.TrimSpace(teamState.ActiveTeam),
	}, formatTeamLeave)
}

func acceptTeamInviteWithDetails(input teamInviteAcceptanceRequest) (*acceptedTeamInvite, error) {
	workingDir, token, opts := input.WorkingDir, input.Token, input.Options
	if awid.IsHostedSpawnInviteToken(token) {
		return acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
			WorkingDir: workingDir,
			Token:      token,
			Options:    opts,
		})
	}

	decoded, err := awconfig.DecodeInviteToken(token)
	if err != nil {
		return nil, nativeInviteRenewalRefusal(err)
	}

	invite, err := awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nativeInviteRenewalRefusal(err)
		}
		return nil, nativeInviteIssuanceRefusal(&awconfig.TeamInvite{InviteID: decoded.InviteID}, err)
	}
	inviteLock, err := awconfig.LockTeamInvite(decoded.InviteID)
	if err != nil {
		return nil, err
	}
	defer closeTeamInviteLock(inviteLock)
	invite, err = awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil {
		return nil, nativeInviteIssuanceRefusal(&awconfig.TeamInvite{InviteID: decoded.InviteID}, err)
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	issuance, err := awconfig.InspectTeamInviteIssuance(invite)
	if err != nil {
		return nil, nativeInviteIssuanceRefusal(invite, err)
	}
	if issuance != nil {
		return resumeNativeInviteIssuance(ctx, nativeInviteResumeRequest{WorkingDir: workingDir, Options: opts, Invite: invite, Issuance: issuance})
	}
	lifecycle, err := awconfig.InspectTeamInviteLifecycle(awconfig.TeamInviteLifecycleRequest{Invite: invite, Now: time.Now()})
	if err != nil || lifecycle.State == awconfig.TeamInviteExpired || lifecycle.State == awconfig.TeamInviteUnknown {
		return nil, nativeInviteRenewalRefusal(err)
	}
	if lifecycle.State == awconfig.TeamInviteConsumed {
		return nil, withErrorCode("invite_already_used", usageError("this invite was already used; retain its recipient home and recover that membership instead of accepting it again"))
	}
	scope, err := validateTeamInviteAcceptance(teamInviteAcceptanceRequest{
		WorkingDir: workingDir,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}

	if invite.Secret != decoded.Secret {
		return nil, nativeInviteRenewalRefusal(errors.New("invite secret mismatch"))
	}

	teamID := awid.BuildTeamID(invite.Domain, invite.TeamName)

	teamKey, err := awconfig.LoadTeamKey(invite.Domain, invite.TeamName)
	if err != nil {
		return nil, fmt.Errorf("local team controller key for %s not found: %w (cross-machine joins should use `aw id team request`, controller-side `aw id team add-member`, then invitee-side `aw id team fetch-cert`)", teamID, err)
	}

	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return nil, err
	}
	registryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryTeamRoute, Override: invite.RegistryURL, Domain: invite.Domain, TeamID: teamID, DefaultURL: registry.DefaultRegistryURL,
	})
	if err != nil {
		return nil, err
	}
	home, err := identityHomeForTarget(workingDir, opts.IdentityHome)
	if err != nil {
		return nil, err
	}
	attribution := nativeInviteExistingIdentity
	if scope == awid.IdentityModeLocal && invite.IDChild != nil && opts.ParentHome == "" {
		bound, err := bindTeamInviteIDChild(ctx, invite, home.Root)
		if err != nil {
			return nil, err
		}
		if bound {
			attribution = nativeInviteChildIdentity
		}
	}
	plan, err := resolveTeamMemberEnrollment(ctx, teamMemberEnrollmentResolveOptions{
		WorkingDir:        workingDir,
		IdentityHome:      opts.IdentityHome,
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
	if err := prepareNativeInviteAttribution(ctx, nativeInviteAttributionRequest{WorkingDir: workingDir, Token: token, Options: opts, Home: home, Invite: invite, Plan: plan, Registry: registry, Attribution: attribution}); err != nil {
		return nil, err
	}

	parentInviteID := ""
	if opts.ParentHome != "" {
		parentInviteID, _, err = loadTeamInviteParentRecord(token, home.Root)
		if err != nil {
			return nil, err
		}
	}
	appliedDefaultClaim, err := claimNativeInviteDefaultAddress(ctx, nativeInviteDefaultClaimRequest{Plan: plan, Registry: registry, RegistryURL: registryURL})
	if err != nil {
		return nil, err
	}

	cert, err := issueNativeInviteCertificate(ctx, nativeInviteIssuanceRequest{Invite: invite, Plan: plan, Home: home, ParentInviteID: parentInviteID, TeamKey: teamKey, Registry: registry, RegistryURL: registryURL, DefaultClaimResult: appliedDefaultClaim})
	if err != nil {
		return nil, err
	}

	certPath, err := saveAcceptedTeamCertificate(workingDir, opts.IdentityHome, teamID, cert)
	if err != nil {
		return nil, issuedInvitePersistenceRefusal(issuedInvitePersistenceFailure{Cause: err, Invite: invite, Certificate: cert, RegistryURL: registryURL})
	}

	if attribution == nativeInviteChildIdentity {
		if err := writeExternalLocalIdentityStateIfNeeded(home.Root, cert); err != nil {
			return nil, retainedIssuedIdentityStateFailure(cert, err)
		}
	}
	if err := consumeInviteParent(parentInviteID); err != nil {
		return nil, retainIdentityForRecovery(err)
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
		AwebURL:     strings.TrimSpace(invite.AwebURL),
		Domain:      invite.Domain,
		TeamName:    invite.TeamName,
	}, nil
}

func rollbackDefaultAddressClaimAfterCertificateFailure(
	registry *awid.RegistryClient,
	registryURL string,
	claim *awid.AtomicAddressClaimParams,
	result *awid.AtomicAddressClaimResult,
	cause error,
) error {
	if claim == nil || result == nil || strings.TrimSpace(result.AddressStatus) != "created" {
		return cause
	}
	address := awconfig.NormalizeDomain(claim.Domain) + "/" + strings.ToLower(strings.TrimSpace(claim.AddressName))
	if result.Address == nil {
		return fmt.Errorf(
			"%w; default address %s was newly claimed, but the registry response omitted its rollback identity; its state is unknown, so retry the same invite and address (the claim is idempotent) rather than choosing a new identity",
			cause,
			address,
		)
	}
	rollbackCtx, cancel := commandAPIContext(nil)
	defer cancel()
	if err := registry.DeleteAddressIfMatchesAt(
		rollbackCtx,
		registryURL,
		claim.Domain,
		claim.AddressName,
		result.Address.AddressID,
		result.Address.DIDAW,
		result.Address.CurrentDIDKey,
		claim.NamespaceControllerSigningKey,
		"rollback default address claim after team certificate registration failure",
	); err != nil {
		return fmt.Errorf(
			"%w; default address %s was newly claimed, but rollback failed: %v; its state is unknown, so retry the same invite and address (the claim is idempotent) rather than choosing a new identity",
			cause,
			address,
			err,
		)
	}
	return fmt.Errorf("%w; newly claimed default address %s was rolled back", cause, address)
}

func acceptHostedTeamInviteWithDetails(input teamInviteAcceptanceRequest) (result *acceptedTeamInvite, resultErr error) {
	workingDir, token, opts := input.WorkingDir, input.Token, input.Options
	home, err := identityHomeForTarget(workingDir, opts.IdentityHome)
	if err != nil {
		return nil, err
	}
	var creation *hostedInviteCreation
	var recoveryLock io.Closer
	defer func() {
		resultErr = retainHostedInviteRecoveryFailure(hostedInviteRecoveryFailure{Home: home, Creation: creation, Cause: resultErr})
		if recoveryLock != nil {
			closeTeamInviteLock(recoveryLock)
		}
	}()
	scope, err := validateTeamInviteAcceptance(teamInviteAcceptanceRequest{
		WorkingDir: workingDir,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}

	recipient, err := resolveHostedInviteRecipient(teamInviteAcceptanceRequest{
		WorkingDir: workingDir,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}
	alias, memberAddress := recipient.Alias, recipient.Address

	// Global reuse is checked before locking can create a recipient home.
	material := workspaceTeamIdentityMaterial{IdentityScope: scope}
	if scope == awid.IdentityModeGlobal {
		material, err = loadGlobalHostedInviteMaterial(teamInviteAcceptanceRequest{
			WorkingDir: workingDir,
			Options:    opts,
		})
		if err != nil {
			return nil, err
		}
	}

	recoveryPath, err := awconfig.IdentityHomePath(home, hostedInviteRecoveryFile)
	if err != nil {
		return nil, err
	}
	if err := pathpreflight.PreflightFile(recoveryPath+".lock", "hosted invite recovery lock", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return nil, err
	}
	lock, err := awconfig.TryLockExclusive(recoveryPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("hosted invite acceptance already in progress: %w", err)
	}
	recoveryLock = lock
	prior, err := loadHostedInviteCreation(recoveryPath)
	if err != nil {
		return nil, err
	}

	mintedKey := false
	if scope == awid.IdentityModeLocal {
		material, err = loadLocalHostedInviteMaterial(localHostedInviteMaterialRequest{WorkingDir: workingDir, Home: home, Prior: prior})
		if err != nil {
			return nil, err
		}
		mintedKey, err = (acceptanceMintedKey{Home: home}).present()
		if err != nil {
			return nil, err
		}
	}

	awebURL := firstNonEmpty(opts.AwebURL, resolveInitAwebURLOverride())
	awebURL = awebURLOrDefault(awebURL)
	awebURL, err = normalizeAwebBaseURL(awebURL)
	if err != nil {
		return nil, err
	}
	client, err := awid.NewWithIdentity(awebURL, material.SigningKey, material.DIDKey)
	if err != nil {
		return nil, err
	}

	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	// An attempt without a submission fact can be released for a new token
	// only if its frozen chain proves a different human from its condition;
	// that selection cannot pass the pre-submission check.
	if prior != nil && prior.AcceptAttempted == nil && prior.ResponseJSON == "" && prior.ForHuman != nil && prior.MembershipChain != nil && prior.TokenHash != strings.TrimPrefix(hostedTeamInviteRecordID(token), "hosted-") {
		subjectID := prior.StableID
		if subjectID == "" {
			subjectID = prior.DIDKey
		}
		_, refusal := verifyInviteMembership(ctx, prior.MembershipChain, awid.IDChainSubject{ID: subjectID, DIDKey: prior.DIDKey}, prior.ForHuman, opts.Registry, opts.TXTResolver)
		if awid.IDCertificateErrorCode(refusal) == "human_mismatch" {
			if err := discardHostedInviteAttempt(recoveryPath); err != nil {
				return nil, errors.Join(refusal, err)
			}
			prior = nil
		}
	}
	creation, err = prepareHostedInviteCreation(ctx, prior, strings.TrimSpace(token), awebURL, alias, memberAddress, opts.NoAddress, material, mintedKey, opts.ParentFromSource, opts.ParentHome, recoveryPath)
	if err != nil {
		return nil, err
	}
	opts.ParentHome = creation.ParentHome
	if creation.IssuerCreationStarted && !creation.parentageSelected() {
		return nil, uncertainHostedInviteError(home.Root, creation.TeamID, errors.New("retained creation has no recorded key mint or explicit parent; reconcile the earlier attempt before retrying"))
	}
	if err := creation.save(recoveryPath); err != nil {
		return nil, err
	}
	request := hostedInviteAcceptanceRequest{
		WorkingDir: workingDir, Token: token, Options: opts, Scope: teamInviteMemberScope(scope), Alias: alias,
		MemberAddress: memberAddress, Material: material, Home: home, Creation: creation,
		RecoveryPath: recoveryPath, Client: client,
	}
	history := hostedInviteSubmissionBefore(creation)
	accepted, err := completeHostedInviteAcceptance(ctx, request)
	if err != nil {
		return nil, finishHostedInviteRefusal(request, history, err)
	}
	return accepted, nil
}

// hostedAcceptSigningKeyAt prepares a hosted invite key and retains it for
// retry. A completed identity or unmarked key is refused rather than overwritten.
func hostedAcceptSigningKeyAt(workingDir, identityHome string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	homeForChain, err := identityHomeForTarget(workingDir, identityHome)
	if err != nil {
		return nil, nil, err
	}
	if key, err := unjoinedChainSigningKey(homeForChain.Root); err != nil {
		return nil, nil, err
	} else if key != nil {
		return key.Public().(ed25519.PublicKey), key, nil
	}
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return nil, nil, err
	}
	home, err := identityHomeForTarget(workingDir, identityHome)
	if err != nil {
		return nil, nil, err
	}
	keyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, nil, err
	}
	marker := acceptanceMintedKey{Home: home}
	if _, err := os.Stat(keyPath); err == nil {
		markerPresent, markerErr := marker.present()
		if markerErr != nil {
			return nil, nil, markerErr
		}
		identityPath, pathErr := awconfig.IdentityHomePath(home, "identity.yaml")
		if pathErr != nil {
			return nil, nil, pathErr
		}
		workspacePath, pathErr := awconfig.IdentityHomePath(home, "workspace.yaml")
		if pathErr != nil {
			return nil, nil, pathErr
		}
		completedPaths := []string{identityPath, workspacePath}
		for _, path := range completedPaths {
			if _, err := os.Stat(path); err == nil {
				if path == identityPath && markerPresent {
					metadata, loadErr := awconfig.LoadWorktreeIdentityFrom(identityPath)
					key, keyErr := awid.LoadSigningKey(keyPath)
					if loadErr != nil {
						return nil, nil, loadErr
					}
					if keyErr != nil {
						return nil, nil, keyErr
					}
					public, publicErr := teamInviteSigningPublicKey(key)
					if publicErr != nil {
						return nil, nil, publicErr
					}
					if metadata.IdentityScope == awid.IdentityModeLocal && metadata.Custody == awid.CustodySelf && metadata.DID == awid.ComputeDIDKey(public) {
						continue
					}
				}
				return nil, nil, usageError("refusing to overwrite existing %s", path)
			} else if !os.IsNotExist(err) {
				return nil, nil, err
			}
		}
		if err := marker.require(); err != nil {
			return nil, nil, err
		}
		certsPath := filepath.Join(home.Root, "team-certs")
		if err := pathpreflight.PreflightDir(certsPath, "team certificate directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
			return nil, nil, err
		}
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
	if err := ensureHostedAcceptTargetClean(workingDir, home.Root); err != nil {
		return nil, nil, err
	}
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, err
	}
	if err := awid.SaveSigningKey(keyPath, signingKey); err != nil {
		return nil, nil, fmt.Errorf("save pending hosted accept signing key: %w", err)
	}
	if err := marker.save(); err != nil {
		return nil, nil, err
	}
	return pub, signingKey, nil
}

func ensureHostedAcceptTargetClean(workingDir, identityHome string) error {
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return err
	}
	root := filepath.Clean(strings.TrimSpace(identityHome))
	if root == "" {
		return fmt.Errorf("identity home is required")
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != hostedInviteRecoveryFile+".lock" && entry.Name() != initInviteRecoveryFile && entry.Name() != initInviteRecoveryFile+".lock" {
			return usageError("refusing to overwrite non-empty identity home %s", root)
		}
	}
	return nil
}

func identityHomeForTarget(workingDir, identityHome string) (awconfig.IdentityHome, error) {
	if strings.TrimSpace(identityHome) != "" {
		return awconfig.IdentityHome{Root: filepath.Clean(identityHome)}, nil
	}
	return identityHomeForDir(workingDir)
}

type hostedInviteResponseExpectation struct {
	Response  *awid.SpawnAcceptInviteResponse
	DIDKey    string
	Alias     string
	StableID  string
	Address   string
	Scope     string
	NoAddress bool
}

func validateHostedTeamInviteAcceptResponse(expected hostedInviteResponseExpectation) (*awid.TeamCertificate, string, error) {
	resp, didKey, requestedAlias := expected.Response, expected.DIDKey, expected.Alias
	expectedStableID, expectedAddress := expected.StableID, expected.Address
	expectedScope, expectedNoAddress := expected.Scope, expected.NoAddress
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
	if _, err := awid.ExtractPublicKey(strings.TrimSpace(cert.TeamDIDKey)); err != nil {
		return nil, "", fmt.Errorf("hosted team invite certificate has invalid team_did_key %q: %w", cert.TeamDIDKey, err)
	}
	if err := awid.CheckDecodedTeamCertificate(cert, strings.TrimSpace(cert.TeamDIDKey)); err != nil {
		return nil, "", fmt.Errorf("hosted team invite certificate is invalid: %w", err)
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
	actualScope := awid.NormalizeIdentityScope(cert.IdentityScope)
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

	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	registryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryTeamRoute, Override: firstNonEmptyString(accepted.RegistryURL, accepted.observedRegistryURL), Domain: accepted.Domain,
		TeamID: awid.BuildTeamID(accepted.Domain, accepted.TeamName), DefaultURL: registry.DefaultRegistryURL,
	})
	if err != nil {
		return err
	}

	teamKey, err := awconfig.LoadTeamKey(accepted.Domain, accepted.TeamName)
	if err != nil {
		return fmt.Errorf("load team key for %s/%s: %w", accepted.Domain, accepted.TeamName, err)
	}

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
		return withErrorCode(codeControllerKeyMissing, fmt.Errorf(
			"local team controller key for %s was not found: %w\n\nThis looks like an aweb.ai hosted namespace. Hosted teams keep the team controller key in cloud, so this raw AWID command cannot sign the add-member operation locally. Use the hosted dashboard Add existing agent action for hosted teams. Use `aw id team add-member` only for BYOIDT/BYOD teams where you hold ~/.awid/team-keys/<namespace>/<team>.key",
			teamID,
			err,
		))
	}
	return withErrorCode(codeControllerKeyMissing, fmt.Errorf(
		"local team controller key for %s was not found: %w (this command is for BYOIDT/BYOD teams where you hold ~/.awid/team-keys/<namespace>/<team>.key; hosted aweb.ai teams should use the dashboard Add existing agent action)",
		teamID,
		err,
	))
}

func resolveTeamAddMemberScope(cmd *cobra.Command) (string, error) {
	requestedScope := awid.IdentityModeLocal
	if teamAddMemberGlobal && teamAddMemberLocal {
		return "", usageError("--global and --local cannot be used together")
	}
	if teamAddMemberGlobal {
		requestedScope = awid.IdentityModeGlobal
	}

	if cmd.Flags().Changed("lifetime") {
		legacyScope := awid.IdentityScopeFromLegacyLifetime(teamAddMemberDeprecatedScopeValue)
		if legacyScope == "" {
			return "", usageError("--lifetime must be ephemeral or persistent")
		}
		if (teamAddMemberGlobal || teamAddMemberLocal) && requestedScope != legacyScope {
			return "", usageError("--lifetime conflicts with --global or --local")
		}
		requestedScope = legacyScope
	}
	return requestedScope, nil
}

// teamAddMemberRegistryClient is the registry client add-member uses.
var teamAddMemberRegistryClient = func() (*awid.RegistryClient, error) {
	return newConfiguredRegistryClient(nil)
}

func runTeamAddMember(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamAddTeam))
	domain := awconfig.NormalizeDomain(teamAddNamespace)
	member := strings.TrimSpace(teamAddMember)
	memberDID := strings.TrimSpace(teamAddMemberDID)
	memberAlias := strings.TrimSpace(teamAddMemberAlias)
	identityScope, err := resolveTeamAddMemberScope(cmd)
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
			if identityScope != awid.IdentityModeGlobal {
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

	ctx, cancel := commandAPIContext(cmd)
	defer cancel()

	registry, err := teamAddMemberRegistryClient()
	if err != nil {
		return err
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	teamRegistryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryTeamRoute, Registry: registry, Domain: domain, TeamID: teamID,
		WorkingDir: workingDir, IdentityHome: externalIdentityHomeRoot(home),
	})
	if err != nil {
		return fmt.Errorf("resolve the registry for namespace %s: %w", domain, err)
	}

	if member != "" {
		// Resolve member's did:key from their address via awid.
		memberDomain, memberName, err := parseAddress(member)
		if err != nil {
			return err
		}

		lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
		if err != nil {
			return err
		}
		memberRegistryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{Kind: registryDomainRoute, Registry: registry, Domain: memberDomain})
		if err != nil {
			return fmt.Errorf("resolve the registry for member namespace %s: %w", memberDomain, err)
		}
		var address *awid.RegistryAddress
		if lookupSigningKey != nil {
			address, _, err = registry.GetNamespaceAddressAtSigned(ctx, memberRegistryURL, memberDomain, memberName, lookupSigningKey)
		} else {
			address, _, err = registry.GetNamespaceAddressAt(ctx, memberRegistryURL, memberDomain, memberName)
		}
		if err != nil {
			return fmt.Errorf("resolve member address %s: %w", member, err)
		}

		memberDID = address.CurrentDIDKey
		memberDIDAW = address.DIDAW
		memberAddress = member
		memberAlias = memberName
		// Local/global flags only apply to the direct --did path; address-backed members are always global.
		identityScope = awid.IdentityModeGlobal
	}

	if member == "" && memberDID != "" && memberAddress != "" {
		lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
		if err != nil {
			return err
		}
		addressDomain, _, err := parseAddress(memberAddress)
		if err != nil {
			return err
		}
		addressRegistryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{Kind: registryDomainRoute, Registry: registry, Domain: addressDomain})
		if err != nil {
			return fmt.Errorf("resolve the registry for member namespace %s: %w", addressDomain, err)
		}
		if err := validateMemberAddressForCertificate(ctx, registry, addressRegistryURL, memberAddress, memberDIDAW, memberDID, lookupSigningKey); err != nil {
			return err
		}
	}

	issuer := teamMembershipIssuer{TeamID: teamID, Key: teamKey, Registry: registry, RegistryURL: teamRegistryURL}
	cert, err := issuer.issue(ctx, awid.TeamCertificateFields{
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         memberAlias,
		IdentityScope: identityScope,
	})
	if err != nil {
		return err
	}

	fetchCommand := teamFetchCertificateCommand(domain, team, cert.CertificateID, "")
	return printOutput(teamAddMemberOutput{
		Status:        "added",
		Member:        firstNonEmpty(memberAddress, memberDID),
		TeamID:        teamID,
		MemberAddress: memberAddress,
		CertificateID: cert.CertificateID,
		FetchCommand:  fetchCommand,
	}, formatTeamAddMember)
}

func runTeamFetchCert(cmd *cobra.Command, args []string) error {
	if activeHuman != nil {
		return runHumanFetchCert(cmd)
	}
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
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if awconfig.IsGrantHome(home.Root) {
		return errGrantHomeRootAuthority
	}
	identityRoot := externalIdentityHomeRoot(home)
	certPathAbs, err := awconfig.IdentityHomeStoredPath(home, awconfig.TeamCertificateRelativePath(teamID))
	if err != nil {
		return err
	}
	existingCert, existingErr := loadTeamCertificateAt(workingDir, identityRoot, teamID)
	if existingErr == nil && existingCert != nil {
		if strings.TrimSpace(existingCert.CertificateID) != certificateID && !teamFetchCertForce {
			return usageError("team certificate already exists at %s with certificate_id %s; use --force to overwrite", certPathAbs, existingCert.CertificateID)
		}
	} else if !os.IsNotExist(existingErr) {
		if !teamFetchCertForce {
			return fmt.Errorf("existing team certificate at %s could not be read: %w (use --force to overwrite)", certPathAbs, existingErr)
		}
	}
	signingKeyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return err
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return fmt.Errorf("load local signing key: %w (run `aw id create` first on this machine)", err)
	}

	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	registryURL, err := resolveTeamCommandRegistry(ctx, registry, workingDir, domain, teamID, teamFetchCertRegistry)
	if err != nil {
		return err
	}

	cert, err := registry.FetchTeamCertificate(ctx, registryURL, domain, team, certificateID, signingKey)
	if err != nil {
		return fmt.Errorf("fetch certificate: %w", err)
	}
	if strings.TrimSpace(cert.Team) != teamID {
		return fmt.Errorf("fetched certificate team_id %q does not match requested %q", cert.Team, teamID)
	}
	// Held or not, a certificate is installed only while it is registered,
	// unrevoked and under the team's current key.
	if err := checkCurrentTeamCertificate(ctx, teamCertificateInstall{RegistryURL: registryURL, Registry: registry}, cert); err != nil {
		return err
	}
	status := certificateInstalled
	if existingErr == nil && existingCert != nil {
		same, err := sameTeamCertificate(existingCert, cert)
		if err != nil {
			return err
		}
		if same {
			status = certificateAlreadyInstalled
		}
	}
	if _, err := commitTeamCertificate(certificateCommit{WorkingDir: workingDir, IdentityHome: identityRoot, Command: "fetch-cert", Certificate: cert, RegistryURL: registryURL, WorkspacePath: "", Decide: func() (certificateInstallStatus, error) { return status, nil }}); err != nil {
		return err
	}

	return printOutput(teamFetchCertOutput{
		Status:        string(status),
		TeamID:        teamID,
		Alias:         strings.TrimSpace(cert.Alias),
		CertificateID: strings.TrimSpace(cert.CertificateID),
		CertPath:      awconfig.TeamCertificateRelativePath(teamID),
	}, formatTeamFetchCert)
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

	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}

	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	registryURL, err := resolveTeamCommandRegistry(ctx, registry, workingDir, domain, teamID, teamRemoveRegistryURL)
	if err != nil {
		return err
	}

	if certificateID == "" {
		// The typed namespace is discarded here on purpose-for-now: the alias is
		// resolved against the TEAM's namespace, because cross-namespace membership
		// is real and the alias is the key within a team. What is missing is any
		// check that the member the alias resolves to is the one the operator named,
		// and the output then reports the typed address rather than the resolved one.
		// aweb-aaum.7 owns that verification and will land it in one helper covering
		// this site and the copy in team_human.go revokeTeamCertificate. Two copies
		// until then, deliberately, because the correction does not exist yet and
		// merging two wrong copies buys nothing.
		// The add path in this file already does it correctly: runTeamAddMember binds
		// memberDomain and passes it through to the namespace address lookup.
		_, memberName, err := parseAddress(member)
		if err != nil {
			return err
		}
		memberRef, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, memberName, teamKey)
		if err != nil {
			// The team key is in hand here, so a visibility refusal means this
			// key is not the team's - a different fault from an unresolvable
			// member, and it is stated rather than wrapped in a lookup failure.
			if friendly := friendlyTeamReadError(err, teamID, true); friendly != err {
				return friendly
			}
			// A 404 here is ambiguous: it looks the same whether the member has
			// no active certificate or the request never reached the registry at
			// all. The command cannot establish the postcondition, so it fails
			// rather than reporting a removal it did not make.
			return fmt.Errorf("resolve team member %s in %s: %w", memberName, teamID, err)
		}
		if err := verifyNamedMember(member, domain, memberRef); err != nil {
			return err
		}
		certificateID = strings.TrimSpace(memberRef.CertificateID)
	}

	result, err := revokeRegistryTeamCertificate(ctx, registry, registryURL, domain, team, certificateID, teamKey)
	if err != nil {
		return err
	}

	return printOutput(teamRemoveMemberOutput{
		Status:        result.Result,
		TeamID:        teamID,
		MemberAddress: firstNonEmpty(result.MemberAddress, member),
		CertificateID: certificateID,
	}, formatTeamRemoveMember)
}

// verifyNamedMember refuses when the member an alias resolved to is not the one
// the operator named.
//
// Resolving by alias is correct: the alias is the key within a team, and
// cross-namespace membership is real, so a member of another namespace can hold
// an alias here. What was missing is any check that the member it resolved to is
// the one that was named. Without it, naming the wrong namespace revokes the
// team's own holder of that alias and reports success for the address that was
// typed, so the audit trail records an address that was never true.
//
// The comparison is two-part because the two kinds of member carry different
// evidence:
//
//	member_address set    the address is the member's own identity; the typed
//	                      address must be it
//	member_address empty  a local member has no address at all - local scope
//	                      rejects --address, and awid stores the column nullable -
//	                      so the only namespace that means anything for one is the
//	                      team's own, and that is what the typed domain must be
//
// Both sides are parsed before comparing. parseAddress normalizes what was typed
// while member_address is a raw stored column that the awid write path does not
// normalize, so comparing the strings as they arrived would refuse a correct
// address over case or whitespace - and a verification that refuses valid
// retirements is one that gets switched off.
func verifyNamedMember(typedAddress, teamDomain string, ref *awid.TeamMemberReference) error {
	typedDomain, typedName, err := parseAddress(typedAddress)
	if err != nil {
		return err
	}
	if resolvedAlias := strings.ToLower(strings.TrimSpace(ref.Alias)); resolvedAlias != "" && resolvedAlias != typedName {
		return fmt.Errorf(
			"refusing to act on %s: that name resolved to member %q, which is not the one named",
			typedAddress, strings.TrimSpace(ref.Alias),
		)
	}

	resolvedAddress := strings.TrimSpace(ref.MemberAddress)
	if resolvedAddress == "" {
		if typedDomain != awconfig.NormalizeDomain(teamDomain) {
			return fmt.Errorf(
				"refusing to act on %s: %s is a member of this team only and holds no address of its own, so the namespace that names it is %s, not %s",
				typedAddress, typedName, awconfig.NormalizeDomain(teamDomain), typedDomain,
			)
		}
		return nil
	}

	resolvedDomain, resolvedName, err := parseAddress(resolvedAddress)
	if err != nil {
		return fmt.Errorf("refusing to act on %s: the registry returned an unreadable member address %q", typedAddress, resolvedAddress)
	}
	if resolvedDomain != typedDomain || resolvedName != typedName {
		return fmt.Errorf(
			"refusing to act on %s: that name resolves to %s, a different principal",
			typedAddress, resolvedAddress,
		)
	}
	return nil
}

// revokeRegistryTeamCertificate revokes under local team-controller authority.
//
// The registry answers a revoke that changed nothing in two ways, and they mean
// different things. 409 says the certificate exists and was already revoked: the
// member holds no active certificate, which is the postcondition, so it is
// success. 404 says no such certificate, which is indistinguishable from a
// request that never reached the registry, so it stays an error. A 409 carries
// that meaning wherever it arrives, including after a by-name resolve raced a
// concurrent revoke.
func revokeRegistryTeamCertificate(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, team, certificateID string,
	teamKey ed25519.PrivateKey,
) (certificateStoreResult, error) {
	result := certificateStoreResult{CertificateID: certificateID}
	err := registry.RevokeCertificate(ctx, registryURL, domain, team, certificateID, teamKey)
	if err == nil {
		result.Result = certificateRevoked
		return result, nil
	}
	if registryReportsCertificateAlreadyRevoked(err) {
		result.Result = certificateAlreadyRevoked
		return result, nil
	}
	return certificateStoreResult{}, fmt.Errorf("revoke certificate: %w", err)
}

// registryReportsCertificateAlreadyRevoked matches the registry's own
// already-revoked answer, not any 409. The status alone is not enough: a
// revocation command must not read an unrelated conflict as a completed
// revocation.
//
// The detail text is a cross-repo coupling: awid raises
// HTTPException(409, "Certificate already revoked") from revoke_certificate in
// awid/src/awid_service/routes/teams.py, immediately after re-looking-up a
// certificate whose conditional UPDATE changed no row. Rewording that raise costs
// this distinction, and the failure is safe rather than silent - an unmatched 409
// falls through to a loud error - but the caller goes back to being unable to tell
// an already-revoked certificate from one that was never there.
func registryReportsCertificateAlreadyRevoked(err error) bool {
	status, ok := awid.HTTPStatusCode(err)
	if !ok || status != http.StatusConflict {
		return false
	}
	body, ok := awid.HTTPErrorBody(err)
	if !ok {
		return false
	}
	var envelope struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		return false
	}
	return strings.Contains(strings.ToLower(envelope.Detail), "already revoked")
}

func runHostedTeamRemoveMember(teamID, memberAddress, certificateID string) error {
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	result, err := revokeHostedTeamCertificate(ctx, teamID, memberAddress, certificateID)
	if err != nil {
		return err
	}
	return printOutput(teamRemoveMemberOutput{
		Status:        result.Result,
		TeamID:        teamID,
		MemberAddress: firstNonEmpty(result.MemberAddress, memberAddress),
		CertificateID: firstNonEmpty(result.CertificateID, certificateID),
		AgentID:       result.AgentID,
		WorkspaceID:   result.WorkspaceID,
	}, formatTeamRemoveMember)
}

// revokeHostedTeamCertificate revokes through the cloud-mediated controller.
//
// The endpoint answers with two distinct statuses and both are success. status
// reports what the call's own removal did on the hosted side: removed when this
// call reaped the hosted record, not_found when it did not. It is NOT a statement
// about certificates - a call can revoke a live certificate and still answer
// not_found, because whether it revoked and whether it reaped are separate facts
// settled at different moments. The service reports the revocation separately, in
// revoke_outcome (revoked / already_revoked / not_found / not_attempted).
//
// revoke_outcome is deliberately not consumed here yet: reading it would change
// what this function reports, which is a behaviour change wanting its own review.
// Unknown fields decode away harmlessly, so leaving it unread is safe.
//
// An unrecognised status is an error rather than a default, because a revocation
// command that treats an unknown answer as success cannot be used to establish that
// access was removed. That also makes any NEW status string a breaking change for
// every deployed client, which is why the service reports the revocation in a new
// field rather than a new status.
func revokeHostedTeamCertificate(ctx context.Context, teamID, memberAddress, certificateID string) (certificateStoreResult, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return certificateStoreResult{}, err
	}
	awebURL, apiKey, err := resolveHostedTeamRemoveAuth(workingDir, teamID)
	if err != nil {
		return certificateStoreResult{}, err
	}
	resp, err := postHostedTeamRemoveMember(ctx, awebURL, apiKey, teamID, hostedTeamRemoveMemberRequest{
		MemberAddress: strings.TrimSpace(memberAddress),
		CertificateID: strings.TrimSpace(certificateID),
	})
	if err != nil {
		return certificateStoreResult{}, err
	}
	result := certificateStoreResult{
		CertificateID: firstNonEmpty(resp.CertificateID, certificateID),
		MemberAddress: firstNonEmpty(resp.MemberAddress, memberAddress),
		AgentID:       strings.TrimSpace(resp.AgentID),
		WorkspaceID:   strings.TrimSpace(resp.WorkspaceID),
	}
	switch strings.ToLower(strings.TrimSpace(resp.Status)) {
	case "removed":
		result.Result = certificateRevoked
	case "not_found":
		result.Result = certificateNothingReported
	default:
		return certificateStoreResult{}, fmt.Errorf(
			"hosted remove-member returned unrecognised status %q; refusing to report the certificate revoked",
			strings.TrimSpace(resp.Status),
		)
	}
	return result, nil
}

func resolveHostedTeamRemoveAuth(workingDir, teamID string) (awebURL, apiKey string, err error) {
	return resolveHostedTeamRemoveAuthWithAwebURL(workingDir, teamID, teamRemoveAwebURL, teamRemoveAPIKey)
}

func resolveHostedTeamRemoveAuthWithAwebURL(workingDir, teamID, explicitAwebURL, explicitAPIKey string) (awebURL, apiKey string, err error) {
	awebURL = strings.TrimSpace(explicitAwebURL)
	apiKey = firstNonEmptyLibraryValue(explicitAPIKey, os.Getenv(initAPIKeyEnvVar))
	home, homeErr := identityHomeForDir(workingDir)
	if homeErr != nil {
		return "", "", homeErr
	}
	workspace, teamState, _, loadErr := loadCurrentWorkspaceAndTeamState(workingDir, externalIdentityHomeRoot(home))
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
		// This is the error a member hits when it tries to retire ITSELF with
		// remove-agent: it holds only its workspace-bound key, which cannot carry
		// team authority. Name the command that does work, because "you need an
		// admin key" reads as "ask a human" when self-retirement needs nobody.
		return "", "", usageError("hosted remove for %s requires --api-key or %s with a team-scoped owner/admin API key; workspace-bound API keys cannot remove hosted team members. To retire YOURSELF, run `aw workspace delete <your-own-workspace>` instead: it uses your own workspace-bound key, revokes your certificate through the hosted team controller, and releases your alias", teamID, initAPIKeyEnvVar)
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
	resp, err := awid.DoServerRequest(&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}, req, awebURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseLimit := int64(awid.MaxResponseSize)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseLimit = awid.MaxErrorResponseSize
	}
	responseBody, err := awid.ReadAllBounded(resp.Body, responseLimit)
	if err != nil {
		return nil, fmt.Errorf("read hosted remove-member response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, err := decodeTeamServiceRefusalDetail(responseBody)
		if err != nil {
			return nil, fmt.Errorf("hosted remove-member returned %d: %w", resp.StatusCode, err)
		}
		if detail != "" {
			return nil, fmt.Errorf("hosted remove-member returned %d: %s", resp.StatusCode, detail)
		}
		return nil, fmt.Errorf("hosted remove-member returned %d", resp.StatusCode)
	}
	var out hostedTeamRemoveMemberResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, fmt.Errorf("decode hosted remove-member response: %w", err)
	}
	// The response carries removed and not_found as distinct values, and both are
	// success. They distinguish whether THIS call reaped the hosted record - not
	// whether the member ends with an active certificate, which this response does
	// not establish and which revoke_outcome answers separately. Passed through
	// rather than collapsed, because callers need the difference.
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
	return printOutput(output, formatTeamImportRequest)
}

func runTeamRegister(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
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
	return printOutput(out, formatTeamRegister)
}

func runTeamCleanupCloud(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
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
	return printOutput(out, formatTeamCleanupCloud)
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
	signature := signaturewire.SignStd(teamKey, []byte(canonical))
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
	resp, err := awid.DoServerRequest(newTeamCloudHTTPClient(), req, strings.TrimSuffix(endpoint, "/v1/teams/service-register"))
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			debugLog("close service registration response: %v", err)
		}
	}()
	responseLimit := int64(awid.MaxResponseSize)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseLimit = awid.MaxErrorResponseSize
	}
	responseBody, err := awid.ReadAllBounded(resp.Body, responseLimit)
	if err != nil {
		return fmt.Errorf("read service register response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return serviceRegisterRefusal(serviceRegisterFailure{Status: resp.StatusCode, Body: responseBody})
	}
	if out != nil {
		if err := json.Unmarshal(responseBody, out); err != nil {
			return err
		}
	}
	return nil
}

type serviceRegisterFailure struct {
	Status int
	Body   []byte
}

// Keep the released registration sentence while the shared error reader carries
// the service's code and HTTP metadata (docs/cli-identity-selection.md:13).
func serviceRegisterRefusal(failure serviceRegisterFailure) error {
	refusal := &awid.APIError{StatusCode: failure.Status, Body: string(failure.Body)}
	message := fmt.Sprintf("service register: http %d", failure.Status)
	var body struct {
		Detail any `json:"detail"`
	}
	if err := json.Unmarshal(failure.Body, &body); err != nil {
		debugLog("read service registration refusal detail: %v", err)
	} else if body.Detail != nil {
		encoded, err := json.Marshal(body.Detail)
		if err != nil {
			return fmt.Errorf("encode service registration refusal detail: %w", err)
		}
		message += ": " + strings.TrimSpace(string(encoded))
	}
	var result error = &plainRefusal{text: message, jsonMessage: message, err: refusal}
	if code := awid.RefusalCode(refusal); code != "" {
		result = withErrorCode(code, result)
	}
	return result
}

func newTeamCloudHTTPClient() *http.Client {
	return &http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}
}

func verifyTeamRegisterLocalKey(ctx context.Context, teamKey ed25519.PrivateKey, domain, teamName, registryURL string) error {
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	}
	team, err := registry.GetTeam(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, teamName, teamKey)
	if err != nil {
		teamID := awid.BuildTeamID(domain, teamName)
		if friendly := friendlyTeamReadError(err, teamID, true); friendly != err {
			return friendly
		}
		return fmt.Errorf("load AWID team %s: %w", teamID, err)
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
	signature := signaturewire.SignStd(teamKey, []byte(canonical))
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
	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, teamCleanupCloudTXTResolver, domain)
	if err != nil {
		return nil, fmt.Errorf("verify DNS authority for %s: %w", domain, err)
	}
	if authority.Inherited || authority.DNSName != awid.AWIDTXTName(domain) {
		return nil, fmt.Errorf("no own-domain TXT record found at %s", awid.AWIDTXTName(domain))
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
	signature := signaturewire.SignStd(controllerKey, []byte(canonical))
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
	resp, err := awid.DoServerRequest(newTeamCloudHTTPClient(), req, awebURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	responseLimit := int64(awid.MaxResponseSize)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseLimit = awid.MaxErrorResponseSize
	}
	responseBody, err := awid.ReadAllBounded(resp.Body, responseLimit)
	if err != nil {
		return fmt.Errorf("read cloud cleanup response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, err := decodeTeamServiceRefusalDetail(responseBody)
		if err != nil {
			return fmt.Errorf("aweb: http %d: %w", resp.StatusCode, err)
		}
		if detail != "" {
			return fmt.Errorf("aweb: http %d: %s", resp.StatusCode, detail)
		}
		return fmt.Errorf("aweb: http %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(responseBody, out); err != nil {
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

	return printOutput(certShowOutput{
		TeamID:        cert.Team,
		Alias:         cert.Alias,
		MemberDIDKey:  cert.MemberDIDKey,
		MemberDIDAW:   cert.MemberDIDAW,
		MemberAddress: cert.MemberAddress,
		TeamDIDKey:    cert.TeamDIDKey,
		IdentityScope: awid.NormalizeIdentityScope(cert.IdentityScope),
		IssuedAt:      cert.IssuedAt,
		CertificateID: cert.CertificateID,
	}, formatCertShow)
}

func loadCurrentTeamCertificate(workingDir string) (*awid.TeamCertificate, string, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return nil, "", err
	}
	teamState, stateErr := loadSelectedTeamState(workingDir, home)
	if stateErr == nil && teamState != nil {
		selectedTeamID := strings.TrimSpace(teamFlag)
		selectedMembership := teamState.Membership(selectedTeamID)
		if selectedTeamID == "" {
			selectedMembership = teamState.ActiveMembership()
		}
		if selectedMembership == nil {
			return nil, "", fmt.Errorf("teams state is missing selected team membership")
		}
		certPath, err := awconfig.IdentityHomeStoredPath(home, selectedMembership.CertPath)
		if err != nil {
			return nil, "", err
		}
		cert, err := awid.LoadTeamCertificate(certPath)
		if err != nil {
			return nil, "", fmt.Errorf("load active team certificate %s: %w", certPath, err)
		}
		return cert, certPath, nil
	}

	if home.External() {
		return nil, "", fmt.Errorf("load selected identity home %s: %w", home.Root, stateErr)
	}
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return nil, "", stateErr
	}
	if selectedTeamID := strings.TrimSpace(teamFlag); selectedTeamID != "" {
		certPath, err := awconfig.TeamCertificatePathFromIdentityHome(home.Root, selectedTeamID)
		if err != nil {
			return nil, "", err
		}
		cert, err := awid.LoadTeamCertificate(certPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", fmt.Errorf("no local certificate for team %s; join that team or select an installed team with --team", selectedTeamID)
		}
		return cert, certPath, err
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
	certPath, err := awconfig.WorktreeStoredIdentityPath(workingDir, stored[0].CertPath)
	if err != nil {
		return nil, "", err
	}
	return stored[0].Certificate, certPath, nil
}

func saveCurrentTeamState(workingDir, identityHome string, state *awconfig.TeamState) error {
	if strings.TrimSpace(identityHome) != "" {
		return awconfig.SaveTeamStateToIdentityHome(identityHome, state)
	}
	return awconfig.SaveTeamState(workingDir, state)
}

func loadTeamCertificateAt(workingDir, identityHome, teamID string) (*awid.TeamCertificate, error) {
	if strings.TrimSpace(identityHome) != "" {
		return awconfig.LoadTeamCertificateForTeamFromIdentityHome(identityHome, teamID)
	}
	return awconfig.LoadTeamCertificateForTeam(workingDir, teamID)
}

func saveAcceptedTeamCertificate(workingDir, identityHome, teamID string, cert *awid.TeamCertificate) (string, error) {
	if strings.TrimSpace(identityHome) != "" {
		return awconfig.SaveTeamCertificateForTeamToIdentityHome(identityHome, teamID, cert)
	}
	return awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert)
}

func requireTeamStateForMembershipAt(workingDir, identityHome string) (*awconfig.TeamState, error) {
	var teamState *awconfig.TeamState
	var err error
	if strings.TrimSpace(identityHome) != "" {
		teamState, err = awconfig.LoadTeamStateFromIdentityHome(identityHome)
	} else {
		teamState, err = awconfig.LoadTeamState(workingDir)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil, usageError("current identity is missing .aw/teams.yaml; join a team first")
		}
		return nil, err
	}
	return teamState, nil
}

func rollbackAddedTeamCertificate(workingDir, identityHome string, accepted *acceptedTeamInvite, cause error) error {
	if err := revokeAcceptedTeamCertificate(accepted); err != nil {
		pending := fmt.Errorf("rollback of certificate %s failed: %w. Retain the identity home and ask the team controller to revoke this certificate before retrying.", accepted.Certificate.CertificateID, err)
		return retainIdentityForRecovery(withErrorCode("certificate_rollback_pending", errors.Join(cause, pending)))
	}
	var cleanupErr error
	if accepted != nil && accepted.Output != nil && strings.TrimSpace(accepted.Output.CertPath) != "" {
		home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(workingDir)}
		if identityHome != "" {
			home.Root = identityHome
		}
		certPath, err := awconfig.IdentityHomeStoredPath(home, accepted.Output.CertPath)
		if err != nil {
			cleanupErr = fmt.Errorf("resolve rolled-back certificate path: %w", err)
		} else if err := os.Remove(certPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = fmt.Errorf("remove rolled-back certificate: %w", err)
		}
	}
	return errors.Join(cause, cleanupErr)
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

	if err := settleUnconfirmedTeamKey(ctx, registry, registryURL, domain, name); err != nil {
		return nil, err
	}

	// The key is in local custody before the registry pins the team to it,
	// so an interrupted run is completed by a retry that reuses it.
	teamPriv, created, err := teamKeyForCreate(domain, name)
	if err != nil {
		return nil, err
	}
	teamPub := teamPriv.Public().(ed25519.PublicKey)
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	_, err = registry.CreateTeam(ctx, registryURL, domain, name, strings.TrimSpace(displayName), teamDIDKey, controllerKey)
	if err != nil {
		if code, ok := registryStatusCode(err); !ok || code != http.StatusConflict {
			return nil, fmt.Errorf("create team at registry: %w", err)
		}
		existingTeam, getErr := registry.GetTeam(ctx, registryURL, domain, name, teamPriv)
		if awid.IsTeamPrivateError(getErr) {
			// A private team refuses this read, signed with teamPriv, only
			// when teamPriv is neither its key nor a member's: the registry
			// pins another key.
			taken := withErrorCode(codeTeamNameTaken, fmt.Errorf("create team at registry: %w\nRestore this team's controller key to reuse it, or choose another --name.", err))
			if created {
				if removeErr := awconfig.RemoveTeamKey(domain, name, teamPub); removeErr != nil {
					return nil, fmt.Errorf("%w. The unregistered team key this run saved was kept: %v", taken, removeErr)
				}
			}
			return nil, taken
		}
		if getErr != nil {
			// The registry has the name but could not say which key holds
			// it; a failed read is not a taken name. A key this run created
			// may be the registered one (another run here registered it
			// first), so it is set aside, never destroyed, and never read as
			// the team key until a read settles it.
			aside := ""
			if created {
				path, asideErr := awconfig.SetAsideUnconfirmedTeamKey(domain, name, teamPub)
				if asideErr != nil {
					return nil, fmt.Errorf("%w. The team key this run saved could not be set aside: %v", unconfirmedTeamNameError(domain, name, "", getErr), asideErr)
				}
				aside = path
			}
			return nil, unconfirmedTeamNameError(domain, name, aside, getErr)
		}
		if strings.TrimSpace(existingTeam.TeamDIDKey) != teamDIDKey {
			pinned := teamPinnedElsewhereError(domain, name, existingTeam.TeamDIDKey)
			// A key this run created was never registered; keep no key file
			// for a team pinned to another key.
			if created {
				if removeErr := awconfig.RemoveTeamKey(domain, name, teamPub); removeErr != nil {
					return nil, fmt.Errorf("%w. The unregistered team key this run saved was kept: %v", pinned, removeErr)
				}
			}
			return nil, pinned
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

// settleUnconfirmedTeamKey settles a team key an earlier run set aside as
// unconfirmed, before this run reads or creates a team key. A registry read
// that succeeds restores it when the registry pins exactly that key, and
// removes it, refusing the name as taken, when the registry pins another; a
// private team's refusal of the read signed with that key shows the same. A
// read that fails otherwise leaves it set aside and refuses: no new key is
// created while one that may be registered is unsettled.
func settleUnconfirmedTeamKey(ctx context.Context, registry *awid.RegistryClient, registryURL, domain, name string) error {
	key, aside, err := awconfig.LoadUnconfirmedTeamKey(domain, name)
	if err != nil || key == nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	team, err := registry.GetTeam(ctx, registryURL, domain, name, key)
	var pinned error
	switch {
	case awid.IsTeamPrivateError(err):
		// A private team refuses a read signed with the set-aside key only
		// when that key is neither its key nor a member's.
		pinned = withErrorCode(codeTeamNameTaken, fmt.Errorf("team %s/%s is private and refuses a read signed with the team key this machine set aside, so another key holds it: %w\nRestore this team's controller key to reuse it, or choose another --name.", domain, name, err))
	case err != nil:
		return unconfirmedTeamNameError(domain, name, aside, err)
	case strings.TrimSpace(team.TeamDIDKey) == awid.ComputeDIDKey(pub):
		return awconfig.RestoreUnconfirmedTeamKey(domain, name)
	default:
		pinned = teamPinnedElsewhereError(domain, name, team.TeamDIDKey)
	}
	if err := awconfig.RemoveUnconfirmedTeamKey(domain, name, pub); err != nil {
		return fmt.Errorf("%w. The unconfirmed team key at %s was kept: %v", pinned, aside, err)
	}
	return pinned
}

// unconfirmedTeamNameError is the refusal when the registry has a team's name
// and a read could not say which key holds it. aside is where this machine's
// unconfirmed key waits, or "" when no key was set aside.
func unconfirmedTeamNameError(domain, name, aside string, readErr error) error {
	held := ""
	if aside != "" {
		held = fmt.Sprintf("\nThe team key this machine created is set aside at %s and is not used as the team key.", aside)
	}
	return withErrorCode(codeTeamNameUnconfirmed, fmt.Errorf("team %s/%s already exists at the registry, and reading it to confirm which key holds it failed: %w%s\nRun the same command again once the registry answers: aw restores a set-aside key the registry pins and removes one it does not.", domain, name, readErr, held))
}

// teamPinnedElsewhereError is the refusal when the registry pins a team's
// name to another key.
func teamPinnedElsewhereError(domain, name, pinnedDIDKey string) error {
	return withErrorCode(codeTeamNameTaken, fmt.Errorf("team %s/%s is already pinned to %s\nRestore its current controller key to reuse this team, or choose another --name.", domain, name, pinnedDIDKey))
}

// teamKeyForCreate returns the team key to register: the key already saved
// for the team, or a new key saved exclusively before any registry call.
// created reports that this run saved the key. When another run saved a key
// first, that key is used, so concurrent runs register one key.
func teamKeyForCreate(domain, name string) (key ed25519.PrivateKey, created bool, err error) {
	exists, err := awconfig.TeamKeyExists(domain, name)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		_, key, err = awid.GenerateKeypair()
		if err != nil {
			return nil, false, err
		}
		err = awconfig.CreateTeamKey(domain, name, key)
		if err == nil {
			return key, true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, false, err
		}
	}
	key, err = awconfig.LoadTeamKey(domain, name)
	if err != nil {
		return nil, false, err
	}
	return key, false, nil
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
		recordedAlias, readErr := resolveAliasFromIdentityAt(teamMembershipLocation{WorkingDir: opts.WorkingDir, IdentityHome: opts.IdentityHome})
		if readErr != nil {
			return teamMemberEnrollmentPlan{}, readErr
		}
		alias = recordedAlias
	}
	if alias == "" {
		return teamMemberEnrollmentPlan{}, usageError("--name is required (no identity found to derive name from)")
	}
	var err error
	alias, err = normalizeIDCreateName(alias)
	if err != nil {
		return teamMemberEnrollmentPlan{}, err
	}
	plan := teamMemberEnrollmentPlan{Name: alias, Scope: scope}
	if scope == awid.IdentityModeLocal {
		if strings.TrimSpace(opts.Address) != "" {
			return teamMemberEnrollmentPlan{}, usageError("--address requires --global")
		}
		if opts.NoAddress {
			return teamMemberEnrollmentPlan{}, usageError("--no-address requires --global")
		}
		teamState, err := loadOptionalTeamState(teamMembershipLocation{WorkingDir: opts.WorkingDir, IdentityHome: opts.IdentityHome})
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		if teamState != nil && len(teamState.Memberships) > 0 {
			return teamMemberEnrollmentPlan{}, usageError("local identities can only enroll in one team; use --first-agent-global/--global to reuse a global identity across teams, or use a fresh workspace for local")
		}
		if identity, err := resolveTeamAcceptIdentity(opts.WorkingDir, opts.IdentityHome); err == nil && strings.TrimSpace(identity.IdentityScope) == awid.IdentityModeGlobal {
			return teamMemberEnrollmentPlan{}, usageError("this workspace already has a global identity; use --global/--first-agent-global to reuse it, or use a fresh workspace for local")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return teamMemberEnrollmentPlan{}, err
		}
		mint := requireExistingMemberKey
		if opts.AllowLocalMint {
			mint = allowLocalMemberKeyMint
		}
		memberDIDKey, err := resolveOrGenerateMemberDIDKeyAt(memberKeySelection{Location: teamMembershipLocation{WorkingDir: opts.WorkingDir, IdentityHome: opts.IdentityHome}, Mint: mint})
		if err != nil {
			return teamMemberEnrollmentPlan{}, err
		}
		plan.MemberDIDKey = memberDIDKey
		return plan, nil
	}

	identity, signingKey, err := resolveGlobalIdentityForTeamAccept(opts.WorkingDir, opts.IdentityHome)
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
		if err := validateMemberAddressForCertificate(ctx, opts.Registry, opts.RegistryURL, plan.MemberAddress, plan.MemberDIDAW, plan.MemberDIDKey, signingKey); err != nil {
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

func ensureTeamAcceptScopeAllowed(workingDir, identityHome, scope string) error {
	teamState, err := loadOptionalTeamState(teamMembershipLocation{WorkingDir: workingDir, IdentityHome: identityHome})
	if err != nil {
		return err
	}
	if scope == awid.IdentityModeLocal && teamState != nil && len(teamState.Memberships) > 0 {
		return usageError("local identities can only join one team; use --global to reuse a global identity across teams, or accept this local invite in a fresh workspace")
	}
	identity, err := resolveTeamAcceptIdentity(workingDir, identityHome)
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

func resolveTeamAcceptIdentity(workingDir, identityHome string) (*awconfig.ResolvedIdentity, error) {
	if strings.TrimSpace(identityHome) != "" {
		return awconfig.ResolveIdentityFromHome(workingDir, identityHome)
	}
	return awconfig.ResolveIdentity(workingDir)
}

func resolveGlobalIdentityForTeamAccept(workingDir, identityHome string) (*awconfig.ResolvedIdentity, ed25519.PrivateKey, error) {
	identity, err := resolveTeamAcceptIdentity(workingDir, identityHome)
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

type memberKeyMintPolicy uint8

const (
	requireExistingMemberKey memberKeyMintPolicy = iota
	allowLocalMemberKeyMint
)

type memberKeySelection struct {
	Location teamMembershipLocation
	Mint     memberKeyMintPolicy
}

// resolveOrGenerateMemberDIDKeyAt preserves the selected home's custody. Only
// absence permits local creation; corrupt or unreadable state is a refusal
// (docs/cli-identity-selection.md:9-14,26-29).
func resolveOrGenerateMemberDIDKeyAt(request memberKeySelection) (string, error) {
	workingDir, identityHome := request.Location.WorkingDir, request.Location.IdentityHome
	identityPath := awconfig.WorktreeIdentityPath(workingDir)
	if strings.TrimSpace(identityHome) != "" {
		path, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "identity.yaml")
		if err != nil {
			return "", err
		}
		identityPath = path
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err == nil && strings.TrimSpace(identity.DID) != "" {
		return strings.TrimSpace(identity.DID), nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read selected member identity: %w; repair its identity.yaml and retry", err)
	}
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if strings.TrimSpace(identityHome) != "" {
		path, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "signing.key")
		if err != nil {
			return "", err
		}
		signingKeyPath = path
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err == nil {
		public, err := teamInviteSigningPublicKey(signingKey)
		if err != nil {
			return "", err
		}
		return awid.ComputeDIDKey(public), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read selected member signing key: %w; restore its original signing.key and retry", err)
	}
	if request.Mint != allowLocalMemberKeyMint {
		return "", usageError("no identity found; run `aw id create` first, or use --local invite")
	}
	public, private, err := awid.GenerateKeypair()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(identityHome) == "" {
		if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
			return "", err
		}
	}
	if err := awid.SaveSigningKeyExclusive(signingKeyPath, private); err != nil {
		return "", err
	}
	return awid.ComputeDIDKey(public), nil
}

// loadOptionalInviteIdentity reads only the caller-selected credential store.
// Corrupt or unreadable state is not absence (docs/cli-identity-selection.md:9-14).
func loadOptionalInviteIdentity(location teamMembershipLocation) (*awconfig.WorktreeIdentity, error) {
	path := awconfig.WorktreeIdentityPath(location.WorkingDir)
	if strings.TrimSpace(location.IdentityHome) != "" {
		selected, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: location.IdentityHome}, "identity.yaml")
		if err != nil {
			return nil, err
		}
		path = selected
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read selected invite identity: %w; repair its identity.yaml and retry", err)
	}
	return identity, nil
}

func resolveAliasFromIdentityAt(location teamMembershipLocation) (string, error) {
	identity, err := loadOptionalInviteIdentity(location)
	if err != nil {
		return "", err
	}
	if identity == nil || strings.TrimSpace(identity.Address) == "" {
		return "", nil
	}
	parts := strings.SplitN(identity.Address, "/", 2)
	if len(parts) == 2 {
		return parts[1], nil
	}
	return "", nil
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
