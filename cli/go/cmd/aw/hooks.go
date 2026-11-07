package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
	"github.com/spf13/cobra"
)

// ownerActLifetime is how long an act the CLI signs stays valid: long enough
// to reach the server, well inside the contract's ten-minute bound.
const ownerActLifetime = 5 * time.Minute

var hooksCmd = &cobra.Command{
	Use:   "hooks",
	Short: "Read the team's app hook bindings and activate or revoke them as the team owner",
	Long: "Read the team's app hook bindings and activate or revoke them as the team owner.\n" +
		"Activation and revocation are aweb.owner-act/1 acts signed with the team's controller key,\n" +
		"which only the team owner holds.",
}

func init() {
	bindingsCmd := &cobra.Command{
		Use:   "bindings <app-id>",
		Short: "List an installed app's hook bindings in the selected team",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID, err := installedAppID(args[0])
			if err != nil {
				return err
			}
			client, selection, err := resolveClientSelection()
			if err != nil {
				return err
			}
			ctx, cancel := commandAPIContext(cmd)
			defer cancel()
			listed, err := listHookBindings(ctx, client, selection.TeamID, appID)
			if err != nil {
				return err
			}
			printOutput(listed, formatHookBindings)
			return nil
		},
	}
	hooksCmd.GroupID = groupUtility
	hooksCmd.AddCommand(bindingsCmd,
		hookOwnerActCmd("activate", "hook-binding.activate", "Activate a pending hook binding as the team owner"),
		hookOwnerActCmd("revoke", "hook-binding.revoke", "Revoke a pending or active hook binding as the team owner"))
	rootCmd.AddCommand(hooksCmd)
}

func hookOwnerActCmd(verb, act, short string) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   verb + " <app-id> <binding-id>",
		Short: short,
		Long: short + ".\n" +
			"The binding is checked against the app manifest fetched from its origin at its pinned digest,\n" +
			"and what will be signed is shown before the team's controller key signs it.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID, err := installedAppID(args[0])
			if err != nil {
				return err
			}
			return runHookOwnerAct(cmd, act, appID, strings.TrimSpace(args[1]), yes)
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Sign without asking for confirmation (what is signed is still shown)")
	return cmd
}

type hookBindingsOutput struct {
	TeamID   string        `json:"team_id"`
	Bindings []hookBinding `json:"bindings"`
}

func listHookBindings(ctx context.Context, client *aweb.Client, teamID, appID string) (*hookBindingsOutput, error) {
	var listed hookBindingsOutput
	query := "?team_id=" + url.QueryEscape(teamID) + "&app_id=" + url.QueryEscape(appID)
	if err := client.Get(ctx, "/v1/apps/hook-bindings"+query, &listed); err != nil {
		return nil, fmt.Errorf("read hook bindings: %w", err)
	}
	return &listed, nil
}

func runHookOwnerAct(cmd *cobra.Command, act, appID, bindingID string, yes bool) error {
	client, selection, err := resolveClientSelection()
	if err != nil {
		return err
	}
	audience, err := ownerActAudience(selection.BaseURL)
	if err != nil {
		return err
	}
	teamKey, err := loadOwnerTeamKey(selection.TeamID)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	listed, err := listHookBindings(ctx, client, selection.TeamID, appID)
	if err != nil {
		return err
	}
	var binding *hookBinding
	for i := range listed.Bindings {
		if listed.Bindings[i].BindingID == bindingID {
			binding = &listed.Bindings[i]
		}
	}
	if binding == nil {
		return withErrorCode("binding_not_found", fmt.Errorf("%s has no hook binding %s in team %s", appID, bindingID, selection.TeamID))
	}
	live := binding.State == "pending" || (act == "hook-binding.revoke" && binding.State == "active")
	if !live {
		return withErrorCode("binding_not_live", fmt.Errorf("binding %s is %s", binding.BindingID, binding.State))
	}
	variant, err := discoverManifest(binding.Origin)
	if err != nil {
		return manifestError(err)
	}
	if variant.Digest != binding.Digest {
		return withErrorCode("binding_manifest_mismatch", fmt.Errorf("%s serves manifest %s, not the %s this binding pins; update the app installation", binding.Origin, variant.Digest, binding.Digest))
	}
	resolved, err := appmanifest.Load(variant.Bytes, nil)
	if err != nil {
		return manifestError(err)
	}
	subject, err := hookBindingSubject(*binding, resolved)
	if err != nil {
		return err
	}
	fields, err := newOwnerAct(act, selection.TeamID, audience, teamKey, subject, time.Now())
	if err != nil {
		return err
	}
	// Refuse an act a verifier would refuse before asking the owner to sign it.
	if _, err := awid.OwnerActSigningBytes(fields); err != nil {
		return err
	}
	stderr := cmd.ErrOrStderr()
	fmt.Fprint(stderr, formatHookOwnerAct(fields, *binding))
	if err := confirmOwnerAct(yes, cmd.InOrStdin(), stderr); err != nil {
		return err
	}
	signing, signature, err := awid.SignOwnerAct(teamKey, fields)
	if err != nil {
		return err
	}
	verb := strings.TrimPrefix(act, "hook-binding.")
	var result hookBinding
	body := map[string]string{"act": base64.StdEncoding.EncodeToString(signing), "signature": signature}
	if err := client.Post(ctx, "/v1/apps/hook-bindings/"+url.PathEscape(binding.BindingID)+"/"+verb, body, &result); err != nil {
		return fmt.Errorf("%s hook binding: %w", verb, err)
	}
	printOutput(result, func(value any) string {
		b := value.(hookBinding)
		return fmt.Sprintf("Binding %s is %s.\n", b.BindingID, b.State)
	})
	return nil
}

// loadOwnerTeamKey is the team's controller key from this machine's AWID
// state: the custody under which a team owner signs owner acts. A member
// without it cannot sign one.
func loadOwnerTeamKey(teamID string) (ed25519.PrivateKey, error) {
	domain, name, err := awid.ParseTeamID(strings.TrimSpace(teamID))
	if err != nil {
		return nil, err
	}
	key, err := awconfig.LoadTeamKey(domain, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, withErrorCode("owner_key_required", fmt.Errorf("only the owner of team %s can sign this; its controller key is not held here", teamID))
	}
	if err != nil {
		return nil, fmt.Errorf("load the controller key of team %s: %w", teamID, err)
	}
	return key, nil
}

// newOwnerAct is the unsigned aweb.owner-act/1 for subject, naming the
// team's controller key as its signer, with a fresh nonce.
func newOwnerAct(act, teamID, audience string, teamKey ed25519.PrivateKey, subject map[string]any, now time.Time) (map[string]any, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	issued := now.UTC().Truncate(time.Second)
	return map[string]any{
		"v": 1, "type": "aweb.owner-act", "act": act, "team_id": teamID, "aud": audience,
		"team_key_did": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)), "subject": subject,
		"issued_at": issued.Format(time.RFC3339), "expires_at": issued.Add(ownerActLifetime).Format(time.RFC3339),
		"nonce": hex.EncodeToString(nonce),
	}, nil
}

// confirmOwnerAct asks the owner to sign what was just shown. Without a
// terminal to ask on, only an explicit --yes signs.
func confirmOwnerAct(yes bool, in io.Reader, out io.Writer) error {
	if yes {
		return nil
	}
	if readerIsNonTerminalFile(in) {
		return withErrorCode("confirmation_required", usageError("there is no terminal to confirm on; rerun with --yes to sign what is shown above"))
	}
	sign, err := promptYesNoWithIO("Sign this owner act?", false, in, out)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return withErrorCode("confirmation_required", usageError("no confirmation was given; rerun with --yes to sign what is shown above"))
		}
		return err
	}
	if !sign {
		return withErrorCode("owner_act_declined", usageError("nothing was signed"))
	}
	return nil
}

func formatHookOwnerAct(fields map[string]any, binding hookBinding) string {
	subject := fields["subject"].(map[string]any)
	var b strings.Builder
	fmt.Fprintf(&b, "Owner act %s for team %s\n", fields["act"], fields["team_id"])
	fmt.Fprintf(&b, "  verifier:  %s\n", fields["aud"])
	fmt.Fprintf(&b, "  signer:    %s\n", fields["team_key_did"])
	fmt.Fprintf(&b, "  app:       %s at %s\n", subject["app_id"], subject["origin"])
	fmt.Fprintf(&b, "  manifest:  %s (fetched from the origin and checked)\n", subject["digest"])
	fmt.Fprintf(&b, "  binding:   %s, %s of installation %s generation %d\n", subject["binding_id"], subject["kind"], subject["installation_id"], subject["generation"])
	fmt.Fprintf(&b, "  hook:      %s/%d %s\n", subject["catalog_id"], subject["catalog_version"], subject["hook"])
	if binding.Kind == "registration" {
		fmt.Fprintf(&b, "  target:    tool %s, %s %s\n", subject["tool"], subject["method"], subject["path"])
		fmt.Fprintf(&b, "  scopes:    %s\n", joinOwnerActList(subject["scopes"]))
	} else {
		fmt.Fprintf(&b, "  reads:     %s\n", joinOwnerActList(subject["reads"]))
	}
	fmt.Fprintf(&b, "  valid:     %s to %s\n", fields["issued_at"], fields["expires_at"])
	return b.String()
}

func joinOwnerActList(value any) string {
	items, _ := value.([]any)
	if len(items) == 0 {
		return "(none)"
	}
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = fmt.Sprint(item)
	}
	return strings.Join(names, ", ")
}

func formatHookBindings(value any) string {
	listed := value.(*hookBindingsOutput)
	if len(listed.Bindings) == 0 {
		return fmt.Sprintf("No hook bindings in team %s.\n", listed.TeamID)
	}
	var b strings.Builder
	for _, binding := range listed.Bindings {
		fmt.Fprintf(&b, "%s  %-8s %-12s %s/%d %s", binding.BindingID, binding.State, binding.Kind, binding.CatalogID, binding.CatalogVersion, binding.Hook)
		if binding.Kind == "registration" {
			fmt.Fprintf(&b, " -> %s (%s %s) scopes: %s", binding.Tool, binding.Method, binding.Path, strings.Join(binding.Scopes, ", "))
		} else {
			fmt.Fprintf(&b, " reads: %s", strings.Join(binding.Reads, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// hookBinding is one row of the team server's hook bindings, as
// GET /v1/apps/hook-bindings returns it.
type hookBinding struct {
	BindingID      string   `json:"binding_id"`
	Kind           string   `json:"kind"`
	TeamID         string   `json:"team_id"`
	InstallationID string   `json:"installation_id"`
	Generation     int64    `json:"generation"`
	AppID          string   `json:"app_id"`
	Origin         string   `json:"origin"`
	Digest         string   `json:"digest"`
	CatalogID      string   `json:"catalog_id"`
	CatalogVersion int64    `json:"catalog_version"`
	Hook           string   `json:"hook"`
	Tool           string   `json:"tool"`
	Method         string   `json:"method"`
	Path           string   `json:"path"`
	Scopes         []string `json:"scopes"`
	Reads          []string `json:"reads"`
	State          string   `json:"state"`
	EndedBy        string   `json:"ended_by,omitempty"`
	ActivatedAt    string   `json:"activated_at,omitempty"`
	ActiveFrom     string   `json:"active_from,omitempty"`
	RevokedAt      string   `json:"revoked_at,omitempty"`
}

// hookBindingSubject is the aweb.owner-act/1 subject for binding, built from
// the app's digest-pinned manifest. The server's row supplies only what the
// manifest cannot: the binding and installation identity. Every declared fact
// is taken from the manifest and must equal the row, so the owner signs what
// the app declared and never a row that disagrees with it. Scopes and reads
// are sorted by code point and distinct, as the contract requires.
func hookBindingSubject(binding hookBinding, resolved *appmanifest.Resolved) (map[string]any, error) {
	if binding.InstallationID == "" || binding.Generation <= 0 {
		return nil, withErrorCode("installation_identity_required", fmt.Errorf("binding %s has no installation identity yet", binding.BindingID))
	}
	mismatch := func(format string, args ...any) error {
		return withErrorCode("binding_manifest_mismatch", fmt.Errorf("binding %s: "+format, append([]any{binding.BindingID}, args...)...))
	}
	if resolved.AppID != binding.AppID || resolved.Manifest.App.Origin != binding.Origin {
		return nil, mismatch("the manifest is for %s at %s", resolved.AppID, resolved.Manifest.App.Origin)
	}
	subject := map[string]any{
		"binding_id": binding.BindingID, "installation_id": binding.InstallationID, "generation": binding.Generation,
		"app_id": binding.AppID, "origin": binding.Origin, "digest": binding.Digest, "kind": binding.Kind,
		"catalog_id": binding.CatalogID, "catalog_version": binding.CatalogVersion, "hook": binding.Hook,
	}
	declares := func(id string, version int, hook string) bool {
		return id == binding.CatalogID && int64(version) == binding.CatalogVersion && hook == binding.Hook
	}
	var hooks appmanifest.ResolvedHooks
	if resolved.Hooks != nil {
		hooks = *resolved.Hooks
	}
	switch binding.Kind {
	case "registration":
		for _, reg := range hooks.Registrations {
			if !declares(reg.CatalogID, reg.CatalogVersion, reg.Hook) || reg.Tool != binding.Tool {
				continue
			}
			tool, ok := resolved.Tool(reg.Tool)
			if !ok {
				return nil, mismatch("the manifest declares no tool %s", reg.Tool)
			}
			scopes := ownerActNames(reg.Scopes)
			if tool.Method != binding.Method || tool.Path != binding.Path || !reflect.DeepEqual(scopes, ownerActNames(binding.Scopes)) {
				return nil, mismatch("the server's target or scopes differ from the manifest")
			}
			subject["tool"], subject["method"], subject["path"] = reg.Tool, tool.Method, tool.Path
			subject["scopes"] = ownerActList(scopes)
			return subject, nil
		}
	case "production":
		for _, prod := range hooks.Productions {
			if !declares(prod.CatalogID, prod.CatalogVersion, prod.Hook) {
				continue
			}
			reads := ownerActNames(prod.Reads)
			if !reflect.DeepEqual(reads, ownerActNames(binding.Reads)) {
				return nil, mismatch("the server's reads differ from the manifest")
			}
			subject["reads"] = ownerActList(reads)
			return subject, nil
		}
	}
	return nil, mismatch("the manifest declares no %s for %s/%d %s", binding.Kind, binding.CatalogID, binding.CatalogVersion, binding.Hook)
}

// ownerActNames sorts names by code point and drops repeats.
func ownerActNames(names []string) []string {
	out := append([]string{}, names...)
	sort.Strings(out)
	distinct := out[:0]
	for i, name := range out {
		if i == 0 || name != out[i-1] {
			distinct = append(distinct, name)
		}
	}
	return distinct
}

func ownerActList(names []string) []any {
	out := make([]any, len(names))
	for i, name := range names {
		out[i] = name
	}
	return out
}

// ownerActAudience is the origin of the aweb server the owner's own
// configuration selects: the one verifier the act is for. Owner acts name
// only https audiences, so a server reached over http cannot verify one.
func ownerActAudience(serverURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid aweb server URL %q", serverURL)
	}
	if u.Scheme != "https" {
		return "", withErrorCode("owner_act_requires_https", fmt.Errorf("owner acts are verified only by an https aweb server; %s is %s", u.Host, u.Scheme))
	}
	return "https://" + strings.ToLower(u.Host), nil
}
