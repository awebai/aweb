package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type teamRequestOutput struct {
	Command       string `json:"command"`
	TeamID        string `json:"team_id"`
	Team          string `json:"team"`
	Domain        string `json:"domain"`
	DIDKey        string `json:"did_key"`
	Alias         string `json:"alias"`
	DIDAW         string `json:"did_aw,omitempty"`
	Address       string `json:"address,omitempty"`
	Status        string `json:"status,omitempty"`
	IdentityScope string `json:"identity_scope,omitempty"`
	Custody       string `json:"custody,omitempty"`
	IdentityHome  string `json:"identity_home,omitempty"`
	KeyCreated    *bool  `json:"key_created,omitempty"`
}

var (
	teamRequestTeamID         string
	teamRequestAlias          string
	teamRequestCreateLocalKey bool
)

var teamRequestCmd = &cobra.Command{
	Annotations: map[string]string{identityKeyPreparationAnnotation: "create-local-key"},
	Long: `Print the public add-member command for the team controller.

On a fresh worker, --create-local-key prepares a self-custodial local key
without contacting a registry or server. It accepts only an empty identity
home or a valid signing.key alone; retries reuse that key. Existing identity
state must use request without the flag. Select the current directory's .aw
or an explicit absolute --identity-home; an inherited AWEB_IDENTITY_HOME is
not a preparation destination. Unsafe or symlinked paths refuse.

Preparation writes only signing.key (0600). It grants no membership, address
or global identity. JSON adds status=prepared, identity_scope=local,
custody=self, identity_home and key_created. The home is a custody locator,
not a security boundary.

Have the controller run the printed add-member command, then use its
certificate ID with id team fetch-cert on this machine, selecting the same
identity home. Connect afterward with aw workspace connect --service <url>.
Without --create-local-key, request remains read-only and requires an
existing signing key.`,
	Use:   "request",
	Short: "Protocol/admin bridge: print the add-member command the team owner should run",
	RunE:  runTeamRequest,
}

func init() {
	teamRequestCmd.Flags().StringVar(&teamRequestTeamID, "team", "", "Canonical team ID (<name>:<domain>)")
	teamRequestCmd.Flags().StringVar(&teamRequestAlias, "name", "", "Suggested member name for the new team membership")
	teamRequestCmd.Flags().StringVar(&teamRequestAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(teamRequestCmd, "alias", "name")
	teamRequestCmd.Flags().BoolVar(&teamRequestCreateLocalKey, "create-local-key", false, "Prepare a local key in an empty or key-only identity home; membership still requires controller approval")
	teamCmd.AddCommand(teamRequestCmd)
}

func runTeamRequest(cmd *cobra.Command, args []string) error {
	teamID := strings.TrimSpace(teamRequestTeamID)
	alias := strings.TrimSpace(teamRequestAlias)
	if teamID == "" {
		return usageError("--team is required")
	}
	if alias == "" {
		return usageError("--name is required")
	}
	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return usageError("invalid --team %q: %v", teamID, err)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if home.External() {
		signingKeyPath, err = awconfig.IdentityHomePath(home, "signing.key")
		if err != nil {
			return err
		}
	}
	var keyCreated bool
	if teamRequestCreateLocalKey {
		keyCreated, err = prepareTeamRequestKey(home)
		if err != nil {
			return err
		}
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return usageError("current identity has no local signing key")
		}
		return fmt.Errorf("load signing key: %w", err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))

	commandParts := []string{
		"aw", "id", "team", "add-member",
		"--team", teamName,
		"--namespace", teamDomain,
		"--did", didKey,
		"--name", alias,
	}

	out := teamRequestOutput{
		TeamID: teamID,
		Team:   teamName,
		Domain: teamDomain,
		DIDKey: didKey,
		Alias:  alias,
	}

	if teamRequestCreateLocalKey {
		out.Status = "prepared"
		out.IdentityScope = awid.IdentityModeLocal
		out.Custody = awid.CustodySelf
		out.IdentityHome = home.Root
		out.KeyCreated = &keyCreated
	}

	identity, err := loadOptionalTeamRequestIdentityAt(workingDir, externalIdentityHomeRoot(home))
	if err != nil {
		return err
	}
	if identity != nil && strings.TrimSpace(identity.IdentityScope) == awid.IdentityModeGlobal {
		stableID := strings.TrimSpace(identity.StableID)
		address := strings.TrimSpace(identity.Address)
		if stableID == "" || address == "" {
			return usageError("current global identity is missing stable_id or address; restore .aw/identity.yaml or run `aw id create` again")
		}
		commandParts = append(commandParts,
			"--global",
			"--did-aw", stableID,
			"--address", address,
		)
		out.DIDAW = stableID
		out.Address = address
	}

	out.Command = strings.Join(commandParts, " ")
	printOutput(out, formatTeamRequest)
	return nil
}

func loadOptionalTeamRequestIdentity(workingDir string) (*awconfig.ResolvedIdentity, error) {
	return loadOptionalTeamRequestIdentityAt(workingDir, "")
}

func loadOptionalTeamRequestIdentityAt(workingDir, identityHome string) (*awconfig.ResolvedIdentity, error) {
	var identity *awconfig.ResolvedIdentity
	var err error
	if strings.TrimSpace(identityHome) != "" {
		identity, err = awconfig.ResolveIdentityFromHome(workingDir, identityHome)
	} else {
		identity, err = awconfig.ResolveIdentity(workingDir)
	}
	if err == nil {
		if err := validateResolvedIdentity(identity); err != nil {
			return nil, err
		}
		return identity, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}

func formatTeamRequest(v any) string {
	out := v.(teamRequestOutput)
	if out.Status == "prepared" {
		return "Local signing key prepared; team membership pending controller approval\n" + out.DIDKey + "\n" + strings.TrimSpace(out.Command) + "\n"
	}
	return strings.TrimSpace(out.Command) + "\n"
}

// prepareTeamRequestKey accepts only an empty destination or a valid key alone.
// It grants no membership and does not initialize a connected identity.
func prepareTeamRequestKey(home awconfig.IdentityHome) (bool, error) {
	if home.Source == awconfig.IdentityHomeEnvVar {
		return false, usageError("--create-local-key requires the current directory or an explicit --identity-home, not inherited AWEB_IDENTITY_HOME")
	}
	path, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return false, err
	}
	exists, err := teamRequestKeyOnly(home.Root, path)
	if err != nil || exists {
		return false, err
	}
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		return false, err
	}
	if err := awid.SaveSigningKeyExclusive(path, key); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Another preparer won. Never overwrite it or treat a partial/malformed
			// key (or any additional identity state) as a successful preparation.
			if valid, checkErr := teamRequestKeyOnly(home.Root, path); checkErr != nil {
				return false, checkErr
			} else if valid {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func teamRequestKeyOnly(root, keyPath string) (bool, error) {
	refuse := func() error {
		return usageError("--create-local-key requires an empty identity home or a valid signing.key alone; use `aw id team request` without --create-local-key for an existing identity")
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(entries) == 0 {
		return false, nil
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(keyPath) {
		return false, refuse()
	}
	if _, err := awid.LoadSigningKey(keyPath); err != nil {
		return false, refuse()
	}
	return true, nil
}
