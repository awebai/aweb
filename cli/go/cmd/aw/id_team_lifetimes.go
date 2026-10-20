package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var lifetimeFields = []string{"member_certificate", "ephemeral_certificate", "identity_grant", "hosted_mcp_grant"}

func init() {
	lifetimes := &cobra.Command{Use: "lifetimes", Short: "Controller: show or set the team's optional credential lifetimes"}
	for _, action := range []string{"show", "set"} {
		action := action
		command := &cobra.Command{Use: action, Args: cobra.NoArgs, Short: action + " the team credential lifetime policy", RunE: func(cmd *cobra.Command, args []string) error {
			return runTeamLifetimes(cmd, action)
		}}
		command.Flags().String("team", "", "Team name")
		command.Flags().String("namespace", "", "Namespace domain")
		command.Flags().String("registry", "", "AWID registry origin")
		if action == "set" {
			command.Long = "Publish a complete policy signed by the local team controller. Supply all four limits\n" +
				"as durations (for example 24h) or 'none'. Unset team policies have no expiry.\n" +
				"Grant changes take effect within a minute and may end existing over-limit grants.\n" +
				"Certificate limits trigger controller renewal; existing signed deadlines never extend.\n" +
				"This also repairs a policy stranded on an old key after a non-atomic rotation.\n" +
				"Every value must be explicit; no values from an unverified record are reused."
			for _, field := range lifetimeFields {
				command.Flags().String(strings.ReplaceAll(field, "_", "-"), "", "Duration or none (required)")
			}
		}
		lifetimes.AddCommand(command)
	}
	teamCmd.AddCommand(lifetimes)
}

func runTeamLifetimes(cmd *cobra.Command, action string) error {
	domain, _ := cmd.Flags().GetString("namespace")
	name, _ := cmd.Flags().GetString("team")
	domain, name = strings.TrimSpace(domain), strings.TrimSpace(name)
	if domain == "" || name == "" {
		return usageError("--team and --namespace are required")
	}
	key, err := loadReissueCertController(domain, name)
	if err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	origin, _ := cmd.Flags().GetString("registry")
	if origin == "" {
		if meta, err := awconfig.LoadControllerMeta(domain); err == nil && meta != nil {
			origin = meta.RegistryURL
		}
	}
	if origin == "" {
		origin = registry.DefaultRegistryURL
	}
	if err := registry.SetFallbackRegistryURL(origin); err != nil {
		return err
	}
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	team, err := registry.GetTeam(cmd.Context(), origin, domain, name, key)
	if err != nil {
		return err
	}
	if team.TeamID != awid.BuildTeamID(domain, name) || team.TeamDIDKey != did {
		return fmt.Errorf("local controller is not the team's current key")
	}
	var record map[string]any
	if action == "show" {
		record, err = registry.GetTeamCredentialPolicy(cmd.Context(), origin, domain, name, did)
		if err != nil {
			return fmt.Errorf("authority_unavailable: policy does not verify under the current controller; repair with lifetimes set and all four explicit limits: %w", err)
		}
	} else {
		record = map[string]any{"v": 1, "type": "aweb.team-credential-policy", "team_id": team.TeamID, "team_did_key": did, "issued_at": time.Now().UTC().Format("2006-01-02T15:04:05Z")}
		for _, field := range lifetimeFields {
			flag := strings.ReplaceAll(field, "_", "-")
			if !cmd.Flags().Changed(flag) {
				return usageError("--%s is required; use none for no limit", flag)
			}
			raw, _ := cmd.Flags().GetString(flag)
			if strings.EqualFold(strings.TrimSpace(raw), "none") {
				record[field] = nil
				continue
			}
			duration, parseErr := time.ParseDuration(raw)
			if parseErr != nil || duration < time.Second || duration%time.Second != 0 || duration/time.Second > math.MaxInt32 {
				return usageError("--%s must be none or a positive whole-second duration", flag)
			}
			record[field] = int64(duration / time.Second)
		}
		revision, readErr := registry.TeamCredentialPolicyRevision(cmd.Context(), origin, domain, name)
		if readErr != nil {
			return readErr
		}
		record["revision"] = revision + 1
		if err = registry.SetTeamCredentialPolicy(cmd.Context(), origin, domain, name, record, key); err != nil {
			return err
		}
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"team_id": team.TeamID, "record": record})
	}
	if record == nil {
		fmt.Fprintln(cmd.OutOrStdout(), "No limits (no team policy)")
		return nil
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}
