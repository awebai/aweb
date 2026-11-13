package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// A protected team's admission policy, read from the operator-provisioned
// protected service (human-assurance-contract.md section 5) as this identity.
// The read is a status: it grants no admission and creates no policy.

var teamAdmissionPolicyTeamFlag string

var teamAdmissionPolicyCmd = &cobra.Command{
	Use:   "admission-policy",
	Short: "Read a protected team's agent admission policy from its protected service",
	Long: "Read a team's agent admission policy from the protected service named by\n" +
		"--protected-profile, proving this identity's current key.\n\n" +
		"The answer says whether the team is protected or legacy and, for a protected\n" +
		"team, the immutable policy version and digest an admission binds. A protected\n" +
		"team without a policy refuses admission_policy_missing: the operator provisions\n" +
		"or approves one; aw never creates it. A read that cannot be answered refuses\n" +
		"receipt_unavailable and never means the team has no policy.",
	Args: cobra.NoArgs,
	RunE: runTeamAdmissionPolicy,
}

func init() {
	teamAdmissionPolicyCmd.Flags().StringVar(&teamAdmissionPolicyTeamFlag, "team", "", "The team (name:domain) whose policy to read; the profile must bind its controller")
	teamAdmissionPolicyCmd.Flags().StringVar(&appProtectedProfileFlag, "protected-profile", "", "The operator-provisioned protected-service profile to read the policy from (default: AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home)")
	teamCmd.AddCommand(teamAdmissionPolicyCmd)
}

// admissionPolicyScope is the policy read's exact scope: this service and
// team, nothing else.
func admissionPolicyScope(profile *handoff.Profile, team string) map[string]any {
	return map[string]any{"service_id": profile.ServiceID, "team_id": team}
}

// admissionPolicyReport reads team's policy and reports it complete, with the
// version and digest an admission binds; a protected team without a policy
// refuses.
func admissionPolicyReport(ctx context.Context, opts handoff.GovernanceOptions, profile *handoff.Profile, team string) (map[string]any, error) {
	read, err := handoff.ReadAdmissionPolicy(ctx, opts, profile.ServiceID, team)
	if err != nil {
		return nil, err
	}
	policy, err := read.RequireAdmissionPolicy()
	if err != nil {
		return nil, err
	}
	report := map[string]any{"service_id": read.ServiceID, "team_id": read.TeamID, "mode": read.Mode, "policy": nil}
	if policy != nil {
		report["policy"] = policy.Fields
	}
	return report, nil
}

func runTeamAdmissionPolicy(cmd *cobra.Command, _ []string) error {
	team := strings.TrimSpace(teamAdmissionPolicyTeamFlag)
	if team == "" {
		return usageError("--team is required")
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	opts := handoff.GovernanceOptions{
		Request: profile.RequestOrigin,
		Sign:    protectedRequesterSigner(profile, admissionPolicyScope(profile, team), identity),
	}
	report, err := admissionPolicyReport(cmd.Context(), opts, profile, team)
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return withErrorCode(code, fmt.Errorf("team %s: %w", team, err))
		}
		return err
	}
	printOutput(report, func(any) string {
		policy, _ := report["policy"].(map[string]any)
		if policy == nil {
			return fmt.Sprintf("Team %s is %s at %s, with no admission policy.\n", team, report["mode"], profile.ServiceID)
		}
		return fmt.Sprintf("Team %s is protected at %s by admission policy version %v\n  digest: %s\n", team, profile.ServiceID, policy["version"], policy["digest"])
	})
	return nil
}
