package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type doctorStatus string
type doctorMode string
type doctorSource string
type doctorAuthority string

const (
	doctorVersion = "doctor.v1"

	doctorStatusOK      doctorStatus = "ok"
	doctorStatusInfo    doctorStatus = "info"
	doctorStatusWarn    doctorStatus = "warn"
	doctorStatusFail    doctorStatus = "fail"
	doctorStatusUnknown doctorStatus = "unknown"
	doctorStatusBlocked doctorStatus = "blocked"

	doctorModeAuto    doctorMode = "auto"
	doctorModeOffline doctorMode = "offline"
	doctorModeOnline  doctorMode = "online"

	doctorSourceLocal     doctorSource = "local"
	doctorSourceAweb      doctorSource = "aweb"
	doctorSourceAwid      doctorSource = "awid"
	doctorSourceAwebCloud doctorSource = "aweb-cloud"
	doctorSourceDashboard doctorSource = "dashboard"

	doctorAuthorityAnonymous           doctorAuthority = "anonymous"
	doctorAuthorityCaller              doctorAuthority = "caller"
	doctorAuthorityTeamAdmin           doctorAuthority = "team-admin"
	doctorAuthorityOrgAdmin            doctorAuthority = "org-admin"
	doctorAuthorityNamespaceController doctorAuthority = "namespace-controller"
	doctorAuthoritySupport             doctorAuthority = "support"
	doctorAuthorityService             doctorAuthority = "service"
)

var (
	doctorVerbose bool
	doctorOffline bool
	doctorOnline  bool
	doctorFixFlag bool
	doctorDryRun  bool

	doctorSupportBundleOutput string
)

var doctorCmd = &cobra.Command{
	Use:   "doctor [check-id]",
	Short: "Diagnose local identity, workspace, and coordination state",
	Args:  cobra.RangeArgs(0, 1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 && !doctorFixFlag {
			return usageError("check-id arguments are only supported with --fix")
		}
		fixTarget := ""
		if len(args) > 0 {
			fixTarget = args[0]
		}
		return runDoctorCommand(cmd, doctorRunOptions{
			Categories: []string{"local", "identity", "workspace", "team", "registry", "messaging"},
			Mode:       selectedDoctorMode(),
			Verbose:    doctorVerbose,
			Fix:        doctorFixFlag,
			DryRun:     doctorDryRun,
			FixTarget:  fixTarget,
		})
	},
}

var doctorSupportBundleCmd = &cobra.Command{
	Use:   "support-bundle",
	Short: "Write a redacted doctor support bundle",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(doctorSupportBundleOutput) == "" {
			return usageError("--output is required")
		}
		return runDoctorSupportBundle(cmd, doctorRunOptions{
			Categories: []string{"local", "identity", "workspace", "team", "registry", "messaging"},
			Mode:       selectedDoctorMode(),
			Verbose:    doctorVerbose,
		})
	},
}

type doctorRunOptions struct {
	Categories []string
	Mode       doctorMode
	Verbose    bool
	Fix        bool
	DryRun     bool
	FixTarget  string
}

type doctorOutput struct {
	Version       string                   `json:"version"`
	GeneratedAt   string                   `json:"generated_at"`
	Status        doctorStatus             `json:"status"`
	Mode          doctorMode               `json:"mode"`
	Subject       doctorSubject            `json:"subject"`
	Checks        []doctorCheck            `json:"checks"`
	Redactions    []doctorRedaction        `json:"redactions"`
	SupportBundle *doctorSupportBundleInfo `json:"support_bundle,omitempty"`
	Fixes         []doctorFixPlan          `json:"fixes,omitempty"`
}

type doctorSubject struct {
	WorkingDir   string `json:"working_dir"`
	AwebURL      string `json:"aweb_url,omitempty"`
	TeamID       string `json:"team_id,omitempty"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
	Alias        string `json:"alias,omitempty"`
	Lifetime     string `json:"lifetime,omitempty"`
	IdentityPath string `json:"identity_path,omitempty"`
}

type doctorCheck struct {
	ID            string          `json:"id"`
	Status        doctorStatus    `json:"status"`
	Source        doctorSource    `json:"source"`
	Authority     doctorAuthority `json:"authority"`
	Target        *doctorTarget   `json:"target,omitempty"`
	Authoritative bool            `json:"authoritative"`
	Message       string          `json:"message"`
	Detail        map[string]any  `json:"detail,omitempty"`
	NextStep      string          `json:"next_step,omitempty"`
	Fix           *doctorFixInfo  `json:"fix,omitempty"`
	Handoff       *doctorHandoff  `json:"handoff,omitempty"`
}

type doctorTarget struct {
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
	Display string `json:"display,omitempty"`
}

type doctorFixInfo struct {
	Available bool   `json:"available"`
	Safe      bool   `json:"safe"`
	Command   string `json:"command,omitempty"`
	DryRun    bool   `json:"dry_run,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type doctorAuthorityStatus string

const (
	doctorAuthorityStatusPresent       doctorAuthorityStatus = "present"
	doctorAuthorityStatusNotDetected   doctorAuthorityStatus = "not_detected"
	doctorAuthorityStatusUnknown       doctorAuthorityStatus = "unknown"
	doctorAuthorityStatusNotApplicable doctorAuthorityStatus = "not_applicable"
)

type doctorHandoff struct {
	Action                  string                `json:"action"`
	RequiredAuthority       doctorAuthority       `json:"required_authority"`
	CallerAuthorityStatus   doctorAuthorityStatus `json:"caller_authority_status"`
	CallerAuthorityEvidence []string              `json:"caller_authority_evidence,omitempty"`
	ExpectedAction          string                `json:"expected_action,omitempty"`
	ExplicitCommand         string                `json:"explicit_command,omitempty"`
	DryRunCommand           string                `json:"dry_run_command,omitempty"`
	DashboardAction         string                `json:"dashboard_action,omitempty"`
	Consequences            []string              `json:"consequences,omitempty"`
	DoctorRefusalReason     string                `json:"doctor_refusal_reason"`
	ReplacementGuidance     string                `json:"replacement_guidance,omitempty"`
	SupportRunbookRef       string                `json:"support_runbook_ref,omitempty"`
}

type doctorRedaction struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func init() {
	doctorCmd.PersistentFlags().BoolVar(&doctorVerbose, "verbose", false, "Include verbose diagnostic details")
	doctorCmd.PersistentFlags().BoolVar(&doctorOffline, "offline", false, "Run without network checks")
	doctorCmd.PersistentFlags().BoolVar(&doctorOnline, "online", false, "Allow online checks")
	doctorCmd.Flags().BoolVar(&doctorFixFlag, "fix", false, "Apply safe doctor fixes")
	doctorCmd.Flags().BoolVar(&doctorDryRun, "dry-run", false, "Plan fixes without applying them")

	for _, category := range []string{"local", "identity", "workspace", "team", "registry", "messaging"} {
		category := category
		doctorCmd.AddCommand(&cobra.Command{
			Use:   category,
			Short: fmt.Sprintf("Run %s doctor checks", category),
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runDoctorCommand(cmd, doctorRunOptions{
					Categories: []string{category},
					Mode:       selectedDoctorMode(),
					Verbose:    doctorVerbose,
				})
			},
		})
	}

	doctorSupportBundleCmd.Flags().StringVar(&doctorSupportBundleOutput, "output", "", "Output JSON file")
	doctorCmd.AddCommand(doctorSupportBundleCmd)
	rootCmd.AddCommand(doctorCmd)
}

func selectedDoctorMode() doctorMode {
	if doctorOffline {
		return doctorModeOffline
	}
	if doctorOnline {
		return doctorModeOnline
	}
	return doctorModeAuto
}

func validateDoctorModeFlags() error {
	if doctorOffline && doctorOnline {
		return usageError("--offline and --online are mutually exclusive")
	}
	if doctorDryRun && !doctorFixFlag {
		return usageError("--dry-run requires --fix")
	}
	return nil
}

func runDoctorCommand(cmd *cobra.Command, opts doctorRunOptions) error {
	if err := validateDoctorModeFlags(); err != nil {
		return err
	}
	out := buildDoctorOutput(opts)
	printOutput(out, formatDoctorOutput)
	return nil
}

func runDoctorSupportBundle(cmd *cobra.Command, opts doctorRunOptions) error {
	if err := validateDoctorModeFlags(); err != nil {
		return err
	}
	out, knownSecrets, err := buildDoctorSupportBundle(opts)
	if err != nil {
		return err
	}
	outputPath := filepath.Clean(strings.TrimSpace(doctorSupportBundleOutput))
	if err := writeDoctorSupportBundleFile(outputPath, out, knownSecrets); err != nil {
		return err
	}
	if jsonFlag {
		printOutput(out, formatDoctorOutput)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Wrote doctor support bundle to %s\n", outputPath)
	return nil
}

func writeDoctorSupportBundleFile(outputPath string, out doctorOutput, knownSecrets []doctorKnownSecret) error {
	data, err := marshalDoctorSupportBundle(out, knownSecrets)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0o600)
}

func marshalDoctorSupportBundle(out doctorOutput, knownSecrets []doctorKnownSecret) ([]byte, error) {
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := scanDoctorSupportBundleBytes(data, knownSecrets); err != nil {
		return nil, err
	}
	return data, nil
}

func buildDoctorOutput(opts doctorRunOptions) doctorOutput {
	workingDir, err := os.Getwd()
	if err != nil {
		workingDir = "."
	}
	runner := doctorRunner{
		opts:       opts,
		workingDir: workingDir,
		output: doctorOutput{
			Version:     doctorVersion,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Status:      doctorStatusInfo,
			Mode:        opts.Mode,
			Subject:     collectDoctorSubject(workingDir),
			Checks:      []doctorCheck{},
			Redactions:  defaultDoctorRedactions(),
		},
	}
	runner.addContractCheck()
	for _, category := range opts.Categories {
		runner.runCategory(category)
	}
	if opts.Fix {
		runner.runFixFramework()
	}
	runner.output.Status = aggregateDoctorStatus(runner.output.Checks)
	return runner.output
}

type doctorRunner struct {
	opts       doctorRunOptions
	workingDir string
	output     doctorOutput
}

func (r *doctorRunner) add(check doctorCheck) {
	r.output.Checks = append(r.output.Checks, check)
}

func (r *doctorRunner) addContractCheck() {
	r.add(doctorCheck{
		ID:            "doctor.contract.v1",
		Status:        doctorStatusInfo,
		Source:        doctorSourceLocal,
		Authority:     doctorAuthorityCaller,
		Authoritative: true,
		Message:       "Doctor output contract is available.",
		Detail: map[string]any{
			"version": doctorVersion,
			"mode":    r.opts.Mode,
		},
	})
}

func (r *doctorRunner) runCategory(category string) {
	switch category {
	case "local":
		r.runLocalChecks()
	case "identity":
		r.runIdentityDoctorChecks()
	case "registry":
		r.runRegistryDoctorChecks()
	case "workspace":
		r.runWorkspaceDoctorChecks()
	case "team":
		r.runTeamDoctorChecks()
	case "messaging":
		r.runMessagingDoctorChecks()
	default:
		r.add(categoryPlaceholderCheck(category))
	}
}

func categoryPlaceholderCheck(category string) doctorCheck {
	source := doctorSourceLocal
	switch category {
	case "workspace", "team":
		source = doctorSourceAweb
	case "registry":
		source = doctorSourceAwid
	case "messaging":
		source = doctorSourceAweb
	}
	return doctorCheck{
		ID:            category + ".contract.v1",
		Status:        doctorStatusInfo,
		Source:        source,
		Authority:     doctorAuthorityCaller,
		Authoritative: false,
		Message:       fmt.Sprintf("%s doctor checks are not implemented in this release.", category),
		NextStep:      "This category will be populated by AWEB-06/AWEB-07/AWEB-08.",
	}
}

func collectDoctorSubject(workingDir string) doctorSubject {
	subject := doctorSubject{WorkingDir: strings.TrimSpace(workingDir)}
	if subject.WorkingDir == "" {
		subject.WorkingDir = "."
	}
	if sel, err := awconfig.ResolveWorkspace(awconfig.ResolveOptions{
		ServerName:        serverFlag,
		TeamIDOverride:    strings.TrimSpace(teamFlag),
		WorkingDir:        subject.WorkingDir,
		AllowEnvOverrides: true,
	}); err == nil && sel != nil {
		if awebURL, urlErr := sanitizeLocalURLForOutput(sel.BaseURL); urlErr == nil {
			subject.AwebURL = awebURL
		}
		subject.TeamID = strings.TrimSpace(sel.TeamID)
		subject.WorkspaceID = strings.TrimSpace(sel.WorkspaceID)
		subject.Alias = strings.TrimSpace(sel.Alias)
		subject.Lifetime = strings.TrimSpace(sel.Lifetime)
	}
	if identity, identityPath, err := awconfig.LoadWorktreeIdentityFromDir(subject.WorkingDir); err == nil && identity != nil {
		subject.IdentityPath = strings.TrimSpace(identityPath)
		if strings.TrimSpace(subject.Lifetime) == "" {
			subject.Lifetime = strings.TrimSpace(identity.Lifetime)
		}
	}
	return subject
}

func defaultDoctorRedactions() []doctorRedaction {
	return []doctorRedaction{
		{Field: "signing_key", Reason: "secret_key_material"},
		{Field: "api_key", Reason: "credential"},
		{Field: "team_certificate.signature", Reason: "credential_signature"},
	}
}

func aggregateDoctorStatus(checks []doctorCheck) doctorStatus {
	if len(checks) == 0 {
		return doctorStatusOK
	}
	best := doctorStatusOK
	for _, check := range checks {
		if doctorStatusRank(check.Status) > doctorStatusRank(best) {
			best = check.Status
		}
	}
	return best
}

func doctorStatusRank(status doctorStatus) int {
	switch status {
	case doctorStatusFail:
		return 6
	case doctorStatusBlocked:
		return 5
	case doctorStatusWarn:
		return 4
	case doctorStatusUnknown:
		return 3
	case doctorStatusInfo:
		return 2
	case doctorStatusOK:
		return 1
	default:
		return 0
	}
}

func formatDoctorOutput(v any) string {
	out := v.(doctorOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Doctor: %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Mode:   %s\n", out.Mode))
	if out.Subject.WorkingDir != "" {
		sb.WriteString(fmt.Sprintf("Path:   %s\n", abbreviateUserHome(out.Subject.WorkingDir)))
	}
	if len(out.Checks) == 0 {
		sb.WriteString("Checks: none\n")
		return sb.String()
	}
	sb.WriteString("Checks:\n")
	for _, check := range out.Checks {
		sb.WriteString(fmt.Sprintf("  [%s] %s — %s\n", check.Status, check.ID, check.Message))
		if check.Handoff != nil {
			sb.WriteString(fmt.Sprintf("        handoff: %s\n", conciseDoctorHandoffLine(check.Handoff)))
			if doctorVerbose {
				sb.WriteString(fmt.Sprintf("        authority: %s (%s)\n", check.Handoff.RequiredAuthority, check.Handoff.CallerAuthorityStatus))
				if len(check.Handoff.CallerAuthorityEvidence) > 0 {
					sb.WriteString(fmt.Sprintf("        evidence: %s\n", strings.Join(check.Handoff.CallerAuthorityEvidence, ", ")))
				}
				if check.Handoff.ExplicitCommand != "" {
					sb.WriteString(fmt.Sprintf("        command: %s\n", check.Handoff.ExplicitCommand))
				}
				if check.Handoff.DryRunCommand != "" {
					sb.WriteString(fmt.Sprintf("        dry-run: %s\n", check.Handoff.DryRunCommand))
				}
				if check.Handoff.DashboardAction != "" {
					sb.WriteString(fmt.Sprintf("        dashboard: %s\n", check.Handoff.DashboardAction))
				}
				if len(check.Handoff.Consequences) > 0 {
					sb.WriteString(fmt.Sprintf("        consequences: %s\n", strings.Join(check.Handoff.Consequences, "; ")))
				}
			}
		}
		if doctorVerbose && check.NextStep != "" {
			sb.WriteString(fmt.Sprintf("        next: %s\n", check.NextStep))
		}
	}
	return sb.String()
}
