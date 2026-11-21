package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

const doctorCheckAdditionalKeyPermissions = "local.private_keys.permissions"

type privateKeyPermissionFinding struct{ Path, Command string }

// Inspect metadata only within the explicitly named private roots. No key bytes
// or unrelated parent directories are read (docs/signature-primitives.md).
func additionalPrivateKeyPermissionFindings(ctx doctorFixContext) ([]privateKeyPermissionFinding, error) {
	if !awid.SupportsPOSIXPermissions() {
		return nil, nil
	}
	selectedSigningKey := doctorFixIdentityPath(ctx, "signing.key")
	seen := make(map[string]bool)
	var findings []privateKeyPermissionFinding
	for _, root := range privateRootChecks {
		path, err := privateRootPath(root.Kind, ctx)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		err = filepath.WalkDir(path, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".key") || path == selectedSigningKey || seen[path] {
				return nil
			}
			seen[path] = true
			command, err := awid.PrivateKeyPermissionFix(path)
			if err != nil {
				return err
			}
			if command != "" {
				findings = append(findings, privateKeyPermissionFinding{Path: path, Command: command})
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inspect private key permissions under %s: %w", path, err)
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Path < findings[j].Path })
	return findings, nil
}

func (r *doctorRunner) runAdditionalPrivateKeyPermissionsChecks() {
	findings, err := additionalPrivateKeyPermissionFindings(doctorFixContext{WorkingDir: r.workingDir, IdentityHome: r.identityHome})
	if err != nil {
		r.add(localCheck(doctorCheckAdditionalKeyPermissions, doctorStatusWarn, nil, "Some private key permissions could not be inspected.", "Check access to the named private roots and retry.", map[string]any{"error": err.Error()}))
		return
	}
	if len(findings) == 0 {
		return
	}
	commands := make([]string, 0, len(findings))
	for _, finding := range findings {
		commands = append(commands, finding.Command)
	}
	check := localCheck(doctorCheckAdditionalKeyPermissions, doctorStatusWarn, nil, "Some private keys are readable by group or others.", "Run "+strings.Join(commands, "; ")+".", nil)
	check.Fix = safeDoctorFixInfo(doctorCheckAdditionalKeyPermissions)
	r.add(check)
}

type additionalPrivateKeyPermissionsFix struct{}

func init() { registerDoctorFixHandler(additionalPrivateKeyPermissionsFix{}) }
func (additionalPrivateKeyPermissionsFix) CheckID() string {
	return doctorCheckAdditionalKeyPermissions
}
func (additionalPrivateKeyPermissionsFix) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	findings, err := additionalPrivateKeyPermissionFindings(ctx)
	if err != nil {
		return plan, err
	}
	if len(findings) == 0 {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	for _, finding := range findings {
		plan.PlannedMutations = append(plan.PlannedMutations, doctorFixMutation{Operation: doctorFixChmod, permissionMode: privateKeyPermissionMode, Path: finding.Path, Description: "Restrict private-key file permissions to 0600 without changing its bytes."})
	}
	return plan, nil
}
func (additionalPrivateKeyPermissionsFix) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	findings, err := additionalPrivateKeyPermissionFindings(ctx)
	if err != nil {
		return plan, err
	}
	current := make(map[string]privateKeyPermissionFinding, len(findings))
	for _, finding := range findings {
		current[finding.Path] = finding
	}
	for _, mutation := range plan.PlannedMutations {
		finding, present := current[mutation.Path]
		if !present {
			continue
		}
		if err := awid.FixPrivateKeyPermissions(finding.Path); err != nil {
			return plan, fmt.Errorf("restrict private key permissions; run %s when the mount permits it: %w", finding.Command, err)
		}
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}
