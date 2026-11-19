package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type privateRootKind uint8

const (
	workspacePrivateRoot privateRootKind = iota
	selectedIdentityPrivateRoot
	awidPrivateRoot
	controllerPrivateRoot
	teamKeysPrivateRoot
)

type privateRootCheck struct {
	ID   string
	Kind privateRootKind
}

var privateRootChecks = []privateRootCheck{
	{ID: "local.private_directory.workspace", Kind: workspacePrivateRoot},
	{ID: "local.private_directory.identity_home", Kind: selectedIdentityPrivateRoot},
	{ID: "local.private_directory.awid", Kind: awidPrivateRoot},
	{ID: "local.private_directory.controllers", Kind: controllerPrivateRoot},
	{ID: "local.private_directory.team_keys", Kind: teamKeysPrivateRoot},
}

func init() {
	for _, root := range privateRootChecks {
		registerDoctorFixHandler(privateRootPermissionsFix{Root: root})
	}
}

func privateRootPath(root privateRootKind, ctx doctorFixContext) (string, error) {
	switch root {
	case workspacePrivateRoot:
		return filepath.Join(ctx.WorkingDir, ".aw"), nil
	case selectedIdentityPrivateRoot:
		if strings.TrimSpace(ctx.IdentityHome) != "" {
			return filepath.Clean(ctx.IdentityHome), nil
		}
		return awconfig.WorktreeIdentityHome(ctx.WorkingDir), nil
	case awidPrivateRoot:
		return awconfig.DefaultAWIDStateDir()
	case controllerPrivateRoot:
		return awconfig.DefaultControllersDir()
	case teamKeysPrivateRoot:
		return awconfig.DefaultTeamKeysDir()
	default:
		return "", errors.New("unknown private root; select a named aw private directory")
	}
}

// Report only roots aw owns and names; arbitrary key parents are never changed
// by key I/O (docs/signature-primitives.md, Local private keys).
func (r *doctorRunner) runPrivateRootPermissionsChecks() {
	if !awid.SupportsPOSIXPermissions() {
		return
	}
	ctx := doctorFixContext{WorkingDir: r.workingDir, IdentityHome: r.identityHome}
	seen := make(map[string]bool)
	for _, root := range privateRootChecks {
		path, err := privateRootPath(root.Kind, ctx)
		if err != nil {
			r.add(localCheck(root.ID, doctorStatusWarn, nil, "Private directory could not be located.", "Check the selected identity and user home configuration.", map[string]any{"error": err.Error()}))
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			r.add(localPathCheck(root.ID, doctorStatusWarn, path, "Private directory could not be inspected.", "Check directory ownership and mount access.", map[string]any{"error": err.Error()}))
			continue
		}
		if !info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0o077 == 0 {
			r.add(localPathCheck(root.ID, doctorStatusOK, path, "Private directory permissions are owner-only.", "", nil))
			continue
		}
		command, commandErr := awid.PermissionFixCommand(path, 0o700)
		if commandErr != nil {
			r.add(localPathCheck(root.ID, doctorStatusWarn, path, "Private directory needs restricted permissions.", "Check the selected directory path and retry.", map[string]any{"error": commandErr.Error()}))
			continue
		}
		check := localPathCheck(root.ID, doctorStatusWarn, path, "Private directory is accessible by group or others.", "Run "+command+".", nil)
		check.Fix = safeDoctorFixInfo(root.ID)
		r.add(check)
	}
}

type privateRootPermissionsFix struct{ Root privateRootCheck }

func (fix privateRootPermissionsFix) CheckID() string { return fix.Root.ID }

func (fix privateRootPermissionsFix) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	path, err := privateRootPath(fix.Root.Kind, ctx)
	if err != nil {
		return plan, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return plan, fmt.Errorf("inspect private root before changing permissions: %w", err)
	}
	if !info.IsDir() {
		return plan, errors.New("private root is not a regular directory; select its real directory before fixing permissions")
	}
	if info.Mode().Perm()&0o077 == 0 {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	plan.PlannedMutations = []doctorFixMutation{{Operation: doctorFixChmod, permissionMode: 0o700, Path: path, Description: "Restrict the explicitly selected private directory to 0700."}}
	return plan, nil
}

func (fix privateRootPermissionsFix) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	if len(plan.PlannedMutations) == 0 {
		return plan, nil
	}
	path, err := privateRootPath(fix.Root.Kind, ctx)
	if err != nil {
		return plan, err
	}
	if len(plan.PlannedMutations) != 1 || plan.PlannedMutations[0].Path != path {
		return plan, errors.New("selected private root changed; rerun doctor and review a new fix plan")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return plan, fmt.Errorf("inspect private root before changing permissions: %w", err)
	}
	if !info.IsDir() {
		return plan, errors.New("private root changed; inspect its real directory before applying this fix")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return plan, fmt.Errorf("restrict private root permissions; run the printed chmod command when the mount permits it: %w", err)
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}
