package main

import (
	"log"
	"os"
)

const privateKeyPermissionMode os.FileMode = 0o600

type privateKeyPermissionPaths map[string]os.FileMode

// ownedPrivateKeyPermissionPaths limits the mode-only repair exception to the
// two concrete local owners and their currently selected paths. Check IDs alone
// grant no exception (docs/signature-primitives.md, Local private keys).
func ownedPrivateKeyPermissionPaths(ctx doctorFixContext, check doctorCheck, plan doctorFixPlan) privateKeyPermissionPaths {
	if check.Source != doctorSourceLocal || plan.Source != doctorSourceLocal || plan.CheckID != check.ID {
		return nil
	}
	handler, registered := doctorFixHandlers[check.ID]
	if !registered || handler == nil || handler.CheckID() != check.ID {
		return nil
	}
	switch handler.(type) {
	case signingKeyPermissionsFix:
		return privateKeyPermissionPaths{doctorFixIdentityPath(ctx, "signing.key"): privateKeyPermissionMode}
	case additionalPrivateKeyPermissionsFix:
		findings, err := additionalPrivateKeyPermissionFindings(ctx)
		if err != nil {
			log.Printf("aw doctor: cannot confirm private-key permission scope: %v. Inspect the private roots and rerun doctor.", err)
			return privateKeyPermissionPaths{}
		}
		paths := make(privateKeyPermissionPaths, len(findings))
		for _, finding := range findings {
			paths[finding.Path] = privateKeyPermissionMode
		}
		return paths
	default:
		return nil
	}
}

// permits admits only chmod0600 of a path owned by this repair. Metadata writes,
// replacement, deletion, other modes and additional resource targets refuse.
func (paths privateKeyPermissionPaths) permits(mutation doctorFixMutation) bool {
	mode, owned := paths[mutation.Path]
	return owned && mutation.Path != "" &&
		mutation.Operation == doctorFixChmod && mutation.permissionMode == mode &&
		mutation.Target == nil && mutation.Resource == "" && mutation.SourceOfTruth == ""
}
