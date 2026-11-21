package main

import (
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
)

const privateKeyPermissionMode os.FileMode = 0o600

type doctorMetadataMutation struct {
	Operation  doctorFixOperation
	Path       string
	TargetPath string
	Resource   doctorFixMetadataField
}

type doctorMutationScope struct {
	CheckID     string
	Permissions map[string]os.FileMode
	Metadata    *doctorMetadataMutation
	Refusal     doctorFixSafetyReason
}

func (scope doctorMutationScope) permits(mutation doctorFixMutation) bool {
	if mode, owned := scope.Permissions[mutation.Path]; owned {
		return mutation.Operation == doctorFixChmod && mutation.permissionMode == mode &&
			mutation.Target == nil && mutation.Resource == "" && mutation.SourceOfTruth == ""
	}
	metadata := scope.Metadata
	if metadata == nil || mutation.Target == nil {
		return false
	}
	return mutation.Operation == metadata.Operation && mutation.permissionMode == 0 &&
		mutation.Path == metadata.Path && mutation.Resource == metadata.Resource &&
		mutation.Target.Type == "local_path" &&
		filepath.Clean(mutation.Target.ID) == filepath.Clean(metadata.TargetPath)
}

func (fix signingKeyPermissionsFix) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixPrivateKeyMaterial,
		Permissions: map[string]os.FileMode{doctorFixIdentityPath(ctx, "signing.key"): privateKeyPermissionMode}}, nil
}

func (fix additionalPrivateKeyPermissionsFix) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	findings, err := additionalPrivateKeyPermissionFindings(ctx)
	if err != nil {
		return doctorMutationScope{}, err
	}
	paths := make(map[string]os.FileMode, len(findings))
	for _, finding := range findings {
		paths[finding.Path] = privateKeyPermissionMode
	}
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixPrivateKeyMaterial, Permissions: paths}, nil
}

func (fix privateRootPermissionsFix) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	path, err := privateRootPath(fix.Root.Kind, ctx)
	if err != nil {
		return doctorMutationScope{}, err
	}
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixUnsafe,
		Permissions: map[string]os.FileMode{path: 0o700}}, nil
}

func (fix localActiveTeamFixHandler) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixUnsafe, Metadata: &doctorMetadataMutation{
		Operation: doctorFixRewriteTeamsMetadata, Path: awconfig.DefaultTeamStateRelativePath(),
		TargetPath: doctorFixIdentityPath(ctx, "teams.yaml"), Resource: doctorFixActiveTeamField}}, nil
}

func (fix localWorkspaceURLFixHandler) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixUnsafe, Metadata: &doctorMetadataMutation{
		Operation: doctorFixRewriteWorkspaceMetadata, Path: awconfig.DefaultWorktreeWorkspaceRelativePath(),
		TargetPath: doctorFixIdentityPath(ctx, "workspace.yaml"), Resource: doctorFixAwebURLField}}, nil
}

func (fix localIdentityRegistryURLFixHandler) doctorMutationScope(ctx doctorFixContext) (doctorMutationScope, error) {
	return doctorMutationScope{CheckID: fix.CheckID(), Refusal: doctorFixUnsafe, Metadata: &doctorMetadataMutation{
		Operation: doctorFixRewriteIdentityMetadata, Path: awconfig.DefaultWorktreeIdentityRelativePath(),
		TargetPath: doctorFixIdentityPath(ctx, "identity.yaml"), Resource: doctorFixRegistryURLField}}, nil
}
