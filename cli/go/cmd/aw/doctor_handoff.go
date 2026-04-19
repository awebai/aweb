package main

import "strings"

const doctorIdentityRecoveryRunbook = "docs/support/agent-identity-recovery.md"

func conciseDoctorHandoffLine(h *doctorHandoff) string {
	if h == nil {
		return ""
	}
	if summary := strings.TrimSpace(h.ExpectedAction); summary != "" {
		return summary
	}
	switch h.Action {
	case "persistent_identity_registry_repair_review":
		return "Review caller-authorized DID registry repair before considering replacement."
	case "persistent_lifecycle_review":
		return "Review persistent lifecycle with an authorized owner; doctor will not apply it automatically."
	case "persistent_replacement_review":
		return "Review replacement only with the required authority; doctor will not replace identities."
	case "managed_address_repair_review":
		return "Review address repair with namespace authority; doctor will not change registry state."
	case "namespace_controller_recovery_review":
		return "Review namespace-controller recovery with the controller owner."
	case "suspected_key_mismatch_review":
		return "Review the key mismatch before any recovery action."
	default:
		return "Review this high-impact action with the required authority."
	}
}

func persistentLifecycleReviewHandoff() *doctorHandoff {
	return &doctorHandoff{
		Action:                "persistent_lifecycle_review",
		RequiredAuthority:     doctorAuthorityTeamAdmin,
		CallerAuthorityStatus: doctorAuthorityStatusUnknown,
		ExpectedAction:        "Review persistent lifecycle with an authorized owner; missing local state alone is not enough to archive, replace, delete, or unclaim.",
		DashboardAction:       "Hosted dashboard archive/replace is conditional on confirmed team or org authority and managed identity context.",
		Consequences: []string{
			"persistent identities outlive workspace paths",
			"archive or replacement changes identity lifecycle and trust continuity",
		},
		DoctorRefusalReason: "high_impact_persistent_lifecycle",
		ReplacementGuidance: "Do not replace a persistent identity solely because local files are missing; inspect registry and authority first.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
}

func persistentIdentityRegistryRepairReviewHandoff(authorityStatus doctorAuthorityStatus, evidence []string) *doctorHandoff {
	handoff := &doctorHandoff{
		Action:                  "persistent_identity_registry_repair_review",
		RequiredAuthority:       doctorAuthorityCaller,
		CallerAuthorityStatus:   authorityStatus,
		CallerAuthorityEvidence: evidence,
		ExpectedAction:          "Review caller-authorized DID registry repair; register or repair the existing DID when the local DID key is valid.",
		DryRunCommand:           "aw doctor registry --online",
		Consequences: []string{
			"DID registration changes registry state for the persistent identity",
			"doctor will not register or replace the identity automatically",
		},
		DoctorRefusalReason: "persistent_identity_registry_repair_required",
		ReplacementGuidance: "Caller-authorized DID repair or registration is preferred before replacement when the existing DID key is valid.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
	if authorityStatus == doctorAuthorityStatusPresent {
		handoff.ExplicitCommand = "aw id register"
	}
	return handoff
}

func persistentReplacementReviewHandoff(authorityStatus doctorAuthorityStatus, evidence []string) *doctorHandoff {
	return &doctorHandoff{
		Action:                  "persistent_replacement_review",
		RequiredAuthority:       doctorAuthorityTeamAdmin,
		CallerAuthorityStatus:   authorityStatus,
		CallerAuthorityEvidence: evidence,
		ExpectedAction:          "Review persistent replacement only after identity key loss or unusable custody is confirmed with the required authority.",
		DashboardAction:         "Hosted dashboard Replace is conditional on dashboard/team authority and managed namespace authority.",
		Consequences: []string{
			"replacement creates a new identity continuity claim",
			"address continuity requires namespace/controller authority",
		},
		DoctorRefusalReason: "high_impact_persistent_replacement",
		ReplacementGuidance: "When the existing DID key is valid, repair DID/address registration before considering replacement.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
}

func managedAddressRepairReviewHandoff(authorityStatus doctorAuthorityStatus, evidence []string) *doctorHandoff {
	return &doctorHandoff{
		Action:                  "managed_address_repair_review",
		RequiredAuthority:       doctorAuthorityNamespaceController,
		CallerAuthorityStatus:   authorityStatus,
		CallerAuthorityEvidence: evidence,
		ExpectedAction:          "Review address repair with namespace authority; prefer address repair when the existing DID key is valid.",
		DashboardAction:         "Use a hosted managed-address repair action only when the namespace is cloud-managed and the caller has dashboard authority.",
		Consequences: []string{
			"address registration or reassignment changes public reachability",
			"doctor will not use public namespace discovery as ownership proof",
		},
		DoctorRefusalReason: "high_impact_address_repair",
		ReplacementGuidance: "Address repair is first-line when the existing DID key remains valid; replacement is for lost or unusable identity key/custody plus address-continuity authority.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
}

func namespaceControllerRecoveryReviewHandoff() *doctorHandoff {
	return &doctorHandoff{
		Action:                "namespace_controller_recovery_review",
		RequiredAuthority:     doctorAuthorityNamespaceController,
		CallerAuthorityStatus: doctorAuthorityStatusNotDetected,
		ExpectedAction:        "Review BYOD namespace recovery with the namespace-controller owner; doctor does not recover or rotate controller keys.",
		DashboardAction:       "Hosted dashboard recovery applies only when cloud actually holds managed namespace/controller authority.",
		Consequences: []string{
			"without namespace-controller authority, address repair or reassignment cannot be proven",
			"if both identity and BYOD controller keys are lost, there may be no safe recovery path",
		},
		DoctorRefusalReason: "namespace_controller_authority_required",
		ReplacementGuidance: "Do not use hosted replacement for BYOD addresses unless controller authority is available.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
}

func suspectedKeyMismatchReviewHandoff(authorityStatus doctorAuthorityStatus, evidence []string) *doctorHandoff {
	return &doctorHandoff{
		Action:                  "suspected_key_mismatch_review",
		RequiredAuthority:       doctorAuthorityCaller,
		CallerAuthorityStatus:   authorityStatus,
		CallerAuthorityEvidence: evidence,
		ExpectedAction:          "Review the key mismatch before any recovery action; doctor will not rotate, replace, or rewrite identity keys.",
		Consequences: []string{
			"wrong key repair can break identity continuity",
			"registry key mismatch may indicate corruption or stale local state",
		},
		DoctorRefusalReason: "suspected_key_mismatch",
		ReplacementGuidance: "When the existing DID key is valid, repair registry/address state before replacement.",
		SupportRunbookRef:   doctorIdentityRecoveryRunbook,
	}
}
