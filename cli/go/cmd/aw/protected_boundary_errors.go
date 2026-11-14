package main

import "github.com/awebai/aw/awid"

func protectedBoundaryRefusalText(err error, text string) string {
	code := awid.RefusalCode(err)
	if code == "" {
		code = awid.DescribeError(err).Detail
	}
	if code == "" {
		code = errorCodeOf(err)
	}
	switch code {
	case "protected_admission_required":
		return text + "\nUse the configured protected service and root-admission path (--protected-profile <profile>); this team requires protected admission. Keep the existing identity and invitation state."
	case "protected_controller_required":
		return text + "\nUse the configured protected service (--protected-profile <profile>) for this controller act and its human approval."
	case "protected_state_unavailable":
		return text + "\nThe configured registry cannot provide current protection evidence; restore its verified response before continuing."
	}
	return text
}
