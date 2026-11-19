package approval

import "errors"

// PurposeBindingRefresh is the released string purpose accepted by SignedRequest.
const PurposeBindingRefresh = "binding_refresh"

type requestPurpose string

const (
	purposeSubmit             requestPurpose = "submit"
	purposePoll               requestPurpose = "poll"
	purposeCancel             requestPurpose = "cancel"
	purposeEnrollmentStart    requestPurpose = "enrollment_start"
	purposeEnrollmentMaterial requestPurpose = "enrollment_material"
	purposeEnrollmentConfirm  requestPurpose = "enrollment_confirm"
	purposeEnrollmentActivate requestPurpose = "enrollment_activate"
	purposeBindingRefresh     requestPurpose = PurposeBindingRefresh
)

var routes = map[requestPurpose]string{
	purposeSubmit: "/v1/requests/submit", purposePoll: "/v1/requests/poll",
	purposeCancel: "/v1/requests/cancel", purposeEnrollmentStart: "/v1/enrollments/start",
	purposeEnrollmentMaterial: "/v1/enrollments/material", purposeEnrollmentConfirm: "/v1/enrollments/confirm",
	purposeEnrollmentActivate: "/v1/enrollments/activate", purposeBindingRefresh: "/v1/enrollment-bindings/refresh",
}

func checkedPurpose(value string) (requestPurpose, error) {
	purpose := requestPurpose(value)
	if _, ok := routes[purpose]; !ok {
		return "", errors.New("http_binding_mismatch")
	}
	return purpose, nil
}

type answerState string

const answerPending answerState = "pending"

type retentionKind string

const (
	retainRequest retentionKind = "request"
	retainReceipt retentionKind = "receipt"
)
