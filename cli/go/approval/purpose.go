package approval

import "errors"

// RequestPurpose names one shared approval HTTP operation, without granting authority.
type RequestPurpose string

const (
	purposeSubmit             RequestPurpose = "submit"
	purposePoll               RequestPurpose = "poll"
	purposeCancel             RequestPurpose = "cancel"
	PurposeEnrollmentStart    RequestPurpose = "enrollment_start"
	PurposeEnrollmentMaterial RequestPurpose = "enrollment_material"
	PurposeEnrollmentConfirm  RequestPurpose = "enrollment_confirm"
	PurposeEnrollmentActivate RequestPurpose = "enrollment_activate"
	PurposeBindingRefresh     RequestPurpose = "binding_refresh"
)

var routes = map[RequestPurpose]string{
	purposeSubmit: "/v1/requests/submit", purposePoll: "/v1/requests/poll",
	purposeCancel: "/v1/requests/cancel", PurposeEnrollmentStart: "/v1/enrollments/start",
	PurposeEnrollmentMaterial: "/v1/enrollments/material", PurposeEnrollmentConfirm: "/v1/enrollments/confirm",
	PurposeEnrollmentActivate: "/v1/enrollments/activate", PurposeBindingRefresh: "/v1/enrollment-bindings/refresh",
}

func checkedPurpose(value string) (RequestPurpose, error) {
	purpose := RequestPurpose(value)
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
