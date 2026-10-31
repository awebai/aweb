package awid

import (
	"encoding/json"
	"errors"
	"strings"
)

// ErrorDetail is an error's stable machine description: its class code and,
// for a refusal by an aweb server or AWID registry, the HTTP status and the
// string detail of the response's JSON body, never its headers or any other
// text. The message an error prints is not stable; this is.
type ErrorDetail struct {
	Code       string `json:"code"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// DescribeError classifies err. Codes: http_error, outcome_unknown,
// encryption_key_missing, decrypt_failed, recipient_custodial_no_e2ee, and
// error for any other error.
func DescribeError(err error) ErrorDetail {
	detail := ErrorDetail{Code: "error"}
	var apiErr *APIError
	var registryErr *RegistryError
	if errors.As(err, &registryErr) {
		detail = ErrorDetail{Code: "http_error", HTTPStatus: registryErr.StatusCode, Detail: responseDetail(registryErr.Detail)}
	} else if errors.As(err, &apiErr) {
		detail = ErrorDetail{Code: "http_error", HTTPStatus: apiErr.StatusCode, Detail: responseDetail(apiErr.Body)}
	}
	var unknown *OutcomeUnknownError
	if errors.As(err, &unknown) {
		detail.Code = "outcome_unknown"
	}
	var decryption *DecryptionError
	if errors.As(err, &decryption) {
		detail.Code = decryption.Code
	}
	var custodial *CustodialRecipientError
	if errors.As(err, &custodial) {
		detail.Code = ErrorCodeRecipientCustodialNoE2EE
		detail.Detail = ""
		if !custodial.Unverified {
			detail.Detail = strings.Join(custodial.Recipients, ", ")
		}
	}
	return detail
}

// responseDetail is the string detail of a JSON error body, or "".
func responseDetail(body string) string {
	var server struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &server) != nil {
		return ""
	}
	detail, _ := server.Detail.(string)
	return detail
}
