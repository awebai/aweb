package awid

import (
	"encoding/json"
	"errors"
	"strings"
)

// ErrorDetail is an error's stable machine description: its class code and,
// for a refusal by an aweb server or AWID registry, the HTTP status, the
// string detail of the response's JSON body and the server's own refusal
// code as Reason, never its headers or any other text. The message an error
// prints is not stable; this is.
type ErrorDetail struct {
	Code       string `json:"code"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// DescribeError classifies err. Codes: http_error, alias_conflict (a refusal
// whose detail carries the code alias_active), outcome_unknown,
// encryption_key_missing, decrypt_failed, recipient_custodial_no_e2ee, and
// error for any other error.
func DescribeError(err error) ErrorDetail {
	detail := ErrorDetail{Code: "error"}
	body, status, refused := refusalBody(err)
	if refused {
		detail.HTTPStatus = status
		serverCode, text := responseDetail(body)
		detail.Code, detail.Detail, detail.Reason = "http_error", text, serverCode
		if serverCode == "alias_active" {
			detail.Code = "alias_conflict"
		}
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

// RefusalCode is the server's code for a refusal: the code of its coded
// detail {"code", "message"}, else its top-level reason, or "" when err is no
// refusal by an aweb server or AWID registry or its body carries no code.
func RefusalCode(err error) string {
	body, _, refused := refusalBody(err)
	if !refused {
		return ""
	}
	code, _ := responseDetail(body)
	return code
}

// CodedRefusal is the server's own message for a refusal whose JSON detail is
// coded, {"code", "message"}, together with the refusal's error text, which a
// caller's error may wrap. ok is false for any other error.
func CodedRefusal(err error) (refusal, message string, ok bool) {
	var registryErr *RegistryError
	var apiErr *APIError
	var body string
	switch {
	case errors.As(err, &registryErr):
		refusal, body = registryErr.Error(), registryErr.Detail
	case errors.As(err, &apiErr):
		refusal, body = apiErr.Error(), apiErr.Body
	default:
		return "", "", false
	}
	var server struct {
		Detail struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &server) != nil || strings.TrimSpace(server.Detail.Code) == "" || strings.TrimSpace(server.Detail.Message) == "" {
		return "", "", false
	}
	return refusal, strings.TrimSpace(server.Detail.Message), true
}

// refusalBody is the response body and HTTP status of a refusal by an aweb
// server or AWID registry.
func refusalBody(err error) (body string, status int, refused bool) {
	var apiErr *APIError
	var registryErr *RegistryError
	if errors.As(err, &registryErr) {
		return registryErr.Detail, registryErr.StatusCode, true
	}
	if errors.As(err, &apiErr) {
		return apiErr.Body, apiErr.StatusCode, true
	}
	return "", 0, false
}

// responseDetail reads a JSON error body: a string detail is its text; a coded
// detail {"code", "message"} gives its code and its message as text; without
// a coded detail, a top-level reason is the code.
func responseDetail(body string) (code, text string) {
	var server struct {
		Detail any    `json:"detail"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(body), &server) != nil {
		return "", ""
	}
	code = server.Reason
	switch detail := server.Detail.(type) {
	case string:
		text = detail
	case map[string]any:
		if coded, _ := detail["code"].(string); coded != "" {
			code = coded
		}
		text, _ = detail["message"].(string)
	}
	return code, text
}
