package awid

import (
	"encoding/json"
	"errors"
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

// DescribeError classifies err. Codes: http_error, alias_conflict (a refusal
// whose detail carries the code alias_active), outcome_unknown,
// encryption_key_missing, decrypt_failed, and error for any other error.
func DescribeError(err error) ErrorDetail {
	detail := ErrorDetail{Code: "error"}
	body, status, refused := refusalBody(err)
	if refused {
		detail.HTTPStatus = status
		serverCode, text := responseDetail(body)
		detail.Code, detail.Detail = "http_error", text
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
	return detail
}

// RefusalCode is the code of a refusal's coded detail {"code", "message"}, or
// "" when err is no refusal by an aweb server or AWID registry or its detail
// carries no code.
func RefusalCode(err error) string {
	body, _, refused := refusalBody(err)
	if !refused {
		return ""
	}
	code, _ := responseDetail(body)
	return code
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

// responseDetail reads a JSON error body's detail: a string is its text; a
// coded detail {"code", "message"} gives its code and its message as text.
func responseDetail(body string) (code, text string) {
	var server struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &server) != nil {
		return "", ""
	}
	switch detail := server.Detail.(type) {
	case string:
		return "", detail
	case map[string]any:
		code, _ = detail["code"].(string)
		text, _ = detail["message"].(string)
		return code, text
	}
	return "", ""
}
