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
	var apiErr *APIError
	var registryErr *RegistryError
	body, refused := "", false
	if errors.As(err, &registryErr) {
		body, refused, detail.HTTPStatus = registryErr.Detail, true, registryErr.StatusCode
	} else if errors.As(err, &apiErr) {
		body, refused, detail.HTTPStatus = apiErr.Body, true, apiErr.StatusCode
	}
	if refused {
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
