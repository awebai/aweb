package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var workspaceInitRequestID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// This is a display summary, not a transaction outcome or retry instruction.
// Do not echo arbitrary bodies, messages, unknown codes or request-ID text.
// Raw native output still needs protected operator capture outside this renderer.
func workspaceInitHTTPDiagnostic(resp *http.Response, body []byte, apiKey string) string {
	type fields struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	var envelope struct {
		fields
		Error  fields `json:"error"`
		Detail fields `json:"detail"`
	}
	code, requestID := "unknown", "unknown"
	var candidates []string
	for name, values := range resp.Header {
		if strings.EqualFold(name, "X-Request-ID") {
			candidates = append(candidates, values...)
		}
	}
	// Struct decoding and Header.Get would discard duplicate/case-variant
	// evidence before comparison. Reject ambiguous JSON before decoding fields.
	ambiguousBody := json.Valid(body) && !workspaceInitUnambiguousJSON(body)
	if ambiguousBody {
		candidates = append(candidates, "ambiguous")
	}
	if !ambiguousBody && json.Unmarshal(body, &envelope) == nil {
		for _, value := range []fields{envelope.fields, envelope.Error, envelope.Detail} {
			// Fixed public vocabulary only. Unknown service codes remain private.
			if value.Code == "INTERNAL_ERROR" {
				code = "INTERNAL_ERROR"
			}
			candidates = append(candidates, value.RequestID)
		}
	}
	for _, value := range candidates {
		if value == "" {
			continue
		}
		if !workspaceInitRequestID.MatchString(value) || (apiKey != "" && strings.Contains(value, apiKey)) {
			requestID = "unknown"
			break
		}
		value = strings.ToLower(value)
		if requestID != "unknown" && requestID != value {
			requestID = "unknown"
			break
		}
		requestID = value
	}
	if apiKey != "" && strings.Contains(code, apiKey) {
		code = "unknown"
	}
	return fmt.Sprintf("category=hosted_http_failure status=%d error_code=%s request_id=%s (response body omitted; remote effects unknown)", resp.StatusCode, code, requestID)
}

// Conservative display admission: duplicate object names (case-insensitive),
// including enclosing error/detail objects, make correlation metadata unknown.
// This does not change the service response or native bootstrap state contract.
func workspaceInitUnambiguousJSON(body []byte) bool {
	d := json.NewDecoder(bytes.NewReader(body))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 32 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			var seen []string
			for d.More() {
				token, err := d.Token()
				if err != nil {
					return false
				}
				key, ok := token.(string)
				if !ok {
					return false
				}
				// encoding/json uses Unicode simple folding for struct fields,
				// not lowercasing (for example long s also matches ASCII s).
				for _, prior := range seen {
					if strings.EqualFold(prior, key) {
						return false
					}
				}
				seen = append(seen, key)
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
