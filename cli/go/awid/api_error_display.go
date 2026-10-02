package awid

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// Response IDs are untrusted input. Three headers capped at 128 ASCII bytes,
// plus fixed labels and summaries, keep non-JSON error display below 1024 bytes.
// The bounded raw body remains available through HTTPErrorBody for existing
// structured error handling; it is not printed as a non-JSON diagnostic.
func errorHeaderValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 128 {
		value = value[:125] + "..."
	}
	return value
}

func newAPIError(resp *http.Response, body string) *APIError {
	return &APIError{
		StatusCode: resp.StatusCode, Body: body,
		RequestID:       resp.Header.Get("X-Request-ID"),
		CfRay:           resp.Header.Get("Cf-Ray"),
		CfMitigated:     resp.Header.Get("Cf-Mitigated"),
		responseSummary: nonJSONErrorSummary(body, resp.Header.Get("Content-Type"), resp.Header.Get("Cf-Mitigated")),
	}
}

var knownErrorPageTitle = regexp.MustCompile(`(?is)<title\s*>\s*(blocked|just a moment\.\.\.)\s*</title\s*>`)

func nonJSONErrorSummary(body, contentType, mitigated string) string {
	if body == "" || json.Valid([]byte(body)) {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(mitigated), "challenge") {
		return "challenge response (body omitted)"
	}
	lowerBody := strings.ToLower(strings.TrimSpace(body))
	lowerType := strings.ToLower(contentType)
	if strings.Contains(lowerType, "text/html") || strings.Contains(lowerType, "application/xhtml+xml") || strings.HasPrefix(lowerBody, "<html") || strings.HasPrefix(lowerBody, "<!doctype html") {
		// Recognize only fixed titles; arbitrary page text can contain credentials.
		// A title describes the received page, not its provider or the rule applied.
		if match := knownErrorPageTitle.FindStringSubmatch(body); len(match) > 1 {
			if strings.EqualFold(match[1], "blocked") {
				return "HTML response titled Blocked (body omitted)"
			}
			return "HTML response titled Just a moment... (body omitted)"
		}
		return "HTML error response (body omitted)"
	}
	return "non-JSON error response (body omitted)"
}
