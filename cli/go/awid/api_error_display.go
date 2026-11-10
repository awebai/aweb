package awid

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Response IDs are untrusted input. Three headers capped at 128 ASCII bytes,
// an answering mount capped likewise and shown twice, plus fixed labels and
// summaries, keep non-JSON error display below 1024 bytes.
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

const blockedFirewallAdvice = "The server's firewall refused this request. That usually happens when what you sent contains a curl or wget command with a web address inside backticks. Reword that part or remove the backticks, then try again."

func newAPIError(resp *http.Response, body string) *APIError {
	contentType := resp.Header.Get("Content-Type")
	summary := nonJSONErrorSummary(body, contentType, resp.Header.Get("Cf-Mitigated"))
	if resp.StatusCode == http.StatusForbidden && summary != "" && isHTMLResponse(body, contentType) {
		if match := knownErrorPageTitle.FindStringSubmatch(body); len(match) > 1 && strings.EqualFold(match[1], "blocked") {
			summary += "\n" + blockedFirewallAdvice
		}
	}
	return &APIError{
		StatusCode: resp.StatusCode, Body: body,
		RequestID:       resp.Header.Get("X-Request-ID"),
		CfRay:           resp.Header.Get("Cf-Ray"),
		CfMitigated:     resp.Header.Get("Cf-Mitigated"),
		RetryAfter:      resp.Header.Get("Retry-After"),
		responseSummary: summary,
		answeringMount:  answeringMountOf(resp),
	}
}

// AnsweringMountHeader is a response header the client sets for itself, never
// one a server's value is taken from: a transport that finds the API answering
// at another mount of the configured server puts that mount's URL here on the
// 404 it returns, for the error display. Such a transport deletes any value a
// server sent under this name.
const AnsweringMountHeader = "X-Aw-Client-Answering-Mount"

// SameOrigin reports whether a and b have the same scheme, host and port.
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || a.Scheme == "" || a.Host == "" {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// answeringMountOf is the mount named by AnsweringMountHeader on a 404, or ""
// unless it is a plain URL on the origin the request was sent to. Only its
// scheme, host and path are displayed.
func answeringMountOf(resp *http.Response) string {
	raw := resp.Header.Get(AnsweringMountHeader)
	if raw == "" || len(raw) > 128 || resp.StatusCode != http.StatusNotFound || resp.Request == nil {
		return ""
	}
	mount, err := url.Parse(raw)
	if err != nil || !SameOrigin(resp.Request.URL, mount) || mount.User != nil || mount.RawQuery != "" || mount.Fragment != "" || mount.Opaque != "" {
		return ""
	}
	display := (&url.URL{Scheme: mount.Scheme, Host: mount.Host, Path: mount.Path}).String()
	if len(display) > 128 || errorHeaderValue(display) != display {
		return ""
	}
	return display
}

func answeringMountAdvice(mount string) string {
	return "The server answers at " + mount + ". The configured server URL should be that: set aweb_url in workspace.yaml to " + mount + "."
}

var knownErrorPageTitle = regexp.MustCompile(`(?is)<title\s*>\s*(blocked|just a moment\.\.\.)\s*</title\s*>`)

func nonJSONErrorSummary(body, contentType, mitigated string) string {
	if body == "" || json.Valid([]byte(body)) {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(mitigated), "challenge") {
		return "challenge response (body omitted)"
	}
	if isHTMLResponse(body, contentType) {
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

func isHTMLResponse(body, contentType string) bool {
	lowerBody := strings.ToLower(strings.TrimSpace(body))
	lowerType := strings.ToLower(contentType)
	return strings.Contains(lowerType, "text/html") || strings.Contains(lowerType, "application/xhtml+xml") || strings.HasPrefix(lowerBody, "<html") || strings.HasPrefix(lowerBody, "<!doctype html")
}
