package awid

import (
	"fmt"
	"net/url"
	"strings"
)

// CanonicalServerOrigin normalizes an aweb delivery origin.
//
// Delivery origins are origins, not API base URLs: scheme + host + optional
// non-default port, with no path, userinfo, query, or fragment.
func CanonicalServerOrigin(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("server URL must be non-empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("server URL scheme must be http or https")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("server URL must not include userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("server URL must not include query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("server URL must not include a path (origin only)")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("server URL must include a host")
	}
	hostOut := host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		hostOut = "[" + host + "]"
	}
	port := parsed.Port()
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return scheme + "://" + hostOut, nil
	}
	return scheme + "://" + hostOut + ":" + port, nil
}
