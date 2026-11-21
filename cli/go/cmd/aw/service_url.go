package main

import (
	"net/url"
	"strings"
)

// parseAwebSelectionURL reads a service selection, not a registry origin or a
// request target. Registry URLs use awid.CanonicalRegistryServerOrigin.
func parseAwebSelectionURL(raw string) (*url.URL, error) {
	return url.Parse(strings.TrimSpace(raw))
}

// awebSelectionURLString removes request-only query/fragment and encoded-path
// spellings from a selected service base, retaining its configured mount path.
// Its caller owns any additional route/mount validation and path trimming.
func awebSelectionURLString(value *url.URL) string {
	value.RawPath = ""
	value.RawQuery = ""
	value.Fragment = ""
	return strings.TrimSuffix(value.String(), "/")
}

func normalizeAwebBaseURL(raw string) (string, error) {
	value, err := parseAwebSelectionURL(raw)
	if err != nil {
		return "", err
	}
	value.Path = strings.TrimSuffix(value.Path, "/")
	return awebSelectionURLString(value), nil
}
