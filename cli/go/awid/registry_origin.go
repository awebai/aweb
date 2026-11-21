package awid

import (
	"fmt"
	"net/url"
	"strings"
)

// RegistryURLRefusalReason identifies the invalid part without retaining input credentials.
type RegistryURLRefusalReason string

const (
	RegistryURLMalformed RegistryURLRefusalReason = "registry_url_malformed"
	RegistryURLScheme    RegistryURLRefusalReason = "registry_url_scheme"
	RegistryURLUserinfo  RegistryURLRefusalReason = "registry_url_userinfo"
	RegistryURLPath      RegistryURLRefusalReason = "registry_url_path"
	RegistryURLQuery     RegistryURLRefusalReason = "registry_url_query"
	RegistryURLFragment  RegistryURLRefusalReason = "registry_url_fragment"
)

// RegistryURLRefusal describes a URL refusal with a credential-free origin remedy.
type RegistryURLRefusal struct {
	Reason     RegistryURLRefusalReason
	OriginForm string
}

func (e *RegistryURLRefusal) Error() string {
	var message string
	switch e.Reason {
	case RegistryURLScheme:
		message = "Registry URL scheme must be http or https."
	case RegistryURLUserinfo:
		message = "Registry URL must not include credentials."
	case RegistryURLPath:
		message = "Registry URL must be an origin or its /api alias, without another path prefix."
	case RegistryURLQuery:
		message = "Registry URL must not include a query."
	case RegistryURLFragment:
		message = "Registry URL must not include a fragment."
	default:
		message = "Registry URL must be a valid HTTP(S) origin."
	}
	if e.OriginForm != "" {
		return fmt.Sprintf("%s Use %s.", message, e.OriginForm)
	}
	return message + " Use an origin such as https://registry.example."
}

// CanonicalRegistryServerOrigin implements identity-messaging-contract.md:218-222
// and the /api aliases in vectors/atomic-address-claim-v1.json. Requests, stored
// routing and administrative pin validation share this registry-specific owner.
// Canonicalization never admits a private network destination by itself.
func CanonicalRegistryServerOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", &RegistryURLRefusal{Reason: RegistryURLMalformed}
	}
	scheme := strings.ToLower(parsed.Scheme)
	remedyScheme := scheme
	if remedyScheme != "http" && remedyScheme != "https" {
		remedyScheme = "https"
	}
	// Userinfo, path, query and fragment are excluded from every displayed remedy.
	origin, err := canonicalServerOrigin((&url.URL{Scheme: remedyScheme, Host: parsed.Host}).String())
	if err != nil {
		return "", &RegistryURLRefusal{Reason: RegistryURLMalformed}
	}
	refuse := func(reason RegistryURLRefusalReason) (string, error) {
		return "", &RegistryURLRefusal{Reason: reason, OriginForm: origin}
	}
	if scheme != "http" && scheme != "https" {
		return refuse(RegistryURLScheme)
	}
	if parsed.User != nil {
		return refuse(RegistryURLUserinfo)
	}
	if parsed.RawQuery != "" {
		return refuse(RegistryURLQuery)
	}
	if parsed.Fragment != "" {
		return refuse(RegistryURLFragment)
	}
	if parsed.Path != "" && parsed.Path != "/" && strings.TrimRight(parsed.Path, "/") != "/api" {
		return refuse(RegistryURLPath)
	}
	return origin, nil
}
