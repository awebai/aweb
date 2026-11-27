package a2a

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/awebai/aw/awid"
)

// ValidateCredentialURL is the transport policy for secrets sent by the A2A
// client and managed gateway. Plain HTTP is limited to literal loopback hosts
// for local development; DNS names cannot opt a remote connection into it
// (docs/a2a.md:1014-1017).
func ValidateCredentialURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("invalid A2A credential destination. Use an absolute HTTPS URL without user information or a fragment.")
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("A2A credentials require HTTPS. Configure an HTTPS endpoint, or use http://127.0.0.1 for local development instead of http://localhost.")
}

// OriginPair identifies the fetched card origin and its advertised RPC destination.
type OriginPair struct {
	Source      string
	Destination string
}

// ValidateRPCOrigin binds card credential selection to its advertised RPC
// destination (docs/a2a.md:1012-1013), using the common origin comparator.
func ValidateRPCOrigin(pair OriginPair) error {
	a, err := url.Parse(strings.TrimSpace(pair.Source))
	if err != nil {
		return fmt.Errorf("Invalid A2A card URL. Use an absolute card URL from the RPC endpoint's origin.")
	}
	b, err := url.Parse(strings.TrimSpace(pair.Destination))
	if err != nil {
		return fmt.Errorf("Invalid A2A RPC URL. Use a card served by the RPC endpoint's origin.")
	}
	if !awid.SameOrigin(a, b) {
		return fmt.Errorf("A2A card and RPC endpoint must use the same origin. Use a card served by the RPC endpoint's origin before sending credentials.")
	}
	return nil
}

// CredentialHTTPClient copies the caller's client, keeping its transport and
// redirect policy while preventing secrets in custom headers escaping origin.
func CredentialHTTPClient(base *http.Client) *http.Client {
	client := *effectiveHTTPClient(base)
	previous := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many A2A redirects. Use the final endpoint URL.")
		}
		if len(via) > 0 && !awid.SameOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("A2A credentials must stay on the same origin. Use the destination's own card and credential.")
		}
		if err := ValidateCredentialURL(req.URL.String()); err != nil {
			return err
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	return &client
}
