package awid

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type pinnedFederationRoundTripper struct {
	origin      *url.URL
	selectedIP  netip.Addr
	transport   *http.Transport
	poolKey     string
	approvedIPs []string
	generation  int64
}

func NewPinnedFederationHTTPClient(origin string, approvedIPs []string, generation int64, tlsConfig *tls.Config) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") || generation < 1 || len(approvedIPs) == 0 {
		return nil, federationReason("sender_registry_origin_forbidden")
	}
	selected, err := netip.ParseAddr(strings.TrimSpace(approvedIPs[0]))
	if err != nil {
		return nil, federationReason("sender_registry_origin_forbidden")
	}
	canonical := make([]string, 0, len(approvedIPs))
	for _, value := range approvedIPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return nil, federationReason("sender_registry_origin_forbidden")
		}
		canonical = append(canonical, addr.String())
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		config = tlsConfig.Clone()
		if config.MinVersion == 0 {
			config.MinVersion = tls.VersionTLS12
		}
	}
	config.ServerName = parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     false,
		DisableCompression:    true,
		TLSClientConfig:       config,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   4,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(selected.String(), port))
		},
	}
	roundTripper := &pinnedFederationRoundTripper{
		origin:      parsed,
		selectedIP:  selected,
		transport:   transport,
		poolKey:     origin + "|" + strings.Join(canonical, ",") + fmt.Sprintf("|%d", generation),
		approvedIPs: canonical,
		generation:  generation,
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: roundTripper,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func (p *pinnedFederationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || request.URL.Scheme != p.origin.Scheme ||
		!strings.EqualFold(request.URL.Host, p.origin.Host) || request.URL.User != nil {
		return nil, federationReason("sender_registry_protocol_invalid")
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Set("Accept-Encoding", "identity")
	clone.Header.Del("Authorization")
	clone.Header.Del("Proxy-Authorization")
	clone.Header.Del("Cookie")
	clone.Host = p.origin.Host
	response, err := p.transport.RoundTrip(clone)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "certificate") || strings.Contains(strings.ToLower(err.Error()), "tls") {
			return nil, federationReason("sender_registry_tls_invalid")
		}
		return nil, federationReason("sender_registry_unavailable")
	}
	encoding := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		response.Body.Close()
		return nil, federationReason("sender_registry_protocol_invalid")
	}
	return response, nil
}

func (p *pinnedFederationRoundTripper) CloseIdleConnections() {
	p.transport.CloseIdleConnections()
}
