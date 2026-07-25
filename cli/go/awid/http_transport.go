package awid

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// HTTP transport tuning for hostile venue networks (conference WiFi, NAT
// table pressure, captive portals, silent blackholing). Normal API calls and
// SSE streams get separate tuned transports; neither shares raw
// http.DefaultTransport.

// APITimeoutEnvVar configures the overall timeout for normal API requests.
// It accepts Go duration strings such as "30s" or "1m".
const APITimeoutEnvVar = "AWEB_HTTP_TIMEOUT"

const MaxErrorResponseSize = 64 * 1024

var apiTimeoutWarnOnce sync.Once

var ErrResponseTooLarge = errors.New("HTTP response exceeds maximum size")

// ReadAllBounded reads at most max+1 bytes so an exactly-at-limit response is
// accepted while any trailing byte is rejected.
func ReadAllBounded(reader io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("maximum response size must not be negative")
	}
	data, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

// ReadErrorExcerpt returns a bounded single-line diagnostic. Error bodies are
// attacker-controlled and must not inject terminal control sequences or force
// the client to retain an arbitrarily large response.
func ReadErrorExcerpt(reader io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(reader, MaxErrorResponseSize+1))
	if err != nil {
		return ""
	}
	if len(data) > MaxErrorResponseSize {
		data = data[:MaxErrorResponseSize]
	}
	return SanitizeErrorText(string(data))
}

func SanitizeErrorText(text string) string {
	text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)
	return strings.Join(strings.Fields(text), " ")
}

// DoNoRedirect sends req without allowing an HTTP redirect to cross the
// request's original trust boundary. The shallow copy preserves the caller's
// transport, timeout, and other policy without mutating a client that may be
// shared by concurrent requests.
func DoNoRedirect(client *http.Client, req *http.Request) (*http.Response, error) {
	return doNoRedirect(client, req, 0)
}

// DoNoRedirectWithTimeout also supplies the overall deadline when an injected
// client has no Timeout. Callers may customize transport policy, but cannot
// remove the trust-path deadline by passing a zero-value client.
func DoNoRedirectWithTimeout(client *http.Client, req *http.Request, timeout time.Duration) (*http.Response, error) {
	return doNoRedirect(client, req, timeout)
}

func doNoRedirect(client *http.Client, req *http.Request, defaultTimeout time.Duration) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}
	noRedirectClient := *client
	if defaultTimeout > 0 && (noRedirectClient.Timeout <= 0 || noRedirectClient.Timeout > defaultTimeout) {
		noRedirectClient.Timeout = defaultTimeout
	}
	noRedirectClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return noRedirectClient.Do(req)
}

// APITimeout returns the overall timeout for normal API requests:
// AWEB_HTTP_TIMEOUT when set to a valid positive Go duration, otherwise
// DefaultTimeout. Invalid values warn once and fall back to the default, so
// a typo degrades to default behavior instead of breaking every command.
func APITimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv(APITimeoutEnvVar))
	if raw == "" {
		return DefaultTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		apiTimeoutWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "Warning: invalid %s %q; using default %s\n", APITimeoutEnvVar, raw, DefaultTimeout)
		})
		return DefaultTimeout
	}
	return parsed
}

// NewAPITransport returns a transport tuned for normal API requests on
// hostile networks: finite dial/TLS/header timeouts so blackholed
// connections surface quickly, and a short idle window so a pooled
// connection killed by an aggressive NAT is not reused long after death.
//
// Keepalives stay enabled: the awid client is shared by long-lived
// processes (gateway, channel daemons) and multi-request commands, where
// per-request TLS handshakes on flaky WiFi would hurt more than stale-reuse
// risk. The 15s IdleConnTimeout bounds that reuse window instead.
func NewAPITransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		// Follows the effective API timeout: the observed venue failure
		// class is "Client.Timeout exceeded while awaiting headers", so a
		// header timeout below AWEB_HTTP_TIMEOUT would make the documented
		// override a no-op for exactly that class. Short-lived callers
		// (probes) still bound the total via their http.Client.Timeout.
		ResponseHeaderTimeout: APITimeout(),
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       15 * time.Second,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   4,
	}
}

// NewSSETransport returns a transport for long-lived SSE streams. It keeps
// finite dial/TLS timeouts so a blackholed connect still fails fast, but a
// generous response-header window and no overall client timeout: the
// stream body is expected to stay open indefinitely. Callers must put this
// on an http.Client with no Timeout.
func NewSSETransport() *http.Transport {
	transport := NewAPITransport()
	transport.ResponseHeaderTimeout = 30 * time.Second
	return transport
}
