package awid

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxGzipRequestSize matches the server's separate encoded and decoded caps.
// Larger requests retain their existing plain representation.
const MaxGzipRequestSize = 1 << 20

// Discovery is optional; do not spend an entire API budget asking an old or
// unreachable server whether it supports compression.
const gzipDiscoveryTimeout = 2 * time.Second

type requestCompressionSupport struct {
	ready   chan struct{}
	enabled atomic.Bool
}

// Capabilities are process-local and keyed by the complete server base,
// including its mount prefix. A new process discovers again after an upgrade.
var requestCompressionServers sync.Map

// DoServerRequest sends a request to a known aweb server, without redirects.
// Rewindable write bodies are gzipped only after that exact server base has
// advertised support through /health. Authentication must cover the original
// body: compression is an HTTP representation, decoded before server auth.
// Registry, arbitrary HTTP and local custody requests use DoNoRedirect instead.
func DoServerRequest(client *http.Client, req *http.Request, serverBase string) (*http.Response, error) {
	return doServerRequest(client, req, serverBase, 0)
}

// DoServerRequestWithTimeout also preserves the injected-client deadline rule
// of DoNoRedirectWithTimeout.
func DoServerRequestWithTimeout(client *http.Client, req *http.Request, serverBase string, timeout time.Duration) (*http.Response, error) {
	return doServerRequest(client, req, serverBase, timeout)
}

func doServerRequest(client *http.Client, req *http.Request, serverBase string, timeout time.Duration) (*http.Response, error) {
	// A relocating transport must negotiate after it selects each actual base.
	if client != nil {
		if owner, ok := client.Transport.(interface{ HandlesServerRequestCompression() bool }); ok && owner.HandlesServerRequestCompression() {
			return doNoRedirect(client, req, timeout)
		}
	}
	wire, support := compressedServerRequest(client, req, serverBase)
	resp, err := doNoRedirect(client, wire, timeout)
	if support != nil && resp != nil && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnsupportedMediaType) {
		// A rejected write is never replayed to negotiate compression. Future
		// writes use plain bytes, even if later responses advertise gzip again.
		support.enabled.Store(false)
	}
	return resp, err
}

// RoundTripServerRequest lets a transport that selects API bases negotiate at
// its actual-send boundary. transport must be the underlying sender, without
// base recovery, and serverBase must be the base selected for this attempt.
// The outer http.Client still owns cancellation, deadlines and redirects.
func RoundTripServerRequest(transport http.RoundTripper, req *http.Request, serverBase string) (*http.Response, error) {
	if transport == nil {
		transport = http.DefaultTransport
	}
	wire, support := compressedServerRequest(&http.Client{Transport: transport}, req, serverBase)
	resp, err := transport.RoundTrip(wire)
	if support != nil && resp != nil && (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnsupportedMediaType) {
		support.enabled.Store(false)
	}
	return resp, err
}

func compressedServerRequest(client *http.Client, req *http.Request, serverBase string) (*http.Request, *requestCompressionSupport) {
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return req, nil
	}
	if req.Body == nil || req.GetBody == nil || req.ContentLength <= 0 || req.ContentLength > MaxGzipRequestSize {
		return req, nil
	}
	encodings := req.Header.Values("Content-Encoding")
	if len(encodings) > 1 || (len(encodings) == 1 && encodings[0] != "" && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity")) {
		return req, nil
	}
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(serverBase), "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return req, nil
	}
	if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || !strings.HasPrefix(req.URL.EscapedPath(), strings.TrimRight(base.EscapedPath(), "/")+"/") {
		return req, nil
	}
	support := serverCompressionSupport(req.Context(), client, base)
	if support == nil || !support.enabled.Load() {
		return req, nil
	}
	original, err := req.GetBody()
	if err != nil {
		return req, nil
	}
	body, err := ReadAllBounded(original, MaxGzipRequestSize)
	original.Close()
	if err != nil {
		return req, nil
	}
	var encoded bytes.Buffer
	zw := gzip.NewWriter(&encoded)
	if _, err = zw.Write(body); err != nil {
		zw.Close()
		return req, nil
	}
	if err = zw.Close(); err != nil || encoded.Len() > MaxGzipRequestSize {
		return req, nil
	}
	wire := req.Clone(req.Context())
	data := encoded.Bytes()
	wire.Body = io.NopCloser(bytes.NewReader(data))
	wire.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }
	wire.ContentLength = int64(len(data))
	wire.TransferEncoding = nil
	wire.Header.Del("Content-Length")
	wire.Header.Del("Transfer-Encoding")
	wire.Header.Set("Content-Encoding", "gzip")
	// The original reader was not consumed. Close it as a normal HTTP send
	// would; the clone owns the encoded reader that the transport closes.
	req.Body.Close()
	return wire, support
}

func serverCompressionSupport(ctx context.Context, client *http.Client, base *url.URL) *requestCompressionSupport {
	candidate := &requestCompressionSupport{ready: make(chan struct{})}
	actual, loaded := requestCompressionServers.LoadOrStore(base.String(), candidate)
	support := actual.(*requestCompressionSupport)
	if !loaded {
		support.enabled.Store(probeServerCompression(ctx, client, base))
		close(support.ready)
	}
	select {
	case <-support.ready:
		return support
	case <-ctx.Done():
		return nil
	}
}

func probeServerCompression(ctx context.Context, client *http.Client, base *url.URL) bool {
	ctx, cancel := context.WithTimeout(ctx, gzipDiscoveryTimeout)
	defer cancel()
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/health", nil)
	if err != nil {
		return false
	}
	probe.Header.Set("Accept", "application/json")
	// Never inherit a cookie jar, URL credentials or any write headers. Retain
	// the caller's transport (including TLS policy) and shorter client timeout.
	safeClient := http.Client{}
	if client != nil {
		safeClient = *client
	}
	safeClient.Jar = nil
	resp, err := DoNoRedirectWithTimeout(&safeClient, probe, APITimeout())
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Redirect advertisements do not establish support at the requested base.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, MaxErrorResponseSize)); err != nil {
		return false
	}
	return usableGzipAdvertisement(resp.Header.Values("Accept-Encoding"))
}

func usableGzipAdvertisement(values []string) bool {
	found := false
	for _, value := range values {
		for _, coding := range strings.Split(value, ",") {
			parts := strings.Split(coding, ";")
			if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
				continue
			}
			if len(parts) > 2 {
				return false
			}
			if len(parts) == 2 {
				key, q, ok := strings.Cut(strings.TrimSpace(parts[1]), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
					return false
				}
				weight, err := strconv.ParseFloat(strings.TrimSpace(q), 64)
				if err != nil || !(weight > 0 && weight <= 1) {
					return false
				}
			}
			found = true
		}
	}
	return found
}
