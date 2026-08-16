package awid

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func federationTestCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func TestPinnedFederationHTTPPreservesSNIHostAndSelectedIP(t *testing.T) {
	cert, roots := federationTestCertificate(t, "registry.test")
	var mu sync.Mutex
	var observedSNI string
	var observedHost string
	var observedEncoding string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observedHost = r.Host
		observedEncoding = r.Header.Get("Accept-Encoding")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			observedSNI = hello.ServerName
			mu.Unlock()
			return nil, nil
		},
	}
	server.StartTLS()
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewPinnedFederationHTTPClient(
		"https://registry.test:"+port,
		[]string{"127.0.0.1"},
		7,
		&tls.Config{RootCAs: roots},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.test:"+port+"/v1/test", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if observedSNI != "registry.test" || observedHost != "registry.test:"+port || observedEncoding != "identity" {
		t.Fatalf("SNI=%q host=%q encoding=%q", observedSNI, observedHost, observedEncoding)
	}
}

func TestPinnedFederationHTTPDoesNotRedirectOrUseProxy(t *testing.T) {
	cert, roots := federationTestCertificate(t, "registry.test")
	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Redirect(w, r, "https://internal.example/secret", http.StatusFound)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	t.Setenv("HTTPS_PROXY", "http://user:secret@proxy.invalid")
	client, err := NewPinnedFederationHTTPClient(
		"https://registry.test:"+port,
		[]string{"127.0.0.1"},
		8,
		&tls.Config{RootCAs: roots},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://registry.test:" + port + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || requests != 1 {
		t.Fatalf("status=%d requests=%d", resp.StatusCode, requests)
	}
}

func TestPinnedFederationHTTPRejectsUnapprovedRequestHost(t *testing.T) {
	client, err := NewPinnedFederationHTTPClient(
		"https://registry.test",
		[]string{"93.184.216.34"},
		9,
		&tls.Config{},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://other.example/v1/test", nil)
	_, err = client.Do(req)
	if !IsFederationReason(err, "sender_registry_protocol_invalid") || !strings.Contains(err.Error(), "sender_registry_protocol_invalid") {
		t.Fatalf("error=%v", err)
	}
}
