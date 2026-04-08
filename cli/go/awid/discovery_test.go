package awid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverServices(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"onboarding_url":"https://app.aweb.ai",
			"aweb_url":"https://coord.aweb.ai",
			"registry_url":"https://api.awid.ai",
			"version":"1.7.0",
			"features":["managed_namespaces","bootstrap_tokens"]
		}`))
	}))
	defer srv.Close()

	resp, err := DiscoverServices(context.Background(), srv.URL+"/api")
	if err != nil {
		t.Fatalf("DiscoverServices: %v", err)
	}
	if gotPath != "/api/v1/discovery" {
		t.Fatalf("path=%q", gotPath)
	}
	if resp.OnboardingURL != "https://app.aweb.ai" {
		t.Fatalf("onboarding_url=%q", resp.OnboardingURL)
	}
	if resp.AwebURL != "https://coord.aweb.ai" {
		t.Fatalf("aweb_url=%q", resp.AwebURL)
	}
	if resp.RegistryURL != "https://api.awid.ai" {
		t.Fatalf("registry_url=%q", resp.RegistryURL)
	}
	if resp.Version != "1.7.0" {
		t.Fatalf("version=%q", resp.Version)
	}
	if len(resp.Features) != 2 {
		t.Fatalf("features=%v", resp.Features)
	}
}

func TestDiscoverServicesServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := DiscoverServices(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error")
	}
}
