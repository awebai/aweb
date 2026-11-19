package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedInitialFailureUsesTypedBearerErrorThroughWrapping(t *testing.T) {
	cfg := fileConfig{ManagedConfig: managedConfig{ConfigURL: "https://provider.example/config", GatewayID: "gateway"}}
	err := applyManagedRuntimeConfig(&cfg)
	if !errors.Is(err, errManagedBearerRequired) || !strings.Contains(err.Error(), "Configure managed_config.bearer_token or bearer_token_env and retry") {
		t.Fatalf("error=%v", err)
	}
	if !isFatalInitialManagedRuntimeConfigError(fmt.Errorf("initialize: %w", err)) {
		t.Fatal("wrapped bearer failure not fatal")
	}
	if isFatalInitialManagedRuntimeConfigError(errors.New("peer text says bearer token is required")) {
		t.Fatal("peer error text selected fatal policy")
	}
}

func TestManagedConfigAndRegistryReadFailuresAreNotHealthyOrAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "10000")
		if _, err := fmt.Fprint(w, `{"status":"healthy","version":"0.5.11"}`); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	cfg := fileConfig{ManagedConfig: managedConfig{ConfigURL: server.URL + "/config", GatewayID: "gateway", BearerToken: "token"}}
	err := applyManagedRuntimeConfig(&cfg)
	var fetch *managedRuntimeConfigFetchError
	if !errors.As(err, &fetch) || !strings.Contains(err.Error(), "Check the provider connection and retry") {
		t.Fatalf("error=%v", err)
	}
	health := checkRegistryHealth(server.URL)
	if !health.Reachable || health.Compatible || health.Status != registryResponseUnreadable || !strings.Contains(health.Error, "Check the registry connection and retry") {
		t.Fatalf("health=%#v", health)
	}
}

func TestRegistryMalformedHealthRefusesReadinessBesideValidNeighbor(t *testing.T) {
	for _, body := range []string{`not-json`, `{"status":"healthy","version":"0.5.11"}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := fmt.Fprint(w, body); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			health := checkRegistryHealth(server.URL)
			if body == "not-json" {
				if health.Compatible || health.Status != registryResponseMalformed || !strings.Contains(health.Error, "Repair the registry health endpoint and retry") {
					t.Fatalf("health=%#v", health)
				}
			} else if !health.Reachable || !health.Compatible || health.Version != "0.5.11" {
				t.Fatalf("health=%#v", health)
			}
		})
	}
}
