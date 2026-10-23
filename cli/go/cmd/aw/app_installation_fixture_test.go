package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// installationWireFixture supplies the team's current-install/read and CAS
// protocol to CLI custody tests. Real server origin fetching/admin enforcement
// is covered by test_installation_cli.py and the wakes journey, not this stub.
func installationWireFixture(t *testing.T, manifest func() []byte) func(http.ResponseWriter, *http.Request) bool {
	t.Helper()
	type record struct {
		appInstallationReceipt
		Origin string
	}
	var mu sync.Mutex
	installs := map[string]record{}
	return func(w http.ResponseWriter, r *http.Request) bool {
		read := r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/apps/") && strings.HasSuffix(r.URL.Path, "/installation")
		write := r.Method == http.MethodPost && r.URL.Path == "/v1/apps/install"
		if !read && !write {
			return false
		}
		mu.Lock()
		defer mu.Unlock()
		team := r.URL.Query().Get("team_id")
		if team == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Error("installation request lacks selected team/certificate")
			http.Error(w, "auth", http.StatusUnauthorized)
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		if read {
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/apps/"), "/installation")
			current, ok := installs[team+"/"+id]
			if !ok {
				http.NotFound(w, r)
			} else {
				_ = json.NewEncoder(w).Encode(current.appInstallationReceipt)
			}
			return true
		}
		var request struct {
			AppID              string   `json:"app_id"`
			Origin             string   `json:"origin"`
			Digest             string   `json:"digest"`
			GrantedScopes      []string `json:"granted_scopes"`
			ExpectedGeneration *int64   `json:"expected_generation"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Errorf("installation wire body: %v", err)
			http.Error(w, "invalid body", 422)
			return true
		}
		key := team + "/" + request.AppID
		current, exists := installs[key]
		refuse := func(code string) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"detail": code})
		}
		if exists && current.Origin != request.Origin {
			refuse("app_origin_conflict")
			return true
		}
		if (exists && (request.ExpectedGeneration == nil || *request.ExpectedGeneration != current.Generation)) || (!exists && request.ExpectedGeneration != nil) {
			t.Error("CLI did not condition installation on its current read")
			refuse("generation_conflict")
			return true
		}
		raw := manifest()
		var pin struct {
			App struct {
				ID     string `json:"id"`
				Origin string `json:"origin"`
			} `json:"app"`
		}
		if err := json.Unmarshal(raw, &pin); err != nil || pin.App.ID != request.AppID || pin.App.Origin != request.Origin || sha256Digest(raw) != request.Digest {
			t.Error("installation confirmation differs from served manifest pin")
			refuse("manifest_pin_mismatch")
			return true
		}
		current.Origin = request.Origin
		current.InstallationID = "fixture-" + request.AppID
		current.Generation++
		current.State, current.OriginVerified = "active", true
		current.Digest, current.GrantedScopes = request.Digest, request.GrantedScopes
		installs[key] = current
		_ = json.NewEncoder(w).Encode(current.appInstallationReceipt)
		return true
	}
}

// The deployed contract fixtures stay byte-pinned on disk. Only their deployment
// origin is filled for binary tests, retaining every tool/key/event declaration.
func manifestAtTestOrigin(t *testing.T, raw []byte, origin string) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["app"].(map[string]any)["origin"] = origin
	filled, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return filled
}
