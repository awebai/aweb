package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
)

// installationAnswer is one scripted answer of the installation route.
type installationAnswer struct {
	status     int
	retryAfter string
	digest     string
}

// installationService answers each installation read with the next scripted
// answer, the last one repeating, and counts the reads.
type installationService struct {
	mu      sync.Mutex
	answers []installationAnswer
	reads   int
}

func newInstallationService(t *testing.T, answers ...installationAnswer) (*installationService, *aweb.Client) {
	t.Helper()
	s := &installationService{answers: answers}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		answer := s.answers[min(s.reads, len(s.answers)-1)]
		s.reads++
		s.mu.Unlock()
		if r.URL.Path != "/v1/apps/secrets/installation" || r.URL.Query().Get("team_id") != "team:example.com" {
			t.Errorf("read %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		if answer.retryAfter != "" {
			w.Header().Set("Retry-After", answer.retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		if answer.status != http.StatusOK {
			_, _ = w.Write([]byte(`{"detail":"identity_binding_unavailable"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(appInstallationReceipt{InstallationID: "inst-1", Generation: 1, State: "active",
			Digest: answer.digest, OriginVerified: true})
	}))
	t.Cleanup(server.Close)
	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return s, client
}

func (s *installationService) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

var installedSecrets = &holderApp{Name: "secrets", AppID: "secrets", Digest: "sha256:pinned"}

var (
	activeAnswer    = installationAnswer{status: http.StatusOK, digest: "sha256:pinned"}
	throttledAnswer = func(retryAfter string) installationAnswer {
		return installationAnswer{status: http.StatusServiceUnavailable, retryAfter: retryAfter}
	}
)

func TestAnAppLookupKeepsTheHintWithoutWaiting(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("1"), activeAnswer)
	_, err := installedSecrets.installation(context.Background(), client, "team:example.com")
	var unavailable *installationUnavailable
	if errorCodeOf(err) != "app_installation_unavailable" || !errors.As(err, &unavailable) || unavailable.retryAfter != time.Second || service.count() != 1 {
		t.Fatalf("err %v after %d reads", err, service.count())
	}
}
