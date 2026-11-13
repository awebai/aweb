package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
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

func withinBound(t *testing.T, bound time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	t.Cleanup(cancel)
	return ctx
}

func TestAProtectedLookupWaitsOutTheServicesHintAndReadsAgain(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("1"), activeAnswer)
	started := time.Now()
	id, err := installedSecrets.installationWithinBound(withinBound(t, 10*time.Second), client, "team:example.com")
	if err != nil || id != "inst-1" {
		t.Fatalf("id %q err %v", id, err)
	}
	if service.count() != 2 || time.Since(started) < time.Second {
		t.Fatalf("%d reads in %s", service.count(), time.Since(started))
	}
}

func TestAHintBeyondTheBoundIsUnavailableAtOnce(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("600"))
	started := time.Now()
	_, err := installedSecrets.installationWithinBound(withinBound(t, 2*time.Second), client, "team:example.com")
	if errorCodeOf(err) != "app_installation_unavailable" || !strings.Contains(err.Error(), "600") {
		t.Fatalf("err %v", err)
	}
	if service.count() != 1 || time.Since(started) > time.Second {
		t.Fatalf("%d reads in %s", service.count(), time.Since(started))
	}
}

func TestAnUnusableHintIsNotWaitedFor(t *testing.T) {
	for _, hint := range []string{"Wed, 21 Oct 2099 07:28:00 GMT", "-1", "1.5"} {
		service, client := newInstallationService(t, throttledAnswer(hint), activeAnswer)
		_, err := installedSecrets.installationWithinBound(withinBound(t, 10*time.Second), client, "team:example.com")
		if errorCodeOf(err) != "app_installation_unavailable" || service.count() != 1 {
			t.Errorf("%q: err %v after %d reads", hint, err, service.count())
		}
	}
}

func TestABare503KeepsItsBriefTransportRetriesAndIsNotWaitedOut(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer(""))
	_, err := installedSecrets.installationWithinBound(withinBound(t, 10*time.Second), client, "team:example.com")
	if errorCodeOf(err) != "app_installation_unavailable" || service.count() != 4 {
		t.Fatalf("err %v after %d reads", err, service.count())
	}
}

func TestAnInactiveOrOtherManifestInstallationRefusesWithoutWaiting(t *testing.T) {
	for code, answer := range map[string]installationAnswer{
		"app_installation_inactive":      {status: http.StatusNotFound},
		"installation_manifest_mismatch": {status: http.StatusOK, digest: "sha256:other"},
	} {
		service, client := newInstallationService(t, answer, activeAnswer)
		_, err := installedSecrets.installationWithinBound(withinBound(t, 10*time.Second), client, "team:example.com")
		if errorCodeOf(err) != code || service.count() != 1 {
			t.Errorf("%s: err %v after %d reads", code, err, service.count())
		}
	}
}

func TestAWaitEndsWithTheCallersCancellationOrEarlierDeadline(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("5"), activeAnswer)
	ctx, cancel := context.WithCancel(withinBound(t, 30*time.Second))
	time.AfterFunc(200*time.Millisecond, cancel)
	started := time.Now()
	if _, err := installedSecrets.installationWithinBound(ctx, client, "team:example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if service.count() != 1 || time.Since(started) > 2*time.Second {
		t.Fatalf("%d reads in %s", service.count(), time.Since(started))
	}

	// A caller deadline earlier than the hint is never waited past.
	service, client = newInstallationService(t, throttledAnswer("2"), activeAnswer)
	started = time.Now()
	_, err := installedSecrets.installationWithinBound(withinBound(t, 500*time.Millisecond), client, "team:example.com")
	if errorCodeOf(err) != "app_installation_unavailable" || service.count() != 1 || time.Since(started) > time.Second {
		t.Fatalf("err %v after %d reads in %s", err, service.count(), time.Since(started))
	}
}

func TestAnUnprotectedLookupKeepsTheHintButDoesNotWait(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("1"), activeAnswer)
	_, err := installedSecrets.installation(withinBound(t, 10*time.Second), client, "team:example.com")
	var unavailable *installationUnavailable
	if errorCodeOf(err) != "app_installation_unavailable" || !errors.As(err, &unavailable) || unavailable.retryAfter != time.Second || service.count() != 1 {
		t.Fatalf("err %v after %d reads", err, service.count())
	}
}

func commandWithin(t *testing.T, bound time.Duration) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(withinBound(t, bound))
	return cmd
}

func TestOnlyAProtectedRoleActWaitsOutTheInstallationHint(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("1"), activeAnswer)
	id, err := roleActInstallation(commandWithin(t, time.Minute), installedSecrets, client, "team:example.com", true)
	if err != nil || id != "inst-1" || service.count() != 2 {
		t.Fatalf("protected: id %q err %v after %d reads", id, err, service.count())
	}

	service, client = newInstallationService(t, throttledAnswer("1"), activeAnswer)
	if _, err := roleActInstallation(commandWithin(t, time.Minute), installedSecrets, client, "team:example.com", false); errorCodeOf(err) != "app_installation_unavailable" || service.count() != 1 {
		t.Fatalf("local: err %v after %d reads", err, service.count())
	}
}

func TestTheCommandsEarlierDeadlineBoundsTheProtectedLookup(t *testing.T) {
	service, client := newInstallationService(t, throttledAnswer("2"), activeAnswer)
	started := time.Now()
	_, err := roleActInstallation(commandWithin(t, 500*time.Millisecond), installedSecrets, client, "team:example.com", true)
	if errorCodeOf(err) != "app_installation_unavailable" || service.count() != 1 || time.Since(started) > time.Second {
		t.Fatalf("err %v after %d reads in %s", err, service.count(), time.Since(started))
	}
}
