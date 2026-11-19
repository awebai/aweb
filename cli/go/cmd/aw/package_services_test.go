package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// packageServicesDeadlines bound the disposable services. Starting both
// containers and waiting for PostgreSQL took a few seconds locally; the bound
// leaves room for a slow Docker daemon.
var packageServicesDeadlines = commandStackDeadlines{Ready: 2 * time.Minute, Command: time.Minute, Stop: time.Minute}

// packageServices supplies PostgreSQL and Redis to the package's real-service
// fixtures: the runner's own when it sets PGHOST, otherwise one disposable
// pair (scripts/test-egress/disposable_services.py) for the whole run. Each
// fixture isolates itself in its own database or schema on them.
var packageServices struct {
	once    sync.Once
	err     error
	env     []string
	process *commandStackProcess
}

// errTestServicesNotOptedIn refuses to start real services in a run that did
// not ask for them: a plain local go test must not start AWID, PostgreSQL or
// Docker containers. The gate and the development VMs set AWEB_TEST_SERVICES=1.
var errTestServicesNotOptedIn = errors.New("this test needs the real service stack; run it on the gate or a dev VM (AWEB_TEST_SERVICES=1)")

// requireTestServices reports whether this run opted into the real service
// stack.
func requireTestServices() error {
	if os.Getenv("AWEB_TEST_SERVICES") != "1" {
		return errTestServicesNotOptedIn
	}
	return nil
}

// packageServicesEnv returns the settings a fixture adds to its environment:
// none when the runner supplies services, the disposable pair's otherwise.
// Every real-service fixture comes through here, so a run without the opt-in
// fails before anything starts.
func packageServicesEnv() ([]string, error) {
	if err := requireTestServices(); err != nil {
		return nil, err
	}
	packageServices.once.Do(func() { packageServices.env, packageServices.err = startPackageServices() })
	return packageServices.env, packageServices.err
}

func startPackageServices() ([]string, error) {
	for _, setting := range awTestBinary.env {
		if strings.HasPrefix(setting, "PGHOST=") && setting != "PGHOST=" {
			return nil, nil
		}
	}
	// The harness chooses the password, so it never travels on stdout.
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	password := hex.EncodeToString(secret)
	script := filepath.Join(awTestBinary.sourceDir, "../../scripts/test-egress/disposable_services.py")
	command := exec.Command("python3", script)
	command.Env = append(append([]string{}, awTestBinary.env...), "PGPASSWORD="+password)
	command.Stderr = os.Stderr
	started := time.Now()
	process, line, err := startCommandStackProcess(command, packageServicesDeadlines)
	if err != nil {
		return nil, fmt.Errorf("disposable package services: %w", err)
	}
	packageServices.process = process
	var services struct {
		PGHost   string `json:"PGHOST"`
		PGPort   string `json:"PGPORT"`
		RedisURL string `json:"REDIS_URL"`
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&services); err != nil || services.PGHost == "" || services.PGPort == "" || services.RedisURL == "" {
		return nil, process.fail(fmt.Errorf("disposable package services readiness %q: %v", line, err))
	}
	fmt.Fprintf(os.Stderr, "disposable package services start: %s\n", time.Since(started).Round(time.Millisecond))
	return []string{
		"PGHOST=" + services.PGHost, "PGPORT=" + services.PGPort, "PGUSER=postgres",
		"PGPASSWORD=" + password, "REDIS_URL=" + services.RedisURL,
	}, nil
}

// stopPackageServices removes the disposable pair, after every fixture using
// it has stopped.
func stopPackageServices() error {
	if packageServices.process == nil {
		return nil
	}
	return packageServices.process.stop()
}

func TestServiceFixturesRefuseWithoutTheExplicitOptIn(t *testing.T) {
	const refusal = "this test needs the real service stack; run it on the gate or a dev VM (AWEB_TEST_SERVICES=1)"
	for _, value := range []string{"", "0", "true"} {
		t.Setenv("AWEB_TEST_SERVICES", value)
		env, err := packageServicesEnv()
		if err == nil || err.Error() != refusal || env != nil {
			t.Fatalf("AWEB_TEST_SERVICES=%q: got env %v, err %v; want the refusal before anything starts", value, env, err)
		}
	}
	t.Setenv("AWEB_TEST_SERVICES", "1")
	if err := requireTestServices(); err != nil {
		t.Fatalf("an opted-in run was refused: %v", err)
	}
}
