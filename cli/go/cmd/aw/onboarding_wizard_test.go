package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type singleByteReader struct {
	data string
}

func (r *singleByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestGuidedOnboardingReconnectSkipsWizardWhenIdentityAndCertExist(t *testing.T) {
	oldConnect := guidedOnboardingConnect
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingConnect = oldConnect
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "identity.yaml"), []byte("name: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "default:jack.aweb.ai", &awid.TeamCertificate{Team: "default:jack.aweb.ai"}); err != nil {
		t.Fatal(err)
	}

	var connectWorkingDir, connectServerURL string
	var connectOpts certificateConnectOptions
	var hostedCalls, byodCalls int
	guidedOnboardingConnect = func(workingDir, serverURL string, opts certificateConnectOptions) (connectOutput, error) {
		connectWorkingDir = workingDir
		connectServerURL = serverURL
		connectOpts = opts
		return connectOutput{
			Status:  "connected",
			TeamID:  "default:alice.aweb.ai",
			Alias:   "alice",
			AwebURL: serverURL,
		}, nil
	}
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		return &guidedOnboardingResult{}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{}, nil
	}

	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("2\n"),
		PromptOut:  &bytes.Buffer{},
		BaseURL:    "https://app.aweb.ai",
		Role:       "reviewer",
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if connectWorkingDir != tmp {
		t.Fatalf("working_dir=%q", connectWorkingDir)
	}
	if connectServerURL != "https://app.aweb.ai/api" {
		t.Fatalf("server_url=%q", connectServerURL)
	}
	if connectOpts.Role != "reviewer" {
		t.Fatalf("role=%q", connectOpts.Role)
	}
	if hostedCalls != 0 || byodCalls != 0 {
		t.Fatalf("expected reconnect path only, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
}

func TestExecuteReconnectPathFailsOnLegacyServerURLWorkspace(t *testing.T) {
	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "identity.yaml"), []byte("did: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "default:jack.aweb.ai", &awid.TeamCertificate{Team: "default:jack.aweb.ai"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "workspace.yaml"), []byte("server_url: https://app.aweb.ai\nteam_id: default:jack.aweb.ai\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := executeReconnectPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader(""),
		PromptOut:  &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected legacy workspace to fail")
	}
	if !strings.Contains(err.Error(), "workspace.yaml uses removed server_url") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGuidedOnboardingDefaultsToHostedPath(t *testing.T) {
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	var hostedReq guidedOnboardingRequest
	var hostedCalls, byodCalls int
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		hostedReq = req
		return &guidedOnboardingResult{InitialPrompt: "study the agent guide"}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{}, nil
	}

	var out bytes.Buffer
	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("\n"),
		PromptOut:  &out,
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if hostedCalls != 1 || byodCalls != 0 {
		t.Fatalf("expected hosted path, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
	if strings.TrimSpace(result.InitialPrompt) != "study the agent guide" {
		t.Fatalf("initial_prompt=%q", result.InitialPrompt)
	}
	if hostedReq.WorkingDir == "" {
		t.Fatal("expected hosted path to receive request")
	}
	if !strings.Contains(out.String(), "Hosted is the fastest path") {
		t.Fatalf("expected onboarding choice copy, got %q", out.String())
	}
}

func TestGuidedOnboardingCanSelectBYODPath(t *testing.T) {
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	var hostedCalls, byodCalls int
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		return &guidedOnboardingResult{}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{InitialPrompt: "byod"}, nil
	}

	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("2\n"),
		PromptOut:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if hostedCalls != 0 || byodCalls != 1 {
		t.Fatalf("expected byod path, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
	if strings.TrimSpace(result.InitialPrompt) != "byod" {
		t.Fatalf("initial_prompt=%q", result.InitialPrompt)
	}
}

func TestExecuteHostedPathRejectsServersWithoutManagedOnboarding(t *testing.T) {
	oldProvision := guidedOnboardingProvisionBYODIdentity
	t.Cleanup(func() {
		guidedOnboardingProvisionBYODIdentity = oldProvision
	})

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery" {
			http.NotFound(w, r)
			return
		}
		t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
	}))
	guidedOnboardingProvisionBYODIdentity = func(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
		return nil, usageError("byod fallback hit")
	}

	var out bytes.Buffer
	_, err := executeHostedPath(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("\nAlice\nacme.com\n"),
		PromptOut:  &out,
		BaseURL:    server.URL,
	})
	if err == nil {
		t.Fatal("expected hosted path to return an error")
	}
	if !strings.Contains(err.Error(), "byod fallback hit") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out.String(), "Switching to BYOD") {
		t.Fatalf("expected fallback message, got %q", out.String())
	}
}

func TestGuidedOnboardingBYODErrorsBubbleUpInsteadOfPanicking(t *testing.T) {
	oldProvision := guidedOnboardingProvisionBYODIdentity
	t.Cleanup(func() {
		guidedOnboardingProvisionBYODIdentity = oldProvision
	})

	guidedOnboardingProvisionBYODIdentity = func(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
		return nil, usageError("byod provisioning failed")
	}

	var out bytes.Buffer
	_, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("2\n\nalice\nacme.com\n"),
		PromptOut:  &out,
	})
	if err == nil {
		t.Fatal("expected BYOD path to return an error")
	}
	if !strings.Contains(err.Error(), "byod provisioning failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteBYODPathDefaultsToEphemeralAlias(t *testing.T) {
	oldProvision := guidedOnboardingProvisionBYODIdentity
	oldConnect := guidedOnboardingConnect
	t.Cleanup(func() {
		guidedOnboardingProvisionBYODIdentity = oldProvision
		guidedOnboardingConnect = oldConnect
	})

	tmp := t.TempDir()
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	cert, err := awid.SignTeamCertificate(signingKey, awid.TeamCertificateFields{
		Team:         "default:acme.com",
		MemberDIDKey: didKey,
		Alias:        "alice",
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotReq guidedOnboardingRequest
	var gotName, gotDomain string
	guidedOnboardingProvisionBYODIdentity = func(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
		gotReq = req
		gotName = name
		gotDomain = domain
		return &guidedBYODProvision{
			Identity: &preparedIDCreate{
				Plan: &idCreatePlan{
					Name:           name,
					Domain:         "acme.com",
					Address:        "acme.com/" + name,
					DIDAW:          awid.ComputeStableID(pub),
					DIDKey:         didKey,
					RegistryURL:    "https://registry.example",
					IdentityPath:   filepath.Join(tmp, ".aw", "identity.yaml"),
					SigningKeyPath: filepath.Join(tmp, ".aw", "signing.key"),
					CreatedAt:      "2026-04-07T00:00:00Z",
				},
				IdentityKey: signingKey,
			},
			Certificate: cert,
		}, nil
	}
	guidedOnboardingConnect = func(workingDir, serverURL string, opts certificateConnectOptions) (connectOutput, error) {
		return connectOutput{Status: "connected", TeamID: "default:acme.com", Alias: "alice", AwebURL: serverURL}, nil
	}

	var out bytes.Buffer
	_, err = executeBYODPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("\nAlice\nAcme.com\n"),
		PromptOut:  &out,
		BaseURL:    "https://app.example",
		Role:       "developer",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}

	if gotReq.Persistent {
		t.Fatal("expected default BYOD identity type to be ephemeral")
	}
	if gotName != "alice" {
		t.Fatalf("name=%q", gotName)
	}
	if gotDomain != "Acme.com" {
		t.Fatalf("domain=%q", gotDomain)
	}
	output := out.String()
	for _, want := range []string{
		"Ephemeral",
		"Persistent",
		"Agent alias",
		"Creating ephemeral BYOD identity",
		`Agent alias "alice"`,
		"No public did:aw address will be registered",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "Name:") {
		t.Fatalf("BYOD wizard should not prompt with bare Name:\n%s", output)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("ephemeral BYOD should not write identity.yaml: %v", err)
	}
	savedCert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:acme.com"))
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	if savedCert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%q", savedCert.Lifetime)
	}
	if savedCert.MemberDIDAW != "" || savedCert.MemberAddress != "" {
		t.Fatalf("ephemeral cert should not carry stable fields: %+v", savedCert)
	}
}

func TestExecuteBYODPathCreatesIdentityMaterialAndConnects(t *testing.T) {
	oldProvision := guidedOnboardingProvisionBYODIdentity
	oldConnect := guidedOnboardingConnect
	t.Cleanup(func() {
		guidedOnboardingProvisionBYODIdentity = oldProvision
		guidedOnboardingConnect = oldConnect
	})

	tmp := t.TempDir()
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	didAW := awid.ComputeStableID(pub)

	var gotName, gotDomain string
	var gotReq guidedOnboardingRequest
	cert, err := awid.SignTeamCertificate(signingKey, awid.TeamCertificateFields{
		Team:          "default:acme.com",
		MemberDIDKey:  didKey,
		MemberDIDAW:   didAW,
		MemberAddress: "acme.com/alice",
		Alias:         "alice",
		Lifetime:      awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	guidedOnboardingProvisionBYODIdentity = func(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
		gotReq = req
		gotName = name
		gotDomain = domain
		normalizedDomain := awconfig.NormalizeDomain(domain)
		return &guidedBYODProvision{
			Identity: &preparedIDCreate{
				Plan: &idCreatePlan{
					Name:           name,
					Domain:         normalizedDomain,
					Address:        normalizedDomain + "/" + name,
					DIDAW:          didAW,
					DIDKey:         didKey,
					RegistryURL:    "https://registry.example",
					IdentityPath:   filepath.Join(tmp, ".aw", "identity.yaml"),
					SigningKeyPath: filepath.Join(tmp, ".aw", "signing.key"),
					CreatedAt:      "2026-04-07T00:00:00Z",
				},
				IdentityKey: signingKey,
			},
			Certificate: cert,
		}, nil
	}

	var connectWorkingDir, connectServerURL string
	var connectOpts certificateConnectOptions
	guidedOnboardingConnect = func(workingDir, serverURL string, opts certificateConnectOptions) (connectOutput, error) {
		connectWorkingDir = workingDir
		connectServerURL = serverURL
		connectOpts = opts
		return connectOutput{
			Status:  "connected",
			TeamID:  "default:acme.com",
			Alias:   "alice",
			AwebURL: serverURL,
		}, nil
	}

	_, err = executeBYODPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("2\nAlice\nAcme.com\n"),
		PromptOut:  &bytes.Buffer{},
		BaseURL:    "https://app.example",
		Role:       "developer",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}

	if gotName != "alice" {
		t.Fatalf("name=%q", gotName)
	}
	if !gotReq.Persistent {
		t.Fatal("expected persistent BYOD identity type")
	}
	if gotDomain != "Acme.com" {
		t.Fatalf("domain=%q", gotDomain)
	}
	if connectWorkingDir != tmp {
		t.Fatalf("working_dir=%q", connectWorkingDir)
	}
	if connectServerURL != "https://app.example" {
		t.Fatalf("server_url=%q", connectServerURL)
	}
	if connectOpts.Role != "developer" {
		t.Fatalf("role=%q", connectOpts.Role)
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.Address != "acme.com/alice" {
		t.Fatalf("address=%q", identity.Address)
	}
	if identity.DID != didKey {
		t.Fatalf("did=%q", identity.DID)
	}
	if identity.StableID != didAW {
		t.Fatalf("stable_id=%q", identity.StableID)
	}
	if identity.RegistryURL != "https://registry.example" {
		t.Fatalf("registry_url=%q", identity.RegistryURL)
	}
	if identity.RegistryStatus != "registered" {
		t.Fatalf("registry_status=%q", identity.RegistryStatus)
	}
	if identity.CreatedAt != "2026-04-07T00:00:00Z" {
		t.Fatalf("created_at=%q", identity.CreatedAt)
	}

	loadedKey, err := awid.LoadSigningKey(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if got := awid.ComputeDIDKey(loadedKey.Public().(ed25519.PublicKey)); got != didKey {
		t.Fatalf("saved signing key did=%q want %q", got, didKey)
	}

	savedCert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:acme.com"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if savedCert.Team != "default:acme.com" {
		t.Fatalf("team=%q", savedCert.Team)
	}
	if savedCert.MemberAddress != "acme.com/alice" {
		t.Fatalf("member_address=%q", savedCert.MemberAddress)
	}
}

func TestExecuteBYODPathProvisionsEphemeralTeamWithoutIdentityRegistrationAgainstServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWID_SKIP_DNS_VERIFY", "true")

	var gotNamespacePayload map[string]any
	var gotTeamPayload map[string]any
	var gotCertPayload map[string]any
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      gotNamespacePayload["controller_did"],
				"verification_status": "verified",
				"created_at":          "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			t.Fatal("ephemeral BYOD must not register a did:aw identity")
		case strings.Contains(r.URL.Path, "/addresses"):
			t.Fatalf("ephemeral BYOD must not register or resolve public addresses: %s %s", r.Method, r.URL.Path)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotTeamPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "team-1",
				"domain":       "acme.com",
				"name":         "default",
				"team_did_key": gotTeamPayload["team_did_key"],
				"created_at":   "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/default/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCertPayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected registry %s %s", r.Method, r.URL.Path)
		}
	}))

	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			cert := requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:acme.com",
				"alias":        cert.Alias,
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": gotTeamPayload["team_did_key"],
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected aweb %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	var out bytes.Buffer
	_, err := executeBYODPath(guidedOnboardingRequest{
		WorkingDir:  tmp,
		PromptIn:    strings.NewReader("\nAlice\nAcme.com\n"),
		PromptOut:   &out,
		BaseURL:     awebServer.URL,
		RegistryURL: registryServer.URL,
		Role:        "developer",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}

	if gotNamespacePayload == nil {
		t.Fatal("expected namespace registration")
	}
	if gotCertPayload["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%v", gotCertPayload["lifetime"])
	}
	if _, ok := gotCertPayload["member_did_aw"]; ok {
		t.Fatalf("ephemeral certificate registration should omit member_did_aw: %v", gotCertPayload["member_did_aw"])
	}
	if _, ok := gotCertPayload["member_address"]; ok {
		t.Fatalf("ephemeral certificate registration should omit member_address: %v", gotCertPayload["member_address"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("ephemeral BYOD should not write identity.yaml: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:acme.com"))
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("saved cert lifetime=%q", cert.Lifetime)
	}
}

func TestExecuteHostedPathConnectsAndClaimsHumanAgainstServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var didRequests []map[string]any
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didRequests = append(didRequests, body)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			var current map[string]any
			for _, req := range didRequests {
				if req["did_aw"] == stableID {
					current = req
					break
				}
			}
			if current == nil {
				t.Fatalf("missing did registration for %s", stableID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": current["new_did_key"],
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	var checkBodies []map[string]any
	var signupBody map[string]any
	var claimBody map[string]any
	var connectBody map[string]any
	var onboardingURL string
	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&connectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:jack.aweb.ai",
				"alias":        "laptop",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
			})
		default:
			t.Fatalf("unexpected aweb %s %s", r.Method, r.URL.Path)
		}
	}))

	onboardingServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       awebServer.URL,
				"registry_url":   registryServer.URL,
				"version":        "1.7.0",
				"features":       []string{"managed_namespaces", "claim_human"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			checkBodies = append(checkBodies, body)
			username := strings.TrimSpace(body["username"].(string))
			w.Header().Set("Content-Type", "application/json")
			if username == "Invalid_Probe" {
				_, _ = w.Write([]byte(`{"available":false,"reason":"invalid_format"}`))
				return
			}
			_, _ = w.Write([]byte(`{"available":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			username := strings.TrimSpace(signupBody["username"].(string))
			alias := strings.TrimSpace(signupBody["alias"].(string))
			didKey := strings.TrimSpace(signupBody["did_key"].(string))
			didAW := strings.TrimSpace(signupBody["did_aw"].(string))
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "default:" + username + ".aweb.ai",
				MemberDIDKey: didKey,
				Alias:        alias,
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encodedCert, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         username,
				"org_id":           "org-1",
				"namespace_domain": username + ".aweb.ai",
				"team_id":          "default:" + username + ".aweb.ai",
				"certificate":      encodedCert,
				"did_aw":           didAW,
				"member_address":   "",
				"alias":            alias,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/claim-human":
			if err := json.NewDecoder(r.Body).Decode(&claimBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "verification_sent",
				"email":  claimBody["email"],
			})
		default:
			t.Fatalf("unexpected hosted onboarding request %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = onboardingServer.URL

	tmp := t.TempDir()
	var out bytes.Buffer
	_, err = executeHostedPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("jack\nlaptop\ny\njack@example.com\n"),
		PromptOut:  &out,
		BaseURL:    onboardingServer.URL + "/api",
		Role:       "developer",
		HumanName:  "Operator Jane",
		AgentType:  "codex",
	})
	if err != nil {
		t.Fatalf("executeHostedPath: %v", err)
	}

	if len(checkBodies) != 1 {
		t.Fatalf("check username calls=%d", len(checkBodies))
	}
	if checkBodies[0]["username"] != "jack" {
		t.Fatalf("username=%v", checkBodies[0]["username"])
	}
	if len(didRequests) != 0 {
		t.Fatalf("did registrations=%d", len(didRequests))
	}
	if signupBody["username"] != "jack" {
		t.Fatalf("signup username=%v", signupBody["username"])
	}
	if signupBody["alias"] != "laptop" {
		t.Fatalf("signup alias=%v", signupBody["alias"])
	}
	if signupBody["did_aw"] != "" {
		t.Fatalf("signup did_aw=%v want empty string", signupBody["did_aw"])
	}
	if connectBody["role"] != "developer" {
		t.Fatalf("connect role=%v", connectBody["role"])
	}
	if connectBody["human_name"] != "Operator Jane" {
		t.Fatalf("connect human_name=%v", connectBody["human_name"])
	}
	if connectBody["agent_type"] != "codex" {
		t.Fatalf("connect agent_type=%v", connectBody["agent_type"])
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for ephemeral hosted onboarding: %v", err)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeWorkspaceFrom: %v", err)
	}
	activeMembership := activeMembershipForTest(t, workspace)
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("LoadTeamState: %v", err)
	}
	if teamState.ActiveTeam != "default:jack.aweb.ai" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if workspace.AwebURL != awebServer.URL {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
	if workspace.AwebURL != awebServer.URL {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
	if activeMembership.TeamID != "default:jack.aweb.ai" {
		t.Fatalf("team_id=%q", activeMembership.TeamID)
	}
	if activeMembership.Alias != "laptop" {
		t.Fatalf("alias=%q", activeMembership.Alias)
	}
	if workspace.HumanName != "Operator Jane" {
		t.Fatalf("human_name=%q", workspace.HumanName)
	}
	if workspace.AgentType != "codex" {
		t.Fatalf("agent_type=%q", workspace.AgentType)
	}

	loadedKey, err := awid.LoadSigningKey(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if got := awid.ComputeDIDKey(loadedKey.Public().(ed25519.PublicKey)); got != strings.TrimSpace(signupBody["did_key"].(string)) {
		t.Fatalf("saved signing key did=%q want %v", got, signupBody["did_key"])
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:jack.aweb.ai"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if cert.Team != "default:jack.aweb.ai" {
		t.Fatalf("cert team=%q", cert.Team)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("cert member_did_aw=%q want empty", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("cert member_address=%q want empty", cert.MemberAddress)
	}
	if claimBody["username"] != "jack" {
		t.Fatalf("claim username=%v", claimBody["username"])
	}
	if claimBody["email"] != "jack@example.com" {
		t.Fatalf("claim email=%v", claimBody["email"])
	}
	if claimBody["did_key"] != strings.TrimSpace(signupBody["did_key"].(string)) {
		t.Fatalf("claim did_key=%v want %v", claimBody["did_key"], signupBody["did_key"])
	}

	output := out.String()
	if !strings.Contains(output, "Run aw claim-human now?") {
		t.Fatalf("expected claim-human prompt in hosted output: %q", output)
	}
}

func TestExecuteHostedPathRetriesUsernameAfterSignupConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var didRequests []map[string]any
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didRequests = append(didRequests, body)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			var current map[string]any
			for _, req := range didRequests {
				if req["did_aw"] == stableID {
					current = req
					break
				}
			}
			if current == nil {
				t.Fatalf("missing did registration for %s", stableID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": current["new_did_key"],
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Setenv("AWID_REGISTRY_URL", registryServer.URL)

	var signupBodies []map[string]any
	var onboardingURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   registryServer.URL,
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			username := strings.TrimSpace(body["username"].(string))
			w.Header().Set("Content-Type", "application/json")
			if username == "Invalid_Probe" {
				_, _ = w.Write([]byte(`{"available":false,"reason":"invalid_format"}`))
				return
			}
			_, _ = w.Write([]byte(`{"available":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			signupBodies = append(signupBodies, body)
			username := strings.TrimSpace(body["username"].(string))
			if len(signupBodies) == 1 {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"detail":"username taken"}`))
				return
			}
			alias := strings.TrimSpace(body["alias"].(string))
			didKey := strings.TrimSpace(body["did_key"].(string))
			didAW := strings.TrimSpace(body["did_aw"].(string))
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "default:" + username + ".aweb.ai",
				MemberDIDKey: didKey,
				Alias:        alias,
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encodedCert, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         username,
				"org_id":           "org-1",
				"namespace_domain": username + ".aweb.ai",
				"team_id":          "default:" + username + ".aweb.ai",
				"certificate":      encodedCert,
				"did_aw":           didAW,
				"member_address":   "",
				"alias":            alias,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:jack-2.aweb.ai",
				"alias":        "laptop",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	tmp := t.TempDir()
	var out bytes.Buffer
	_, err = executeHostedPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("jack\nlaptop\njack-2\nn\n"),
		PromptOut:  &out,
		BaseURL:    server.URL,
	})
	if err != nil {
		t.Fatalf("executeHostedPath: %v", err)
	}

	if len(signupBodies) != 2 {
		t.Fatalf("signup calls=%d", len(signupBodies))
	}
	if len(didRequests) != 0 {
		t.Fatalf("did registrations=%d", len(didRequests))
	}
	if signupBodies[0]["username"] != "jack" || signupBodies[1]["username"] != "jack-2" {
		t.Fatalf("signup usernames=%v", signupBodies)
	}
	if signupBodies[0]["did_aw"] != "" || signupBodies[1]["did_aw"] != "" {
		t.Fatalf("expected empty ephemeral did_aw on retry, got %v", signupBodies)
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for ephemeral hosted onboarding retry: %v", err)
	}
	if !strings.Contains(out.String(), "Run aw claim-human now?") {
		t.Fatalf("expected claim-human prompt in hosted retry output: %q", out.String())
	}
	if !strings.Contains(out.String(), `Username "jack" was taken during signup.`) {
		t.Fatalf("expected retry message, got %q", out.String())
	}
}

func TestExecuteBYODPathProvisionsIdentityTeamAndWorkspaceAgainstServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	domain := "acme.com"
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	var gotNamespacePayload map[string]any
	var gotAddressPayload map[string]any
	var gotDIDPayload map[string]any
	var gotTeamPayload map[string]any
	var gotCertPayload map[string]any

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"last_verified_at":    "2026-04-07T00:00:00Z",
				"created_at":          "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/addresses":
			if err := json.NewDecoder(r.Body).Decode(&gotAddressPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          gotAddressPayload["did_aw"],
				"current_did_key": gotAddressPayload["current_did_key"],
				"reachability":    gotAddressPayload["reachability"],
				"created_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			if err := json.NewDecoder(r.Body).Decode(&gotDIDPayload); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := gotDIDPayload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": gotDIDPayload["new_did_key"],
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotTeamPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "team-1",
				"domain":       "acme.com",
				"name":         "default",
				"team_did_key": gotTeamPayload["team_did_key"],
				"created_at":   "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/default/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCertPayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	if err := awconfig.SaveControllerKey(domain, controllerKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: controllerDID,
		RegistryURL:   registryServer.URL,
		CreatedAt:     "2026-04-07T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	var gotConnectBody map[string]any
	connectServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&gotConnectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:acme.com",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": gotTeamPayload["team_did_key"],
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	t.Setenv("AWID_REGISTRY_URL", registryServer.URL)
	tmp := t.TempDir()
	var out bytes.Buffer
	_, err = executeBYODPath(guidedOnboardingRequest{
		WorkingDir:  tmp,
		PromptIn:    strings.NewReader("2\nAlice\nAcme.com\n"),
		PromptOut:   &out,
		BaseURL:     connectServer.URL,
		RegistryURL: registryServer.URL,
		Role:        "developer",
		HumanName:   "Operator Jane",
		AgentType:   "codex",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}

	if gotNamespacePayload["domain"] != "acme.com" {
		t.Fatalf("namespace domain=%v", gotNamespacePayload["domain"])
	}
	if gotAddressPayload["name"] != "alice" {
		t.Fatalf("address name=%v", gotAddressPayload["name"])
	}
	for _, field := range []string{"did_key", "server", "address", "handle"} {
		if _, ok := gotDIDPayload[field]; ok {
			t.Fatalf("did registration unexpectedly carried %q", field)
		}
	}
	if gotAddressPayload["did_aw"] != gotDIDPayload["did_aw"] {
		t.Fatalf("address did_aw=%v want %v", gotAddressPayload["did_aw"], gotDIDPayload["did_aw"])
	}
	if gotAddressPayload["current_did_key"] != gotDIDPayload["new_did_key"] {
		t.Fatalf("address current_did_key=%v want %v", gotAddressPayload["current_did_key"], gotDIDPayload["new_did_key"])
	}
	if gotTeamPayload["name"] != "default" {
		t.Fatalf("team name=%v", gotTeamPayload["name"])
	}
	if gotCertPayload["member_address"] != "acme.com/alice" {
		t.Fatalf("cert member_address=%v", gotCertPayload["member_address"])
	}
	if gotConnectBody["role"] != "developer" {
		t.Fatalf("connect role=%v", gotConnectBody["role"])
	}
	if gotConnectBody["human_name"] != "Operator Jane" {
		t.Fatalf("connect human_name=%v", gotConnectBody["human_name"])
	}
	if gotConnectBody["agent_type"] != "codex" {
		t.Fatalf("connect agent_type=%v", gotConnectBody["agent_type"])
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.Address != "acme.com/alice" {
		t.Fatalf("identity address=%q", identity.Address)
	}
	if identity.RegistryURL != registryServer.URL {
		t.Fatalf("registry_url=%q", identity.RegistryURL)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeWorkspaceFrom: %v", err)
	}
	activeMembership := activeMembershipForTest(t, workspace)
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("LoadTeamState: %v", err)
	}
	if teamState.ActiveTeam != "default:acme.com" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if workspace.AwebURL != connectServer.URL {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
	if workspace.HumanName != "Operator Jane" {
		t.Fatalf("human_name=%q", workspace.HumanName)
	}
	if workspace.AgentType != "codex" {
		t.Fatalf("agent_type=%q", workspace.AgentType)
	}

	if activeMembership.TeamID != "default:acme.com" {
		t.Fatalf("team_id=%q", activeMembership.TeamID)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:acme.com"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if cert.Team != "default:acme.com" {
		t.Fatalf("cert team=%q", cert.Team)
	}
}

func TestExecuteBYODPathUsesSplitOriginServiceDiscovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWID_SKIP_DNS_VERIFY", "true")

	domain := "acme.com"
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

	var gotNamespacePayload map[string]any
	var gotAddressPayload map[string]any
	var gotDIDPayload map[string]any
	var gotTeamPayload map[string]any
	var gotCertPayload map[string]any
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"last_verified_at":    "2026-04-07T00:00:00Z",
				"created_at":          "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/addresses":
			if err := json.NewDecoder(r.Body).Decode(&gotAddressPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          gotAddressPayload["did_aw"],
				"current_did_key": gotAddressPayload["current_did_key"],
				"reachability":    gotAddressPayload["reachability"],
				"created_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			if err := json.NewDecoder(r.Body).Decode(&gotDIDPayload); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := gotDIDPayload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": gotDIDPayload["new_did_key"],
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotTeamPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "team-1",
				"domain":       "acme.com",
				"name":         "default",
				"team_did_key": gotTeamPayload["team_did_key"],
				"created_at":   "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/default/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCertPayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected registry %s %s", r.Method, r.URL.Path)
		}
	}))

	if err := awconfig.SaveControllerKey(domain, controllerKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: controllerDID,
		CreatedAt:     "2026-04-07T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	var gotConnectBody map[string]any
	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&gotConnectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:acme.com",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": gotTeamPayload["team_did_key"],
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			t.Fatal("connect should use discovered aweb_url with /api")
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected aweb %s %s", r.Method, r.URL.Path)
		}
	}))

	var discoveryHit bool
	onboardingServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			discoveryHit = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": "http://" + r.Host,
				"aweb_url":       awebServer.URL + "/api",
				"registry_url":   registryServer.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			t.Fatal("connect should use discovered aweb_url, not onboarding_url")
		default:
			t.Fatalf("unexpected onboarding %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = executeBYODPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("2\nAlice\nAcme.com\n"),
		PromptOut:  &bytes.Buffer{},
		BaseURL:    onboardingServer.URL,
		Role:       "developer",
		HumanName:  "Operator Jane",
		AgentType:  "codex",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}
	if !discoveryHit {
		t.Fatal("expected discovery endpoint to be used")
	}
	if gotNamespacePayload["domain"] != "acme.com" {
		t.Fatalf("namespace domain=%v", gotNamespacePayload["domain"])
	}
	for _, field := range []string{"did_key", "server", "address", "handle"} {
		if _, ok := gotDIDPayload[field]; ok {
			t.Fatalf("did registration unexpectedly carried %q", field)
		}
	}
	if gotAddressPayload["did_aw"] != gotDIDPayload["did_aw"] {
		t.Fatalf("address did_aw=%v want %v", gotAddressPayload["did_aw"], gotDIDPayload["did_aw"])
	}
	if gotAddressPayload["current_did_key"] != gotDIDPayload["new_did_key"] {
		t.Fatalf("address current_did_key=%v want %v", gotAddressPayload["current_did_key"], gotDIDPayload["new_did_key"])
	}
	if gotCertPayload["member_address"] != "acme.com/alice" {
		t.Fatalf("cert member_address=%v", gotCertPayload["member_address"])
	}
	if gotConnectBody["role"] != "developer" {
		t.Fatalf("connect role=%v", gotConnectBody["role"])
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.RegistryURL != registryServer.URL {
		t.Fatalf("registry_url=%q", identity.RegistryURL)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeWorkspaceFrom: %v", err)
	}
	if workspace.AwebURL != awebServer.URL+"/api" {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
}

func TestGuidedOnboardingReconnectRunsPostInitSetupOnce(t *testing.T) {
	oldConnect := guidedOnboardingConnect
	oldInjectDocs := guidedOnboardingInjectDocs
	oldSetupHooks := guidedOnboardingSetupHooks
	oldSetupChannel := guidedOnboardingSetupChannel
	t.Cleanup(func() {
		guidedOnboardingConnect = oldConnect
		guidedOnboardingInjectDocs = oldInjectDocs
		guidedOnboardingSetupHooks = oldSetupHooks
		guidedOnboardingSetupChannel = oldSetupChannel
	})

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "identity.yaml"), []byte("did: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "default:acme.com", &awid.TeamCertificate{Team: "default:acme.com"}); err != nil {
		t.Fatal(err)
	}

	var docsCalls, hooksCalls, channelCalls int
	guidedOnboardingConnect = func(workingDir, serverURL string, opts certificateConnectOptions) (connectOutput, error) {
		return connectOutput{
			Status:  "connected",
			TeamID:  "default:acme.com",
			Alias:   "alice",
			AwebURL: serverURL,
		}, nil
	}
	guidedOnboardingInjectDocs = func(repoRoot string) *injectDocsResult {
		docsCalls++
		return &injectDocsResult{}
	}
	guidedOnboardingSetupChannel = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		channelCalls++
		return &claudeHooksResult{}
	}
	guidedOnboardingSetupHooks = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		hooksCalls++
		return &claudeHooksResult{}
	}

	_, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir:         tmp,
		PromptIn:           &singleByteReader{data: "y\nn\nn\n"},
		PromptOut:          &bytes.Buffer{},
		BaseURL:            "https://app.example",
		AskPostCreateSetup: true,
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if docsCalls != 1 {
		t.Fatalf("docs calls=%d", docsCalls)
	}
	if channelCalls != 0 {
		t.Fatalf("channel calls=%d", channelCalls)
	}
	if hooksCalls != 0 {
		t.Fatalf("hooks calls=%d", hooksCalls)
	}
}

func TestRunGuidedPostInitSetupKeepsDocsChannelHooksPrompts(t *testing.T) {
	oldInjectDocs := guidedOnboardingInjectDocs
	oldSetupHooks := guidedOnboardingSetupHooks
	oldSetupChannel := guidedOnboardingSetupChannel
	t.Cleanup(func() {
		guidedOnboardingInjectDocs = oldInjectDocs
		guidedOnboardingSetupHooks = oldSetupHooks
		guidedOnboardingSetupChannel = oldSetupChannel
	})

	tmp := t.TempDir()
	var docsRepo, hooksRepo, channelRepo string
	var hooksAsk bool
	guidedOnboardingInjectDocs = func(repoRoot string) *injectDocsResult {
		docsRepo = repoRoot
		return &injectDocsResult{}
	}
	guidedOnboardingSetupChannel = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		channelRepo = repoRoot
		return &claudeHooksResult{}
	}
	guidedOnboardingSetupHooks = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		hooksRepo = repoRoot
		hooksAsk = askConfirmation
		return &claudeHooksResult{}
	}

	err := runGuidedPostInitSetup(guidedOnboardingRequest{
		WorkingDir:         tmp,
		PromptIn:           &singleByteReader{data: "y\nn\ny\n"},
		PromptOut:          &bytes.Buffer{},
		AskPostCreateSetup: true,
	})
	if err != nil {
		t.Fatalf("runGuidedPostInitSetup: %v", err)
	}
	if docsRepo != tmp {
		t.Fatalf("docs_repo=%q", docsRepo)
	}
	if channelRepo != "" {
		t.Fatalf("expected channel setup to be skipped, got %q", channelRepo)
	}
	if hooksRepo != tmp {
		t.Fatalf("hooks_repo=%q", hooksRepo)
	}
	if hooksAsk {
		t.Fatal("expected wizard to handle hooks confirmation before setup call")
	}
}

func TestPromptIdentityLifetimeShowsDescriptions(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\n") // accept default (ephemeral)
	var out bytes.Buffer
	persistent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if persistent {
		t.Fatal("expected ephemeral (default), got persistent")
	}
	output := out.String()
	if !strings.Contains(output, "workspace-bound") {
		t.Fatalf("expected ephemeral description, got %q", output)
	}
	if !strings.Contains(output, "public addresses") {
		t.Fatalf("expected persistent description, got %q", output)
	}
	if strings.Contains(output, "number") {
		t.Fatalf("prompt should not say 'number', got %q", output)
	}
}

func TestPromptIdentityLifetimePersistent(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("2\n")
	var out bytes.Buffer
	persistent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !persistent {
		t.Fatal("expected persistent, got ephemeral")
	}
}

func TestGuidedOnboardingSkipDNSVerifyFromEnv(t *testing.T) {
	t.Setenv("AWID_SKIP_DNS_VERIFY", "true")
	if !guidedOnboardingSkipDNSVerify() {
		t.Fatal("expected AWID_SKIP_DNS_VERIFY=true to enable skip")
	}

	t.Setenv("AWID_SKIP_DNS_VERIFY", "0")
	if guidedOnboardingSkipDNSVerify() {
		t.Fatal("expected AWID_SKIP_DNS_VERIFY=0 to disable skip")
	}
}
