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
	if err := os.WriteFile(filepath.Join(awDir, "team-cert.pem"), []byte("{}\n"), 0o600); err != nil {
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
			Status:      "connected",
			TeamAddress: "alice.aweb.ai/default",
			Alias:       "alice",
			ServerURL:   serverURL,
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
		ServerURL:  "https://app.aweb.ai",
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
	if connectServerURL != "https://app.aweb.ai" {
		t.Fatalf("server_url=%q", connectServerURL)
	}
	if connectOpts.Role != "reviewer" {
		t.Fatalf("role=%q", connectOpts.Role)
	}
	if hostedCalls != 0 || byodCalls != 0 {
		t.Fatalf("expected reconnect path only, got hosted=%d byod=%d", hostedCalls, byodCalls)
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

func TestGuidedOnboardingHostedStubReturnsUsageErrorInsteadOfPanicking(t *testing.T) {
	var out bytes.Buffer
	_, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("\n"),
		PromptOut:  &out,
	})
	if err == nil {
		t.Fatal("expected hosted path to return an error")
	}
	if !strings.Contains(err.Error(), "guided Hosted onboarding is not available in this build yet") {
		t.Fatalf("unexpected error: %v", err)
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
		PromptIn:   strings.NewReader("2\nalice\nacme.com\n"),
		PromptOut:  &out,
	})
	if err == nil {
		t.Fatal("expected BYOD path to return an error")
	}
	if !strings.Contains(err.Error(), "byod provisioning failed") {
		t.Fatalf("unexpected error: %v", err)
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
	cert, err := awid.SignTeamCertificate(signingKey, awid.TeamCertificateFields{
		Team:          "acme.com/default",
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
			Status:      "connected",
			TeamAddress: "acme.com/default",
			Alias:       "alice",
			ServerURL:   serverURL,
		}, nil
	}

	_, err = executeBYODPath(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("Alice\nAcme.com\n"),
		PromptOut:  &bytes.Buffer{},
		ServerURL:  "https://app.example",
		Role:       "developer",
	})
	if err != nil {
		t.Fatalf("executeBYODPath: %v", err)
	}

	if gotName != "alice" {
		t.Fatalf("name=%q", gotName)
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

	savedCert, err := awid.LoadTeamCertificate(filepath.Join(tmp, ".aw", "team-cert.pem"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if savedCert.Team != "acme.com/default" {
		t.Fatalf("team=%q", savedCert.Team)
	}
	if savedCert.MemberAddress != "acme.com/alice" {
		t.Fatalf("member_address=%q", savedCert.MemberAddress)
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
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			handle := "alice"
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": gotDIDPayload["did_key"],
				"server":          "",
				"address":         "acme.com/alice",
				"handle":          &handle,
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
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&gotConnectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": "acme.com/default",
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
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("Alice\nAcme.com\n"),
		PromptOut:  &out,
		ServerURL:  connectServer.URL,
		Role:       "developer",
		HumanName:  "Operator Jane",
		AgentType:  "codex",
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
	if gotDIDPayload["address"] != "acme.com/alice" {
		t.Fatalf("did address=%v", gotDIDPayload["address"])
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
	if workspace.TeamAddress != "acme.com/default" {
		t.Fatalf("team_address=%q", workspace.TeamAddress)
	}
	if workspace.ServerURL != connectServer.URL {
		t.Fatalf("server_url=%q", workspace.ServerURL)
	}
	if workspace.HumanName != "Operator Jane" {
		t.Fatalf("human_name=%q", workspace.HumanName)
	}
	if workspace.AgentType != "codex" {
		t.Fatalf("agent_type=%q", workspace.AgentType)
	}

	cert, err := awid.LoadTeamCertificate(filepath.Join(tmp, ".aw", "team-cert.pem"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if cert.Team != "acme.com/default" {
		t.Fatalf("cert team=%q", cert.Team)
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
	if err := os.WriteFile(filepath.Join(awDir, "team-cert.pem"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var docsCalls, hooksCalls, channelCalls int
	guidedOnboardingConnect = func(workingDir, serverURL string, opts certificateConnectOptions) (connectOutput, error) {
		return connectOutput{
			Status:      "connected",
			TeamAddress: "acme.com/default",
			Alias:       "alice",
			ServerURL:   serverURL,
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
		ServerURL:          "https://app.example",
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
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permanent {
		t.Fatal("expected ephemeral (default), got permanent")
	}
	output := out.String()
	if !strings.Contains(output, "workspace-bound") {
		t.Fatalf("expected ephemeral description, got %q", output)
	}
	if !strings.Contains(output, "public addresses") {
		t.Fatalf("expected permanent description, got %q", output)
	}
	if strings.Contains(output, "number") {
		t.Fatalf("prompt should not say 'number', got %q", output)
	}
}

func TestPromptIdentityLifetimePermanent(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("2\n")
	var out bytes.Buffer
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permanent {
		t.Fatal("expected permanent, got ephemeral")
	}
}
