package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	awrun "github.com/awebai/aw/run"
	"github.com/spf13/cobra"
)

func TestRunInitUsesRunConfigWorkflow(t *testing.T) {
	initRunCommandVars()
	var loadedDir string
	var initCalled bool

	oldLoad := runLoadUserConfig
	oldInit := runInitUserConfig
	oldResolveClient := runResolveClientForDir
	oldGetwd := runGetwd
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runInitUserConfig = oldInit
		runResolveClientForDir = oldResolveClient
		runGetwd = oldGetwd
		initRunCommandVars()
	})

	runGetwd = func() (string, error) { return "/tmp/work", nil }
	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) {
		loadedDir = dir
		return awrun.UserConfig{}, nil
	}
	runInitUserConfig = func(in io.Reader, out io.Writer, existing awrun.UserConfig) error {
		initCalled = true
		return nil
	}
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		t.Fatal("client resolution should not run for --init")
		return nil, nil, nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runInitConfig = true
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, nil); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if loadedDir != "/tmp/work" {
		t.Fatalf("expected run config load for /tmp/work, got %q", loadedDir)
	}
	if !initCalled {
		t.Fatal("expected run init workflow to execute")
	}
}

func TestRunBuildsLoopOptionsFromConfigAndFlags(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	oldResolveClaimedTaskRef := runResolveClaimedTaskRef
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		runResolveClaimedTaskRef = oldResolveClaimedTaskRef
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) {
		if !strings.HasSuffix(dir, "testdata") {
			t.Fatalf("expected absolute testdata dir, got %q", dir)
		}
		return awrun.UserConfig{}, nil
	}
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		if overrides.BasePrompt == nil || *overrides.BasePrompt != "flag base" {
			t.Fatalf("expected base-prompt override, got %#v", overrides.BasePrompt)
		}
		if overrides.WaitSeconds == nil || *overrides.WaitSeconds != 7 {
			t.Fatalf("expected wait override, got %#v", overrides.WaitSeconds)
		}
		return awrun.Settings{
			BasePrompt:      "resolved base",
			WaitSeconds:     9,
			IdleWaitSeconds: 12,
			Services:        []awrun.ServiceConfig{{Name: "api", Command: "make api", Description: "API"}},
		}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		if name != "claude" {
			t.Fatalf("provider=%q", name)
		}
		return awrun.ClaudeProvider{}, nil
	}
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		if !strings.HasSuffix(dir, "testdata") {
			t.Fatalf("expected selection dir to match working dir, got %q", dir)
		}
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose", IdentityID: "ws-1"}, nil
	}
	runWorkspaceStateForDir = func(dir string) (runWorkspaceState, error) {
		return runWorkspaceStateInitialized, nil
	}
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus {
		if client == nil {
			t.Fatal("expected client for event bus")
		}
		return nil
	}
	runResolveClaimedTaskRef = func(ctx context.Context, client *aweb.Client, workspaceID string) (string, error) {
		if workspaceID == "" {
			t.Fatal("expected workspace id for claim lookup")
		}
		return "aweb-aaag", nil
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }

	var capturedLoop *awrun.Loop
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		capturedLoop = awrun.NewLoop(provider, out)
		return capturedLoop
	}

	var capturedOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedOpts = opts
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runWorkingDir = "testdata"
	runContinueMode = true
	runMaxRuns = 3
	runAllowedTools = "Read,Write"
	runModel = "sonnet"
	runProviderPTY = true
	runTripOnDanger = true
	runAutofeedWork = true
	runBasePrompt = "flag base"
	runInitialPrompt = "finish the migration"
	runWaitSeconds = 7
	cmd.Command.Flags().Set("base-prompt", "flag base")
	cmd.Command.Flags().Set("prompt", "finish the migration")
	cmd.Command.Flags().Set("wait", "7")
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedLoop == nil {
		t.Fatal("expected loop to be constructed")
	}
	if capturedLoop.StatusIdentity != "claude@team:rose" {
		t.Fatalf("status identity=%q", capturedLoop.StatusIdentity)
	}
	if capturedLoop.Dispatch == nil {
		t.Fatal("expected run loop to have a dispatcher")
	}
	if capturedLoop.OnUserPrompt == nil || capturedLoop.OnRunComplete == nil {
		t.Fatal("expected interaction log hooks on loop")
	}
	if capturedOpts.InitialPrompt != "finish the migration" {
		t.Fatalf("initial prompt=%q", capturedOpts.InitialPrompt)
	}
	if capturedOpts.BasePrompt != "resolved base" {
		t.Fatalf("base prompt=%q", capturedOpts.BasePrompt)
	}
	if capturedOpts.WaitSeconds != 9 || capturedOpts.IdleWaitSeconds != 12 {
		t.Fatalf("wait settings=%+v", capturedOpts)
	}
	if !capturedOpts.ContinueMode || !capturedOpts.Autofeed {
		t.Fatalf("expected continue and autofeed flags in opts: %+v", capturedOpts)
	}
	if capturedOpts.MaxRuns != 3 || capturedOpts.AllowedTools != "Read,Write" || capturedOpts.Model != "sonnet" {
		t.Fatalf("unexpected opts: %+v", capturedOpts)
	}
	if !capturedOpts.TripOnDanger {
		t.Fatalf("expected trip-on-danger in opts, got %+v", capturedOpts)
	}
	if capturedOpts.ClaimedTaskRef != "aweb-aaag" {
		t.Fatalf("expected claimed task ref in opts, got %+v", capturedOpts)
	}
	if capturedOpts.ProviderPTY {
		t.Fatalf("expected ProviderPTY=false when no interactive screen is available, got %+v", capturedOpts)
	}
	if len(capturedOpts.Services) != 1 || capturedOpts.Services[0].Name != "api" {
		t.Fatalf("expected services in opts, got %+v", capturedOpts.Services)
	}
}

func TestRunRequiresPromptWithoutConfiguredBasePrompt(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	err := runRun(&cmd.Command, []string{"claude"})
	if err == nil {
		t.Fatal("expected error")
	}
	var cliErr *cliError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected cliError, got %T", err)
	}
	if !strings.Contains(err.Error(), "missing prompt") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRequiresProviderWhenNonInteractive(t *testing.T) {
	initRunCommandVars()

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	err := runRun(&cmd.Command, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var cliErr *cliError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected cliError, got %T", err)
	}
	if !strings.Contains(err.Error(), "missing provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAllowsEmptyPromptWhenInteractiveScreenIsAvailable(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return awrun.ClaudeProvider{}, nil
	}
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController {
		return &awrun.ScreenController{}
	}
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}

	var capturedOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedOpts = opts
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedOpts.InitialPrompt != "" || capturedOpts.BasePrompt != "" {
		t.Fatalf("expected empty prompts to be allowed interactively, got %+v", capturedOpts)
	}
	if capturedOpts.ProviderPTY {
		t.Fatalf("expected interactive run to default ProviderPTY=false, got %+v", capturedOpts)
	}
}

func TestRunDefaultsCodexToNonPTYWhenInteractive(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return awrun.CodexProvider{}, nil
	}
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController {
		return &awrun.ScreenController{}
	}
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}

	var capturedOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedOpts = opts
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"codex"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedOpts.ProviderPTY {
		t.Fatalf("expected interactive codex run to default ProviderPTY=false, got %+v", capturedOpts)
	}
}

func TestRunHonorsExplicitCodexPTYOverride(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return awrun.CodexProvider{}, nil
	}
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController {
		return &awrun.ScreenController{}
	}
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}

	var capturedOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedOpts = opts
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	if err := cmd.Command.Flags().Set("provider-pty", "true"); err != nil {
		t.Fatalf("set provider-pty: %v", err)
	}
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"codex"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if !capturedOpts.ProviderPTY {
		t.Fatalf("expected explicit provider-pty override to be honored, got %+v", capturedOpts)
	}
}

func TestRunNonInteractiveMissingContextPrintsOnboardingHint(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldResolveClient := runResolveClientForDir
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runResolveClientForDir = oldResolveClient
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{BasePrompt: "mission"}, nil
	}
	runWorkspaceStateForDir = func(dir string) (runWorkspaceState, error) { return runWorkspaceStateMissing, nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	err := runRun(&cmd.Command, []string{"claude"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "current directory is not initialized for aw") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunInteractiveOnboardsWithProjectKeyBeforeRunning(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldResolveClient := runResolveClientForDir
	oldNewScreen := runNewScreenController
	oldNewProvider := runNewProvider
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldWorkspaceState := runWorkspaceStateForDir
	oldResolveBaseURLForCollection := initResolveBaseURLForCollection
	oldFetchSuggestionForCollection := initFetchSuggestionForCollection
	oldExecuteInitFlow := guidedOnboardingExecuteInitFlow
	oldPrintInitSummary := guidedOnboardingPrintInitSummary
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runResolveClientForDir = oldResolveClient
		runNewScreenController = oldNewScreen
		runNewProvider = oldNewProvider
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runWorkspaceStateForDir = oldWorkspaceState
		initResolveBaseURLForCollection = oldResolveBaseURLForCollection
		initFetchSuggestionForCollection = oldFetchSuggestionForCollection
		guidedOnboardingExecuteInitFlow = oldExecuteInitFlow
		guidedOnboardingPrintInitSummary = oldPrintInitSummary
		initRunCommandVars()
	})

	t.Setenv("AWEB_API_KEY", "aw_sk_project")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{BasePrompt: "mission"}, nil
	}
	runWorkspaceStateForDir = func(dir string) (runWorkspaceState, error) { return runWorkspaceStateMissing, nil }

	var resolveCalls int
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		resolveCalls++
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController {
		return &awrun.ScreenController{}
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return awrun.ClaudeProvider{}, nil
	}
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		return nil
	}
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	initResolveBaseURLForCollection = func(baseURL, serverName string) (string, string, *awconfig.GlobalConfig, error) {
		return "https://app.aweb.ai/api", "app.aweb.ai", nil, nil
	}
	initFetchSuggestionForCollection = func(baseURL, nsSlug, authToken string) *awid.SuggestAliasPrefixResponse {
		return &awid.SuggestAliasPrefixResponse{NamePrefix: "alice", Roles: []string{"developer", "reviewer"}}
	}

	var capturedOpts initOptions
	guidedOnboardingExecuteInitFlow = func(opts initOptions) (*initResult, error) {
		capturedOpts = opts
		return &initResult{
			Response:    &awid.BootstrapIdentityResponse{APIKey: "aw_sk_new", Name: "Alice Example", NamespaceSlug: "team", ProjectSlug: "team", Lifetime: awid.LifetimePersistent},
			AccountName: "acct-app__team__alice",
			ServerName:  "app.aweb.ai",
		}, nil
	}
	guidedOnboardingPrintInitSummary = func(resp *awid.BootstrapIdentityResponse, accountName, serverName, role string, attachResult *contextAttachResult, signingKeyPath, workingDir, headline string) {
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader("\n\n2\n1\nAlice Example\n"), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedOpts.Flow != flowProjectKey {
		t.Fatalf("expected project-key onboarding flow, got %+v", capturedOpts)
	}
	if capturedOpts.IdentityName != "Alice Example" || capturedOpts.IdentityAlias != "" {
		t.Fatalf("expected permanent identity onboarding, got %+v", capturedOpts)
	}
	if capturedOpts.Lifetime != awid.LifetimePersistent {
		t.Fatalf("expected persistent lifetime, got %+v", capturedOpts)
	}
	if capturedOpts.WorkspaceRole != "developer" {
		t.Fatalf("expected prompted role to be used, got %+v", capturedOpts)
	}
	if resolveCalls != 1 {
		t.Fatalf("expected client resolution after onboarding, got %d calls", resolveCalls)
	}
}

func TestRunInteractiveCreatesProjectBeforeRunning(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldResolveClient := runResolveClientForDir
	oldNewScreen := runNewScreenController
	oldNewProvider := runNewProvider
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldWorkspaceState := runWorkspaceStateForDir
	oldResolveBaseURLForCollection := initResolveBaseURLForCollection
	oldFetchSuggestionForCollection := initFetchSuggestionForCollection
	oldExecuteInitFlow := guidedOnboardingExecuteInitFlow
	oldInjectDocs := guidedOnboardingInjectDocs
	oldSetupHooks := guidedOnboardingSetupHooks
	oldSetupChannel := guidedOnboardingSetupChannel
	oldPrintInitSummary := guidedOnboardingPrintInitSummary
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runResolveClientForDir = oldResolveClient
		runNewScreenController = oldNewScreen
		runNewProvider = oldNewProvider
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runWorkspaceStateForDir = oldWorkspaceState
		initResolveBaseURLForCollection = oldResolveBaseURLForCollection
		initFetchSuggestionForCollection = oldFetchSuggestionForCollection
		guidedOnboardingExecuteInitFlow = oldExecuteInitFlow
		guidedOnboardingInjectDocs = oldInjectDocs
		guidedOnboardingSetupHooks = oldSetupHooks
		guidedOnboardingSetupChannel = oldSetupChannel
		guidedOnboardingPrintInitSummary = oldPrintInitSummary
		initRunCommandVars()
	})

	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{BasePrompt: "mission"}, nil
	}
	runWorkspaceStateForDir = func(dir string) (runWorkspaceState, error) { return runWorkspaceStateMissing, nil }

	var resolveCalls int
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		resolveCalls++
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController {
		return &awrun.ScreenController{}
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return awrun.ClaudeProvider{}, nil
	}
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		return nil
	}
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	initResolveBaseURLForCollection = func(baseURL, serverName string) (string, string, *awconfig.GlobalConfig, error) {
		return "https://app.aweb.ai/api", "app.aweb.ai", nil, nil
	}
	initFetchSuggestionForCollection = func(baseURL, nsSlug, authToken string) *awid.SuggestAliasPrefixResponse {
		return &awid.SuggestAliasPrefixResponse{NamePrefix: "alice", Roles: []string{"developer", "reviewer"}}
	}

	var capturedOpts initOptions
	guidedOnboardingExecuteInitFlow = func(opts initOptions) (*initResult, error) {
		capturedOpts = opts
		return &initResult{
			Response:    &awid.BootstrapIdentityResponse{APIKey: "aw_sk_new", Alias: "alice", NamespaceSlug: "team", ProjectSlug: "demo-repo", Lifetime: awid.LifetimeEphemeral},
			AccountName: "acct-app__team__alice",
			ServerName:  "app.aweb.ai",
		}, nil
	}
	guidedOnboardingPrintInitSummary = func(resp *awid.BootstrapIdentityResponse, accountName, serverName, role string, attachResult *contextAttachResult, signingKeyPath, workingDir, headline string) {
	}

	var injectedRepo string
	guidedOnboardingInjectDocs = func(repoRoot string) *injectDocsResult {
		injectedRepo = repoRoot
		return &injectDocsResult{}
	}
	var hooksRepo string
	var hooksAsk bool
	guidedOnboardingSetupHooks = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		hooksRepo = repoRoot
		hooksAsk = askConfirmation
		return &claudeHooksResult{}
	}
	var channelRepo string
	guidedOnboardingSetupChannel = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		channelRepo = repoRoot
		return &claudeHooksResult{}
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	tmp := t.TempDir()
	runWorkingDir = tmp
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader("\n\n\n1\ny\ny\n"), &stdout, &stderr)

	var capturedLoopOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedLoopOpts = opts
		return nil
	}

	if err := runRun(&cmd.Command, []string{"codex"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedOpts.Flow != flowHeadless {
		t.Fatalf("expected headless create-project flow, got %+v", capturedOpts)
	}
	if capturedOpts.ProjectSlug != sanitizeSlug(filepath.Base(tmp)) {
		t.Fatalf("expected project slug to follow working dir, got %+v", capturedOpts)
	}
	if capturedOpts.IdentityAlias != "" {
		t.Fatalf("expected create-project flow to let the server allocate the alias, got %+v", capturedOpts)
	}
	if capturedOpts.WorkspaceRole != "" {
		t.Fatalf("expected role selection to be deferred until after bootstrap, got %+v", capturedOpts)
	}
	if !capturedOpts.PromptRoleAfterBootstrap {
		t.Fatalf("expected post-bootstrap role prompt to be enabled, got %+v", capturedOpts)
	}
	if strings.TrimSpace(capturedLoopOpts.InitialPrompt) != "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else." {
		t.Fatalf("expected onboarding guide prompt, got %q", capturedLoopOpts.InitialPrompt)
	}
	if injectedRepo != tmp || channelRepo != tmp {
		t.Fatalf("expected docs/channel on repo root, got docs=%q channel=%q", injectedRepo, channelRepo)
	}
	if hooksRepo != "" {
		t.Fatalf("expected hooks skipped when channel is chosen, got hooks=%q", hooksRepo)
	}
	if hooksAsk {
		t.Fatalf("expected wizard to handle hooks confirmation before setup call")
	}
	if resolveCalls != 1 {
		t.Fatalf("expected client resolution after onboarding, got %d calls", resolveCalls)
	}
}

func TestNewRunDispatcherBuildsMailPrompt(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{
		WorkPromptSuffix:  "work suffix",
		CommsPromptSuffix: "comms suffix",
	}, func(context.Context, awid.AgentEvent) (runWakeResolution, error) {
		return runWakeResolution{CycleContext: "● from mia (mail): API review — please take a look"}, nil
	})

	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		FromAlias: "mia",
		Subject:   "API review",
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if decision.Skip {
		t.Fatalf("expected mail wake to produce a prompt, got %+v", decision)
	}
	if !strings.Contains(decision.CycleContext, "● from mia (mail): API review — please take a look") {
		t.Fatalf("expected hydrated mail content, got %q", decision.CycleContext)
	}
	if len(decision.DisplayLines) == 0 || decision.DisplayLines[0].Kind != awrun.DisplayKindCommunication {
		t.Fatalf("expected communication display lines, got %+v", decision.DisplayLines)
	}
	for _, line := range decision.DisplayLines {
		if strings.Contains(line.Text, "comms suffix") {
			t.Fatalf("expected display lines to exclude prompt suffix, got %+v", decision.DisplayLines)
		}
	}
	if !strings.Contains(decision.CycleContext, "comms suffix") {
		t.Fatalf("expected comms suffix in prompt, got %q", decision.CycleContext)
	}
}

func TestFormatIncomingMailContextIndentsMultiLineBodyUnderAlias(t *testing.T) {
	got := formatIncomingMailContext("ivy", "Review request", "pass is complete.\n1. PTY default-off\n- cmd/aw/run.go")
	want := "● from ivy (mail): Review request\n   pass is complete.\n   1. PTY default-off\n   - cmd/aw/run.go"
	if got != want {
		t.Fatalf("unexpected mail context:\n%s", got)
	}
	if !strings.HasPrefix(got, "● from ivy (mail):") {
		t.Fatalf("expected mail label at the left edge, got %q", got)
	}
}

func TestFormatIncomingChatContextIndentsMultiLineBodyUnderAlias(t *testing.T) {
	got := formatIncomingChatContext("dave", "first line\nsecond line")
	want := "● from dave (chat): first line\n   second line"
	if got != want {
		t.Fatalf("unexpected chat context:\n%s", got)
	}
}

func TestNewRunDispatcherBuildsActionableChatPrompt(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{
		CommsPromptSuffix: "comms suffix",
	}, func(context.Context, awid.AgentEvent) (runWakeResolution, error) {
		return runWakeResolution{CycleContext: "● from henry (chat): ping"}, nil
	})

	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:          awid.AgentEventActionableChat,
		FromAlias:     "henry",
		SessionID:     "s-9",
		WakeMode:      "interrupt",
		SenderWaiting: true,
		UnreadCount:   2,
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if decision.Skip {
		t.Fatalf("expected actionable chat wake to produce a prompt, got %+v", decision)
	}
	if !strings.Contains(decision.CycleContext, "● from henry (chat): ping") {
		t.Fatalf("expected hydrated chat content, got %q", decision.CycleContext)
	}
	if len(decision.DisplayLines) == 0 || decision.DisplayLines[0].Kind != awrun.DisplayKindCommunication {
		t.Fatalf("expected communication display lines, got %+v", decision.DisplayLines)
	}
}

func TestNewRunDispatcherBuildsIdleActionableChatPrompt(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{}, func(context.Context, awid.AgentEvent) (runWakeResolution, error) {
		return runWakeResolution{CycleContext: "● from rose (chat): when you have a moment"}, nil
	})

	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		FromAlias:   "rose",
		SessionID:   "s-10",
		WakeMode:    "idle",
		UnreadCount: 1,
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if decision.Skip {
		t.Fatalf("expected idle actionable chat wake to produce a prompt, got %+v", decision)
	}
	if !strings.Contains(decision.CycleContext, "● from rose (chat): when you have a moment") {
		t.Fatalf("expected chat content, got %q", decision.CycleContext)
	}
	if len(decision.DisplayLines) == 0 || decision.DisplayLines[0].Kind != awrun.DisplayKindCommunication {
		t.Fatalf("expected communication display lines, got %+v", decision.DisplayLines)
	}
}

func TestResolveChatWakeUsesExactUnreadMessageIDBeforePendingLastMessage(t *testing.T) {
	_ = deliveredIDsTestPath(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions/s-1/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"messages":[{"message_id":"m-1","from_agent":"dave","body":"please review the retry path","timestamp":"2026-03-25T00:00:00Z"},{"message_id":"m-2","from_agent":"dave","body":"newer follow-up","timestamp":"2026-03-25T00:01:00Z"}]}`)
		case "/v1/chat/pending":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"pending":[{"session_id":"s-1","participants":["dave","ivy"],"last_message":"newer follow-up","last_from":"dave","unread_count":2,"last_activity":"2026-03-25T00:01:00Z","sender_waiting":true}],"messages_waiting":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resolved, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		MessageID:   "m-1",
		SessionID:   "s-1",
		FromAlias:   "dave",
		UnreadCount: 2,
	})
	if err != nil {
		t.Fatalf("resolveChatWake returned error: %v", err)
	}
	if !strings.Contains(resolved.CycleContext, "please review the retry path") {
		t.Fatalf("expected exact unread message body, got %q", resolved.CycleContext)
	}
	if strings.Contains(resolved.CycleContext, "newer follow-up") {
		t.Fatalf("expected resolver not to collapse to pending last_message, got %q", resolved.CycleContext)
	}
}

func TestNewRunDispatcherSkipsWorkWakeWithoutAutofeed(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{
		WorkPromptSuffix: "work suffix",
	}, nil)

	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:   awid.AgentEventWorkAvailable,
		TaskID: "aw-i4h",
		Title:  "Surface wake stream mode transitions to the user",
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if !decision.Skip {
		t.Fatalf("expected work wake without autofeed to skip, got %+v", decision)
	}
}

func TestNewRunDispatcherBuildsTaskActivityDisplayForWorkWake(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{}, nil)

	decision, err := dispatcher.Next(context.Background(), true, &awid.AgentEvent{
		Type:   awid.AgentEventClaimUpdate,
		TaskID: "aweb-aaat.1",
		Title:  "Introduce a semantic run display model",
		Status: "in_progress",
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if len(decision.DisplayLines) != 1 {
		t.Fatalf("expected one task activity display line, got %+v", decision.DisplayLines)
	}
	if decision.DisplayLines[0].Kind != awrun.DisplayKindTaskActivity {
		t.Fatalf("expected task activity kind, got %+v", decision.DisplayLines)
	}
	if !strings.Contains(decision.DisplayLines[0].Text, "claim changed") {
		t.Fatalf("expected claim activity text, got %+v", decision.DisplayLines)
	}
}

func TestNewRunDispatcherSkipsStaleActionableChat(t *testing.T) {
	dispatcher := newRunDispatcher(awrun.Settings{}, func(context.Context, awid.AgentEvent) (runWakeResolution, error) {
		return runWakeResolution{Skip: true}, nil
	})

	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		FromAlias:   "rose",
		SessionID:   "s-10",
		WakeMode:    "interrupt",
		UnreadCount: 1,
	})
	if err != nil {
		t.Fatalf("Next returned error: %v", err)
	}
	if !decision.Skip {
		t.Fatalf("expected stale actionable chat wake to skip, got %+v", decision)
	}
}

type recordingRunProvider struct {
	mu      sync.Mutex
	prompts []string
	builds  []awrun.BuildOptions
}

func (p *recordingRunProvider) Name() string { return "fake" }

func (p *recordingRunProvider) BuildCommand(prompt string, opts awrun.BuildOptions) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prompts = append(p.prompts, prompt)
	p.builds = append(p.builds, opts)
	return []string{"fake-provider", prompt}, nil
}

func (p *recordingRunProvider) BuildResumeCommand(opts awrun.BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (p *recordingRunProvider) BuildResumeHint(opts awrun.BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (p *recordingRunProvider) ParseOutput(string) (*awrun.Event, error) {
	return &awrun.Event{Type: awrun.EventDone, Session: "sess-42"}, nil
}

func (p *recordingRunProvider) SessionID(event *awrun.Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func (p *recordingRunProvider) snapshot() ([]string, []awrun.BuildOptions) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prompts := append([]string(nil), p.prompts...)
	builds := append([]awrun.BuildOptions(nil), p.builds...)
	return prompts, builds
}

func TestRunUsesWakeEventToTriggerSecondCycle(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("response writer does not support flushing")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			_, _ = io.WriteString(w, "event: connected\ndata: {\"agent_id\":\"a-1\",\"project_id\":\"p-1\"}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "event: actionable_chat\ndata: {\"message_id\":\"m-1\",\"from_alias\":\"mia\",\"session_id\":\"s-1\",\"wake_mode\":\"interrupt\",\"unread_count\":1,\"sender_waiting\":true}\n\n")
			flusher.Flush()
			<-r.Context().Done()
		case r.URL.Path == "/v1/chat/pending":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"pending":[{"session_id":"s-1","participants":["mia","rose"],"last_message":"can you review the retry path?","last_from":"mia","unread_count":1,"last_activity":"2026-03-20T00:00:00Z","sender_waiting":true}],"messages_waiting":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := aweb.NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	runLoadUserConfig = func(string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{
			BasePrompt:      "persistent mission",
			WaitSeconds:     30,
			IdleWaitSeconds: 1,
		}, nil
	}

	provider := &recordingRunProvider{}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return provider, nil
	}
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		return client, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		loop := awrun.NewLoop(provider, out)
		loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
			onLine("done")
			return nil
		}
		loop.Sleep = func(ctx context.Context, d time.Duration) error {
			return context.Canceled
		}
		return loop
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd.Command.SetContext(ctx)
	runMaxRuns = 2
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	prompts, builds := provider.snapshot()
	if len(prompts) != 2 {
		t.Fatalf("expected 2 provider runs, got %d prompts: %#v", len(prompts), prompts)
	}
	if prompts[0] != "persistent mission" {
		t.Fatalf("first prompt=%q", prompts[0])
	}
	if !strings.Contains(prompts[1], "Primary mission:\npersistent mission") {
		t.Fatalf("expected second prompt to preserve base mission, got %q", prompts[1])
	}
	if !strings.Contains(prompts[1], "● from mia (chat): can you review the retry path?") {
		t.Fatalf("expected second prompt to include unread chat content, got %q", prompts[1])
	}
	if len(builds) != 2 {
		t.Fatalf("expected 2 build option records, got %d", len(builds))
	}
	if builds[0].ContinueSession {
		t.Fatalf("first run should not continue a session, got %+v", builds[0])
	}
	if !builds[1].ContinueSession || builds[1].SessionID != "sess-42" {
		t.Fatalf("second run should continue session sess-42, got %+v", builds[1])
	}
}

func TestRunUsesActionableWakeEventToTriggerSecondCycle(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("response writer does not support flushing")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)

			_, _ = io.WriteString(w, "event: connected\ndata: {\"agent_id\":\"a-1\",\"project_id\":\"p-1\"}\n\n")
			flusher.Flush()
			_, _ = io.WriteString(w, "event: actionable_chat\ndata: {\"message_id\":\"m-2\",\"from_alias\":\"henry\",\"session_id\":\"s-9\",\"wake_mode\":\"interrupt\",\"unread_count\":1,\"sender_waiting\":true}\n\n")
			flusher.Flush()
			<-r.Context().Done()
		case r.URL.Path == "/v1/chat/pending":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"pending":[{"session_id":"s-9","participants":["henry","rose"],"last_message":"ping","last_from":"henry","unread_count":1,"last_activity":"2026-03-20T00:00:00Z","sender_waiting":true}],"messages_waiting":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := aweb.NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	runLoadUserConfig = func(string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{
			BasePrompt:      "persistent mission",
			WaitSeconds:     30,
			IdleWaitSeconds: 1,
		}, nil
	}

	provider := &recordingRunProvider{}
	runNewProvider = func(name string) (awrun.Provider, error) {
		return provider, nil
	}
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		return client, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		loop := awrun.NewLoop(provider, out)
		loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
			onLine("done")
			return nil
		}
		return loop
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd.Command.SetContext(ctx)
	runMaxRuns = 2
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	prompts, builds := provider.snapshot()
	if len(prompts) != 2 {
		t.Fatalf("expected 2 provider runs, got %d prompts: %#v", len(prompts), prompts)
	}
	if !strings.Contains(prompts[1], "● from henry (chat): ping") {
		t.Fatalf("expected actionable chat content, got %q", prompts[1])
	}
	if len(builds) != 2 || !builds[1].ContinueSession || builds[1].SessionID != "sess-42" {
		t.Fatalf("expected second run to continue session sess-42, got %+v", builds)
	}
}

func TestRunContinuePrintsRecentInteractionRecap(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		initRunCommandVars()
	})

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	appendInteractionLogForDir(tmp, &InteractionEntry{
		Timestamp: "2026-03-22T10:00:00Z",
		Kind:      interactionKindUser,
		Text:      "please fix the continue UX",
	})
	appendInteractionLogForDir(tmp, &InteractionEntry{
		Timestamp: "2026-03-22T10:01:00Z",
		Kind:      interactionKindAgent,
		Text:      "I can add a compact recap without touching provider history.",
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{BasePrompt: "persistent mission", WaitSeconds: 5, IdleWaitSeconds: 5}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) { return awrun.ClaudeProvider{}, nil }
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error { return nil }

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runContinueMode = true
	runWorkingDir = tmp
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Recent interactions") {
		t.Fatalf("expected interaction recap, got %q", out)
	}
	if !strings.Contains(out, "> please fix the continue UX") {
		t.Fatalf("expected user recap line, got %q", out)
	}
	if !strings.Contains(out, "I can add a compact recap") {
		t.Fatalf("expected agent recap line, got %q", out)
	}
	if strings.Contains(out, "[10:00]") {
		t.Fatalf("did not expect timestamps in recap, got %q", out)
	}
}

func TestSplitRunInvocationArgsSeparatesProviderArgsAfterDash(t *testing.T) {
	positional, providerArgs, err := splitRunInvocationArgs([]string{"claude", "--verbose", "--model", "sonnet"}, 1)
	if err != nil {
		t.Fatalf("splitRunInvocationArgs returned error: %v", err)
	}
	if len(positional) != 1 || positional[0] != "claude" {
		t.Fatalf("unexpected positional args: %#v", positional)
	}
	if strings.Join(providerArgs, " ") != "--verbose --model sonnet" {
		t.Fatalf("unexpected provider args: %#v", providerArgs)
	}
}

func TestSplitRunInvocationArgsRejectsExtraArgsWithoutDash(t *testing.T) {
	if _, _, err := splitRunInvocationArgs([]string{"claude", "--verbose"}, -1); err == nil {
		t.Fatal("expected missing -- separator to return an error")
	}
}

type exitCommandProvider struct {
	resumeOpts awrun.BuildOptions
}

func (p *exitCommandProvider) Name() string { return "claude" }

func (p *exitCommandProvider) BuildCommand(prompt string, opts awrun.BuildOptions) ([]string, error) {
	return []string{"fake-provider", prompt}, nil
}

func (p *exitCommandProvider) BuildResumeCommand(opts awrun.BuildOptions) ([]string, error) {
	p.resumeOpts = opts
	return []string{"claude", "--resume", opts.SessionID, "--add-dir", "/tmp/gitdir", "--debug"}, nil
}

func (p *exitCommandProvider) BuildResumeHint(opts awrun.BuildOptions) ([]string, error) {
	p.resumeOpts = opts
	return []string{"claude", "--resume", opts.SessionID}, nil
}

func (p *exitCommandProvider) ParseOutput(string) (*awrun.Event, error) {
	return &awrun.Event{Type: awrun.EventDone}, nil
}

func (p *exitCommandProvider) SessionID(event *awrun.Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func TestRunPrintsContinueAndProviderCommandsOnExit(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewEventBus := runNewEventBus
	oldNewScreen := runNewScreenController
	oldWorkspaceState := runWorkspaceStateForDir
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewEventBus = oldNewEventBus
		runNewScreenController = oldNewScreen
		runWorkspaceStateForDir = oldWorkspaceState
		initRunCommandVars()
	})

	tmp := t.TempDir()
	runWorkingDir = tmp
	runLoadUserConfig = func(string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{BasePrompt: "mission", WaitSeconds: 5, IdleWaitSeconds: 5}, nil
	}
	provider := &exitCommandProvider{}
	runNewProvider = func(name string) (awrun.Provider, error) { return provider, nil }
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", IdentityHandle: "rose"}, nil
	}
	runWorkspaceStateForDir = func(string) (runWorkspaceState, error) { return runWorkspaceStateInitialized, nil }
	runNewEventBus = func(client *aweb.Client) *awrun.EventBus { return nil }
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		return awrun.NewLoop(provider, out)
	}
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		if loop.OnBuildCommand == nil || loop.OnSessionID == nil {
			t.Fatal("expected exit command callbacks to be set")
		}
		loop.OnBuildCommand(nil, awrun.BuildOptions{
			Model:        "sonnet",
			AddDirs:      []string{"/tmp/gitdir"},
			ProviderArgs: []string{"--debug"},
		})
		loop.OnSessionID("sess-42")
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runWorkingDir = tmp
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"claude"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Session sess-42") {
		t.Fatalf("expected session id in exit summary, got %q", out)
	}
	if !strings.Contains(out, "aw run --dir "+tmp+" claude --continue") {
		t.Fatalf("expected aw continue command, got %q", out)
	}
	if !strings.Contains(out, "claude --resume sess-42") {
		t.Fatalf("expected provider resume hint, got %q", out)
	}
	if strings.Contains(out, "--add-dir") || strings.Contains(out, "--debug") {
		t.Fatalf("resume hint should not include internal flags, got %q", out)
	}
	if provider.resumeOpts.SessionID != "sess-42" {
		t.Fatalf("expected provider resume command to receive session id, got %+v", provider.resumeOpts)
	}
	if len(provider.resumeOpts.ProviderArgs) != 1 || provider.resumeOpts.ProviderArgs[0] != "--debug" {
		t.Fatalf("expected provider args to carry through, got %+v", provider.resumeOpts)
	}
}

type cobraCommandClone struct {
	Command cobra.Command
}

func (c *cobraCommandClone) ResetFlagsForTest() {
	c.Command.ResetFlags()
	c.Command.Flags().StringVar(&runInitialPrompt, "prompt", "", "")
	c.Command.Flags().StringVar(&runBasePrompt, "base-prompt", "", "")
	c.Command.Flags().StringVar(&runWorkPrompt, "work-prompt-suffix", "", "")
	c.Command.Flags().StringVar(&runCommsPrompt, "comms-prompt-suffix", "", "")
	c.Command.Flags().IntVar(&runWaitSeconds, "wait", awrun.DefaultWaitSeconds, "")
	c.Command.Flags().IntVar(&runIdleWait, "idle-wait", awrun.DefaultIdleWaitSeconds, "")
	c.Command.Flags().BoolVar(&runContinueMode, "continue", false, "")
	c.Command.Flags().BoolVar(&runContinueMode, "session", false, "")
	c.Command.Flags().IntVar(&runMaxRuns, "max-runs", 0, "")
	c.Command.Flags().StringVar(&runWorkingDir, "dir", "", "")
	c.Command.Flags().StringVar(&runAllowedTools, "allowed-tools", "", "")
	c.Command.Flags().StringVar(&runModel, "model", "", "")
	c.Command.Flags().BoolVar(&runProviderPTY, "provider-pty", false, "")
	c.Command.Flags().BoolVar(&runAutofeedWork, "autofeed-work", false, "")
	c.Command.Flags().BoolVar(&runInitConfig, "init", false, "")
}
