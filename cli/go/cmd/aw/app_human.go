package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// appHumanLifetime bounds one invocation: two handoffs (a first one and at
// most one renewal) and the sessions they open.
const appHumanLifetime = 45 * time.Minute

var appHumanCmd = &cobra.Command{
	Use:   "human <app> [<action>] [--<param> <value>...]",
	Short: "Run an action an app declares for its role holders, in a passkey session",
	Long: "Runs one of the session actions an app's manifest declares under owner_acts.session_actions,\n" +
		"in a console session that a browser passkey login opens for your holding of the action's role.\n" +
		"`aw app human <app> --help` lists the declared actions. A protected field is typed at the\n" +
		"terminal with echo off and has no flag; a one-time output is written only to the terminal.",
	DisableFlagParsing: true,
}

// terminalAttached reports whether a controlling terminal is attached.
var terminalAttached = awid.ControllingTerminalAttached

func init() {
	appHumanCmd.RunE = runAppHuman
	appCmd.AddCommand(appHumanCmd)
}

// takeGlobalFlags sets aw's global flags found in args, which flag parsing
// does not see for this command, and returns the rest.
func takeGlobalFlags(args []string) ([]string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !strings.HasPrefix(arg, "--") {
			rest = append(rest, arg)
			continue
		}
		var target *string
		switch name {
		case "human":
			target = &humanFlag
		case "human-domain":
			target = &humanDomainFlag
		case "identity-home":
			target = &identityHomeFlag
		case "server-name":
			target = &serverFlag
		case "json", "debug", "trace":
			on := !hasValue || value == "true"
			switch name {
			case "json":
				jsonFlag = on
			case "debug":
				debugFlag = on
			case "trace":
				traceFlag = on
			}
			continue
		default:
			rest = append(rest, arg)
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, usageError("missing value for --%s", name)
			}
			i++
			value = args[i]
		}
		*target = value
	}
	return rest, nil
}

func runAppHuman(cmd *cobra.Command, args []string) error {
	args, err := takeGlobalFlags(args)
	if err != nil {
		return err
	}
	if len(args) == 0 || isManifestHelpToken(args[0]) {
		return cmd.Help()
	}
	app, err := installedHolderApp(args[0])
	if err != nil {
		return err
	}
	actions := app.Resolved.OwnerActs.SessionActions
	if len(args) == 1 || isManifestHelpToken(args[1]) {
		fmt.Fprint(cmd.OutOrStdout(), formatSessionActions(app.Name, actions))
		return nil
	}
	action, err := sessionAction(actions, args[1])
	if err != nil {
		return err
	}
	params, rawBody, err := parseManifestDispatchArgs(args[2:])
	if err != nil {
		return err
	}
	if rawBody != nil {
		var body map[string]any
		if err := json.Unmarshal(rawBody, &body); err != nil {
			return usageError("--body-file must hold a JSON object: %v", err)
		}
		for name, value := range body {
			if _, ok := params[name]; !ok {
				params[name] = value
			}
		}
	}
	if _, ok := params["installation_id"]; ok {
		return withErrorCode("installation_id_not_a_flag", usageError("installation_id is filled by aw from the installed app; it has no flag"))
	}
	protected := protectedParams(action)
	for _, name := range protected {
		if _, ok := params[name]; ok {
			return withErrorCode("protected_input_unavailable", usageError("%s is protected: it is typed at the terminal and has no flag", name))
		}
	}
	if len(protected) > 0 {
		if err := protectedTerminal("protected_input_unavailable", terminalAttached); err != nil {
			return err
		}
	}
	if len(action.TerminalOutput) > 0 {
		if err := protectedTerminal("protected_output_unavailable", terminalAttached); err != nil {
			return err
		}
	}
	if humanSelectionRequested() {
		if err := prepareHumanParticipation(cmd); err != nil {
			return err
		}
	}
	opts, err := app.holderOptions(cmd, action.Role, "session")
	if err != nil {
		return err
	}
	params["installation_id"] = opts.Scope.InstallationID
	var secrets [][]byte
	defer func() {
		for _, value := range secrets {
			clear(value)
		}
	}()
	for _, name := range protected {
		value, err := awid.TerminalPassphrasePrompt()(fmt.Sprintf("%s (typed, not shown): ", name))
		if err != nil {
			return withErrorCode("protected_input_unavailable", err)
		}
		secrets = append(secrets, value)
		params[name] = string(value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), appHumanLifetime)
	defer cancel()
	runner := &sessionRunner{opts: opts}
	if err := runner.open(ctx); err != nil {
		return err
	}
	if action.Kind == appmanifest.SessionActionConfirm {
		return runConfirmAction(ctx, cmd, runner, actions, action, params)
	}
	request, err := action.Request(params)
	if err != nil {
		return err
	}
	resp, err := runner.do(ctx, request)
	if err != nil {
		return err
	}
	return printActionResponse(cmd, resp, nil)
}

// sessionRunner holds the invocation's one live session and its one renewal.
type sessionRunner struct {
	opts    handoff.Options
	session *handoff.Session
	renewed bool
}

func (r *sessionRunner) open(ctx context.Context) error {
	session, err := handoff.OpenSession(ctx, r.opts)
	if err != nil {
		return err
	}
	r.session = session
	return nil
}

func (r *sessionRunner) renew(ctx context.Context) error {
	if r.renewed {
		return withErrorCode("console_session_required", errors.New("the app refused the renewed session too"))
	}
	r.renewed = true
	return r.open(ctx)
}

func (r *sessionRunner) send(ctx context.Context, request *appmanifest.SessionRequest) (*handoff.Response, error) {
	return r.session.Do(ctx, request.Method, request.PathQuery, request.Body)
}

// do sends a read, stage or draft request, renewing the session once when
// the app refuses it. A refused session request had no effect, so it is
// sent again in the renewed session.
func (r *sessionRunner) do(ctx context.Context, request *appmanifest.SessionRequest) (*handoff.Response, error) {
	for {
		resp, err := r.send(ctx, request)
		if err != nil {
			return nil, err
		}
		switch sessionRefusal(resp) {
		case "":
			return resp, nil
		case "console_session_required":
			if err := r.renew(ctx); err != nil {
				return nil, err
			}
		case "role_not_held":
			return nil, roleNotHeld(false)
		default:
			return nil, appRefusal(resp)
		}
	}
}

func runConfirmAction(ctx context.Context, cmd *cobra.Command, runner *sessionRunner, actions []appmanifest.SessionAction, action appmanifest.SessionAction, params map[string]any) error {
	readAction, err := sessionAction(actions, action.Completion.Read)
	if err != nil {
		return err
	}
	readRequest, err := readAction.Request(params)
	if err != nil {
		return err
	}
	confirmRequest, err := action.Request(params)
	if err != nil {
		return err
	}
	outcome, err := runConfirm(ctx, confirmSteps{
		Completion: *action.Completion,
		Read:       func(ctx context.Context) (*handoff.Response, error) { return runner.send(ctx, readRequest) },
		Confirm:    func(ctx context.Context) (*handoff.Response, error) { return runner.send(ctx, confirmRequest) },
		Renew:      runner.renew,
		Sleep:      time.Sleep,
	})
	if err != nil {
		return err
	}
	if outcome.Code == "confirm_already_applied" {
		fmt.Fprintln(cmd.ErrOrStderr(), "confirm_already_applied: the change was already applied; aw did not confirm it again.")
		return nil
	}
	return printActionResponse(cmd, outcome.Response, action.TerminalOutput)
}

// printActionResponse writes the members terminal_output names only to the
// controlling terminal and prints the rest.
func printActionResponse(cmd *cobra.Command, resp *handoff.Response, terminalOutput []string) error {
	var body any
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		if len(terminalOutput) > 0 {
			return fmt.Errorf("the app's answer is not JSON, so its terminal-only members cannot be separated")
		}
		_, err := cmd.OutOrStdout().Write(resp.Body)
		return err
	}
	if len(terminalOutput) > 0 {
		taken, rest := takeTerminalOutput(body, terminalOutput)
		if err := writeToTerminal(taken); err != nil {
			return err
		}
		body = rest
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return err
}

// writeToTerminal writes each value to the controlling terminal, labelled
// with its pointer. It is never logged or traced.
func writeToTerminal(values []terminalValue) error {
	if len(values) == 0 {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return withErrorCode("protected_output_unavailable", fmt.Errorf("open the controlling terminal: %w", err))
	}
	defer tty.Close()
	for _, v := range values {
		text, ok := v.Value.(string)
		if !ok {
			data, _ := json.Marshal(v.Value)
			text = string(data)
		}
		if _, err := io.WriteString(tty, v.Pointer+": "+text+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func sessionAction(actions []appmanifest.SessionAction, name string) (appmanifest.SessionAction, error) {
	for _, a := range actions {
		if strings.TrimSpace(a.Name) == strings.TrimSpace(name) {
			return a, nil
		}
	}
	return appmanifest.SessionAction{}, withErrorCode("session_action_unknown", fmt.Errorf("the app declares no session action %q", strings.TrimSpace(name)))
}

func protectedParams(action appmanifest.SessionAction) []string {
	var names []string
	for _, p := range action.Params {
		if p.Protected != nil && *p.Protected {
			names = append(names, strings.TrimSpace(p.Name))
		}
	}
	return names
}

func formatSessionActions(appName string, actions []appmanifest.SessionAction) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Session actions of %s (aw app human %s <action> ...):\n", appName, appName)
	sorted := append([]appmanifest.SessionAction(nil), actions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, a := range sorted {
		fmt.Fprintf(&b, "  %-24s %-8s %s\n", a.Name, a.Kind, a.Description)
	}
	return b.String()
}
