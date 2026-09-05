package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var serverFlag string
var teamFlag string
var debugFlag bool
var jsonFlag bool
var traceFlag bool
var identityHomeFlag string
var activeIdentityHome awconfig.IdentityHome

const (
	groupWorkspace    = "workspace"
	groupIdentity     = "identity"
	groupNetwork      = "network"
	groupCoordination = "coordination"
	groupObsolete     = "obsolete"
	groupUtility      = "utility"
)

var rootCmd = &cobra.Command{
	Use:   "aw",
	Short: "aweb CLI",
	Long:  "aweb CLI\n\nSet AW_NO_UPDATE_CHECK=1 to disable automatic update checks.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if isIdentityHomeNeutralCommand(cmd) {
			return nil
		}
		if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
			debugFlag = true
		}
		if traceFlag {
			_ = os.Setenv("AW_TRACE", "1")
		}
		identityHomeEnv, hadIdentityHomeEnv := os.LookupEnv(awconfig.IdentityHomeEnv)
		previousActiveIdentityHome := activeIdentityHome
		home, err := awconfig.ResolveIdentityHome("", identityHomeFlag)
		if err != nil {
			return err
		}
		if err := requireIdentityHomeAwareCommand(cmd, home.External()); err != nil {
			return err
		}
		loadDotenvBestEffort()
		if home.External() {
			_ = os.Setenv(awconfig.IdentityHomeEnv, home.Root)
		} else if hadIdentityHomeEnv {
			_ = os.Setenv(awconfig.IdentityHomeEnv, identityHomeEnv)
		} else {
			_ = os.Unsetenv(awconfig.IdentityHomeEnv)
		}
		activeIdentityHome = awconfig.IdentityHome{}
		if home.External() {
			activeIdentityHome = home
		}
		restoreIdentityHomeAfterCommand(cmd, identityHomeEnv, hadIdentityHomeEnv, previousActiveIdentityHome)
		maybeCheckLatestVersion(cmd)
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No-op: version command doesn't require command initialization side-effects.
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(versionReport())
		checkLatestVersion(os.Stderr, "")
	},
}

// versionReport renders the version block. It is separate from the command so the
// output contract can be asserted directly: a reader holding a binary resolves the
// commit it prints, so what it prints is the traceability surface (aweb-aaun.7).
func versionReport() string {
	var b strings.Builder
	fmt.Fprintf(&b, "aw %s\n", version)
	if commit != "none" {
		if commitRepo != "" {
			fmt.Fprintf(&b, "  commit: %s (%s)\n", commit, commitRepo)
		} else {
			fmt.Fprintf(&b, "  commit: %s\n", commit)
		}
	}
	if date != "unknown" {
		fmt.Fprintf(&b, "  built:  %s\n", date)
	}
	return b.String()
}

func init() {
	// Cobra normally runs only the nearest persistent hook. Traversal makes the
	// root identity-home policy unshadowable by commands with their own hooks.
	cobra.EnableTraverseRunHooks = true
	rootCmd.AddGroup(
		&cobra.Group{ID: groupWorkspace, Title: "Workspace Setup"},
		&cobra.Group{ID: groupIdentity, Title: "Identity"},
		&cobra.Group{ID: groupNetwork, Title: "Messaging & Network"},
		&cobra.Group{ID: groupCoordination, Title: "Coordination & Runtime"},
		&cobra.Group{ID: groupObsolete, Title: "Obsolete / Legacy Compatibility"},
		&cobra.Group{ID: groupUtility, Title: "Utility"},
	)
	initCmd.GroupID = groupWorkspace
	resetCmd.GroupID = groupWorkspace
	workspaceCmd.GroupID = groupWorkspace
	checkCmd.GroupID = groupWorkspace

	introspectCmd.GroupID = groupIdentity
	identityCmd.GroupID = groupIdentity
	mcpConfigCmd.GroupID = groupIdentity

	chatCmd.GroupID = groupNetwork
	mailCmd.GroupID = groupNetwork
	contactsCmd.GroupID = groupNetwork
	inboundModeCmd.GroupID = groupNetwork
	directoryCmd.GroupID = groupNetwork
	a2aCmd.GroupID = groupNetwork
	heartbeatCmd.GroupID = groupNetwork
	eventsCmd.GroupID = groupNetwork
	controlCmd.GroupID = groupNetwork
	logCmd.GroupID = groupNetwork

	workCmd.GroupID = groupCoordination
	taskCmd.GroupID = groupCoordination
	runCmd.GroupID = groupCoordination
	lockCmd.GroupID = groupCoordination
	notifyCmd.GroupID = groupCoordination
	instructionsCmd.GroupID = groupCoordination
	rolesCmd.GroupID = groupCoordination

	versionCmd.GroupID = groupUtility
	upgradeCmd.GroupID = groupUtility
	doctorCmd.GroupID = groupUtility
	rootCmd.SetHelpCommandGroupID(groupUtility)
	rootCmd.SetCompletionCommandGroupID(groupUtility)

	rootCmd.PersistentFlags().StringVar(&serverFlag, "server-name", "", "Override the server host or name for this command")
	rootCmd.PersistentFlags().StringVar(&identityHomeFlag, "identity-home", "", "Use identity authority from this absolute credential root")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Log background errors to stderr")
	rootCmd.PersistentFlags().BoolVar(&traceFlag, "trace", false, "Trace redacted HTTP requests and responses to stderr")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	bindTeamSelector(mailCmd)
	bindTeamSelector(chatCmd)
	bindTeamSelector(workCmd)
	bindTeamSelector(taskCmd)
	bindTeamSelector(workspaceCmd)
	bindTeamSelector(checkCmd)
	bindTeamSelector(runCmd)
	bindTeamSelector(lockCmd)
	bindTeamSelector(notifyCmd)
	bindTeamSelector(instructionsCmd)
	bindTeamSelector(rolesCmd)
	bindTeamSelector(roleNameCmd)
	bindTeamSelector(heartbeatCmd)
	bindTeamSelector(eventsCmd)
	bindTeamSelector(controlCmd)
	bindTeamSelector(logCmd)
	bindTeamSelector(contactsCmd)
	bindTeamSelector(inboundModeCmd)
	bindTeamSelector(directoryCmd)
	bindTeamSelector(introspectCmd)
	bindTeamSelector(doctorCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(a2aCmd)
}

func restoreIdentityHomeAfterCommand(cmd *cobra.Command, previousEnv string, hadPreviousEnv bool, previousActive awconfig.IdentityHome) {
	restore := func() {
		if hadPreviousEnv {
			_ = os.Setenv(awconfig.IdentityHomeEnv, previousEnv)
		} else {
			_ = os.Unsetenv(awconfig.IdentityHomeEnv)
		}
		activeIdentityHome = previousActive
	}
	if runE := cmd.RunE; runE != nil {
		cmd.RunE = func(cmd *cobra.Command, args []string) error {
			defer func() {
				restore()
				cmd.RunE = runE
			}()
			return runE(cmd, args)
		}
		return
	}
	if run := cmd.Run; run != nil {
		cmd.Run = func(cmd *cobra.Command, args []string) {
			defer func() {
				restore()
				cmd.Run = run
			}()
			run(cmd, args)
		}
	}
}

func bindTeamSelector(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	cmd.PersistentFlags().StringVar(&teamFlag, "team", "", "Override the selected team_id for this command")
}

// refuseUnknownSubcommands makes a grouping command reject a token it does not
// implement, instead of printing its own help and exiting 0.
//
// aweb-aaxl: `aw id pin-store list` answered with the help for `aw id pin-store` and
// EXIT 0 on a binary without `list`. A missing subcommand did not fail - it returned
// success and a plausible page of text - so the author of that command could not tell it
// was absent from the binary they were running, and read the file by hand instead.
//
// SETTING Args ON THESE COMMANDS DOES NOTHING, which is the trap here. cobra returns
// flag.ErrHelp for a command that is not Runnable BEFORE it validates arguments, and
// ExecuteC turns that into "print help, return nil". So a parent with no Run is never
// asked what arguments it accepts. The command has to become runnable for any argument
// policy to be consulted at all.
//
// Bare invocation stays exactly as it was - help on stdout, exit 0 - because that is how
// a reader asks what a group offers. Only a command that names an unknown token fails.
func refuseUnknownSubcommands(cmd *cobra.Command) {
	if cmd.HasSubCommands() && cmd.Run == nil && cmd.RunE == nil {
		group := cmd
		group.RunE = func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return c.Help()
			}
			return usageError("unknown command %q for %q", args[0], c.CommandPath())
		}
		group.SilenceUsage = true
	}
	for _, sub := range cmd.Commands() {
		refuseUnknownSubcommands(sub)
	}
}

func Execute() {
	refuseUnknownSubcommands(rootCmd)
	if argsContainTraceFlag(os.Args[1:]) {
		_ = os.Setenv("AW_TRACE", "1")
	}
	restorePluginIdentityHome, err := activateIdentityHomeForPluginDispatch(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitCode(err))
	}
	defer restorePluginIdentityHome()
	if code, dispatched := dispatchPluginIfRequested(os.Args[1:]); dispatched {
		os.Exit(code)
	}
	err = rootCmd.Execute()
	checkVersionFromHeader()
	if err != nil {
		msg := err.Error()
		if hint := checkVerificationRequired(err); hint != "" {
			msg = hint
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(exitCode(err))
	}
}

func activateIdentityHomeForPluginDispatch(args []string) (func(), error) {
	previous, existed := os.LookupEnv(awconfig.IdentityHomeEnv)
	explicit := identityHomeForPluginDispatch(args)
	home, err := awconfig.ResolveIdentityHome("", explicit)
	if err != nil {
		return func() {}, err
	}
	if home.External() {
		if err := os.Setenv(awconfig.IdentityHomeEnv, home.Root); err != nil {
			return func() {}, err
		}
	}
	return func() {
		if existed {
			_ = os.Setenv(awconfig.IdentityHomeEnv, previous)
		} else {
			_ = os.Unsetenv(awconfig.IdentityHomeEnv)
		}
	}, nil
}

// identityHomeForPluginDispatch reads the root --identity-home out of argv
// before cobra parses anything, so a plugin — which never reaches cobra — still
// runs under the attached principal.
//
// It stops at the first bare token that names a built-in command, and that stop
// is the point of this function rather than an optimisation. The scan is
// textual, so without it *any* subcommand's own --identity-home is read as the
// principal selector. `aw wake register --identity-home <the instance's own
// identity home>` is exactly that shape: the flag is the instance's, not the
// principal's, and running it through ResolveIdentityHome applies the
// principal path preflight to it — which refuses a home reached through a
// symlinked parent and exits non-zero before the command runs at all. The OATS
// spawn hook reads that exit as a failed spawn.
//
// Stopping at a built-in loses nothing, with one exception worth naming.
// Normally cobra parses the root-level flag itself once it owns the leaf
// command's flag set, in either position, so the scan is redundant there. A
// command with DisableFlagParsing never has its inherited flags parsed by
// cobra at all, in either position, so for those the scan was the only
// mechanism and a trailing --identity-home now reaches nothing. Today that set
// is only the beads-mail stub verbs, whose RunE returns a static usage error
// without touching identity, so the exception has no live consequence — but it
// is an exception, not an absence of one.
//
// A plugin name is not a built-in, so scanning continues past it and a
// plugin's trailing --identity-home keeps the behaviour it has always had.
//
// The built-in set is reservedRootCommandNames() — the same set plugin dispatch
// refuses to let a plugin shadow, and the same set the reserved-app-ids
// artifact publishes. Sharing it is deliberate: two textual argv scanners over
// one flag set would otherwise be free to disagree about what counts as a
// command, and only one of them would get updated.
func identityHomeForPluginDispatch(args []string) string {
	builtins := reservedRootCommandNames()
	explicit := ""
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case strings.HasPrefix(arg, "--identity-home="):
			explicit = strings.TrimSpace(strings.TrimPrefix(arg, "--identity-home="))
			continue
		case arg == "--identity-home" && i+1 < len(args):
			explicit = strings.TrimSpace(args[i+1])
			i++
			continue
		case arg == "--server-name" && i+1 < len(args):
			// Skip its value so a server named after a command is not mistaken
			// for one.
			i++
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		}
		if builtins[arg] {
			break
		}
	}
	return explicit
}

func argsContainTraceFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--trace" {
			return true
		}
	}
	return false
}

// checkVersionFromHeader prints a stderr warning if the server reported
// a newer client version via the X-Latest-Client-Version response header.
func checkVersionFromHeader() {
	if lastClient == nil {
		return
	}
	latest := lastClient.LatestClientVersion()
	if latest == "" {
		return
	}
	current := strings.TrimPrefix(version, "v")
	if current == "dev" || current == "" {
		return
	}
	latest = strings.TrimPrefix(latest, "v")
	if compareVersions(current, latest) < 0 {
		fmt.Fprintf(os.Stderr, "Upgrade available: v%s → v%s (run `aw upgrade`)\n", current, latest)
	}
}
