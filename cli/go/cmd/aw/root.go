package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var serverFlag string
var teamFlag string
var debugFlag bool
var jsonFlag bool
var traceFlag bool

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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
			debugFlag = true
		}
		if traceFlag {
			_ = os.Setenv("AW_TRACE", "1")
		}
		loadDotenvBestEffort()
		maybeCheckLatestVersion(cmd)
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
		fmt.Printf("aw %s\n", version)
		if commit != "none" {
			fmt.Printf("  commit: %s\n", commit)
		}
		if date != "unknown" {
			fmt.Printf("  built:  %s\n", date)
		}
		checkLatestVersion(os.Stderr, "")
	},
}

func init() {
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

func bindTeamSelector(cmd *cobra.Command) {
	if cmd == nil {
		return
	}
	cmd.PersistentFlags().StringVar(&teamFlag, "team", "", "Override the selected team_id for this command")
}

func Execute() {
	if argsContainTraceFlag(os.Args[1:]) {
		_ = os.Setenv("AW_TRACE", "1")
	}
	if code, dispatched := dispatchPluginIfRequested(os.Args[1:]); dispatched {
		os.Exit(code)
	}
	err := rootCmd.Execute()
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
