package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var serverFlag string
var accountFlag string
var debugFlag bool
var jsonFlag bool

const (
	groupWorkspace    = "workspace"
	groupIdentity     = "identity"
	groupNetwork      = "network"
	groupCoordination = "coordination"
	groupUtility      = "utility"
)

var rootCmd = &cobra.Command{
	Use:   "aw",
	Short: "aweb CLI",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
			debugFlag = true
		}
		loadDotenvBestEffort()
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
		checkLatestVersion(os.Stdout, "")
	},
}

func init() {
	rootCmd.AddGroup(
		&cobra.Group{ID: groupWorkspace, Title: "Workspace Setup"},
		&cobra.Group{ID: groupIdentity, Title: "Identity"},
		&cobra.Group{ID: groupNetwork, Title: "Messaging & Network"},
		&cobra.Group{ID: groupCoordination, Title: "Coordination & Runtime"},
		&cobra.Group{ID: groupUtility, Title: "Utility"},
	)
	initCmd.GroupID = groupWorkspace
	projectCmd.GroupID = groupWorkspace
	spawnCmd.GroupID = groupWorkspace
	connectCmd.GroupID = groupWorkspace
	useCmd.GroupID = groupWorkspace
	resetCmd.GroupID = groupWorkspace
	workspaceCmd.GroupID = groupWorkspace

	introspectCmd.GroupID = groupIdentity
	identityCmd.GroupID = groupIdentity
	identitiesCmd.GroupID = groupIdentity
	claimHumanCmd.GroupID = groupIdentity
	mcpConfigCmd.GroupID = groupIdentity

	chatCmd.GroupID = groupNetwork
	mailCmd.GroupID = groupNetwork
	contactsCmd.GroupID = groupNetwork
	directoryCmd.GroupID = groupNetwork
	heartbeatCmd.GroupID = groupNetwork
	eventsCmd.GroupID = groupNetwork
	controlCmd.GroupID = groupNetwork
	logCmd.GroupID = groupNetwork

	workCmd.GroupID = groupCoordination
	taskCmd.GroupID = groupCoordination
	runCmd.GroupID = groupCoordination
	lockCmd.GroupID = groupCoordination
	notifyCmd.GroupID = groupCoordination
	policyCmd.GroupID = groupCoordination

	versionCmd.GroupID = groupUtility
	upgradeCmd.GroupID = groupUtility
	rootCmd.SetHelpCommandGroupID(groupUtility)
	rootCmd.SetCompletionCommandGroupID(groupUtility)

	rootCmd.PersistentFlags().StringVar(&serverFlag, "server-name", "", "Server name from config.yaml")
	rootCmd.PersistentFlags().StringVar(&accountFlag, "account", "", "Account name from config.yaml")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Log background errors to stderr")
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
}

func Execute() {
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
