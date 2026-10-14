package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

const settingEncryptByDefault = "messaging.encrypt_by_default"

const (
	settingSourceDefault  = "default"
	settingSourceSettings = "settings"
	settingSourceGrant    = "grant"
)

type settingOutput struct {
	Key    string `json:"key"`
	Value  bool   `json:"value"`
	Source string `json:"source"`
}

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Show or change this identity's local settings",
	Long: "Show or change this identity's local settings, kept in settings.yaml of its identity home.\n\n" +
		"Settings:\n" +
		"  " + settingEncryptByDefault + "  true encrypts a mail or chat send that no --e2ee/--plaintext flag\n" +
		"      or encrypted source decides, when the recipient has a published key (default false).\n\n" +
		"A grant seat carries the settings its grant was minted with; change them on the\n" +
		"resident identity and mint a new grant.",
}

var settingsGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Show a setting's effective value and where it comes from",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireKnownSetting(args[0]); err != nil {
			return err
		}
		settings, source, err := selectedIdentitySettings()
		if err != nil {
			return err
		}
		printOutput(settingOutput{Key: settingEncryptByDefault, Value: settings.EncryptsByDefault(), Source: source}, formatSetting)
		return nil
	},
}

var settingsSetCmd = &cobra.Command{
	Use:   "set <key> <true|false>",
	Short: "Change a setting of this identity",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requireKnownSetting(args[0]); err != nil {
			return err
		}
		value, err := strconv.ParseBool(strings.TrimSpace(args[1]))
		if err != nil {
			return usageError("%s takes true or false, not %q", settingEncryptByDefault, args[1])
		}
		home, err := identityHomeForDir(mustGetwd())
		if err != nil {
			return err
		}
		if awconfig.IsGrantHome(home.Root) {
			return usageError("a grant seat carries the settings its grant was minted with; change the setting on the resident identity and mint a new grant")
		}
		settings, err := awconfig.LoadIdentitySettings(home.Root)
		if err != nil {
			return err
		}
		settings.Messaging.EncryptByDefault = &value
		if err := awconfig.SaveIdentitySettings(home.Root, settings); err != nil {
			return err
		}
		printOutput(settingOutput{Key: settingEncryptByDefault, Value: value, Source: settingSourceSettings}, formatSetting)
		return nil
	},
}

func init() {
	settingsCmd.AddCommand(settingsGetCmd, settingsSetCmd)
	rootCmd.AddCommand(settingsCmd)
}

func requireKnownSetting(key string) error {
	if strings.TrimSpace(key) != settingEncryptByDefault {
		return usageError("unknown setting %q; known settings: %s", key, settingEncryptByDefault)
	}
	return nil
}

// selectedIdentitySettings returns the settings in effect for the selected
// identity home and where they come from: the grant a seat was minted with,
// the identity's settings.yaml, or the defaults.
func selectedIdentitySettings() (awconfig.Settings, string, error) {
	home, err := identityHomeForDir(mustGetwd())
	if err != nil {
		return awconfig.Settings{}, "", err
	}
	if awconfig.IsGrantHome(home.Root) {
		grant, err := awconfig.LoadGrantHome(home.Root)
		if err != nil {
			return awconfig.Settings{}, "", err
		}
		return grant.Settings, settingSourceGrant, nil
	}
	settings, err := awconfig.LoadIdentitySettings(home.Root)
	if err != nil {
		return awconfig.Settings{}, "", err
	}
	if settings.Messaging.EncryptByDefault == nil {
		return settings, settingSourceDefault, nil
	}
	return settings, settingSourceSettings, nil
}

func formatSetting(v any) string {
	out := v.(settingOutput)
	return fmt.Sprintf("%s = %t (%s)\n", out.Key, out.Value, out.Source)
}
