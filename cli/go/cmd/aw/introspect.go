package main

import (
	"context"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type introspectOutput struct {
	Alias               string `json:"alias,omitempty"`
	HumanName           string `json:"human_name,omitempty"`
	AgentType           string `json:"agent_type,omitempty"`
	AccessMode          string `json:"access_mode,omitempty"`
	Address             string `json:"address,omitempty"`
	Domain              string `json:"domain,omitempty"`
	DID                 string `json:"did,omitempty"`
	StableID            string `json:"stable_id,omitempty"`
	Custody             string `json:"custody,omitempty"`
	Lifetime            string `json:"lifetime,omitempty"`
	InboundMode         string `json:"inbound_mode,omitempty"`
	InboundModeLabel    string `json:"inbound_mode_label,omitempty"`
	InboundConfigurable *bool  `json:"inbound_configurable,omitempty"`
	InboundModeError    string `json:"inbound_mode_error,omitempty"`
}

var introspectCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"introspect"},
	Short:   "Show the current identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}

		alias := sel.Alias

		out := introspectOutput{
			Alias:    alias,
			Domain:   sel.Domain,
			Address:  selectionAddress(sel),
			DID:      sel.DID,
			StableID: sel.StableID,
			Custody:  sel.Custody,
			Lifetime: awid.LegacyLifetimeForIdentityScope(sel.IdentityScope),
		}
		if out.Address == "" {
			out.Address = deriveIdentityAddress(sel.Domain, alias)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if inbound, err := c.Client.GetMyInboundMode(ctx); err == nil && inbound != nil {
			configurable := inbound.Configurable
			out.InboundMode = strings.TrimSpace(inbound.InboundMode)
			out.InboundModeLabel = inboundModeLabel(inbound.InboundMode)
			out.InboundConfigurable = &configurable
		} else if err != nil && !isInboundModeUnsupportedError(err) {
			out.InboundModeError = err.Error()
		}
		printOutput(out, formatIntrospect)
		return nil
	},
}

func isInboundModeUnsupportedError(err error) bool {
	if code, ok := awid.HTTPStatusCode(err); ok {
		return code == 404 || code == 405
	}
	return false
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
