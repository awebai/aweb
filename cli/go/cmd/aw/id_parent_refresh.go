package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var idParentRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh current registered ancestry without re-signing your certificate",
	Long:  "Fetch and verify current registered ancestry, preserving local certificates below it.\nFor a branch with only local ancestors, use parent request --resign with the parent.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := executeIDParentRefresh(cmd.Context(), idParentOptionsFromFlags(cmd))
		if err != nil {
			return err
		}
		printOutput(result, func(v any) string { return fmt.Sprintf("Refreshed ancestry: %s.\n", v.(*awid.IDChainResult).Outcome) })
		return nil
	},
}

func init() {
	idParentRefreshCmd.Flags().StringVar(&idParentDomain, "domain", "", "Organization namespace for agent operations (defaults to the chain)")
	idParentRefreshCmd.Flags().StringVar(&idParentRegistry, "registry", "", "Registry origin when DNS names none")
	idParentCmd.AddCommand(idParentRefreshCmd)
}

func parentRegistry(ctx context.Context, opts idParentOptions, domain string) (*awid.RegistryClient, string, error) {
	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, opts.TXTResolver, domain)
	if err != nil {
		return nil, "", err
	}
	origin, err := domainRegistryURL(authority, opts.RegistryURL)
	if err != nil {
		return nil, "", err
	}
	registry := newAWIDRegistryClient(opts.HTTPClient, opts.TXTResolver)
	registry.DefaultRegistryURL = origin
	return registry, origin, nil
}

func executeIDParentRefresh(ctx context.Context, opts idParentOptions) (*awid.IDChainResult, error) {
	r, err := selectRequester(opts)
	if err != nil {
		return nil, err
	}
	defer r.close()
	installed, err := awconfig.LoadInstalledIDChain(r.dir)
	if err != nil {
		return nil, err
	}
	anchor := r.id
	var suffix []any
	if installed != nil {
		certs := installed.Bundle["certificates"].([]any)
		anchor = ""
		for i := len(certs) - 1; i >= 0; i-- {
			c := certs[i].(map[string]any)["certificate"].(map[string]any)
			if c["domain"] != r.domain {
				return nil, &awid.IDCertificateError{Code: "domain_mismatch"}
			}
			if strings.HasPrefix(c["id"].(string), "did:aw:") {
				anchor = c["id"].(string)
				suffix = certs[i+1:]
				break
			}
		}
	}
	if !strings.HasPrefix(anchor, "did:aw:") {
		return nil, usageError("local ancestry needs its parent: use `aw id parent request --resign`, then import the parent's response")
	}
	registry, origin, err := parentRegistry(ctx, opts, r.domain)
	if err != nil {
		return nil, err
	}
	subject := awid.IDChainSubject{ID: r.id, DIDKey: r.didKey}
	var old map[string]any
	if installed != nil {
		old = installed.Bundle
	}
	evidence := idStatusAt(registry, opts.TXTResolver, origin).IDChainEvidence(ctx, old, subject, r.domain)
	chain, err := awid.RegisteredIDChain(evidence.Status, anchor)
	if err != nil {
		return nil, err
	}
	chain["certificates"] = append(chain["certificates"].([]any), suffix...)
	verdict := awid.VerifyIDChain(chain, subject, evidence, r.domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, &awid.IDCertificateError{Code: verdict.Reason}
	}
	encoded, err := awid.CanonicalJSONValue(chain)
	if err != nil {
		return nil, err
	}
	check := func() error {
		current, err := awconfig.LoadInstalledIDChain(r.dir)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, installed) {
			return fmt.Errorf("installed chain changed during refresh; retry")
		}
		return nil
	}
	if err := installParentChain(r.dir, "parent-refresh", "", []byte(encoded), chain, check); err != nil {
		return nil, err
	}
	return &verdict, nil
}
