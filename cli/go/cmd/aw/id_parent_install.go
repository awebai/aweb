package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var idParentInstallCmd = &cobra.Command{
	Use:   "install <chain-file|->",
	Short: "Install an already-issued chain for this home's own local key",
	Long:  "Verify and install an already-issued public ID chain for this home's own did:key.\nThe home must have no chain or the identical chain. This does not adopt or re-parent.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, err := readExchangeFile(args[0])
		if err != nil {
			return err
		}
		result, err := executeIDParentInstall(cmd.Context(), idParentOptionsFromFlags(cmd), raw)
		if err != nil {
			return err
		}
		printOutput(result, func(v any) string {
			return fmt.Sprintf("Installed verified chain: %s.\n", v.(*awid.IDChainResult).Outcome)
		})
		return nil
	},
}

func init() {
	idParentInstallCmd.Flags().StringVar(&idParentDomain, "domain", "", "Organization namespace for agent operations (defaults to the chain)")
	idParentInstallCmd.Flags().StringVar(&idParentRegistry, "registry", "", "Registry origin when DNS names none")
	idParentCmd.AddCommand(idParentInstallCmd)
}
func executeIDParentInstall(ctx context.Context, opts idParentOptions, raw []byte) (*awid.IDChainResult, error) {
	chain, err := awid.DecodeIDChainHeader(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return nil, err
	}
	certs := chain["certificates"].([]any)
	leaf := certs[len(certs)-1].(map[string]any)["certificate"].(map[string]any)
	if opts.Domain == "" {
		opts.Domain = leaf["domain"].(string)
	}
	r, err := selectRequester(opts)
	if err != nil {
		return nil, err
	}
	defer r.close()
	if r.id != r.didKey || !strings.HasPrefix(r.id, "did:key:") || leaf["id"] != r.id || leaf["kind"] != "agent" || leaf["domain"] != r.domain {
		return nil, &awid.IDCertificateError{Code: "request_binding_mismatch"}
	}
	check := func() error {
		installed, err := awconfig.LoadInstalledIDChain(r.dir)
		if err != nil {
			return err
		}
		if installed != nil && !reflect.DeepEqual(installed.Bundle, chain) {
			return &awid.IDCertificateError{Code: "request_binding_mismatch"}
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	registry, origin, err := parentRegistry(ctx, opts, r.domain)
	if err != nil {
		return nil, err
	}
	subject := awid.IDChainSubject{ID: r.id, DIDKey: r.didKey}
	evidence := idStatusAt(registry, opts.TXTResolver, origin).IDChainEvidence(ctx, chain, subject, r.domain)
	verdict := awid.VerifyIDChain(chain, subject, evidence, r.domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, &awid.IDCertificateError{Code: verdict.Reason}
	}
	if err := installParentChain(r.dir, "parent-install", "", raw, chain, check); err != nil {
		return nil, err
	}
	return &verdict, nil
}
