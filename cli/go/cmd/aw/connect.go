package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var connectSetDefault bool

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Import an existing identity context using environment credentials",
	Long: `Reads AWEB_URL and AWEB_API_KEY from the environment (or .env.aweb),
validates them via introspect, and writes local config so future commands
work without environment variables. This command imports the server's
current identity state; it does not create or mutate an identity.`,
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().BoolVar(&connectSetDefault, "set-default", false, "Set this account as default even if one already exists")
	rootCmd.AddCommand(connectCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	baseURL := strings.TrimSpace(os.Getenv("AWEB_URL"))
	apiKey := strings.TrimSpace(os.Getenv("AWEB_API_KEY"))

	if baseURL == "" {
		return usageError("AWEB_URL is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
	}
	if apiKey == "" {
		return usageError("AWEB_API_KEY is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
	}

	baseURL, err := resolveWorkingBaseURL(baseURL)
	if err != nil {
		return err
	}

	serverName, _ := awconfig.DeriveServerNameFromURL(baseURL)

	client, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Introspect(ctx)
	if err != nil {
		return err
	}

	if strings.TrimSpace(resp.IdentityID) == "" {
		return usageError("This API key is not bound to an identity. Use an identity-bound key from the dashboard.")
	}

	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		return usageError("server did not return namespace_slug for the current identity; cannot import addressable identity state safely")
	}

	handle := handleFromAddress(resp.Address)
	if handle == "" {
		handle = strings.TrimSpace(resp.IdentityHandle())
	}
	if handle == "" {
		return usageError("server did not return an addressable identity handle; cannot import identity state safely")
	}
	identityID := strings.TrimSpace(resp.IdentityID)

	// Derive account name from server + identity_id (stable across handle changes).
	accountName := "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(identityID)

	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}

	// Check existing config for identity fields before provisioning.
	existingCfg, _ := awconfig.LoadGlobalFrom(cfgPath)
	var existingDID, existingSigningKey, existingStableID, existingCustody, existingLifetime string
	if existingCfg != nil {
		for _, acct := range existingCfg.Accounts {
			if strings.TrimSpace(acct.IdentityID) == identityID && strings.TrimSpace(acct.Server) == serverName {
				existingDID = strings.TrimSpace(acct.DID)
				existingSigningKey = strings.TrimSpace(acct.SigningKey)
				existingStableID = strings.TrimSpace(acct.StableID)
				existingCustody = strings.TrimSpace(acct.Custody)
				existingLifetime = strings.TrimSpace(acct.Lifetime)
				break
			}
		}
	}

	identityDID := existingDID
	signingKeyPath := existingSigningKey
	stableID := existingStableID
	custody := existingCustody
	lifetime := existingLifetime
	if identityDID == "" || stableID == "" || custody == "" || lifetime == "" {
		serverDID, serverStableID, serverCustody, serverLifetime := resolveServerIdentityState(
			ctx, client, namespaceSlug, handle, strings.TrimSpace(resp.Address),
		)
		if strings.TrimSpace(serverDID) != "" {
			identityDID = strings.TrimSpace(serverDID)
		}
		if strings.TrimSpace(serverStableID) != "" {
			stableID = strings.TrimSpace(serverStableID)
		}
		if strings.TrimSpace(serverCustody) != "" {
			custody = strings.TrimSpace(serverCustody)
		}
		if strings.TrimSpace(serverLifetime) != "" {
			lifetime = strings.TrimSpace(serverLifetime)
		}
	}
	if stableID == "" && existingStableID != "" {
		stableID = existingStableID
	}

	updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
		if cfg.Servers == nil {
			cfg.Servers = map[string]awconfig.Server{}
		}
		if cfg.Accounts == nil {
			cfg.Accounts = map[string]awconfig.Account{}
		}
		if cfg.ClientDefaultAccounts == nil {
			cfg.ClientDefaultAccounts = map[string]string{}
		}

		// Check for existing account with same server+identity_id — update it.
		for name, acct := range cfg.Accounts {
			if strings.TrimSpace(acct.IdentityID) == identityID && strings.TrimSpace(acct.Server) == serverName {
				accountName = name
				break
			}
		}

		cfg.Servers[serverName] = awconfig.Server{URL: baseURL}

		cfg.Accounts[accountName] = awconfig.Account{Account: awid.Account{
			Server:         serverName,
			APIKey:         apiKey,
			IdentityID:     identityID,
			IdentityHandle: handle,
			NamespaceSlug:  namespaceSlug,
			DID:            identityDID,
			StableID:       stableID,
			SigningKey:     signingKeyPath,
			Custody:        custody,
			Lifetime:       lifetime,
		}}

		if strings.TrimSpace(cfg.DefaultAccount) == "" || connectSetDefault {
			cfg.DefaultAccount = accountName
		}
		// Per-client default: let `aw` pick this account by default without
		// clobbering other clients' defaults.
		cfg.ClientDefaultAccounts["aw"] = accountName
		return nil
	})
	if updateErr != nil {
		return updateErr
	}

	if err := writeOrUpdateContextWithOptions(serverName, accountName, connectSetDefault); err != nil {
		return err
	}

	identityLabel := handle
	if address := strings.TrimSpace(resp.Address); address != "" {
		identityLabel = address
	}
	if identityLabel == "" {
		identityLabel = "current identity"
	}
	fmt.Fprintf(os.Stderr, "Imported identity context for %s\n", identityLabel)
	if identityDID != "" {
		fmt.Fprintf(os.Stderr, "Identity DID: %s\n", identityDID)
	}
	if lifetime != "" {
		fmt.Fprintf(os.Stderr, "Identity: %s\n", awid.DescribeIdentityClass(lifetime))
	}
	if custody != "" {
		fmt.Fprintf(os.Stderr, "Custody: %s\n", custody)
	}
	if stableID != "" {
		fmt.Fprintf(os.Stderr, "Permanent ID: %s\n", stableID)
	}
	if awid.IsSelfCustodial(custody) && awid.IdentityClassFromLifetime(lifetime) == awid.IdentityClassPermanent && signingKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Warning: this self-custodial permanent identity has no local signing key configured.")
	}
	fmt.Fprintf(os.Stderr, "Config written to %s\n", cfgPath)

	if jsonFlag {
		printJSON(resp)
	}

	return nil
}

func resolveServerIdentityState(
	ctx context.Context,
	client *aweb.Client,
	namespaceSlug, alias, authoritativeAddress string,
) (did, stableID, custody, lifetime string) {
	address := strings.TrimSpace(authoritativeAddress)
	if address == "" && strings.TrimSpace(namespaceSlug) != "" && strings.TrimSpace(alias) != "" {
		address = deriveIdentityAddress(namespaceSlug, "", alias)
	}
	if address == "" {
		return "", "", "", ""
	}
	resolver := &awid.ServerResolver{Client: client.Client}
	identity, err := resolver.Resolve(ctx, address)
	if err != nil || identity == nil {
		return "", "", "", ""
	}
	return strings.TrimSpace(identity.DID), strings.TrimSpace(identity.StableID), strings.TrimSpace(identity.Custody), strings.TrimSpace(identity.Lifetime)
}
