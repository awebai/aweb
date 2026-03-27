package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var connectSetDefault bool

type connectOptions struct {
	WorkingDir string
	BaseURL    string
	APIKey     string
	SetDefault bool
}

type connectResult struct {
	Response       *awid.IntrospectResponse
	IdentityLabel  string
	IdentityDID    string
	Lifetime       string
	Custody        string
	StableID       string
	SigningKeyPath string
	ConfigPath     string
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Import an existing identity into this directory",
	Long: `Reads AWEB_URL and AWEB_API_KEY from the environment (or .env.aweb),
validates them via introspect, and writes local config so future commands
work without environment variables. This command imports the server's
current identity state; it does not create or mutate an identity.

Use this when you already have an identity-bound API key and want to bind
the current directory to that identity.`,
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

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	result, err := executeConnect(connectOptions{
		WorkingDir: workingDir,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		SetDefault: connectSetDefault,
	})
	if err != nil {
		return err
	}

	printConnectSummary(cmd.ErrOrStderr(), result)

	if jsonFlag {
		printJSON(result.Response)
	}

	return nil
}

func executeConnect(opts connectOptions) (*connectResult, error) {
	baseURL := strings.TrimSpace(opts.BaseURL)
	apiKey := strings.TrimSpace(opts.APIKey)
	workingDir := strings.TrimSpace(opts.WorkingDir)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		workingDir = wd
	}

	serverName, _ := awconfig.DeriveServerNameFromURL(baseURL)

	client, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Introspect(ctx)
	if err != nil {
		return nil, err
	}

	identityID := strings.TrimSpace(resp.CurrentIdentityID())
	if identityID == "" {
		return nil, usageError("This API key is not bound to an identity. Use an identity-bound key from the dashboard.")
	}

	projectSlug := ""
	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	address := strings.TrimSpace(resp.Address)
	handle := handleFromAddress(resp.Address)
	if handle == "" {
		handle = strings.TrimSpace(resp.IdentityHandle())
	}
	if handle == "" {
		return nil, usageError("server did not return an addressable identity handle; cannot import identity state safely")
	}

	if namespaceSlug == "" || address == "" {
		project, err := client.GetCurrentProject(ctx)
		if err != nil {
			return nil, err
		}
		projectSlug = strings.TrimSpace(project.Slug)
		if projectSlug == "" {
			return nil, usageError("server did not return a project slug for the current auth context; cannot import identity state safely")
		}
	}
	if projectSlug == "" {
		projectSlug = namespaceSlug
	}
	if projectSlug != "" {
		client.Client.SetProjectSlug(projectSlug)
	}

	// Derive account name from server + identity_id (stable across handle changes).
	accountName := "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(identityID)

	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return nil, err
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
	if namespaceSlug == "" || address == "" || identityDID == "" || stableID == "" || custody == "" || lifetime == "" {
		serverAddress, serverDID, serverStableID, serverCustody, serverLifetime := resolveServerIdentityState(
			ctx, client, namespaceSlug, projectSlug, handle, address,
		)
		if address == "" && strings.TrimSpace(serverAddress) != "" {
			address = strings.TrimSpace(serverAddress)
		}
		if namespaceSlug == "" {
			namespaceSlug = namespaceFromAddress(address)
		}
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
	if namespaceSlug == "" {
		namespaceSlug = namespaceFromAddress(address)
	}
	if namespaceSlug == "" {
		namespaceSlug = projectSlug
	}
	if namespaceSlug == "" {
		return nil, usageError("server did not return enough identity routing data; cannot import addressable identity state safely")
	}
	if address == "" {
		address = deriveIdentityAddress(namespaceSlug, projectSlug, handle)
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

		if strings.TrimSpace(cfg.DefaultAccount) == "" || opts.SetDefault {
			cfg.DefaultAccount = accountName
		}
		// Per-client default: let `aw` pick this account by default without
		// clobbering other clients' defaults.
		cfg.ClientDefaultAccounts["aw"] = accountName
		return nil
	})
	if updateErr != nil {
		return nil, updateErr
	}

	if err := writeOrUpdateContextAt(workingDir, serverName, accountName, opts.SetDefault); err != nil {
		return nil, err
	}

	identityLabel := handle
	if address != "" {
		identityLabel = address
	}
	if identityLabel == "" {
		identityLabel = "current identity"
	}
	return &connectResult{
		Response:       resp,
		IdentityLabel:  identityLabel,
		IdentityDID:    identityDID,
		Lifetime:       lifetime,
		Custody:        custody,
		StableID:       stableID,
		SigningKeyPath: signingKeyPath,
		ConfigPath:     cfgPath,
	}, nil
}

func printConnectSummary(out io.Writer, result *connectResult) {
	if result == nil {
		return
	}
	fmt.Fprintf(out, "Imported identity context for %s\n", result.IdentityLabel)
	if result.IdentityDID != "" {
		fmt.Fprintf(out, "Identity DID: %s\n", result.IdentityDID)
	}
	if result.Lifetime != "" {
		fmt.Fprintf(out, "Identity: %s\n", awid.DescribeIdentityClass(result.Lifetime))
	}
	if result.Custody != "" {
		fmt.Fprintf(out, "Custody: %s\n", result.Custody)
	}
	if result.StableID != "" {
		fmt.Fprintf(out, "Permanent ID: %s\n", result.StableID)
	}
	if awid.IsSelfCustodial(result.Custody) && awid.IdentityClassFromLifetime(result.Lifetime) == awid.IdentityClassPermanent && result.SigningKeyPath == "" {
		fmt.Fprintln(out, "Warning: this self-custodial permanent identity has no local signing key configured.")
	}
	fmt.Fprintf(out, "Config written to %s\n", result.ConfigPath)
}

func resolveServerIdentityState(
	ctx context.Context,
	client *aweb.Client,
	namespaceSlug, projectSlug, alias, authoritativeAddress string,
) (address, did, stableID, custody, lifetime string) {
	address = strings.TrimSpace(authoritativeAddress)
	if address == "" && strings.TrimSpace(alias) != "" {
		address = deriveIdentityAddress(namespaceSlug, projectSlug, alias)
	}
	if address == "" {
		return "", "", "", "", ""
	}
	resolver := &awid.ServerResolver{Client: client.Client}
	identity, err := resolver.Resolve(ctx, address)
	if err != nil || identity == nil {
		return "", "", "", "", ""
	}
	return strings.TrimSpace(identity.Address), strings.TrimSpace(identity.DID), strings.TrimSpace(identity.StableID), strings.TrimSpace(identity.Custody), strings.TrimSpace(identity.Lifetime)
}

func namespaceFromAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}
	if idx := strings.LastIndexByte(address, '/'); idx > 0 {
		return strings.TrimSpace(address[:idx])
	}
	if idx := strings.LastIndexByte(address, '~'); idx > 0 {
		return strings.TrimSpace(address[:idx])
	}
	return ""
}
