package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var identityDeleteConfirm bool

var identityDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the current ephemeral identity",
	Long:  "Deletes the current ephemeral identity on the server, releases its alias, and removes the matching local workspace/account state.",
	RunE:  runIdentityDelete,
}

func init() {
	identityDeleteCmd.Flags().BoolVar(&identityDeleteConfirm, "confirm", false, "Required to delete the current ephemeral identity")
	identityCmd.AddCommand(identityDeleteCmd)
}

func runIdentityDelete(cmd *cobra.Command, args []string) error {
	if !identityDeleteConfirm {
		return usageError("identity delete requires --confirm")
	}

	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lifetime, custody, err := resolveSelectionIdentityState(ctx, client, sel)
	if err != nil {
		return err
	}
	if awid.IdentityClassFromLifetime(lifetime) == awid.IdentityClassPermanent {
		return usageError("the current identity is permanent; permanent archival and replacement are owner-admin lifecycle flows, not CLI delete")
	}
	if awid.IdentityClassFromLifetime(lifetime) != awid.IdentityClassEphemeral {
		return fmt.Errorf("could not confirm that the current identity is ephemeral")
	}

	if err := deleteCurrentEphemeralIdentity(ctx, client); err != nil {
		return err
	}

	configRemoved, contextRemoved, keyRemoved, err := cleanupDeletedIdentity(sel)
	if err != nil {
		return err
	}

	fmt.Println("Identity deleted.")
	if strings.TrimSpace(sel.IdentityHandle) != "" {
		fmt.Printf("Alias:       %s\n", strings.TrimSpace(sel.IdentityHandle))
	}
	if custody != "" {
		fmt.Printf("Custody:     %s\n", custody)
	}
	fmt.Printf("Identity:    %s\n", describeIdentityClass(lifetime))
	if configRemoved != "" {
		fmt.Printf("Config:      removed %s\n", configRemoved)
	}
	if contextRemoved != "" {
		fmt.Printf("Workspace:   removed %s\n", contextRemoved)
	}
	if keyRemoved != "" {
		fmt.Printf("Key:         removed %s\n", keyRemoved)
	}
	return nil
}

func deleteCurrentEphemeralIdentity(ctx context.Context, client *aweb.Client) error {
	return client.Deregister(ctx)
}

func deleteEphemeralIdentityByWorkspace(ctx context.Context, client *aweb.Client, ws aweb.WorkspaceInfo) (bool, error) {
	namespaceSlug := strings.TrimSpace(derefString(ws.NamespaceSlug))
	projectSlug := strings.TrimSpace(derefString(ws.ProjectSlug))
	alias := strings.TrimSpace(ws.Alias)
	if namespaceSlug == "" {
		namespaceSlug = projectSlug
	}
	if namespaceSlug == "" || alias == "" {
		return false, fmt.Errorf("missing namespace/project slug or alias for gone workspace %s", strings.TrimSpace(ws.WorkspaceID))
	}

	address := deriveIdentityAddress(namespaceSlug, "", alias)
	client.Client.SetProjectSlug(projectSlug)
	resolver := &awid.ServerResolver{Client: client.Client}
	identity, err := resolver.Resolve(ctx, address)
	if err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
			return false, nil
		}
		return false, err
	}
	if identity == nil {
		return false, fmt.Errorf("resolve current identity %q: empty response", address)
	}
	if awid.IdentityClassFromLifetime(identity.Lifetime) != awid.IdentityClassEphemeral {
		return false, nil
	}
	if err := client.DeregisterAgent(ctx, namespaceSlug, alias); err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
			return true, nil
		}
		return false, err
	}
	return true, nil
}

func resolveSelectionIdentityState(ctx context.Context, client *aweb.Client, sel *awconfig.Selection) (lifetime, custody string, err error) {
	intro, err := client.Introspect(ctx)
	if err != nil {
		return "", "", err
	}

	namespaceSlug := strings.TrimSpace(intro.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(sel.NamespaceSlug)
	}
	alias := strings.TrimSpace(intro.Alias)
	if alias == "" {
		alias = strings.TrimSpace(sel.IdentityHandle)
	}
	address := strings.TrimSpace(intro.Address)
	if address == "" && namespaceSlug != "" && alias != "" {
		address = deriveIdentityAddress(namespaceSlug, "", alias)
	}
	if address == "" {
		return "", "", fmt.Errorf("could not determine the current identity address from server state")
	}

	projectSlug := strings.TrimSpace(sel.DefaultProject)
	if projectSlug == "" {
		projectSlug = namespaceSlug
	}
	client.Client.SetProjectSlug(projectSlug)
	resolver := &awid.ServerResolver{Client: client.Client}
	identity, err := resolver.Resolve(ctx, address)
	if err != nil {
		return "", "", fmt.Errorf("resolve current identity %q: %w", address, err)
	}
	if identity == nil {
		return "", "", fmt.Errorf("resolve current identity %q: empty response", address)
	}

	lifetime = strings.TrimSpace(identity.Lifetime)
	custody = strings.TrimSpace(identity.Custody)
	if lifetime == "" || custody == "" {
		return "", "", fmt.Errorf("server did not return complete lifecycle state for %s", address)
	}
	return lifetime, custody, nil
}

func cleanupDeletedIdentity(sel *awconfig.Selection) (configRemoved, contextRemoved, keyRemoved string, err error) {
	if strings.TrimSpace(sel.SigningKey) != "" {
		if removeErr := removeSigningKeyFiles(strings.TrimSpace(sel.SigningKey)); removeErr != nil {
			return "", "", "", removeErr
		}
		keyRemoved = strings.TrimSpace(sel.SigningKey)
	}

	if strings.TrimSpace(sel.AccountName) != "" {
		cfgPath, cfgErr := defaultGlobalPath()
		if cfgErr != nil {
			return "", "", keyRemoved, cfgErr
		}
		if err := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Accounts != nil {
				delete(cfg.Accounts, sel.AccountName)
			}
			if strings.TrimSpace(cfg.DefaultAccount) == strings.TrimSpace(sel.AccountName) {
				cfg.DefaultAccount = firstRemainingAccount(cfg)
			}
			if cfg.ClientDefaultAccounts != nil && strings.TrimSpace(cfg.ClientDefaultAccounts["aw"]) == strings.TrimSpace(sel.AccountName) {
				delete(cfg.ClientDefaultAccounts, "aw")
			}
			return nil
		}); err != nil {
			return "", "", keyRemoved, err
		}
		configRemoved = strings.TrimSpace(sel.AccountName)
	}

	contextRemoved, err = removeCurrentContextBinding(strings.TrimSpace(sel.AccountName))
	if err != nil {
		return configRemoved, "", keyRemoved, err
	}

	if err := removeLocalIdentityPins(sel); err != nil {
		return configRemoved, contextRemoved, keyRemoved, err
	}

	return configRemoved, contextRemoved, keyRemoved, nil
}

func removeLocalIdentityPins(sel *awconfig.Selection) error {
	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return err
	}
	pinPath := filepath.Join(filepath.Dir(cfgPath), "known_agents.yaml")
	ps, err := awid.LoadPinStore(pinPath)
	if err != nil {
		return err
	}
	removed := false
	handle := strings.TrimSpace(sel.IdentityHandle)
	namespaceSlug := strings.TrimSpace(sel.NamespaceSlug)
	defaultProject := strings.TrimSpace(sel.DefaultProject)
	if handle != "" {
		canonical := deriveIdentityAddress(namespaceSlug, defaultProject, handle)
		removed = ps.RemoveAddress(canonical) || removed
		removed = ps.RemoveAddress(handle) || removed
	}
	if removed {
		return ps.Save(pinPath)
	}
	return nil
}

func firstRemainingAccount(cfg *awconfig.GlobalConfig) string {
	for _, name := range sortedAccountNames(cfg) {
		return name
	}
	return ""
}

func removeSigningKeyFiles(signingKeyPath string) error {
	if err := os.Remove(signingKeyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	pubPath := strings.TrimSuffix(signingKeyPath, ".key") + ".pub"
	if err := os.Remove(pubPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeCurrentContextBinding(accountName string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	removedPaths := make([]string, 0, 2)
	resultPath := ""
	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
	} else {
		ctx, err := awconfig.LoadWorktreeContextFrom(ctxPath)
		if err != nil {
			return "", err
		}

		if strings.TrimSpace(accountName) != "" {
			if strings.TrimSpace(ctx.DefaultAccount) == accountName {
				ctx.DefaultAccount = ""
			}
			for serverName, mappedAccount := range ctx.ServerAccounts {
				if strings.TrimSpace(mappedAccount) == accountName {
					delete(ctx.ServerAccounts, serverName)
				}
			}
			for clientName, mappedAccount := range ctx.ClientDefaultAccounts {
				if strings.TrimSpace(mappedAccount) == accountName {
					delete(ctx.ClientDefaultAccounts, clientName)
				}
			}
		}

		if strings.TrimSpace(ctx.DefaultAccount) == "" {
			for _, mappedAccount := range ctx.ServerAccounts {
				ctx.DefaultAccount = mappedAccount
				break
			}
		}
		if strings.TrimSpace(ctx.DefaultAccount) == "" {
			for _, mappedAccount := range ctx.ClientDefaultAccounts {
				ctx.DefaultAccount = mappedAccount
				break
			}
		}

		if strings.TrimSpace(ctx.DefaultAccount) == "" && len(ctx.ServerAccounts) == 0 && len(ctx.ClientDefaultAccounts) == 0 && strings.TrimSpace(ctx.HumanAccount) == "" {
			if err := os.Remove(ctxPath); err != nil && !os.IsNotExist(err) {
				return "", err
			}
			removedPaths = append(removedPaths, ctxPath)
		} else {
			if err := awconfig.SaveWorktreeContextTo(ctxPath, ctx); err != nil {
				return "", err
			}
			resultPath = ctxPath
		}
	}

	workspacePath, wsErr := awconfig.FindWorktreeWorkspacePath(wd)
	if wsErr == nil {
		if err := os.Remove(workspacePath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		removedPaths = append(removedPaths, workspacePath)
	} else if !os.IsNotExist(wsErr) {
		return "", wsErr
	}

	awDir := filepath.Join(wd, ".aw")
	entries, readErr := os.ReadDir(awDir)
	if readErr == nil && len(entries) == 0 {
		_ = os.Remove(awDir)
	}
	if resultPath != "" {
		return resultPath, nil
	}
	if len(removedPaths) == 0 {
		return "", nil
	}
	return removedPaths[0], nil
}
