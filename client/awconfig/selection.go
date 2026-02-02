package awconfig

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type Selection struct {
	AccountName string
	ServerName  string
	BaseURL     string
	APIKey      string

	DefaultProject string
	AgentID        string
	AgentAlias     string
}

type ResolveOptions struct {
	AccountName string
	ServerName  string

	WorkingDir  string
	ContextPath string
	Context     *WorktreeContext

	BaseURLOverride string
	APIKeyOverride  string

	AllowEnvOverrides bool
}

func Resolve(global *GlobalConfig, opts ResolveOptions) (*Selection, error) {
	if global == nil {
		global = &GlobalConfig{}
	}
	if global.Servers == nil {
		global.Servers = map[string]Server{}
	}
	if global.Accounts == nil {
		global.Accounts = map[string]Account{}
	}

	ctx := opts.Context
	if ctx == nil && strings.TrimSpace(opts.ContextPath) != "" {
		loaded, err := LoadWorktreeContextFrom(opts.ContextPath)
		if err != nil {
			return nil, err
		}
		ctx = loaded
	}
	if ctx == nil && strings.TrimSpace(opts.WorkingDir) != "" {
		loaded, _, err := LoadWorktreeContextFromDir(opts.WorkingDir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("invalid worktree context: %w", err)
			}
		} else {
			ctx = loaded
		}
	}
	if ctx != nil && ctx.ServerAccounts == nil {
		ctx.ServerAccounts = map[string]string{}
	}

	accountName := strings.TrimSpace(opts.AccountName)
	if accountName == "" && opts.AllowEnvOverrides {
		accountName = strings.TrimSpace(os.Getenv("AWEB_ACCOUNT"))
	}

	serverName := strings.TrimSpace(opts.ServerName)
	if serverName == "" && opts.AllowEnvOverrides {
		serverName = strings.TrimSpace(os.Getenv("AWEB_SERVER"))
	}

	baseURL := strings.TrimSpace(opts.BaseURLOverride)
	apiKey := strings.TrimSpace(opts.APIKeyOverride)
	baseURLFromEnv := false
	if opts.AllowEnvOverrides {
		if baseURL == "" {
			if v := strings.TrimSpace(os.Getenv("AWEB_URL")); v != "" {
				baseURL = v
				baseURLFromEnv = true
			}
		}
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("AWEB_API_KEY"))
		}
	}
	if baseURLFromEnv {
		if err := ValidateBaseURL(baseURL); err != nil {
			return nil, fmt.Errorf("invalid AWEB_URL: %w", err)
		}
	}

	// If explicit account is given, it wins; server is implied.
	if accountName != "" {
		acct, ok := global.Accounts[accountName]
		if !ok {
			return nil, fmt.Errorf("unknown account %q (configure it in your aw config file)", accountName)
		}
		if strings.TrimSpace(acct.Server) == "" {
			return nil, fmt.Errorf("account %q missing server", accountName)
		}
		if serverName == "" {
			serverName = strings.TrimSpace(acct.Server)
		}

		if baseURL == "" {
			u, err := resolveServerURL(global, serverName)
			if err != nil {
				return nil, err
			}
			baseURL = u
		}
		if apiKey == "" {
			apiKey = strings.TrimSpace(acct.APIKey)
		}

		return finalizeSelection(accountName, serverName, baseURL, apiKey, acct), nil
	}

	// No explicit account: choose one deterministically from server+context+defaults.
	var chosenAccountName string
	if serverName != "" {
		if ctx != nil {
			if v := strings.TrimSpace(ctx.ServerAccounts[serverName]); v != "" {
				chosenAccountName = v
			}
		}
		if chosenAccountName == "" && ctx != nil && strings.TrimSpace(ctx.DefaultAccount) != "" {
			if acct, ok := global.Accounts[strings.TrimSpace(ctx.DefaultAccount)]; ok && strings.TrimSpace(acct.Server) == serverName {
				chosenAccountName = strings.TrimSpace(ctx.DefaultAccount)
			}
		}
		if chosenAccountName == "" && strings.TrimSpace(global.DefaultAccount) != "" {
			if acct, ok := global.Accounts[strings.TrimSpace(global.DefaultAccount)]; ok && strings.TrimSpace(acct.Server) == serverName {
				chosenAccountName = strings.TrimSpace(global.DefaultAccount)
			}
		}
		if chosenAccountName == "" {
			return nil, fmt.Errorf("no account configured for server %q (set .aw/context server_accounts[%q], or pass --account)", serverName, serverName)
		}
	} else {
		if ctx != nil && strings.TrimSpace(ctx.DefaultAccount) != "" {
			chosenAccountName = strings.TrimSpace(ctx.DefaultAccount)
		}
		if chosenAccountName == "" {
			chosenAccountName = strings.TrimSpace(global.DefaultAccount)
		}
		if chosenAccountName == "" {
			return nil, errors.New("no default account configured (set .aw/context default_account or set default_account in your aw config)")
		}
	}

	acct, ok := global.Accounts[chosenAccountName]
	if !ok {
		return nil, fmt.Errorf("unknown account %q referenced by context/defaults", chosenAccountName)
	}
	if strings.TrimSpace(acct.Server) == "" {
		return nil, fmt.Errorf("account %q missing server", chosenAccountName)
	}
	if serverName == "" {
		serverName = strings.TrimSpace(acct.Server)
	}
	if baseURL == "" {
		u, err := resolveServerURL(global, serverName)
		if err != nil {
			return nil, err
		}
		baseURL = u
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(acct.APIKey)
	}
	return finalizeSelection(chosenAccountName, serverName, baseURL, apiKey, acct), nil
}

func finalizeSelection(accountName, serverName, baseURL, apiKey string, acct Account) *Selection {
	return &Selection{
		AccountName:    accountName,
		ServerName:     serverName,
		BaseURL:        baseURL,
		APIKey:         apiKey,
		DefaultProject: strings.TrimSpace(acct.DefaultProject),
		AgentID:        strings.TrimSpace(acct.AgentID),
		AgentAlias:     strings.TrimSpace(acct.AgentAlias),
	}
}

func resolveServerURL(global *GlobalConfig, serverName string) (string, error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return "", errors.New("empty server name")
	}
	if srv, ok := global.Servers[serverName]; ok && strings.TrimSpace(srv.URL) != "" {
		return strings.TrimSpace(srv.URL), nil
	}

	// Derive from server key (host:port or full URL).
	derived, err := DeriveBaseURLFromServerName(serverName)
	if err != nil {
		return "", err
	}
	return derived, nil
}

func DeriveBaseURLFromServerName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty server name")
	}
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return name, nil
	}
	host := name
	isLocal := strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "[::1]")
	scheme := "https"
	if isLocal {
		scheme = "http"
	}
	return scheme + "://" + host, nil
}

func DeriveServerNameFromURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("url missing host: %q", raw)
	}
	return u.Host, nil
}

func ValidateBaseURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty base URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid base URL %q", raw)
	}
	return nil
}
