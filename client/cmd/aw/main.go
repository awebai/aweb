package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aweb/client"
	"github.com/awebai/aweb/client/awconfig"
	"github.com/awebai/aweb/client/chat"
	"github.com/joho/godotenv"
)

func main() {
	loadDotenvBestEffort()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "init":
		runInit(args)
	case "introspect":
		runIntrospect(args)
	case "mail":
		runMail(args)
	case "chat":
		runChat(args)
	case "lock":
		runLock(args)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "aw - aweb CLI (minimal)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  aw init --project-slug ... [--alias ...] [--project-name ...] [--human-name ...] [--agent-type ...] [--server ...] [--url ...] [--account ...]")
	fmt.Fprintln(os.Stderr, "  aw introspect [--server ...] [--account ...]")
	fmt.Fprintln(os.Stderr, "  aw mail send [--server ...] [--account ...] (--to-alias ... | --to-agent-id ...) --body ... [--subject ...]")
	fmt.Fprintln(os.Stderr, "  aw mail inbox [--server ...] [--account ...] [--unread-only] [--limit N]")
	fmt.Fprintln(os.Stderr, "  aw chat send [--server ...] [--account ...] --to-alias ... --message ... [--wait N] [--leaving] [--start-conversation]")
	fmt.Fprintln(os.Stderr, "  aw chat pending [--server ...] [--account ...]")
	fmt.Fprintln(os.Stderr, "  aw chat open [--server ...] [--account ...] --alias ...")
	fmt.Fprintln(os.Stderr, "  aw chat history [--server ...] [--account ...] --alias ...")
	fmt.Fprintln(os.Stderr, "  aw chat hang-on [--server ...] [--account ...] --alias ... --message ...")
	fmt.Fprintln(os.Stderr, "  aw chat show-pending [--server ...] [--account ...] --alias ...")
	fmt.Fprintln(os.Stderr, "  aw lock acquire [--server ...] [--account ...] --resource-key ... [--ttl-seconds N]")
	fmt.Fprintln(os.Stderr, "  aw lock list [--prefix ...]")
	fmt.Fprintln(os.Stderr, "  aw lock release [--server ...] [--account ...] --resource-key ...")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Config:")
	fmt.Fprintln(os.Stderr, "  ~/.config/aw/config.yaml (or AW_CONFIG_PATH)")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Env overrides (optional):")
	fmt.Fprintln(os.Stderr, "  AWEB_SERVER")
	fmt.Fprintln(os.Stderr, "  AWEB_URL")
	fmt.Fprintln(os.Stderr, "  AWEB_API_KEY")
	fmt.Fprintln(os.Stderr, "  AWEB_ACCOUNT")
}

func loadDotenvBestEffort() {
	// Best effort: load from current working directory.
	_ = godotenv.Load()
	_ = godotenv.Overload(".env.aweb")
}

func mustResolve(serverName, accountName string) (*aweb.Client, *awconfig.Selection) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read config:", err)
		os.Exit(2)
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverName,
		AccountName:       accountName,
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	c, err := aweb.NewWithAPIKey(sel.BaseURL, sel.APIKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid base URL:", err)
		os.Exit(2)
	}
	return c, sel
}

func mustClient(serverName, accountName string) *aweb.Client {
	c, _ := mustResolve(serverName, accountName)
	return c
}

func resolveBaseURLForInit(urlFlag, serverFlag string) (baseURL string, serverName string, global *awconfig.GlobalConfig, err error) {
	global, err = awconfig.LoadGlobal()
	if err != nil {
		return "", "", nil, err
	}

	baseURL = strings.TrimSpace(urlFlag)
	serverName = strings.TrimSpace(serverFlag)

	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	if baseURL == "" && serverName != "" {
		if srv, ok := global.Servers[serverName]; ok && strings.TrimSpace(srv.URL) != "" {
			baseURL = strings.TrimSpace(srv.URL)
		} else {
			baseURL, err = awconfig.DeriveBaseURLFromServerName(serverName)
			if err != nil {
				return "", "", nil, err
			}
		}
	}
	if baseURL == "" && strings.TrimSpace(global.DefaultAccount) != "" {
		if acct, ok := global.Accounts[strings.TrimSpace(global.DefaultAccount)]; ok {
			serverName = strings.TrimSpace(acct.Server)
			if srv, ok := global.Servers[serverName]; ok && strings.TrimSpace(srv.URL) != "" {
				baseURL = strings.TrimSpace(srv.URL)
			} else if serverName != "" {
				baseURL, err = awconfig.DeriveBaseURLFromServerName(serverName)
				if err != nil {
					return "", "", nil, err
				}
			}
		}
	}
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}
	if serverName == "" {
		derived, derr := awconfig.DeriveServerNameFromURL(baseURL)
		if derr == nil {
			serverName = derived
		}
	}
	if err := awconfig.ValidateBaseURL(baseURL); err != nil {
		return "", "", nil, err
	}
	return baseURL, serverName, global, nil
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func sanitizeSlug(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "demo"
	}
	return out
}

func promptString(label, defaultValue string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultValue)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	var urlFlag, serverNameFlag, accountNameFlag, projectSlug, projectName, aliasFlag, humanName, agentType string
	var printExports, saveConfig, setDefault, writeContext bool
	fs.StringVar(&urlFlag, "url", "", "Base URL for the aweb server (default: config selection, then http://localhost:8000)")
	fs.StringVar(&serverNameFlag, "server", "", "Server name in config.yaml (default: derive from --url host)")
	fs.StringVar(&accountNameFlag, "account", "", "Account name in config.yaml (default: derived from server/project/alias)")
	fs.StringVar(&projectSlug, "project-slug", "", "Project slug (default: AWEB_PROJECT or prompt in TTY)")
	fs.StringVar(&projectName, "project-name", "", "Project name (default: AWEB_PROJECT_NAME or project-slug)")
	fs.StringVar(&aliasFlag, "alias", "", "Agent alias (optional; default: server-suggested)")
	fs.StringVar(&humanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	fs.StringVar(&agentType, "agent-type", "", "Agent type (default: AWEB_AGENT_TYPE or agent)")
	fs.BoolVar(&saveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	fs.BoolVar(&setDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	fs.BoolVar(&writeContext, "write-context", true, "Write/update .aw/context in the current worktree (non-secret pointer)")
	fs.BoolVar(&printExports, "print-exports", false, "Print shell export lines after JSON output")
	_ = fs.Parse(args)

	baseURL, serverName, _, err := resolveBaseURLForInit(urlFlag, serverNameFlag)
	if err != nil {
		fatal(err)
	}

	if strings.TrimSpace(projectSlug) == "" {
		projectSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG"))
	}
	if strings.TrimSpace(projectSlug) == "" {
		projectSlug = strings.TrimSpace(os.Getenv("AWEB_PROJECT"))
	}

	if strings.TrimSpace(projectSlug) == "" {
		if isTTY() {
			wd, _ := os.Getwd()
			suggested := sanitizeSlug(filepath.Base(wd))
			v, err := promptString("Project slug", suggested)
			if err != nil {
				fatal(err)
			}
			projectSlug = v
		} else {
			fmt.Fprintln(os.Stderr, "Missing project slug (use --project-slug or AWEB_PROJECT)")
			os.Exit(2)
		}
	}

	if strings.TrimSpace(projectName) == "" {
		projectName = strings.TrimSpace(os.Getenv("AWEB_PROJECT_NAME"))
	}
	if strings.TrimSpace(projectName) == "" {
		projectName = projectSlug
	}

	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = strings.TrimSpace(os.Getenv("USER"))
	}
	if strings.TrimSpace(humanName) == "" {
		humanName = "developer"
	}

	if strings.TrimSpace(agentType) == "" {
		agentType = strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE"))
	}
	if strings.TrimSpace(agentType) == "" {
		agentType = "agent"
	}

	alias := strings.TrimSpace(aliasFlag)
	aliasExplicit := alias != ""
	if !aliasExplicit {
		alias = strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
		aliasExplicit = alias != ""
	}

	aliasWasDefaultSuggestion := false
	if !aliasExplicit {
		bootstrapClient, err := aweb.New(baseURL)
		if err != nil {
			fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		suggestion, err := bootstrapClient.SuggestAliasPrefix(ctx, projectSlug)
		if err != nil || strings.TrimSpace(suggestion.NamePrefix) == "" {
			alias = "alice"
		} else {
			alias = suggestion.NamePrefix
		}
		aliasWasDefaultSuggestion = true
	}

	if isTTY() && !aliasExplicit {
		v, err := promptString("Agent alias", alias)
		if err != nil {
			fatal(err)
		}
		aliasWasDefaultSuggestion = v == alias
		alias = strings.TrimSpace(v)
		if alias == "" {
			alias = "alice"
			aliasWasDefaultSuggestion = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bootstrapClient, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	req := &aweb.InitRequest{
		ProjectSlug: projectSlug,
		ProjectName: projectName,
		HumanName:   humanName,
		AgentType:   agentType,
	}
	if strings.TrimSpace(alias) != "" {
		req.Alias = &alias
	}

	resp, err := bootstrapClient.Init(ctx, req)
	if err != nil {
		fatal(err)
	}

	// If we got an existing alias using the default suggestion, retry with server allocation.
	if !aliasExplicit && aliasWasDefaultSuggestion && !resp.Created {
		req.Alias = nil
		resp, err = bootstrapClient.Init(ctx, req)
		if err != nil {
			fatal(err)
		}
	}

	accountName := strings.TrimSpace(accountNameFlag)
	if accountName == "" {
		accountName = deriveAccountName(serverName, projectSlug, resp.Alias)
	}

	if saveConfig {
		updateErr := awconfig.UpdateGlobalAt(mustDefaultGlobalPath(), func(cfg *awconfig.GlobalConfig) error {
			if cfg.Servers == nil {
				cfg.Servers = map[string]awconfig.Server{}
			}
			if cfg.Accounts == nil {
				cfg.Accounts = map[string]awconfig.Account{}
			}
			if _, ok := cfg.Servers[serverName]; !ok || strings.TrimSpace(cfg.Servers[serverName].URL) == "" {
				cfg.Servers[serverName] = awconfig.Server{URL: baseURL}
			}
			cfg.Accounts[accountName] = awconfig.Account{
				Server:         serverName,
				APIKey:         resp.APIKey,
				DefaultProject: projectSlug,
				AgentID:        resp.AgentID,
				AgentAlias:     resp.Alias,
			}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || setDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		})
		if updateErr != nil {
			fatal(updateErr)
		}
	}

	if writeContext {
		if err := writeOrUpdateContext(serverName, accountName); err != nil {
			fatal(err)
		}
	}

	printJSON(resp)
	if printExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + baseURL)
		fmt.Println("export AWEB_API_KEY=" + resp.APIKey)
		fmt.Println("export AWEB_PROJECT_ID=" + resp.ProjectID)
		fmt.Println("export AWEB_AGENT_ID=" + resp.AgentID)
		fmt.Println("export AWEB_AGENT_ALIAS=" + resp.Alias)
	}
}

func runIntrospect(args []string) {
	fs := flag.NewFlagSet("introspect", flag.ExitOnError)
	var serverName string
	var accountName string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).Introspect(ctx)
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func runMail(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "send":
		runMailSend(args[1:])
	case "inbox":
		runMailInbox(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func runMailSend(args []string) {
	fs := flag.NewFlagSet("mail send", flag.ExitOnError)
	var serverName string
	var accountName string
	var toAgentID, toAlias, subject, body, priority string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	fs.StringVar(&toAgentID, "to-agent-id", "", "Recipient agent_id")
	fs.StringVar(&toAlias, "to-alias", "", "Recipient alias")
	fs.StringVar(&subject, "subject", "", "Subject")
	fs.StringVar(&body, "body", "", "Body")
	fs.StringVar(&priority, "priority", "normal", "Priority: low|normal|high|urgent")
	_ = fs.Parse(args)

	if (toAgentID == "" && toAlias == "") || body == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).SendMessage(ctx, &aweb.SendMessageRequest{
		ToAgentID: toAgentID,
		ToAlias:   toAlias,
		Subject:   subject,
		Body:      body,
		Priority:  aweb.MessagePriority(priority),
	})
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func runMailInbox(args []string) {
	fs := flag.NewFlagSet("mail inbox", flag.ExitOnError)
	var serverName string
	var accountName string
	var unreadOnly bool
	var limit int
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	fs.BoolVar(&unreadOnly, "unread-only", false, "Only unread")
	fs.IntVar(&limit, "limit", 50, "Max messages")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).Inbox(ctx, aweb.InboxParams{
		UnreadOnly: unreadOnly,
		Limit:      limit,
	})
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func runChat(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "send":
		runChatSend(args[1:])
	case "pending":
		runChatPending(args[1:])
	case "open":
		runChatOpen(args[1:])
	case "history":
		runChatHistory(args[1:])
	case "hang-on":
		runChatHangOn(args[1:])
	case "show-pending":
		runChatShowPending(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func chatStderrCallback(kind, message string) {
	fmt.Fprintf(os.Stderr, "[chat:%s] %s\n", kind, message)
}

func runChatSend(args []string) {
	fs := flag.NewFlagSet("chat send", flag.ExitOnError)
	var serverName, accountName, toAlias, message string
	var wait int
	var leaving, startConversation bool
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	fs.StringVar(&toAlias, "to-alias", "", "Recipient alias")
	fs.StringVar(&message, "message", "", "Message body")
	fs.IntVar(&wait, "wait", 60, "Seconds to wait for reply (0 = no wait)")
	fs.BoolVar(&leaving, "leaving", false, "Send and leave conversation")
	fs.BoolVar(&startConversation, "start-conversation", false, "Start conversation (5min default wait)")
	_ = fs.Parse(args)

	if toAlias == "" || message == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags: --to-alias and --message")
		os.Exit(2)
	}

	timeout := time.Duration(wait+30) * time.Second
	if timeout < 10*time.Second {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, sel := mustResolve(serverName, accountName)
	result, err := chat.Send(ctx, c, sel.AgentAlias, []string{toAlias}, message, chat.SendOptions{
		Wait:              wait,
		Leaving:           leaving,
		StartConversation: startConversation,
	}, chatStderrCallback)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runChatPending(args []string) {
	fs := flag.NewFlagSet("chat pending", flag.ExitOnError)
	var serverName, accountName string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := chat.Pending(ctx, mustClient(serverName, accountName))
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runChatOpen(args []string) {
	fs := flag.NewFlagSet("chat open", flag.ExitOnError)
	var serverName, accountName, alias string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	fs.StringVar(&alias, "alias", "", "Target agent alias")
	_ = fs.Parse(args)

	if alias == "" {
		fmt.Fprintln(os.Stderr, "Missing required flag: --alias")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := chat.Open(ctx, mustClient(serverName, accountName), alias)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runChatHistory(args []string) {
	fs := flag.NewFlagSet("chat history", flag.ExitOnError)
	var serverName, accountName, alias string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	fs.StringVar(&alias, "alias", "", "Target agent alias")
	_ = fs.Parse(args)

	if alias == "" {
		fmt.Fprintln(os.Stderr, "Missing required flag: --alias")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := chat.History(ctx, mustClient(serverName, accountName), alias)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runChatHangOn(args []string) {
	fs := flag.NewFlagSet("chat hang-on", flag.ExitOnError)
	var serverName, accountName, alias, message string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	fs.StringVar(&alias, "alias", "", "Target agent alias")
	fs.StringVar(&message, "message", "", "Hang-on message")
	_ = fs.Parse(args)

	if alias == "" || message == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags: --alias and --message")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := chat.HangOn(ctx, mustClient(serverName, accountName), alias, message)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runChatShowPending(args []string) {
	fs := flag.NewFlagSet("chat show-pending", flag.ExitOnError)
	var serverName, accountName, alias string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml")
	fs.StringVar(&alias, "alias", "", "Target agent alias")
	_ = fs.Parse(args)

	if alias == "" {
		fmt.Fprintln(os.Stderr, "Missing required flag: --alias")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := chat.ShowPending(ctx, mustClient(serverName, accountName), alias)
	if err != nil {
		fatal(err)
	}
	printJSON(result)
}

func runLock(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "acquire":
		runLockAcquire(args[1:])
	case "release":
		runLockRelease(args[1:])
	case "list":
		runLockList(args[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func runLockAcquire(args []string) {
	fs := flag.NewFlagSet("lock acquire", flag.ExitOnError)
	var serverName string
	var accountName string
	var resourceKey string
	var ttlSeconds int
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	fs.StringVar(&resourceKey, "resource-key", "", "Opaque resource key")
	fs.IntVar(&ttlSeconds, "ttl-seconds", 3600, "TTL seconds")
	_ = fs.Parse(args)

	if resourceKey == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).ReservationAcquire(ctx, &aweb.ReservationAcquireRequest{
		ResourceKey: resourceKey,
		TTLSeconds:  ttlSeconds,
	})
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func runLockRelease(args []string) {
	fs := flag.NewFlagSet("lock release", flag.ExitOnError)
	var serverName string
	var accountName string
	var resourceKey string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	fs.StringVar(&resourceKey, "resource-key", "", "Opaque resource key")
	_ = fs.Parse(args)
	if resourceKey == "" {
		fmt.Fprintln(os.Stderr, "Missing required flags")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).ReservationRelease(ctx, &aweb.ReservationReleaseRequest{
		ResourceKey: resourceKey,
	})
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func runLockList(args []string) {
	fs := flag.NewFlagSet("lock list", flag.ExitOnError)
	var serverName string
	var accountName string
	var prefix string
	fs.StringVar(&serverName, "server", "", "Server name from config.yaml (default: default_server)")
	fs.StringVar(&accountName, "account", "", "Account name from config.yaml (default: context/default_account)")
	fs.StringVar(&prefix, "prefix", "", "Prefix filter")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := mustClient(serverName, accountName).ReservationList(ctx, prefix)
	if err != nil {
		fatal(err)
	}
	printJSON(resp)
}

func mustDefaultGlobalPath() string {
	path, err := awconfig.DefaultGlobalConfigPath()
	if err != nil {
		fatal(err)
	}
	return path
}

func sanitizeKeyComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "x"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "x"
	}
	return out
}

func deriveAccountName(serverName, projectSlug, alias string) string {
	return "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(projectSlug) + "__" + sanitizeKeyComponent(alias)
}

func writeOrUpdateContext(serverName, accountName string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		ctxPath = filepath.Join(wd, awconfig.DefaultWorktreeContextRelativePath())
	}

	ctx := &awconfig.WorktreeContext{
		DefaultAccount: accountName,
		ServerAccounts: map[string]string{serverName: accountName},
	}
	if existing, err := awconfig.LoadWorktreeContextFrom(ctxPath); err == nil {
		ctx = existing
		if ctx.ServerAccounts == nil {
			ctx.ServerAccounts = map[string]string{}
		}
		ctx.DefaultAccount = accountName
		ctx.ServerAccounts[serverName] = accountName
	}

	return awconfig.SaveWorktreeContextTo(ctxPath, ctx)
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
