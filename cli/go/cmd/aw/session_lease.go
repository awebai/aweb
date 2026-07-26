package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{Use: "session", Short: "Session-scoped coordination"}
var sessionLeaseCmd = &cobra.Command{Use: "lease", Short: "Manage the principal's session admission lease"}

func sessionLeaseClient() (*aweb.Client, error) {
	client, _, err := resolveClientSelection()
	return client, err
}

func requireSessionLeaseCredentials(cmd *cobra.Command) (string, string, error) {
	id, _ := cmd.Flags().GetString("session-id")
	key, _ := cmd.Flags().GetString("session-key")
	if id == "" || key == "" {
		return "", "", usageError("--session-id and --session-key are required")
	}
	return id, key, nil
}

func leaseRequest(cmd *cobra.Command) (*aweb.SessionLeaseRequest, error) {
	id, key, err := requireSessionLeaseCredentials(cmd)
	if err != nil {
		return nil, err
	}
	ttl, _ := cmd.Flags().GetInt("ttl-seconds")
	return &aweb.SessionLeaseRequest{SessionID: id, SessionKey: key, TTLSeconds: ttl}, nil
}

func runSessionLeaseStatus(cmd *cobra.Command, _ []string) error {
	client, err := sessionLeaseClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	view, err := client.SessionLeaseGet(ctx)
	if err != nil {
		return err
	}
	printOutput(view, func(v any) string {
		lease := v.(*aweb.SessionLeaseView)
		if lease.SessionID == "" {
			return "No active session admission lease.\n"
		}
		return fmt.Sprintf("Session %s holds admission through %s (generation %d).\n", lease.SessionID, lease.ExpiresAt, lease.Generation)
	})
	return nil
}

func runSessionLeaseAcquire(cmd *cobra.Command, _ []string) error {
	req, err := leaseRequest(cmd)
	if err != nil {
		return err
	}
	client, err := sessionLeaseClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	view, err := client.SessionLeaseAcquire(ctx, req)
	if err != nil {
		return err
	}
	printOutput(view, func(any) string {
		return fmt.Sprintf("Acquired session admission lease for %s through %s.\n", view.SessionID, view.ExpiresAt)
	})
	return nil
}

func runSessionLeaseRenew(cmd *cobra.Command, _ []string) error {
	req, err := leaseRequest(cmd)
	if err != nil {
		return err
	}
	client, err := sessionLeaseClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	view, err := client.SessionLeaseRenew(ctx, req)
	if err != nil {
		return err
	}
	printOutput(view, func(any) string {
		return fmt.Sprintf("Renewed session admission lease for %s through %s.\n", view.SessionID, view.ExpiresAt)
	})
	return nil
}

func runSessionLeaseRelease(cmd *cobra.Command, _ []string) error {
	id, key, err := requireSessionLeaseCredentials(cmd)
	if err != nil {
		return err
	}
	client, err := sessionLeaseClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.SessionLeaseRelease(ctx, &aweb.SessionLeaseReleaseRequest{SessionID: id, SessionKey: key}); err != nil {
		return err
	}
	printOutput(map[string]string{"status": "released", "session_id": id}, func(any) string { return fmt.Sprintf("Released session admission lease for %s.\n", id) })
	return nil
}

func runSessionLeaseTakeover(cmd *cobra.Command, _ []string) error {
	req, err := leaseRequest(cmd)
	if err != nil {
		return err
	}
	reason, _ := cmd.Flags().GetString("reason")
	if reason == "" {
		return usageError("--reason is required for audited takeover")
	}
	client, err := sessionLeaseClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	view, err := client.SessionLeaseTakeover(ctx, &aweb.SessionLeaseTakeoverRequest{SessionID: req.SessionID, SessionKey: req.SessionKey, TTLSeconds: req.TTLSeconds, Reason: reason})
	if err != nil {
		return err
	}
	printOutput(view, func(any) string {
		return fmt.Sprintf("Took over session admission lease for %s at generation %d.\n", view.SessionID, view.Generation)
	})
	return nil
}

func addLeaseFlags(cmd *cobra.Command, ttl bool) {
	cmd.Flags().String("session-id", "", "Per-session identifier")
	cmd.Flags().String("session-key", "", "Per-session secret (at least 32 characters; avoid shell history)")
	if ttl {
		cmd.Flags().Int("ttl-seconds", 300, "Lease TTL in seconds")
	}
}

func init() {
	statusCmd := &cobra.Command{Use: "status", RunE: runSessionLeaseStatus}
	acquireCmd := &cobra.Command{Use: "acquire", RunE: runSessionLeaseAcquire}
	renewCmd := &cobra.Command{Use: "renew", RunE: runSessionLeaseRenew}
	releaseCmd := &cobra.Command{Use: "release", RunE: runSessionLeaseRelease}
	takeoverCmd := &cobra.Command{Use: "takeover", Short: "Explicit audited early takeover", RunE: runSessionLeaseTakeover}
	addLeaseFlags(acquireCmd, true)
	addLeaseFlags(renewCmd, true)
	addLeaseFlags(releaseCmd, false)
	addLeaseFlags(takeoverCmd, true)
	takeoverCmd.Flags().String("reason", "", "Required audited reason")
	sessionLeaseCmd.AddCommand(statusCmd, acquireCmd, renewCmd, releaseCmd, takeoverCmd)
	sessionCmd.AddCommand(sessionLeaseCmd)
	rootCmd.AddCommand(sessionCmd)
}
