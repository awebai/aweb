package main

import (
	"context"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Distributed locks",
}

// lock acquire

var (
	lockAcquireResourceKey string
	lockAcquireTTLSeconds  int
)

var lockAcquireCmd = &cobra.Command{
	Use:   "acquire",
	Short: "Acquire a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockAcquireResourceKey == "" {
			return usageError("missing required flag: --resource-key")
		}

		c, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := c.ReservationAcquire(ctx, &aweb.ReservationAcquireRequest{
			ResourceKey: lockAcquireResourceKey,
			TTLSeconds:  lockAcquireTTLSeconds,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatLockAcquire)
		return nil
	},
}

// lock renew

var (
	lockRenewResourceKey string
	lockRenewTTLSeconds  int
)

var lockRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockRenewResourceKey == "" {
			return usageError("missing required flag: --resource-key")
		}

		c, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := c.ReservationRenew(ctx, &aweb.ReservationRenewRequest{
			ResourceKey: lockRenewResourceKey,
			TTLSeconds:  lockRenewTTLSeconds,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatLockRenew)
		return nil
	},
}

// lock release

var lockReleaseResourceKey string

var lockReleaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Release a lock",
	RunE: func(cmd *cobra.Command, args []string) error {
		if lockReleaseResourceKey == "" {
			return usageError("missing required flag: --resource-key")
		}

		c, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := c.ReservationRelease(ctx, &aweb.ReservationReleaseRequest{
			ResourceKey: lockReleaseResourceKey,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatLockRelease)
		return nil
	},
}

// lock revoke

var lockRevokePrefix string

var lockRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke locks",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := c.ReservationRevoke(ctx, &aweb.ReservationRevokeRequest{
			Prefix: lockRevokePrefix,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatLockRevoke)
		return nil
	},
}

// lock list

var lockListPrefix string

var lockListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active locks",
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := c.ReservationList(ctx, lockListPrefix)
		if err != nil {
			return err
		}
		printOutput(resp, formatLockList)
		return nil
	},
}

func init() {
	lockAcquireCmd.Flags().StringVar(&lockAcquireResourceKey, "resource-key", "", "Opaque resource key")
	lockAcquireCmd.Flags().IntVar(&lockAcquireTTLSeconds, "ttl-seconds", 3600, "TTL seconds")

	lockRenewCmd.Flags().StringVar(&lockRenewResourceKey, "resource-key", "", "Opaque resource key")
	lockRenewCmd.Flags().IntVar(&lockRenewTTLSeconds, "ttl-seconds", 3600, "TTL seconds")

	lockReleaseCmd.Flags().StringVar(&lockReleaseResourceKey, "resource-key", "", "Opaque resource key")

	lockRevokeCmd.Flags().StringVar(&lockRevokePrefix, "prefix", "", "Optional prefix filter")

	lockListCmd.Flags().StringVar(&lockListPrefix, "prefix", "", "Prefix filter")

	lockCmd.AddCommand(lockAcquireCmd, lockRenewCmd, lockReleaseCmd, lockRevokeCmd, lockListCmd)
	rootCmd.AddCommand(lockCmd)
}
