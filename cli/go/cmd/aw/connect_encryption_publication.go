package main

import (
	"context"
	"fmt"
	"io"

	"github.com/awebai/aw/awconfig"
)

type connectedEncryptionSetup struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	Warnings   io.Writer
}

func completeConnectedEncryption(ctx context.Context, input connectedEncryptionSetup) error {
	if err := ensureLocalIdentityEncryptionKeyForDir(input.WorkingDir, explicitEncryptionKeyIdentityHome(input.Home.Root)); err != nil {
		return fmt.Errorf("set up E2E encryption key: %w", err)
	}
	if _, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, input.WorkingDir, false, explicitEncryptionKeyIdentityHome(input.Home.Root)); err != nil {
		fmt.Fprintf(input.Warnings,
			"Warning: could not publish E2E encryption key automatically: %v\n"+
				"Counterparties cannot discover this identity's encryption key until the assertion is published.\n"+
				"Run `aw id encryption-key setup` to publish it; `aw check` reports the unpublished state as identity.e2ee.assertion_published.\n", err)
	}
	return nil
}
