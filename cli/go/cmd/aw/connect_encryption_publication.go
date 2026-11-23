package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/awebai/aw/awconfig"
)

type encryptionPublicationPolicy uint8

const (
	encryptionPublicationBestEffort encryptionPublicationPolicy = iota
	encryptionPublicationRequiredService
)

type encryptionPublicationTarget string

const encryptionServicePublicationTarget encryptionPublicationTarget = "aweb-service"

type connectedEncryptionSetup struct {
	WorkingDir string
	Home       awconfig.IdentityHome
	Warnings   io.Writer
	Policy     encryptionPublicationPolicy
}

// connectedMemberSetupError marks a local completion failure after the member
// binding and its credentials were persisted. Creation rollback must preserve
// those keys, including an encryption assertion whose write may have committed.
type connectedMemberSetupError struct{ cause error }

func (err *connectedMemberSetupError) Error() string         { return err.cause.Error() }
func (err *connectedMemberSetupError) Unwrap() error         { return err.cause }
func (err *connectedMemberSetupError) RetainsIdentity() bool { return true }

type requiredEncryptionPublicationError struct{ cause error }

func (err *requiredEncryptionPublicationError) Error() string {
	return "E2E key publication is not confirmed: " + err.cause.Error()
}
func (err *requiredEncryptionPublicationError) Unwrap() error { return err.cause }

func (policy encryptionPublicationPolicy) validate() error {
	if policy != encryptionPublicationBestEffort && policy != encryptionPublicationRequiredService {
		return errors.New("encryption publication policy is unknown")
	}
	return nil
}

// completeConnectedEncryption publishes only after normal connect has admitted
// this member (docs/identity.md#provisioned-members-and-encryption-discovery).
// Required service publication is confirmed by its actual publication result;
// a failed or skipped write is never converted to provisioning success.
func completeConnectedEncryption(ctx context.Context, input connectedEncryptionSetup) error {
	if err := input.Policy.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(input.Home.Root) == "" {
		return errors.New("connected encryption setup requires an explicit identity home")
	}

	if err := ensureLocalIdentityEncryptionKeyForDir(input.WorkingDir, explicitEncryptionKeyIdentityHome(input.Home.Root)); err != nil {
		return fmt.Errorf("set up E2E encryption key: %w", err)
	}
	publication, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, input.WorkingDir, false, explicitEncryptionKeyIdentityHome(input.Home.Root))
	if input.Policy == encryptionPublicationRequiredService {
		if err != nil {
			return &requiredEncryptionPublicationError{cause: err}
		}
		for _, target := range publication.Published {
			if encryptionPublicationTarget(target) == encryptionServicePublicationTarget {
				return nil
			}
		}
		return &requiredEncryptionPublicationError{cause: errors.New("the service publication was skipped")}
	}
	if err != nil {
		if input.Warnings == nil {
			return err
		}
		if _, writeErr := fmt.Fprintf(input.Warnings,
			"Warning: could not publish E2E encryption key automatically: %v\n"+
				"Counterparties cannot discover this identity's encryption key until the assertion is published.\n"+
				"Run `aw id encryption-key setup` to publish it; `aw check` reports the unpublished state as identity.e2ee.assertion_published.\n", err); writeErr != nil {
			return fmt.Errorf("report unconfirmed encryption publication: %w", writeErr)
		}
	}
	return nil
}
