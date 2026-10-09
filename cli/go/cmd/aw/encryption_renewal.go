package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const encryptionAssertionRenewalWindow = 14 * 24 * time.Hour

// Only existing keys are renewed. Publication precedes replacing the local
// assertion so an offline/partial publication is retried on the next command.
// The private key is already durable and is never changed by renewal.
func renewIdentityEncryptionAssertion(ctx context.Context, workingDir string, home encryptionKeyIdentityHomeIntent) error {
	identity, err := resolveIdentityForEncryptionKeyForDir(workingDir, home)
	if err != nil {
		return err
	}
	if identity.Custody != awid.CustodySelf {
		return nil
	}
	statePath, err := encryptionStatePathForIdentity(identity)
	if err != nil {
		return err
	}
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		return nil
	}
	lock, err := awconfig.TryLockExclusive(statePath + ".lock")
	if errors.Is(err, awconfig.ErrLockUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	record := state.ActiveRecord()
	if record == nil {
		return nil
	}
	assertion, err := loadEncryptionAssertionAt(identity.WorkingDir, identity.IdentityHome, record.AssertionPath)
	if err != nil {
		return err
	}
	expiry, err := time.Parse(time.RFC3339Nano, assertion.ExpiresAt)
	if err != nil {
		return err
	}
	if expiry.After(time.Now().Add(encryptionAssertionRenewalWindow)) {
		return nil
	}
	material, err := validateEncryptionRecordPrivateKeyAt(identity.WorkingDir, identity.IdentityHome, record)
	if err != nil {
		return err
	}
	if err := validateEncryptionRecordForRead(identity, record, assertion, material); err != nil {
		return err
	}
	key, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return err
	}
	if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != identity.DID {
		return fmt.Errorf("identity signing key does not match assertion identity")
	}
	// Copy all signed identity/custody/rotation fields; renew only the window.
	renewed := *assertion
	now := time.Now().UTC().Truncate(time.Second)
	renewed.CreatedAt = now.Format(time.RFC3339)
	renewed.NotBefore = renewed.CreatedAt
	renewed.ExpiresAt = now.Add(90 * 24 * time.Hour).Format(time.RFC3339)
	if err := awid.SignEncryptionKeyAssertion(&renewed, key); err != nil {
		return err
	}
	published, _, err := publishIdentityEncryptionKey(ctx, identity, key, &renewed)
	if err != nil {
		return err
	}
	if len(published) == 0 {
		return fmt.Errorf("no public discovery target available")
	}
	path, err := resolveIdentityStoredPath(identity.WorkingDir, identity.IdentityHome, record.AssertionPath)
	if err != nil {
		return err
	}
	if err := saveEncryptionAssertion(path, &renewed); err != nil {
		return err
	}
	record.CreatedAt, record.NotBefore, record.ExpiresAt = renewed.CreatedAt, renewed.NotBefore, renewed.ExpiresAt
	record.PublishedAt = now.Format(time.RFC3339)
	state.UpsertRecord(*record)
	return awconfig.SaveEncryptionKeyStateTo(statePath, state)
}

func maybeRenewIdentityEncryptionAssertion(ctx context.Context, workingDir string, home encryptionKeyIdentityHomeIntent, warnings io.Writer) {
	// An uninitialized directory or a grant seat has no resident key to renew.
	identity, err := resolveIdentityForEncryptionKeyForDir(workingDir, home)
	if err != nil || identity == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := renewIdentityEncryptionAssertion(ctx, workingDir, home); err != nil {
		fmt.Fprintf(warnings, "Warning: E2E encryption-key assertion renewal failed: %v; will retry on a later check.\n", err)
	}
}
