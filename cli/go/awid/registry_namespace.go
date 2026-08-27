package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type namespaceRegisterRequest struct {
	Domain                string                        `json:"domain"`
	ControllerDID         string                        `json:"controller_did"`
	DefaultDeliveryOrigin string                        `json:"default_delivery_origin,omitempty"`
	DelegationAssertion   *NamespaceDelegationAssertion `json:"delegation_assertion,omitempty"`
}

type namespaceRotateRequest struct {
	NewControllerDID    string                        `json:"new_controller_did"`
	DelegationAssertion *NamespaceDelegationAssertion `json:"delegation_assertion,omitempty"`
	RolloverID          string                        `json:"rollover_id,omitempty"`
}

type namespaceDelegationBackfillRequest struct {
	DelegationAssertion NamespaceDelegationAssertion `json:"delegation_assertion"`
}

type controllerRolloverStartRequest struct {
	NewControllerDID  string                         `json:"new_controller_did"`
	RecoveryMode      ControllerRolloverRecoveryMode `json:"recovery_mode"`
	RecoveryAssertion *NamespaceDelegationAssertion  `json:"recovery_assertion,omitempty"`
}

type controllerRolloverSignaturesRequest struct {
	Signatures []NamespaceControllerRolloverSignature `json:"signatures"`
}

type namespaceDeleteDelegationRequest struct {
	Reason              string                        `json:"reason,omitempty"`
	DelegationAssertion *NamespaceDelegationAssertion `json:"delegation_assertion,omitempty"`
}

type namespaceReverifyRequest struct {
	RolloverID string `json:"rollover_id,omitempty"`
}

type namespaceUpdateRequest struct {
	DefaultDeliveryOrigin string `json:"default_delivery_origin"`
}

type addressRegisterRequest struct {
	Name          string `json:"name"`
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
}

type AtomicAddressClaimParams struct {
	Domain                        string
	AddressName                   string
	DIDAW                         string
	CurrentDIDKey                 string
	IdentitySigningKey            ed25519.PrivateKey
	NamespaceControllerSigningKey ed25519.PrivateKey
	DryRun                        bool
	IdentityCustody               string
	NamespaceCustody              string
}

type atomicAddressClaimRequest struct {
	Operation          string                 `json:"operation"`
	AddressName        string                 `json:"address_name"`
	DIDAW              string                 `json:"did_aw"`
	CurrentDIDKey      string                 `json:"current_did_key"`
	RegistryURL        string                 `json:"registry_url"`
	Timestamp          string                 `json:"timestamp"`
	DryRun             bool                   `json:"dry_run"`
	IdentityCustody    string                 `json:"identity_custody"`
	NamespaceCustody   string                 `json:"namespace_custody"`
	IdentitySignature  string                 `json:"identity_signature"`
	NamespaceSignature string                 `json:"namespace_signature"`
	DIDLogProof        atomicClaimDIDLogProof `json:"did_log_proof"`
}

type atomicClaimDIDLogProof struct {
	DIDAW          string  `json:"did_aw"`
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Timestamp      string  `json:"timestamp"`
	Signature      string  `json:"signature"`
}

type AtomicAddressClaimResult struct {
	Status           string           `json:"status"`
	DryRun           bool             `json:"dry_run"`
	Domain           string           `json:"domain"`
	Name             string           `json:"name"`
	DIDAW            string           `json:"did_aw"`
	CurrentDIDKey    string           `json:"current_did_key"`
	IdentityCustody  string           `json:"identity_custody"`
	NamespaceCustody string           `json:"namespace_custody"`
	DIDStatus        string           `json:"did_status"`
	AddressStatus    string           `json:"address_status"`
	Address          *RegistryAddress `json:"address,omitempty"`
}

type deleteReasonRequest struct {
	Reason string `json:"reason,omitempty"`
}

type conditionalAddressDeleteRequest struct {
	Reason                string `json:"reason,omitempty"`
	ExpectedAddressID     string `json:"expected_address_id"`
	ExpectedDIDAW         string `json:"expected_did_aw"`
	ExpectedCurrentDIDKey string `json:"expected_current_did_key"`
}

type NamespaceReverifyResult struct {
	NamespaceID        string `json:"namespace_id"`
	Domain             string `json:"domain"`
	ControllerDID      string `json:"controller_did,omitempty"`
	VerificationStatus string `json:"verification_status"`
	LastVerifiedAt     string `json:"last_verified_at,omitempty"`
	CreatedAt          string `json:"created_at"`
	OldControllerDID   string `json:"old_controller_did,omitempty"`
	NewControllerDID   string `json:"new_controller_did,omitempty"`
}

func (c *RegistryClient) GetNamespaceAddress(ctx context.Context, domain, name string) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAddressAt(ctx, registryURL, domain, name)
}

func (c *RegistryClient) GetNamespaceAddressSigned(
	ctx context.Context,
	domain, name string,
	signingKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	return c.GetNamespaceAddressAtSigned(ctx, registryURL, domain, name, signingKey)
}

func (c *RegistryClient) GetNamespaceAddressAt(ctx context.Context, registryURL, domain, name string) (*RegistryAddress, string, error) {
	var out RegistryAddress
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/addresses/" + urlPathEscape(strings.TrimSpace(name))
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, "", err
	}
	return &out, registryURL, nil
}

func (c *RegistryClient) GetNamespaceAddressAtSigned(
	ctx context.Context,
	registryURL, domain, name string,
	signingKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	return c.GetNamespaceAddressAt(ctx, registryURL, domain, name)
}

func (c *RegistryClient) RegisterNamespace(
	ctx context.Context,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.RegisterNamespaceAt(ctx, registryURL, domain, controllerDID, signingKey)
	return namespace, registryURL, err
}

func (c *RegistryClient) RegisterNamespaceWithDeliveryOrigin(
	ctx context.Context,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
	defaultDeliveryOrigin string,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.RegisterNamespaceWithDeliveryOriginAt(ctx, registryURL, domain, controllerDID, signingKey, defaultDeliveryOrigin)
	return namespace, registryURL, err
}

func (c *RegistryClient) RegisterNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
) (*RegistryNamespace, error) {
	return c.RegisterNamespaceWithDeliveryOriginAt(ctx, registryURL, domain, controllerDID, signingKey, "")
}

func (c *RegistryClient) RegisterNamespaceWithDeliveryOriginAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	signingKey ed25519.PrivateKey,
	defaultDeliveryOrigin string,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	controllerDID = strings.TrimSpace(controllerDID)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if !strings.HasPrefix(controllerDID, "did:key:") {
		return nil, fmt.Errorf("controllerDID must start with did:key:")
	}
	if err := requireSigningKeyMatchesDID(signingKey, controllerDID); err != nil {
		return nil, err
	}
	defaultDeliveryOrigin = strings.TrimSpace(defaultDeliveryOrigin)
	extraPayload := map[string]string(nil)
	if defaultDeliveryOrigin != "" {
		canonicalOrigin, err := CanonicalServerOrigin(defaultDeliveryOrigin)
		if err != nil {
			return nil, fmt.Errorf("default delivery origin: %w", err)
		}
		defaultDeliveryOrigin = canonicalOrigin
		extraPayload = map[string]string{"default_delivery_origin": defaultDeliveryOrigin}
	}

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		"/v1/namespaces",
		signedNamespaceHeaders(domain, "register", signingKey, extraPayload),
		namespaceRegisterRequest{
			Domain:                domain,
			ControllerDID:         controllerDID,
			DefaultDeliveryOrigin: defaultDeliveryOrigin,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) RegisterDelegatedNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerDID string,
	controllerSigningKey ed25519.PrivateKey,
	parentSigningKey ed25519.PrivateKey,
	assertion NamespaceDelegationAssertion,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	controllerDID = strings.TrimSpace(controllerDID)
	if err := requireSigningKeyMatchesDID(controllerSigningKey, controllerDID); err != nil {
		return nil, err
	}
	if parentSigningKey == nil {
		return nil, fmt.Errorf("parent signing key is required")
	}
	if assertion.Payload.ChildDomain != domain || assertion.Payload.ChildControllerDID != controllerDID {
		return nil, fmt.Errorf("delegation assertion does not match namespace registration")
	}
	canonical, err := CanonicalNamespaceDelegationPayload(assertion.Payload)
	if err != nil {
		return nil, err
	}
	if NamespaceDelegationEntryHash(canonical) != assertion.EntryHash {
		return nil, fmt.Errorf("delegation assertion entry hash mismatch")
	}
	childHeaders := signedNamespaceHeaders(domain, "register", controllerSigningKey, map[string]string{
		"controller_did":        controllerDID,
		"delegation_entry_hash": assertion.EntryHash,
	})
	parent := signedNamespaceHeaders(domain, "authorize_subdomain_registration", parentSigningKey, map[string]string{
		"child_domain":          domain,
		"controller_did":        controllerDID,
		"delegation_entry_hash": assertion.EntryHash,
	})
	childHeaders["X-AWEB-Parent-Authorization"] = parent["Authorization"]
	childHeaders["X-AWEB-Parent-Timestamp"] = parent["X-AWEB-Timestamp"]

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx, http.MethodPost, registryURL, "/v1/namespaces", childHeaders,
		namespaceRegisterRequest{
			Domain: domain, ControllerDID: controllerDID, DelegationAssertion: &assertion,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) GetNamespaceDelegationLogAt(
	ctx context.Context,
	registryURL string,
	domain string,
	afterSequence int64,
	limit int,
	cursor string,
) (*NamespaceDelegationLogPage, error) {
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/delegation-log"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	} else {
		path += fmt.Sprintf("?after_sequence=%d&limit=%d", afterSequence, limit)
	}
	var out NamespaceDelegationLogPage
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) CollectNamespaceDelegationLogAt(
	ctx context.Context,
	registryURL, domain string,
	afterSequence int64,
	limit, maxRestarts int,
) (*NamespaceDelegationLogPage, error) {
restart:
	for attempt := 0; attempt <= maxRestarts; attempt++ {
		var entries []NamespaceDelegationAssertion
		cursor := ""
		seenCursors := map[string]bool{}
		expectedSequence := afterSequence + 1
		previousHash := ""
		var snapshotHeadSequence int64
		var snapshotHeadHash string
		for {
			page, err := c.GetNamespaceDelegationLogAt(ctx, registryURL, domain, afterSequence, limit, cursor)
			if err != nil {
				var registryErr *RegistryError
				if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusConflict && registryErr.Code == "delegation_log_snapshot_changed" && attempt < maxRestarts {
					break
				}
				return nil, err
			}
			if page.HasMore != (page.NextCursor != "") || (page.HasMore && len(page.Entries) == 0) {
				if attempt < maxRestarts {
					continue restart
				}
				return nil, fmt.Errorf("delegation has_more/cursor boundary is inconsistent")
			}
			if snapshotHeadHash == "" {
				snapshotHeadSequence, snapshotHeadHash = page.HeadSequence, page.HeadHash
			} else if page.HeadSequence != snapshotHeadSequence || page.HeadHash != snapshotHeadHash {
				if attempt < maxRestarts {
					continue restart
				}
				return nil, fmt.Errorf("delegation page head changed during collection")
			}
			for _, entry := range page.Entries {
				if err := ValidateNamespaceDelegationAssertion(entry); err != nil {
					return nil, err
				}
				if entry.Payload.Sequence != expectedSequence {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("delegation log is not contiguous")
				}
				if previousHash != "" && (entry.Payload.PreviousDelegationHash == nil || *entry.Payload.PreviousDelegationHash != previousHash) {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("delegation log hash chain is disconnected")
				}
				entries = append(entries, entry)
				previousHash = entry.EntryHash
				expectedSequence++
			}
			if page.NextSequence != expectedSequence-1 {
				if attempt < maxRestarts {
					continue restart
				}
				return nil, fmt.Errorf("delegation next_sequence does not match page boundary")
			}
			if !page.HasMore {
				if len(entries) > 0 {
					last := entries[len(entries)-1]
					if last.EntryHash != page.HeadHash || last.Payload.Sequence != page.HeadSequence {
						if attempt < maxRestarts {
							continue restart
						}
						return nil, fmt.Errorf("delegation final entry does not equal snapshot head")
					}
				} else if afterSequence != page.HeadSequence {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("delegation log returned an invalid empty page")
				}
				namespace, _, err := c.GetNamespaceAt(ctx, registryURL, domain)
				deleted := false
				if err != nil {
					var registryErr *RegistryError
					if !errors.As(err, &registryErr) || registryErr.StatusCode != http.StatusNotFound {
						return nil, err
					}
					deleted = true
				} else if len(namespace.DelegationChain) == 0 {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("active history-backed namespace omitted delegation chain")
				} else if namespace.DelegationChain[len(namespace.DelegationChain)-1].EntryHash != page.HeadHash {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("delegation namespace chain head changed during collection")
				} else if len(entries) > 0 && entries[len(entries)-1].Payload.Operation == "revoke" {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("active namespace cannot end in revoke")
				}
				if deleted && len(entries) > 0 && entries[len(entries)-1].Payload.Operation != "revoke" {
					if attempt < maxRestarts {
						continue restart
					}
					return nil, fmt.Errorf("deleted delegation log does not end in revoke")
				}
				page.Entries = entries
				page.NextCursor = ""
				return page, nil
			}
			if page.NextCursor == "" {
				return nil, fmt.Errorf("delegation log truncated without continuation cursor")
			}
			if page.NextCursor == cursor || seenCursors[page.NextCursor] {
				if attempt < maxRestarts {
					continue restart
				}
				return nil, fmt.Errorf("delegation continuation cursor repeated")
			}
			seenCursors[page.NextCursor] = true
			cursor = page.NextCursor
		}
	}
	return nil, fmt.Errorf("delegation log snapshot changed too many times")
}

func (c *RegistryClient) RotateNamespaceControllerAt(
	ctx context.Context,
	registryURL, domain, newControllerDID string,
	newControllerKey ed25519.PrivateKey,
	rolloverID string,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	if err := requireSigningKeyMatchesDID(newControllerKey, newControllerDID); err != nil {
		return nil, err
	}
	extra := map[string]string{"new_controller_did": newControllerDID}
	if rolloverID != "" {
		extra["rollover_id"] = rolloverID
	}
	var out RegistryNamespace
	if err := c.requestJSON(
		ctx, http.MethodPut, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain),
		signedNamespaceHeaders(domain, "rotate_controller", newControllerKey, extra),
		namespaceRotateRequest{NewControllerDID: newControllerDID, RolloverID: rolloverID},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) RotateDelegatedNamespaceAt(
	ctx context.Context,
	registryURL, domain, newControllerDID string,
	newControllerKey, parentKey ed25519.PrivateKey,
	assertion NamespaceDelegationAssertion,
	rolloverID string,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	if err := requireSigningKeyMatchesDID(newControllerKey, newControllerDID); err != nil {
		return nil, err
	}
	extra := map[string]string{
		"new_controller_did":    newControllerDID,
		"delegation_entry_hash": assertion.EntryHash,
	}
	if rolloverID != "" {
		extra["rollover_id"] = rolloverID
	}
	headers := signedNamespaceHeaders(domain, "rotate_controller", newControllerKey, extra)
	parentExtra := map[string]string{
		"child_domain":          domain,
		"new_controller_did":    newControllerDID,
		"delegation_entry_hash": assertion.EntryHash,
	}
	if rolloverID != "" {
		parentExtra["rollover_id"] = rolloverID
	}
	mergeParentHeaders(headers, signedNamespaceHeaders(domain, "authorize_subdomain_rotation", parentKey, parentExtra))
	var out RegistryNamespace
	if err := c.requestJSON(ctx, http.MethodPut, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain), headers,
		namespaceRotateRequest{NewControllerDID: newControllerDID, DelegationAssertion: &assertion, RolloverID: rolloverID}, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) BackfillNamespaceDelegationAt(
	ctx context.Context,
	registryURL, domain string,
	controllerKey, parentKey ed25519.PrivateKey,
	assertion NamespaceDelegationAssertion,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	controllerDID := ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	headers := signedNamespaceHeaders(domain, "backfill_namespace_delegation", controllerKey, map[string]string{
		"delegation_entry_hash": assertion.EntryHash,
	})
	mergeParentHeaders(headers, signedNamespaceHeaders(domain, "authorize_subdomain_backfill", parentKey, map[string]string{
		"child_domain":          domain,
		"controller_did":        controllerDID,
		"delegation_entry_hash": assertion.EntryHash,
	}))
	var out RegistryNamespace
	if err := c.requestJSON(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/delegation/backfill", headers,
		namespaceDelegationBackfillRequest{DelegationAssertion: assertion}, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) DeleteDelegatedNamespaceAt(
	ctx context.Context,
	registryURL, domain string,
	controllerKey ed25519.PrivateKey,
	assertion NamespaceDelegationAssertion,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	return c.requestJSON(ctx, http.MethodDelete, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain),
		signedNamespaceHeaders(domain, "delete_namespace", controllerKey, map[string]string{
			"delegation_entry_hash": assertion.EntryHash,
		}),
		namespaceDeleteDelegationRequest{Reason: reason, DelegationAssertion: &assertion}, nil,
	)
}

func (c *RegistryClient) StartControllerRolloverAt(
	ctx context.Context,
	registryURL, domain, newControllerDID string,
	currentControllerKey, newControllerKey ed25519.PrivateKey,
) (*NamespaceControllerRollover, error) {
	domain = canonicalizeDomain(domain)
	if err := requireSigningKeyMatchesDID(newControllerKey, newControllerDID); err != nil {
		return nil, err
	}
	extra := map[string]string{"new_controller_did": newControllerDID, "recovery_mode": "none"}
	headers := signedNamespaceHeaders(domain, "start_controller_rollover", currentControllerKey, extra)
	newProof := signedNamespaceHeaders(domain, "prove_controller_rollover_key", newControllerKey, extra)
	headers["X-AWEB-New-Controller-Authorization"] = newProof["Authorization"]
	headers["X-AWEB-New-Controller-Timestamp"] = newProof["X-AWEB-Timestamp"]
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/controller-rollovers", headers,
		controllerRolloverStartRequest{NewControllerDID: newControllerDID, RecoveryMode: ControllerRolloverRecoveryNone}, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) StartExactDNSControllerRecoveryAt(
	ctx context.Context,
	registryURL, domain, newControllerDID string,
	newControllerKey ed25519.PrivateKey,
) (*NamespaceControllerRollover, error) {
	domain = canonicalizeDomain(domain)
	if err := requireSigningKeyMatchesDID(newControllerKey, newControllerDID); err != nil {
		return nil, err
	}
	extra := map[string]string{
		"new_controller_did": newControllerDID,
		"recovery_mode":      string(ControllerRolloverRecoveryExactDNS),
	}
	headers := signedNamespaceHeaders(domain, "recover_controller_rollover", newControllerKey, extra)
	proof := signedNamespaceHeaders(domain, "prove_controller_rollover_key", newControllerKey, extra)
	headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
	headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/controller-rollovers", headers,
		controllerRolloverStartRequest{
			NewControllerDID: newControllerDID,
			RecoveryMode:     ControllerRolloverRecoveryExactDNS,
		}, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) StartDelegatedControllerRecoveryAt(
	ctx context.Context,
	registryURL, domain, newControllerDID string,
	newControllerKey ed25519.PrivateKey,
	recoveryAssertion NamespaceDelegationAssertion,
) (*NamespaceControllerRollover, error) {
	domain = canonicalizeDomain(domain)
	if err := requireSigningKeyMatchesDID(newControllerKey, newControllerDID); err != nil {
		return nil, err
	}
	extra := map[string]string{
		"new_controller_did":  newControllerDID,
		"recovery_mode":       "delegated",
		"recovery_entry_hash": recoveryAssertion.EntryHash,
	}
	headers := signedNamespaceHeaders(domain, "recover_controller_rollover", newControllerKey, extra)
	proof := signedNamespaceHeaders(domain, "prove_controller_rollover_key", newControllerKey, extra)
	headers["X-AWEB-New-Controller-Authorization"] = proof["Authorization"]
	headers["X-AWEB-New-Controller-Timestamp"] = proof["X-AWEB-Timestamp"]
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/controller-rollovers", headers,
		controllerRolloverStartRequest{
			NewControllerDID: newControllerDID, RecoveryMode: ControllerRolloverRecoveryDelegated,
			RecoveryAssertion: &recoveryAssertion,
		}, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) GetControllerRolloverAt(
	ctx context.Context, registryURL, domain, rolloverID string,
) (*NamespaceControllerRollover, error) {
	var out NamespaceControllerRollover
	if err := c.requestJSON(
		ctx, http.MethodGet, registryURL,
		"/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain))+"/controller-rollovers/"+urlPathEscape(rolloverID),
		nil, nil, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) GetControllerRolloverChildrenAt(
	ctx context.Context, registryURL, domain, rolloverID, cursor string, limit int,
) (*NamespaceControllerRolloverChildren, error) {
	path := "/v1/namespaces/" + urlPathEscape(canonicalizeDomain(domain)) + "/controller-rollovers/" + urlPathEscape(rolloverID) + "/children"
	if cursor != "" {
		path += "?cursor=" + url.QueryEscape(cursor)
	} else {
		path += fmt.Sprintf("?limit=%d", limit)
	}
	var out NamespaceControllerRolloverChildren
	if err := c.requestJSON(ctx, http.MethodGet, registryURL, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) AttachControllerRolloverSignaturesAt(
	ctx context.Context, registryURL, domain, rolloverID string,
	newControllerKey ed25519.PrivateKey,
	signatures []NamespaceControllerRolloverSignature,
) (*NamespaceControllerRollover, error) {
	body := controllerRolloverSignaturesRequest{Signatures: signatures}
	canonical, err := CanonicalJSONValue(body)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(canonical))
	batchHash := "sha256:" + hex.EncodeToString(digest[:])
	headers := signedNamespaceHeaders(canonicalizeDomain(domain), "attach_controller_rollover_signatures", newControllerKey, map[string]string{
		"rollover_id": rolloverID, "batch_hash": batchHash,
	})
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodPut, registryURL,
		"/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain))+"/controller-rollovers/"+urlPathEscape(rolloverID)+"/signatures",
		headers, body, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) CompleteControllerRolloverAt(
	ctx context.Context, registryURL, domain, rolloverID string, newControllerKey ed25519.PrivateKey,
) (*NamespaceControllerRollover, error) {
	headers := signedNamespaceHeaders(canonicalizeDomain(domain), "complete_controller_rollover", newControllerKey, map[string]string{"rollover_id": rolloverID})
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodPost, registryURL,
		"/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain))+"/controller-rollovers/"+urlPathEscape(rolloverID)+"/complete",
		headers, nil, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) CancelControllerRolloverAt(
	ctx context.Context, registryURL, domain, rolloverID string, oldControllerKey ed25519.PrivateKey,
) (*NamespaceControllerRollover, error) {
	headers := signedNamespaceHeaders(canonicalizeDomain(domain), "cancel_controller_rollover", oldControllerKey, map[string]string{"rollover_id": rolloverID})
	var out NamespaceControllerRollover
	if err := c.requestJSON(ctx, http.MethodDelete, registryURL,
		"/v1/namespaces/"+urlPathEscape(canonicalizeDomain(domain))+"/controller-rollovers/"+urlPathEscape(rolloverID),
		headers, nil, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func mergeParentHeaders(target, source map[string]string) {
	target["X-AWEB-Parent-Authorization"] = source["Authorization"]
	target["X-AWEB-Parent-Timestamp"] = source["X-AWEB-Timestamp"]
}

func (c *RegistryClient) UpdateNamespaceDeliveryOrigin(
	ctx context.Context,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	deliveryOrigin string,
) (*RegistryNamespace, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	namespace, err := c.UpdateNamespaceDeliveryOriginAt(ctx, registryURL, domain, controllerSigningKey, deliveryOrigin)
	return namespace, registryURL, err
}

func (c *RegistryClient) UpdateNamespaceDeliveryOriginAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	deliveryOrigin string,
) (*RegistryNamespace, error) {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if controllerSigningKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}
	canonicalOrigin, err := CanonicalServerOrigin(deliveryOrigin)
	if err != nil {
		return nil, fmt.Errorf("delivery origin: %w", err)
	}

	var out RegistryNamespace
	if err := c.requestJSON(
		ctx,
		http.MethodPatch,
		registryURL,
		"/v1/namespaces/"+urlPathEscape(domain),
		signedNamespaceHeaders(
			domain,
			"update_namespace",
			controllerSigningKey,
			map[string]string{"default_delivery_origin": canonicalOrigin},
		),
		namespaceUpdateRequest{DefaultDeliveryOrigin: canonicalOrigin},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) DeleteNamespace(
	ctx context.Context,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) (string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return "", err
	}
	return registryURL, c.DeleteNamespaceAt(ctx, registryURL, domain, controllerSigningKey, reason)
}

func (c *RegistryClient) DeleteNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if controllerSigningKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain)
	var body any
	if strings.TrimSpace(reason) != "" {
		body = deleteReasonRequest{Reason: strings.TrimSpace(reason)}
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		path,
		signedNamespaceHeaders(domain, "delete_namespace", controllerSigningKey, nil),
		body,
		nil,
	)
}

func (c *RegistryClient) ReverifyNamespaceAt(
	ctx context.Context,
	registryURL string,
	domain string,
) (*NamespaceReverifyResult, error) {
	return c.ReverifyNamespaceWithRolloverAt(ctx, registryURL, domain, "")
}

func (c *RegistryClient) ReverifyNamespaceWithRolloverAt(
	ctx context.Context,
	registryURL string,
	domain string,
	rolloverID string,
) (*NamespaceReverifyResult, error) {
	domain = canonicalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var out NamespaceReverifyResult
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/reverify",
		nil,
		func() any {
			if rolloverID == "" {
				return nil
			}
			return namespaceReverifyRequest{RolloverID: rolloverID}
		}(),
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) RegisterAddress(
	ctx context.Context,
	domain string,
	name string,
	didAW string,
	currentDIDKey string,
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", err
	}
	address, err := c.RegisterAddressAt(ctx, registryURL, domain, name, didAW, currentDIDKey, controllerSigningKey)
	return address, registryURL, err
}

func (c *RegistryClient) RegisterAddressAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	didAW string,
	currentDIDKey string,
	controllerSigningKey ed25519.PrivateKey,
) (*RegistryAddress, error) {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	didAW = strings.TrimSpace(didAW)
	currentDIDKey = strings.TrimSpace(currentDIDKey)
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if !strings.HasPrefix(didAW, "did:aw:") {
		return nil, fmt.Errorf("didAW must start with did:aw:")
	}
	if !strings.HasPrefix(currentDIDKey, "did:key:") {
		return nil, fmt.Errorf("currentDIDKey must start with did:key:")
	}
	if controllerSigningKey == nil {
		return nil, fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/addresses"
	var out RegistryAddress
	if err := c.requestJSON(
		ctx,
		http.MethodPost,
		registryURL,
		path,
		signedAddressHeaders(domain, name, "register_address", controllerSigningKey),
		addressRegisterRequest{
			Name:          name,
			DIDAW:         didAW,
			CurrentDIDKey: currentDIDKey,
		},
		&out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *RegistryClient) ClaimIdentityAddressAt(
	ctx context.Context,
	registryURL string,
	params AtomicAddressClaimParams,
) (*AtomicAddressClaimResult, error) {
	registryURL, err := canonicalRegistryServerOrigin(registryURL)
	if err != nil {
		return nil, fmt.Errorf("registry_url: %w", err)
	}
	params.Domain = canonicalizeDomain(params.Domain)
	params.AddressName = strings.ToLower(strings.TrimSpace(params.AddressName))
	params.DIDAW = strings.TrimSpace(params.DIDAW)
	params.CurrentDIDKey = strings.TrimSpace(params.CurrentDIDKey)
	if params.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if params.AddressName == "" {
		return nil, fmt.Errorf("address name is required")
	}
	if !strings.HasPrefix(params.DIDAW, "did:aw:") {
		return nil, fmt.Errorf("did_aw must start with did:aw:")
	}
	if !strings.HasPrefix(params.CurrentDIDKey, "did:key:") {
		return nil, fmt.Errorf("current_did_key must start with did:key:")
	}
	if params.IdentitySigningKey == nil {
		return nil, fmt.Errorf("identity signing key is required")
	}
	if params.NamespaceControllerSigningKey == nil {
		return nil, fmt.Errorf("namespace controller signing key is required")
	}
	if did := ComputeDIDKey(params.IdentitySigningKey.Public().(ed25519.PublicKey)); did != params.CurrentDIDKey {
		return nil, fmt.Errorf("identity signing key does not match current_did_key")
	}
	identityCustody := strings.TrimSpace(params.IdentityCustody)
	if identityCustody == "" {
		identityCustody = string(AddressClaimCustodySelf)
	}
	namespaceCustody := strings.TrimSpace(params.NamespaceCustody)
	if namespaceCustody == "" {
		namespaceCustody = string(AddressClaimCustodySelf)
	}

	timestamp := c.now().Format(time.RFC3339)
	logProof, err := c.atomicAddressClaimDIDLogProof(ctx, registryURL, params.DIDAW, params.CurrentDIDKey, params.IdentitySigningKey, timestamp)
	if err != nil {
		return nil, err
	}
	fields := AtomicAddressClaimFields{
		Operation:        AtomicAddressClaimOperation,
		Domain:           params.Domain,
		AddressName:      params.AddressName,
		DIDAW:            params.DIDAW,
		CurrentDIDKey:    params.CurrentDIDKey,
		RegistryURL:      registryURL,
		Timestamp:        timestamp,
		DryRun:           params.DryRun,
		IdentityCustody:  identityCustody,
		NamespaceCustody: namespaceCustody,
	}
	identityCanonical, err := AtomicAddressClaimIdentityCanonical(fields)
	if err != nil {
		return nil, err
	}
	identitySignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(params.IdentitySigningKey, []byte(identityCanonical)),
	)
	identityProofHash, err := AtomicAddressClaimIdentityProofHash(identityCanonical, identitySignature)
	if err != nil {
		return nil, err
	}
	namespaceCanonical, err := AtomicAddressClaimNamespaceCanonical(fields, identityProofHash)
	if err != nil {
		return nil, err
	}
	namespaceSignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(params.NamespaceControllerSigningKey, []byte(namespaceCanonical)),
	)

	body := atomicAddressClaimRequest{
		Operation:          AtomicAddressClaimOperation,
		AddressName:        params.AddressName,
		DIDAW:              params.DIDAW,
		CurrentDIDKey:      params.CurrentDIDKey,
		RegistryURL:        registryURL,
		Timestamp:          timestamp,
		DryRun:             params.DryRun,
		IdentityCustody:    identityCustody,
		NamespaceCustody:   namespaceCustody,
		IdentitySignature:  identitySignature,
		NamespaceSignature: namespaceSignature,
		DIDLogProof: atomicClaimDIDLogProof{
			DIDAW:          params.DIDAW,
			Seq:            logProof.Seq,
			Operation:      strings.TrimSpace(logProof.Operation),
			PreviousDIDKey: logProof.PreviousDIDKey,
			NewDIDKey:      strings.TrimSpace(logProof.NewDIDKey),
			PrevEntryHash:  logProof.PrevEntryHash,
			StateHash:      strings.TrimSpace(logProof.StateHash),
			AuthorizedBy:   strings.TrimSpace(logProof.AuthorizedBy),
			Timestamp:      strings.TrimSpace(logProof.Timestamp),
			Signature:      strings.TrimSpace(logProof.Signature),
		},
	}

	path := "/v1/namespaces/" + urlPathEscape(params.Domain) + "/addresses/claims"
	var out AtomicAddressClaimResult
	if err := c.requestJSON(ctx, http.MethodPost, registryURL, path, nil, body, &out); err != nil {
		return nil, atomicAddressClaimConflictFromError(err)
	}
	return &out, nil
}

func (c *RegistryClient) atomicAddressClaimDIDLogProof(ctx context.Context, registryURL, didAW, currentDIDKey string, signingKey ed25519.PrivateKey, timestamp string) (*DidKeyEvidence, error) {
	if stableID := ComputeStableID(signingKey.Public().(ed25519.PublicKey)); stableID == strings.TrimSpace(didAW) {
		stateHash := stableIdentityStateHash(didAW, currentDIDKey)
		didLogPayload := CanonicalDidLogPayload(didAW, &DidKeyEvidence{
			Seq:            1,
			Operation:      "register_did",
			PreviousDIDKey: nil,
			NewDIDKey:      currentDIDKey,
			PrevEntryHash:  nil,
			StateHash:      stateHash,
			AuthorizedBy:   currentDIDKey,
			Timestamp:      timestamp,
		})
		return &DidKeyEvidence{
			Seq:            1,
			Operation:      "register_did",
			PreviousDIDKey: nil,
			NewDIDKey:      currentDIDKey,
			PrevEntryHash:  nil,
			StateHash:      stateHash,
			AuthorizedBy:   currentDIDKey,
			Timestamp:      timestamp,
			Signature: base64.RawStdEncoding.EncodeToString(
				ed25519.Sign(signingKey, []byte(didLogPayload)),
			),
		}, nil
	}
	resolution, err := c.ResolveKeyAt(ctx, registryURL, didAW)
	if err != nil {
		return nil, fmt.Errorf("resolve did log head for rotated identity %s: %w", didAW, err)
	}
	if strings.TrimSpace(resolution.CurrentDIDKey) != strings.TrimSpace(currentDIDKey) {
		return nil, fmt.Errorf("registry current did:key for %s is %s, not %s", didAW, resolution.CurrentDIDKey, currentDIDKey)
	}
	if resolution.LogHead == nil {
		return nil, fmt.Errorf("registry did log for rotated identity %s has no log head", didAW)
	}
	return resolution.LogHead, nil
}

func (c *RegistryClient) DeleteAddress(
	ctx context.Context,
	domain string,
	name string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) (string, error) {
	registryURL, err := c.DiscoverRegistry(ctx, domain)
	if err != nil {
		return "", err
	}
	return registryURL, c.DeleteAddressAt(ctx, registryURL, domain, name, controllerSigningKey, reason)
}

func (c *RegistryClient) DeleteAddressAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if controllerSigningKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	path := "/v1/namespaces/" + urlPathEscape(domain) + "/addresses/" + urlPathEscape(name)
	var body any
	if strings.TrimSpace(reason) != "" {
		body = deleteReasonRequest{Reason: strings.TrimSpace(reason)}
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		path,
		signedAddressHeaders(domain, name, "delete_address", controllerSigningKey),
		body,
		nil,
	)
}

func (c *RegistryClient) DeleteAddressIfMatchesAt(
	ctx context.Context,
	registryURL string,
	domain string,
	name string,
	expectedAddressID string,
	expectedDIDAW string,
	expectedCurrentDIDKey string,
	controllerSigningKey ed25519.PrivateKey,
	reason string,
) error {
	domain = canonicalizeDomain(domain)
	name = strings.TrimSpace(name)
	expectedAddressID = strings.TrimSpace(expectedAddressID)
	expectedDIDAW = strings.TrimSpace(expectedDIDAW)
	expectedCurrentDIDKey = strings.TrimSpace(expectedCurrentDIDKey)
	if domain == "" || name == "" {
		return fmt.Errorf("domain and name are required")
	}
	if expectedAddressID == "" || expectedDIDAW == "" || expectedCurrentDIDKey == "" {
		return fmt.Errorf("expected address id, did:aw, and current did:key are required")
	}
	if controllerSigningKey == nil {
		return fmt.Errorf("controller signing key is required")
	}

	preconditions := map[string]string{
		"expected_address_id":      expectedAddressID,
		"expected_did_aw":          expectedDIDAW,
		"expected_current_did_key": expectedCurrentDIDKey,
	}
	return c.requestJSON(
		ctx,
		http.MethodDelete,
		registryURL,
		"/v1/namespaces/"+urlPathEscape(domain)+"/addresses/"+urlPathEscape(name),
		signedAddressHeadersWithFields(domain, name, "delete_address", controllerSigningKey, preconditions),
		conditionalAddressDeleteRequest{
			Reason:                strings.TrimSpace(reason),
			ExpectedAddressID:     expectedAddressID,
			ExpectedDIDAW:         expectedDIDAW,
			ExpectedCurrentDIDKey: expectedCurrentDIDKey,
		},
		nil,
	)
}

func requireSigningKeyMatchesDID(signingKey ed25519.PrivateKey, expectedDID string) error {
	if signingKey == nil {
		return fmt.Errorf("signing key is required")
	}
	actual := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if actual != strings.TrimSpace(expectedDID) {
		return fmt.Errorf("signing key does not match %s", strings.TrimSpace(expectedDID))
	}
	return nil
}

func signedNamespaceHeaders(
	domain string,
	operation string,
	signingKey ed25519.PrivateKey,
	extraPayload map[string]string,
) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	fields := map[string]string{
		"domain":    canonicalizeDomain(domain),
		"operation": strings.TrimSpace(operation),
		"timestamp": timestamp,
	}
	for key, value := range extraPayload {
		fields[key] = strings.TrimSpace(value)
	}
	return signedCanonicalHeaders(fields, signingKey, timestamp)
}

func signedAddressHeaders(
	domain string,
	name string,
	operation string,
	signingKey ed25519.PrivateKey,
) map[string]string {
	return signedAddressHeadersWithFields(domain, name, operation, signingKey, nil)
}

func signedAddressHeadersWithFields(
	domain string,
	name string,
	operation string,
	signingKey ed25519.PrivateKey,
	extra map[string]string,
) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	fields := map[string]string{
		"domain":    canonicalizeDomain(domain),
		"name":      strings.TrimSpace(name),
		"operation": strings.TrimSpace(operation),
		"timestamp": timestamp,
	}
	for key, value := range extra {
		fields[key] = strings.TrimSpace(value)
	}
	return signedCanonicalHeaders(fields, signingKey, timestamp)
}

func signedCanonicalHeaders(fields map[string]string, signingKey ed25519.PrivateKey, timestamp string) map[string]string {
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	payload := canonicalRegistryJSON(fields)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(payload)))
	return map[string]string{
		"Authorization":    fmt.Sprintf("DIDKey %s %s", did, signature),
		"X-AWEB-Timestamp": timestamp,
	}
}

func canonicalRegistryJSON(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for idx, key := range keys {
		if idx > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		b.WriteString(key)
		b.WriteString(`":"`)
		writeEscapedString(&b, fields[key])
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}
