package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const (
	supportContractVersion = "support-contract-v1"
	registryReadSchema     = "registry_read.v1"

	registryReadSourceAwid = "awid"

	registryReadAuthorityAnonymous           = "anonymous"
	registryReadAuthorityDIDKey              = "did-key"
	registryReadAuthorityNamespaceController = "namespace-controller"

	registryReadStatusOK      = "ok"
	registryReadStatusFail    = "fail"
	registryReadStatusUnknown = "unknown"
	registryReadStatusBlocked = "blocked"
)

type supportContractTarget struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Label      string `json:"label,omitempty"`
}

type registryReadEnvelope struct {
	Version          string                `json:"version"`
	Source           string                `json:"source"`
	AuthorityMode    string                `json:"authority_mode"`
	AuthoritySubject string                `json:"authority_subject,omitempty"`
	Authoritative    bool                  `json:"authoritative"`
	GeneratedAt      string                `json:"generated_at"`
	RequestID        string                `json:"request_id"`
	Target           supportContractTarget `json:"target"`
	Redactions       []string              `json:"redactions"`
	Payload          registryReadPayload   `json:"payload"`
}

type registryReadPayload struct {
	Schema         string                  `json:"schema"`
	Status         string                  `json:"status"`
	RegistryURL    string                  `json:"registry_url"`
	Operation      string                  `json:"operation"`
	Target         supportContractTarget   `json:"target"`
	OwnershipProof bool                    `json:"ownership_proof"`
	DIDKey         *registryReadDIDKey     `json:"did_key,omitempty"`
	Addresses      []awid.RegistryAddress  `json:"addresses,omitempty"`
	Address        *awid.RegistryAddress   `json:"address,omitempty"`
	Namespace      *awid.RegistryNamespace `json:"namespace,omitempty"`
	Error          *registryReadError      `json:"error,omitempty"`
}

type registryReadDIDKey struct {
	DIDAW         string                  `json:"did_aw"`
	CurrentDIDKey string                  `json:"current_did_key"`
	LogHead       *registryReadDIDLogHead `json:"log_head,omitempty"`
}

type registryReadDIDLogHead struct {
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	EntryHash      string  `json:"entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Timestamp      string  `json:"timestamp"`
}

type registryReadError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Detail  map[string]any `json:"detail,omitempty"`
}

type registryReadAuthority struct {
	Mode       string
	SubjectDID string
	SigningKey ed25519.PrivateKey
}

var (
	idAddressesCmd = &cobra.Command{
		Use:   "addresses <did_aw>",
		Short: "List registry addresses for a did:aw",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDAddresses,
	}

	idNamespaceAddressesAuthority string
	idNamespaceAddressesCmd       = &cobra.Command{
		Use:   "addresses <domain>",
		Short: "List registry namespace addresses",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDNamespaceAddresses,
	}

	idNamespaceResolveAuthority string
	idNamespaceResolveCmd       = &cobra.Command{
		Use:   "resolve <domain>/<name>",
		Short: "Resolve a registry namespace address",
		Args:  cobra.ExactArgs(1),
		RunE:  runIDNamespaceResolve,
	}
)

func init() {
	idNamespaceAddressesCmd.Flags().StringVar(&idNamespaceAddressesAuthority, "authority", registryReadAuthorityAnonymous, "Authority mode: anonymous, did, or namespace-controller")
	idNamespaceResolveCmd.Flags().StringVar(&idNamespaceResolveAuthority, "authority", registryReadAuthorityAnonymous, "Authority mode: anonymous, did, or namespace-controller")
	identityCmd.AddCommand(idAddressesCmd)
	idNamespaceCmd.AddCommand(idNamespaceAddressesCmd)
	idNamespaceCmd.AddCommand(idNamespaceResolveCmd)
}

func runIDAddresses(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workingDir, _ := os.Getwd()
	registry, identity, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return err
	}
	requestID := newRegistryReadRequestID()
	registry.RequestID = requestID
	didAW := strings.TrimSpace(args[0])
	if !strings.HasPrefix(didAW, "did:aw:") {
		return usageError("did_aw must start with did:aw:")
	}
	registryURL, err := registryLookupURL(ctx, registry, identity, didAW)
	if err != nil {
		return err
	}
	target := registryReadDIDTarget(didAW, "")
	addresses, err := registry.ListDIDAddressesAt(ctx, registryURL, didAW)
	env := newRegistryReadEnvelope(requestID, registryReadAuthority{Mode: registryReadAuthorityAnonymous}, registryURL, "list-did-addresses", target)
	if err != nil {
		printRegistryRead(env.withError(err), formatRegistryRead)
		return nil
	}
	env.Payload.Addresses = addresses
	printRegistryRead(env, formatRegistryRead)
	return nil
}

func runIDNamespaceAddresses(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workingDir, _ := os.Getwd()
	registry, _, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return err
	}
	requestID := newRegistryReadRequestID()
	registry.RequestID = requestID
	domain := awconfig.NormalizeDomain(args[0])
	if domain == "" {
		return usageError("domain is required")
	}
	authority, err := resolveRegistryReadAuthority(workingDir, domain, idNamespaceAddressesAuthority)
	if err != nil {
		return err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return err
	}
	target := registryReadNamespaceTarget(domain)
	env := newRegistryReadEnvelope(requestID, authority, registryURL, "list-addresses", target)
	var addresses []awid.RegistryAddress
	if authority.SigningKey != nil {
		addresses, _, err = registry.ListNamespaceAddressesAtSigned(ctx, registryURL, domain, authority.SigningKey)
	} else {
		addresses, _, err = registry.ListNamespaceAddressesAt(ctx, registryURL, domain)
	}
	if err != nil {
		printRegistryRead(env.withError(err), formatRegistryRead)
		return nil
	}
	env.Payload.Addresses = addresses
	if authority.Mode == registryReadAuthorityNamespaceController {
		env.Payload.OwnershipProof = true
	}
	printRegistryRead(env, formatRegistryRead)
	return nil
}

func runIDNamespaceResolve(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	domain, name, ok := awconfig.CutIdentityAddress(args[0])
	if !ok {
		return usageError("address must be <domain>/<name>")
	}
	domain = awconfig.NormalizeDomain(domain)
	workingDir, _ := os.Getwd()
	registry, _, err := resolveRegistryClientForLookup(workingDir)
	if err != nil {
		return err
	}
	requestID := newRegistryReadRequestID()
	registry.RequestID = requestID
	authority, err := resolveRegistryReadAuthority(workingDir, domain, idNamespaceResolveAuthority)
	if err != nil {
		return err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return err
	}
	target := registryReadAddressTarget(domain, name)
	env := newRegistryReadEnvelope(requestID, authority, registryURL, "resolve-address", target)
	var address *awid.RegistryAddress
	if authority.SigningKey != nil {
		address, _, err = registry.GetNamespaceAddressAtSigned(ctx, registryURL, domain, name, authority.SigningKey)
	} else {
		address, _, err = registry.GetNamespaceAddressAt(ctx, registryURL, domain, name)
	}
	if err != nil {
		printRegistryRead(env.withError(err), formatRegistryRead)
		return nil
	}
	env.Payload.Address = address
	if authority.Mode == registryReadAuthorityNamespaceController {
		env.Payload.OwnershipProof = true
	}
	printRegistryRead(env, formatRegistryRead)
	return nil
}

func registryReadResolveKeyEnvelope(ctx context.Context, registry *awid.RegistryClient, registryURL, didAW string) (registryReadEnvelope, error) {
	requestID := strings.TrimSpace(registry.RequestID)
	if requestID == "" {
		requestID = newRegistryReadRequestID()
		registry.RequestID = requestID
	}
	target := registryReadDIDTarget(didAW, "")
	env := newRegistryReadEnvelope(requestID, registryReadAuthority{Mode: registryReadAuthorityAnonymous}, registryURL, "resolve-key", target)
	resolution, err := registry.ResolveKeyAt(ctx, registryURL, didAW)
	if err != nil {
		return env.withError(err), nil
	}
	env.Target.Label = strings.TrimSpace(resolution.CurrentDIDKey)
	env.Payload.Target = env.Target
	env.Payload.DIDKey = registryReadDIDKeyFromResolution(resolution)
	if resolution.LogHead != nil && strings.TrimSpace(resolution.LogHead.Signature) != "" {
		env.Redactions = append(env.Redactions, "payload.did_key.log_head.signature")
	}
	return env, nil
}

func newRegistryReadEnvelope(requestID string, authority registryReadAuthority, registryURL, operation string, target supportContractTarget) registryReadEnvelope {
	if authority.Mode == "" {
		authority.Mode = registryReadAuthorityAnonymous
	}
	env := registryReadEnvelope{
		Version:          supportContractVersion,
		Source:           registryReadSourceAwid,
		AuthorityMode:    authority.Mode,
		AuthoritySubject: strings.TrimSpace(authority.SubjectDID),
		Authoritative:    true,
		GeneratedAt:      supportContractGeneratedAt(time.Now()),
		RequestID:        requestID,
		Target:           target,
		Redactions:       []string{},
		Payload: registryReadPayload{
			Schema:         registryReadSchema,
			Status:         registryReadStatusOK,
			RegistryURL:    strings.TrimSpace(registryURL),
			Operation:      operation,
			Target:         target,
			OwnershipProof: false,
		},
	}
	return env
}

func (env registryReadEnvelope) withError(err error) registryReadEnvelope {
	var regErr *awid.RegistryError
	if errors.As(err, &regErr) {
		env.Payload.Error = registryHTTPReadError(regErr)
		switch regErr.StatusCode {
		case http.StatusNotFound:
			env.Payload.Status = registryReadStatusFail
			env.Authoritative = true
		case http.StatusUnauthorized, http.StatusForbidden:
			env.Payload.Status = registryReadStatusBlocked
			env.Authoritative = true
		default:
			env.Payload.Status = registryReadStatusUnknown
			env.Authoritative = false
		}
		return env
	}
	env.Payload.Status = registryReadStatusUnknown
	env.Authoritative = false
	env.Payload.Error = &registryReadError{
		Code:    "registry.unavailable",
		Message: "Registry unavailable.",
		Detail:  map[string]any{"kind": "transport"},
	}
	return env
}

func registryHTTPReadError(err *awid.RegistryError) *registryReadError {
	code := "registry.unavailable"
	message := "Registry unavailable."
	switch err.StatusCode {
	case http.StatusNotFound:
		code = "target.not_found"
		message = "Target not found."
	case http.StatusUnauthorized:
		code = "auth.forbidden"
		message = "Registry authority rejected the request."
	case http.StatusForbidden:
		code = "auth.authority_insufficient"
		message = "Registry authority is insufficient for this request."
	}
	return &registryReadError{
		Code:    code,
		Message: message,
		Detail:  map[string]any{"status_code": err.StatusCode},
	}
}

func resolveRegistryReadAuthority(workingDir, domain, rawMode string) (registryReadAuthority, error) {
	switch strings.TrimSpace(rawMode) {
	case "", "anonymous":
		return registryReadAuthority{Mode: registryReadAuthorityAnonymous}, nil
	case "did", registryReadAuthorityDIDKey:
		signingKey, err := loadOptionalWorktreeSigningKey(workingDir)
		if err != nil {
			return registryReadAuthority{}, fmt.Errorf("load signing key: %w", err)
		}
		if signingKey == nil {
			return registryReadAuthority{}, usageError("did authority requires .aw/signing.key")
		}
		return registryReadAuthority{
			Mode:       registryReadAuthorityDIDKey,
			SubjectDID: awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)),
			SigningKey: signingKey,
		}, nil
	case registryReadAuthorityNamespaceController:
		signingKey, err := awconfig.LoadControllerKey(domain)
		if err != nil {
			return registryReadAuthority{}, fmt.Errorf("load namespace controller key for %s: %w", domain, err)
		}
		return registryReadAuthority{
			Mode:       registryReadAuthorityNamespaceController,
			SubjectDID: awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)),
			SigningKey: signingKey,
		}, nil
	default:
		return registryReadAuthority{}, usageError("--authority must be anonymous, did, or namespace-controller")
	}
}

func registryReadDIDTarget(didAW, label string) supportContractTarget {
	return supportContractTarget{Type: "did", Identifier: strings.TrimSpace(didAW), Label: strings.TrimSpace(label)}
}

func registryReadDIDKeyFromResolution(resolution *awid.DidKeyResolution) *registryReadDIDKey {
	if resolution == nil {
		return nil
	}
	out := &registryReadDIDKey{
		DIDAW:         strings.TrimSpace(resolution.DIDAW),
		CurrentDIDKey: strings.TrimSpace(resolution.CurrentDIDKey),
	}
	if resolution.LogHead != nil {
		out.LogHead = &registryReadDIDLogHead{
			Seq:            resolution.LogHead.Seq,
			Operation:      resolution.LogHead.Operation,
			PreviousDIDKey: resolution.LogHead.PreviousDIDKey,
			NewDIDKey:      resolution.LogHead.NewDIDKey,
			PrevEntryHash:  resolution.LogHead.PrevEntryHash,
			EntryHash:      resolution.LogHead.EntryHash,
			StateHash:      resolution.LogHead.StateHash,
			AuthorizedBy:   resolution.LogHead.AuthorizedBy,
			Timestamp:      resolution.LogHead.Timestamp,
		}
	}
	return out
}

func registryReadNamespaceTarget(domain string) supportContractTarget {
	domain = awconfig.NormalizeDomain(domain)
	return supportContractTarget{Type: "namespace", Identifier: domain, Label: domain}
}

func registryReadAddressTarget(domain, name string) supportContractTarget {
	identifier := awconfig.NormalizeDomain(domain) + "/" + strings.TrimSpace(name)
	return supportContractTarget{Type: "address", Identifier: identifier, Label: identifier}
}

func supportContractGeneratedAt(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func newRegistryReadRequestID() string {
	return "aw-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
}

func printRegistryRead(out registryReadEnvelope, formatter func(registryReadEnvelope) string) {
	if jsonFlag {
		printJSON(out)
		return
	}
	fmt.Print(formatter(out))
}
