package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

var idOperationStatusIDFlag string

var idOperationCmd = &cobra.Command{
	Use:   "operation",
	Short: "Inspect protected operations this identity requested",
}

var idOperationStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Read a protected operation's receipt without performing it",
	Long: "Read, once, the receipt of a protected operation this identity requested at the\n" +
		"service named by --protected-profile. Nothing is prepared, executed, approved or\n" +
		"resumed, and aw's own saved request is left as it is. The service may record an\n" +
		"outcome that is already confirmed; it never starts or extends anything for a read.\n\n" +
		"The state is the service's receipt: pending (with its reason and deadline),\n" +
		"committed (its result, which this read does not verify), refused or unknown\n" +
		"(with a code), or none when the service holds no such operation for this\n" +
		"requester in that scope. none does not prove an earlier request never took\n" +
		"effect elsewhere. A read that is refused or cannot be made is an error, not a\n" +
		"state.\n\n" +
		"A request aw saved is read under the profile's one binding for its scope; without\n" +
		"one, the profile must have exactly one binding.",
	Args: cobra.NoArgs,
	RunE: runIDOperationStatus,
}

func init() {
	flags := idOperationStatusCmd.Flags()
	flags.StringVar(&idOperationStatusIDFlag, "operation-id", "", "The UUID of the operation to read")
	flags.StringVar(&appProtectedProfileFlag, "protected-profile", "", "The operator-provisioned protected-service profile (default: AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home)")
	idOperationCmd.AddCommand(idOperationStatusCmd)
	identityCmd.AddCommand(idOperationCmd)
}

func runIDOperationStatus(cmd *cobra.Command, _ []string) error {
	operationID := strings.TrimSpace(idOperationStatusIDFlag)
	if operationID == "" {
		return usageError("--operation-id is required")
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	optionsFor := func(scope map[string]any) handoff.GovernanceOptions {
		return governanceOptions(cmd, profile, scope, identity)
	}
	status, err := operationStatus(cmd.Context(), profile, operationID, optionsFor)
	if err != nil {
		return err
	}
	printOutput(status, func(any) string { return operationStatusText(status) })
	return nil
}

// operationStatus reads operationID's receipt once at profile's service,
// signed under the scope readScope selects, and reports it as served. It
// sends nothing else and leaves aw's saved request as it is.
func operationStatus(ctx context.Context, profile *handoff.Profile, operationID string, optionsFor func(map[string]any) handoff.GovernanceOptions) (map[string]any, error) {
	scope, err := readScope(profile, operationID)
	if err != nil {
		return nil, err
	}
	opts := optionsFor(scope)
	readCtx, cancel := context.WithTimeout(ctx, cmp.Or(opts.RetryWithin, handoff.DefaultRetryWithin))
	defer cancel()
	receipt, err := handoff.ReadReceipt(readCtx, opts, operationID)
	if errors.Is(err, handoff.ErrOperationNotFound) {
		return map[string]any{"operation_id": operationID, "state": "none"}, nil
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return nil, withErrorCode(code, fmt.Errorf("operation %s: %w", operationID, err))
		}
		return nil, fmt.Errorf("operation %s: %w", operationID, err)
	}
	status := map[string]any{"operation_id": operationID, "state": receipt.State}
	switch receipt.State {
	case "pending":
		status["reason"] = receipt.Reason
		status["expires_at"] = receipt.ExpiresAt.UTC().Format(time.RFC3339Nano)
	case "committed":
		status["result"] = json.RawMessage(receipt.Result)
		status["result_verification"] = "not_performed"
	default:
		status["code"] = receipt.Code
	}
	return status, nil
}

// readScope is the scope operationID's receipt is read under. A request aw
// saved is read only under the profile's one binding for its scope, whatever
// its authority generation, and only at the origins it was sent to. Without a
// saved request, the profile must have exactly one binding.
func readScope(profile *handoff.Profile, operationID string) (map[string]any, error) {
	saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
	if err != nil {
		return nil, err
	}
	candidates := profile.Bindings
	if saved != nil {
		if saved.RequestOrigin != profile.RequestOrigin || saved.HumanOrigin != profile.HumanOrigin {
			return nil, withErrorCode("operation_conflict", fmt.Errorf("operation %s was requested at another service than this profile names", operationID))
		}
		body, _ := handoff.DecodeObject(saved.Body)
		scope, ok := body["scope"].(map[string]any)
		if !ok {
			return nil, withErrorCode("operation_conflict", fmt.Errorf("aw's saved request for operation %s names no scope", operationID))
		}
		candidates = nil
		for _, binding := range profile.Bindings {
			if sameCanonical(stableScope(binding.Scope), stableScope(scope)) {
				candidates = append(candidates, binding)
			}
		}
	}
	switch len(candidates) {
	case 1:
		return candidates[0].Scope, nil
	case 0:
		return nil, withErrorCode("profile_scope_refused", fmt.Errorf("the protected-service profile configures no binding to read operation %s under", operationID))
	}
	return nil, withErrorCode("profile_scope_ambiguous", fmt.Errorf("the protected-service profile has %d bindings operation %s could be read under; it must be one", len(candidates), operationID))
}

// operationStatusText is status for people.
func operationStatusText(status map[string]any) string {
	id := status["operation_id"]
	switch status["state"] {
	case "none":
		return fmt.Sprintf("Operation %s: the protected service holds no such operation for this identity in this scope.\n", id)
	case "pending":
		return fmt.Sprintf("Operation %s is pending (%s) until %s.\n", id, status["reason"], status["expires_at"])
	case "committed":
		return fmt.Sprintf("Operation %s committed, by the service's receipt; its result was not verified here.\n", id)
	}
	return fmt.Sprintf("Operation %s is %s: %s.\n", id, status["state"], status["code"])
}
