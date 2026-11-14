package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// protectedProfileFile is the profile's name in an identity home, where the
// operator's setup tells the agent to put it.
const protectedProfileFile = "protected-profile.json"

// protectedProfilePath is the profile aw uses: --protected-profile, else
// AWEB_PROTECTED_PROFILE, else protected-profile.json in the identity home.
func protectedProfilePath(flag, identityHome string) (string, error) {
	if path := strings.TrimSpace(flag); path != "" {
		return path, nil
	}
	if path := strings.TrimSpace(os.Getenv("AWEB_PROTECTED_PROFILE")); path != "" {
		return path, nil
	}
	inHome := filepath.Join(identityHome, protectedProfileFile)
	if identityHome != "" {
		if _, err := os.Stat(inHome); err == nil {
			return inHome, nil
		}
	}
	return "", usageError("no protected-service profile: pass --protected-profile, set AWEB_PROTECTED_PROFILE, or put the operator's profile at %s", inHome)
}

// protectedOperationID is the operation id for intent: the caller's explicit
// id; else the id of the one saved, unfinished operation that asked exactly
// intent at this profile's service, which is resumed; else a new id. Two
// saved operations for one request are named for the caller to choose.
func protectedOperationID(flag string, profile *handoff.Profile, intent map[string]any) (id string, resumed bool, err error) {
	if id := strings.TrimSpace(flag); id != "" {
		return id, false, validOperationID(id)
	}
	asked, err := intentCanonical(intent)
	if err != nil {
		return "", false, err
	}
	saved, err := awconfig.ListPendingGovernanceOperations()
	if err != nil {
		return "", false, err
	}
	var matches []string
	for _, op := range saved {
		// A quarantined request is never resumed (guardUnfinished).
		if op.Quarantine != nil || op.RequestOrigin != profile.RequestOrigin || op.HumanOrigin != profile.HumanOrigin {
			continue
		}
		body, ok := handoff.DecodeObject(op.Body)
		if !ok {
			continue
		}
		if canonical, err := intentCanonical(body); err == nil && bytes.Equal(canonical, asked) {
			matches = append(matches, op.OperationID)
		}
	}
	switch len(matches) {
	case 0:
		id, err := awid.GenerateUUID4()
		return id, false, err
	case 1:
		return matches[0], true, nil
	}
	slices.Sort(matches)
	return "", false, usageError("operations %s all wait on this same request; pass --operation-id to choose one", strings.Join(matches, ", "))
}

// intentCanonical is a prepare body's canonical form without the members aw
// sets itself, so a saved body and a new intent compare as the same request.
func intentCanonical(body map[string]any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	members, ok := handoff.DecodeObject(raw)
	if !ok {
		return nil, errors.New("the request is not a JSON object")
	}
	delete(members, "operation_id")
	delete(members, "redirect_uri")
	return awid.StrictCanonicalJSON(members)
}

// announceOperationID settles *id for intent (protectedOperationID) and says
// on stderr when it resumes a saved operation rather than starting one.
func announceOperationID(cmd *cobra.Command, id *string, profile *handoff.Profile, intent map[string]any) error {
	chosen, resumed, err := protectedOperationID(*id, profile, intent)
	if err != nil {
		return err
	}
	if resumed {
		fmt.Fprintf(cmd.ErrOrStderr(), "Continuing the same request from before (operation %s)\n", chosen)
	}
	*id = chosen
	return nil
}

// withAdmissionCounts tells an admission_limit_reached refusal with the
// root's own counts, read by counts. Counts that cannot be read leave the
// refusal as it was; any other error is returned without a read.
func withAdmissionCounts(ctx context.Context, err error, team string, counts func(context.Context) (*handoff.AdmissionCounts, error)) error {
	if handoff.ErrorCode(err) != "admission_limit_reached" || counts == nil {
		return err
	}
	read, readErr := counts(ctx)
	if readErr != nil || read == nil {
		return err
	}
	return handoff.Retell(err, func(f *handoff.Facts) { f.Team, f.Admission = team, read })
}
