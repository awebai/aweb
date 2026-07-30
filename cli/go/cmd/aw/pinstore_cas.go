package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

const maxPinStoreCASRequestBytes int64 = 40 << 20

type pinStoreCASRequest struct {
	ExpectedYAML string `json:"expected_yaml"`
	DesiredYAML  string `json:"desired_yaml"`
}

var pinStoreCmd = &cobra.Command{
	Use:    "pin-store",
	Short:  "Manage the local identity continuity store",
	Hidden: true,
}

var pinStoreCompareAndSetCmd = newPinStoreCompareAndSetCmd()

func init() {
	identityCmd.AddCommand(pinStoreCmd)
	pinStoreCmd.AddCommand(pinStoreCompareAndSetCmd)
	pinStoreCmd.AddCommand(newPinStoreListCmd())
	pinStoreCmd.AddCommand(newPinStoreForgetCmd())
}

func newPinStoreCompareAndSetCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:          "compare-and-set",
		Short:        "Commit a pin-store snapshot if its precondition still holds",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(path) == "" {
				defaultPath, err := awconfig.DefaultKnownAgentsPath()
				if err != nil {
					return err
				}
				path = defaultPath
			}
			request, err := decodePinStoreCASRequest(cmd.InOrStdin())
			if err != nil {
				return err
			}
			return compareAndSetPinStore(path, []byte(request.ExpectedYAML), []byte(request.DesiredYAML))
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Pin-store path (defaults to the shared user trust store)")
	return cmd
}

func decodePinStoreCASRequest(input io.Reader) (*pinStoreCASRequest, error) {
	data, err := readAllBounded(input, maxPinStoreCASRequestBytes)
	if err != nil {
		return nil, fmt.Errorf("read pin-store compare-and-set request: %w", err)
	}
	var request pinStoreCASRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, fmt.Errorf("decode pin-store compare-and-set request: %w", err)
	}
	if strings.TrimSpace(request.ExpectedYAML) == "" || strings.TrimSpace(request.DesiredYAML) == "" {
		return nil, fmt.Errorf("pin-store compare-and-set requires expected_yaml and desired_yaml")
	}
	return &request, nil
}

// compareAndSetPinStore is aw's cross-process pin-store mutation protocol.
// Both snapshots are parsed before acquiring the lock; only the shared pin store
// is state whose read must be serialized with the mutation.
func compareAndSetPinStore(path string, expectedYAML, desiredYAML []byte) error {
	expected, err := awid.ParsePinStore(expectedYAML)
	if err != nil {
		return fmt.Errorf("invalid pin-store precondition: %w", err)
	}
	desired, err := awid.ParsePinStore(desiredYAML)
	if err != nil {
		return fmt.Errorf("invalid desired pin store: %w", err)
	}

	lock, err := lockPinStoreForCAS(path)
	if err != nil {
		return fmt.Errorf("lock trust pin store: %w", err)
	}
	defer func() { _ = lock.Close() }()

	current, err := awid.LoadPinStore(path)
	if err != nil {
		return err
	}
	if !current.SemanticallyEqual(expected) {
		return fmt.Errorf("trust pin store changed since it was read; refusing stale mutation")
	}
	if err := desired.Save(path); err != nil {
		return fmt.Errorf("commit trust pin store: %w", err)
	}
	return nil
}

func lockPinStoreForCAS(path string) (io.Closer, error) {
	if err := pinStoreCASPreLockHook(); err != nil {
		return nil, err
	}
	return awconfig.LockExclusive(path + ".lock")
}
