package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/releaseversion"
	"github.com/awebai/aw/wake"
	"github.com/spf13/cobra"
)

var wakeStatusHome string
var wakeStatusMinVersion string

type wakeReadinessOutput struct {
	wake.Status
	Readiness    []wake.ReadinessVerdict `json:"readiness"`
	ControlError string                  `json:"control_error,omitempty"`
}

type wakeHomeReadinessOutput struct {
	wake.Status
	Readiness    wake.ReadinessVerdict `json:"readiness"`
	ControlError string                `json:"control_error,omitempty"`
}

func runWakeStatus(cmd *cobra.Command, args []string) error {
	if wakeStatusMinVersion != "" {
		if _, valid := releaseversion.Compare(wakeStatusMinVersion, wakeStatusMinVersion); !valid {
			return usageError("invalid --min-daemon-version; pass an aw release version such as 1.36.13")
		}
	}
	store, err := wakeStore()
	if err != nil {
		return err
	}
	var status wake.Status
	response, controlErr := wake.Call(store.SocketPath(), wake.ControlRequest{Op: wake.OpStatus})
	switch {
	case controlErr == nil && response.Status != nil:
		status = *response.Status
	case controlErr != nil:
		// A stored snapshot is diagnostic evidence, never permission for a
		// mutation fallback. Preserve every transport failure in the readiness
		// refusal, including an accepted exchange (docs/cli-integration-contract.md:111).
		status, err = wake.StatusFromStore(store, wakeMaxStreams)
		if err != nil {
			return fmt.Errorf("read wake snapshot after control failure: %w; restore wake control or repair its stored status before retrying", errors.Join(controlErr, err))
		}
	default:
		return withErrorCode("wake_status_invalid", fmt.Errorf("wake control returned no status; restart the wake service and retry"))
	}
	status.ClassifyDaemonVersion()
	homes := []string{}
	if wakeStatusHome != "" {
		home, err := wake.CanonicalHome(wakeStatusHome)
		if err != nil {
			return usageError("invalid --home: %v; pass an absolute instance home", err)
		}
		homes = append(homes, home)
	} else {
		for _, row := range status.Instances {
			homes = append(homes, row.Home)
		}
	}
	verdicts := make([]wake.ReadinessVerdict, 0, len(homes))
	for _, home := range homes {
		registration, exists, err := store.LoadRegistration(home)
		if err != nil {
			return fmt.Errorf("read wake registration for %s: %w; repair or re-register that home", home, err)
		}
		input := wake.ReadinessInput{Home: home, Status: status, MinimumDaemonVersion: wakeStatusMinVersion, ControlError: controlErr, Now: time.Now().UTC()}
		if exists {
			input.Registration = &registration
			input.ForeignGrantHome = foreignReadinessGrant(registration, status)
		}
		verdicts = append(verdicts, wake.EvaluateReadiness(input))
	}
	formatter := func(value any) string {
		var result strings.Builder
		result.WriteString(formatWakeStatus(status))
		for _, verdict := range verdicts {
			fmt.Fprintf(&result, "\n%s: %s — %s\n", verdict.Home, verdict.Code, verdict.Reason)
		}
		return result.String()
	}
	controlErrorText := ""
	if controlErr != nil {
		controlErrorText = controlErr.Error()
	}
	var outputErr error
	if wakeStatusHome != "" {
		outputErr = printOutput(wakeHomeReadinessOutput{Status: status, Readiness: verdicts[0], ControlError: controlErrorText}, formatter)
	} else {
		outputErr = printOutput(wakeReadinessOutput{Status: status, Readiness: verdicts, ControlError: controlErrorText}, formatter)
	}
	if outputErr != nil {
		return fmt.Errorf("write wake status: %w. Check the output destination, then rerun aw wake status.", outputErr)
	}
	return nil
}

func foreignReadinessGrant(registration wake.Registration, status wake.Status) string {
	primary := registration.PrimaryIdentityHome
	if primary == "" {
		primary = registration.IdentityHome
	}
	if !awconfig.IsGrantHome(primary) {
		return ""
	}
	for _, row := range status.Instances {
		if row.Home != registration.Home {
			continue
		}
		for _, binding := range row.ReceiveIdentities {
			if binding.IdentityHome != primary && awconfig.IsGrantHome(binding.IdentityHome) {
				return binding.IdentityHome
			}
		}
	}
	return ""
}

func init() {
	wakeStatusCmd.Flags().StringVar(&wakeStatusHome, "home", "", "Report readiness for this absolute instance home")
	wakeStatusCmd.Flags().StringVar(&wakeStatusMinVersion, "min-daemon-version", "", "Required daemon release version for the readiness verdict")
}
