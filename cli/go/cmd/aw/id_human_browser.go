package main

import (
	"fmt"
	"io"

	"github.com/awebai/aw/awid"
)

// Browser launch is optional once the person has the URL. An output failure
// is returned because the manual next step could not be delivered.
func openHumanApprovalPage(output io.Writer, target string) error {
	if err := openBrowser(target); err != nil {
		if _, writeErr := fmt.Fprintf(output, "Could not open a browser (%s). Open %s yourself to continue.\n", awid.SanitizeErrorText(err.Error()), target); writeErr != nil {
			return fmt.Errorf("Could not show the browser's manual next step: %w", writeErr)
		}
	}
	return nil
}
