package awid

import (
	"errors"
	"fmt"
	"testing"
)

func TestCustodyToolRefusalIdentitySurvivesAdviceAndWrapping(t *testing.T) {
	for _, message := range []string{"", "resident policy denied this tool"} {
		refusal := &CustodyError{Code: "app_tool_denied", Message: message}
		if !errors.Is(fmt.Errorf("sign tool request: %w", refusal), ErrAppToolDenied) {
			t.Fatalf("lost typed refusal: %v", refusal)
		}
	}
	for _, err := range []error{errors.New("app_tool_denied"), &CustodyError{Code: "custody_unavailable"}, &CustodyError{Code: "other", Message: "app_tool_denied"}} {
		if errors.Is(err, ErrAppToolDenied) {
			t.Fatalf("unrelated error classified by text: %v", err)
		}
	}
}
