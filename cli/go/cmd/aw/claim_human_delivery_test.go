package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestClaimHumanPrintsTheObservedEmailDelivery(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"verification failure", `{"status":"verification_sent","email_sent":false,"email_message":"The verification email could not be sent. Run the command again to request a new one."}`, "The verification email could not be sent. Run the command again to request a new one.\n"},
		{"approval failure", `{"status":"approval_sent","email_sent":false,"email_message":"The approval email could not be sent. Run the command again to request a new one."}`, "The approval email could not be sent. Run the command again to request a new one.\n"},
		{"verification success", `{"status":"verification_sent","email_sent":true}`, "Verification email requested for person@example.test. Click the link in the email to activate your dashboard login.\n"},
		{"released verification", `{"status":"verification_sent"}`, "Verification email requested for person@example.test. Click the link in the email to activate your dashboard login.\n"},
		{"approval success", `{"status":"approval_sent","email_sent":true}`, "Approval email requested. Follow the instructions in that email to approve this claim.\n"},
		{"attached ignores delivery", `{"status":"attached","email_sent":false,"email_message":"not applicable"}`, "Human account person@example.test is attached. No verification email was sent because the email is already verified.\n"},
		{"unreadable message fallback", `{"status":"verification_sent","email_sent":false}`, "The verification email could not be sent. Run the command again to request a new one.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var response awid.ClaimHumanResponse
			if err := json.Unmarshal([]byte(tc.body), &response); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := printClaimHumanSuccess(&out, "person@example.test", &response); err != nil {
				t.Fatal(err)
			}
			if out.String() != tc.want {
				t.Fatalf("message=%q want=%q", out.String(), tc.want)
			}
		})
	}
}
