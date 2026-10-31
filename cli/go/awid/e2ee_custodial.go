package awid

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ErrorCodeRecipientCustodialNoE2EE is the stable code of a refusal to
// end-to-end encrypt to a recipient whose key aweb's hosted service holds.
const ErrorCodeRecipientCustodialNoE2EE = "recipient_custodial_no_e2ee"

// errNoPublishedEncryptionKey is a recipient with no published encryption
// key. It says nothing about custody.
var errNoPublishedEncryptionKey = errors.New("recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext")

// CustodialRecipientError refuses end-to-end encryption to recipients whose
// signed encryption key assertion says aweb's hosted service holds their
// key: that service reads their messages, so the encryption would not be
// end to end.
type CustodialRecipientError struct {
	Recipients []string
	// Unverified is set when the server refused a send to several
	// recipients: its reason says that at least one of them is hosted, not
	// which, so none of them is named hosted.
	Unverified bool
	// err is the server's refusal, when the server refused the send.
	err error
}

func (e *CustodialRecipientError) Unwrap() error { return e.err }

func (e *CustodialRecipientError) Error() string {
	if e.Unverified && len(e.Recipients) > 1 {
		return "At least one of " + joinRecipientNames(e.Recipients) + " uses aweb's hosted service, which reads its messages, so end-to-end encryption is not possible. Send it again without --e2ee."
	}
	if len(e.Recipients) == 1 {
		return e.Recipients[0] + " uses aweb's hosted service, which reads its messages, so end-to-end encryption is not possible. Send it again without --e2ee."
	}
	return joinRecipientNames(e.Recipients) + " use aweb's hosted service, which reads their messages, so end-to-end encryption is not possible. Send it again without --e2ee."
}

func joinRecipientNames(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// refuseCustodialRecipients refuses end-to-end encryption when any
// recipient's encryption key assertion, verified against that recipient's
// identity, says aweb's hosted service holds the key. Custody counts only
// from a verified assertion; an assertion that does not verify is refused by
// the envelope's own verification.
func refuseCustodialRecipients(recipients []E2EERecipientKey, now time.Time) error {
	var hosted []string
	for _, recipient := range recipients {
		if recipientKeyIsHosted(recipient, now) {
			hosted = append(hosted, recipientName(recipient))
		}
	}
	if len(hosted) == 0 {
		return nil
	}
	return &CustodialRecipientError{Recipients: hosted}
}

// recipientKeyIsHosted reports whether the recipient's encryption key
// assertion, verified against the recipient's identity, says aweb's hosted
// service holds the key. An assertion that does not verify says nothing.
func recipientKeyIsHosted(recipient E2EERecipientKey, now time.Time) bool {
	assertion := recipient.EncryptionKey
	if assertion == nil || strings.TrimSpace(assertion.Custody) != EncryptionKeyCustodyHosted {
		return false
	}
	return VerifyEncryptionKeyAssertion(assertion, strings.TrimSpace(recipient.DID), strings.TrimSpace(recipient.StableID), now) == nil
}

// recipientName is how a refusal names a recipient: its address, else its
// stable ID, else its did:key.
func recipientName(recipient E2EERecipientKey) string {
	for _, name := range []string{recipient.Address, recipient.StableID, recipient.DID} {
		if name = strings.TrimSpace(name); name != "" {
			return name
		}
	}
	if recipient.EncryptionKey != nil {
		return fmt.Sprintf("recipient %s", strings.TrimSpace(recipient.EncryptionKey.EncryptionKeyID))
	}
	return "the recipient"
}

// serverCustodialRefusal is the client's refusal for a server that refused an
// encrypted send to a hosted recipient: HTTP 422 with the stable reason
// recipient_custodial_no_e2ee. A single recipient is the hosted one; of
// several, the server does not say which. It keeps the server's refusal. Any
// other error is returned as it is.
func serverCustodialRefusal(err error, envelope *E2EEMessageEnvelope) error {
	if status, ok := HTTPStatusCode(err); !ok || status != http.StatusUnprocessableEntity {
		return err
	}
	body, ok := HTTPErrorBody(err)
	if !ok {
		return err
	}
	var refusal struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &refusal) != nil || strings.TrimSpace(refusal.Reason) != ErrorCodeRecipientCustodialNoE2EE {
		return err
	}
	var names []string
	if envelope != nil {
		for _, recipient := range envelope.Recipients {
			names = append(names, recipientName(E2EERecipientKey{Address: recipient.Address, StableID: recipient.StableID, DID: recipient.DID}))
		}
	}
	if len(names) == 0 {
		names = []string{"the recipient"}
	}
	return &CustodialRecipientError{Recipients: names, Unverified: len(names) > 1, err: err}
}
