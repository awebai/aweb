package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/atomicfile"
	"github.com/spf13/cobra"
)

var humanEnrollIssuer, humanEnrollOrigin, humanEnrollIntent string
var humanEnrollRestart bool
var idHumanEnrollCmd = &cobra.Command{
	Use: "enroll", Short: "Enroll an approval key for your new or existing human ID",
	Long: `Run this yourself with --human ID --human-domain DOMAIN at a terminal.
Your identity key stays in the passphrase-protected OS keychain. For a new person,
first run aw id human init and obtain a pending --intent FILE from your issuer.
For an existing person, --issuer URL asks that issuer for an enrollment intent.
After the first use, the issuer is remembered with your human record.
The first signature asks once for your passphrase. The key stays unlocked in
memory for this command, including browser and "type yes" waits, and is wiped
when the command ends or is interrupted. Each signature is described on stderr.

The signed intent supplies the approval service and RP ID; --approval-origin is
an optional equality pin. You see the service before opening its enrollment page.
Register and confirm your key in that browser, then continue at this terminal.
Interrupted commands resume their original enrollment. After expiry, use --restart
to preserve the old attempt and start again; a new person needs a fresh intent.
Once confirmation is saved, resume activation without --restart, even after expiry.
Register a second approval key in the same browser enrollment before continuing.
Lost-key replacement is not implemented: loss of your only key requires the
operator to issue a new ID and revoke the old one. Enrollment of an existing
person never adds or changes a creation claim.

Next: use aw id proof --message-file FILE --out proof.json, then give proof.json
to anyone; they run plain aw verify proof.json on their machine.`,
	Args: cobra.NoArgs, Annotations: map[string]string{humanCommandAnnotation: "prepared"}, RunE: runIDHumanEnroll,
}

type humanEnrollmentSession struct {
	Version      int            `json:"v"`
	Person       string         `json:"person"`
	Key          string         `json:"key"`
	Issuer       string         `json:"issuer"`
	Intent       map[string]any `json:"intent"`
	Start        map[string]any `json:"start,omitempty"`
	Binding      map[string]any `json:"binding,omitempty"`
	RequestBytes string         `json:"request_bytes,omitempty"`
	Receipt      map[string]any `json:"receipt,omitempty"`
	Activation   map[string]any `json:"activation,omitempty"`
	Completed    bool           `json:"completed,omitempty"`
}

func init() {
	idHumanEnrollCmd.Flags().StringVar(&humanEnrollIssuer, "issuer", "", "Your issuer's HTTPS origin; remembered after first use")
	idHumanEnrollCmd.Flags().StringVar(&humanEnrollOrigin, "approval-origin", "", "Optional pin; must equal the service in the issuer's signed intent")
	idHumanEnrollCmd.Flags().StringVar(&humanEnrollIntent, "intent", "", "Pending signed enrollment intent handed to a new person by the issuer")
	idHumanEnrollCmd.Flags().BoolVar(&humanEnrollRestart, "restart", false, "Archive an expired unconfirmed attempt and start fresh; never replace saved confirmation")
	idHumanCmd.AddCommand(idHumanEnrollCmd)
}

func enrollmentObject(value any) map[string]any { object, _ := value.(map[string]any); return object }
func enrollmentText(value any) string           { text, _ := value.(string); return text }
func humanEnrollmentConfirmation(session *humanEnrollmentSession, admission map[string]any) map[string]any {
	return map[string]any{"version": json.Number("1"), "intent": session.Intent, "binding": session.Binding, "request_bytes": session.RequestBytes, "admission": admission}
}
func sameEnrollmentValue(a, b any) bool {
	x, e := proof.Canonical(a)
	y, f := proof.Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}

func humanEnrollmentClient(human *humanParticipation, origin string) *approval.Client {
	requester := map[string]any{"kind": "identity", "id": human.record.StableID, "key": human.record.DIDKey}
	chain := []any{}
	if human.chain != nil {
		chain, _ = human.chain["certificates"].([]any)
	}
	client := &approval.Client{Origin: origin, Requester: requester, Admission: map[string]any{"team_certificate": nil, "id_chain": chain}}
	client.Authorize = func(body []byte, purpose string, issuedAt int64) (string, error) {
		return proof.HTTPAuthorizationWithSigner(body, requester, origin, purpose, issuedAt, human.sign)
	}
	return client
}

func saveHumanEnrollment(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicfile.Options{Mode: 0o600, ParentMode: 0o700}.Write(path, append(raw, '\n'))
}

func loadHumanEnrollment(path string, human *humanParticipation) (*humanEnrollmentSession, error) {
	raw, err := readFileBounded(path, maxResponseBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var session humanEnrollmentSession
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if err := d.Decode(&session); err != nil {
		return nil, err
	}
	if session.Version != 1 || session.Person != human.record.StableID || session.Key != human.record.DIDKey || session.Intent == nil {
		return nil, usageError("saved enrollment belongs to another human or key")
	}
	return &session, nil
}

func humanIssuerRequest(ctx context.Context, human *humanParticipation, origin, path string, body any) (map[string]any, error) {
	result, err := humanIssuerHTTP(ctx, human, origin, path, body)
	if err != nil {
		return nil, err
	}
	if result.Status != http.StatusOK {
		if strings.Contains(string(result.Body), "person_already_exists") {
			return nil, fmt.Errorf("issuer returned HTTP %d: %s; this person already has an enrollment; adding or replacing keys after activation is not implemented. If the only key is lost, ask the operator to issue a new ID and revoke the old one", result.Status, result.Body)
		}
		return nil, fmt.Errorf("issuer returned HTTP %d: %s", result.Status, result.Body)
	}
	return proof.Parse(result.Body)
}

func humanIssuerHTTP(ctx context.Context, human *humanParticipation, origin, path string, body any) (*idRequestExecutionResult, error) {
	origin, err := canonicalHumanIssuer(origin)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(origin)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return nil, usageError("issuer must be an HTTPS origin")
	}
	target.Path = path
	raw, err := proof.Canonical(body)
	if err != nil {
		return nil, err
	}
	var chain *awid.IDChain
	if human.chain != nil {
		checked, err := awid.IDChainFromBundle(human.chain)
		if err != nil {
			return nil, err
		}
		chain = &checked
	}
	req, err := awid.NewSignedIdentityPostRequest(ctx, awid.SignedIdentityPost{
		DIDKey: human.record.DIDKey, StableID: human.record.StableID,
		Sign: human.sign, Target: target, Body: raw, Chain: chain,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	client := awid.NewNoRedirectClient()
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, err := awid.ReadAllBounded(response.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return &idRequestExecutionResult{Status: response.StatusCode, Header: response.Header.Clone(), Body: answer}, nil
}

func canonicalHumanIssuer(value string) (string, error) {
	origin, err := awid.CanonicalServerOrigin(value)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(origin, "https://") {
		return "", usageError("issuer must be an HTTPS origin")
	}
	return origin, nil
}

func humanEnrollmentExchange(ctx context.Context, client *approval.Client, purpose string, body, intent map[string]any, requestBytes []byte) (map[string]any, error) {
	raw, err := proof.Canonical(body)
	if err != nil {
		return nil, err
	}
	req, err := client.SignedRequest(ctx, purpose, raw)
	if err != nil {
		return nil, err
	}
	httpClient := awid.NewNoRedirectClient()
	response, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	answer, err := awid.ReadAllBounded(response.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	return proof.ReadAnswerJSON(purpose, answer, proof.AnswerInput{Status: response.StatusCode, Intent: intent, RequestBytes: requestBytes})
}

func runIDHumanEnroll(cmd *cobra.Command, args []string) error {
	h := activeHuman
	h.operation = "enroll your approval key"
	ctx := cmd.Context()
	sessionPath := filepath.Join(h.dir, "enrollment-session.json")
	session, err := loadHumanEnrollment(sessionPath, h)
	if err != nil {
		return err
	}
	issuer := strings.TrimSpace(humanEnrollIssuer)
	if issuer != "" {
		issuer, err = canonicalHumanIssuer(issuer)
		if err != nil {
			return err
		}
	}
	if session != nil {
		if issuer != "" && issuer != session.Issuer {
			return usageError("issuer differs from your saved enrollment")
		}
		issuer = session.Issuer
	}
	if issuer == "" {
		return usageError("first enrollment needs --issuer URL; ask your organization's operator for it")
	}
	if session != nil {
		archive, err := restartHumanAttempt(sessionPath, enrollmentObject(session.Intent["intent"]), time.Now().Unix(), humanEnrollRestart, session.Receipt != nil || session.Completed)
		if err != nil {
			return err
		}
		if archive != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Expired enrollment preserved in %s. Starting a fresh attempt.\n", archive)
			session = nil
		}
	}
	var supplied map[string]any
	if humanEnrollIntent != "" {
		raw, err := readFileBounded(humanEnrollIntent, maxResponseBytes)
		if err != nil {
			return err
		}
		supplied, err = proof.Parse(raw)
		if err != nil {
			return err
		}
		if supplied["state"] == "enrollment_pending" {
			supplied = enrollmentObject(supplied["intent"])
		}
		if session != nil && !sameEnrollmentValue(supplied, session.Intent) {
			return usageError("intent differs from your saved enrollment; resume the original command")
		}
	}
	if session == nil {
		if supplied == nil {
			if h.record.State != awconfig.HumanRegistered {
				return usageError("ask your issuer for the pending --intent FILE, or register your issued certificate first")
			}
			answer, err := humanIssuerRequest(ctx, h, issuer, "/v1/enrollments/"+url.PathEscape(h.record.StableID), map[string]any{"requester": map[string]any{"kind": "identity", "id": h.record.StableID, "key": h.record.DIDKey}})
			if err != nil {
				return err
			}
			if answer["state"] != "enrollment_pending" {
				return usageError("issuer did not return a pending enrollment")
			}
			supplied = enrollmentObject(answer["intent"])
		}
		session = &humanEnrollmentSession{Version: 1, Person: h.record.StableID, Key: h.record.DIDKey, Issuer: issuer, Intent: supplied}
	}
	i := enrollmentObject(session.Intent["intent"])
	if i["person"] != h.record.StableID || i["identity_key"] != h.record.DIDKey || i["organisation"] != h.record.Domain {
		return usageError("intent does not name your human ID, key and organization")
	}
	origin, rp := enrollmentText(i["origin"]), enrollmentText(i["rp_id"])
	if humanEnrollOrigin != "" && humanEnrollOrigin != origin {
		return usageError("--approval-origin differs from the issuer's signed intent")
	}
	client := humanEnrollmentClient(h, origin)
	resolver := &awid.NetTXTResolver{}
	authority, err := awid.DiscoverAuthoritativeRegistry(ctx, resolver, h.record.Domain)
	if err != nil {
		return err
	}
	registryURL, err := domainRegistryURL(authority, h.record.RegistryURL)
	if err != nil {
		return err
	}
	registry := newAWIDRegistryClient(nil, resolver)
	registry.DefaultRegistryURL = registryURL
	trustRecordedRegistryOrigin(registry.Resolver, registryURL, h.record.RegistryOperatorOrigin)
	issuerKey, err := registry.IDNamespaceController(ctx, h.record.Domain, registryURL, authority)
	if err != nil {
		return err
	}
	status := idStatusAt(registry, resolver, registryURL)
	input := proof.EnrollmentInput{IssuerKey: issuerKey, Requester: client.Requester, Origin: origin, RPID: rp, Now: time.Now().Unix()}
	if h.chain != nil {
		trust, err := proof.ReadTrust(ctx, status, h.chain["certificates"].([]any), h.record.StableID, h.record.DIDKey, h.record.Domain)
		if err != nil {
			return err
		}
		input.Trust = &trust
	}
	if session.Receipt == nil {
		if _, err := proof.CheckEnrollmentIntent(session.Intent, input); err != nil {
			return err
		}
	}
	if err := saveHumanEnrollment(sessionPath, session); err != nil {
		return err
	}
	if session.Completed {
		fmt.Fprint(cmd.ErrOrStderr(), enrollmentKeyAdvice(enrolledKeyCount(session.Binding)))
		printOutput(map[string]any{"status": "already_enrolled", "person": h.record.StableID}, func(any) string {
			return "Your enrollment is already saved. Next: aw id proof --message-file FILE --out proof.json; the recipient runs aw verify proof.json.\n"
		})
		return nil
	}
	if err := registerHumanDID(ctx, h, registry, registryURL); err != nil {
		return err
	}
	save := func() error { return saveHumanEnrollment(sessionPath, session) }
	base := map[string]any{"version": 1, "intent": session.Intent, "admission": client.Admission}
	if session.Start == nil {
		session.Start, err = humanEnrollmentExchange(ctx, client, "enrollment_start", base, session.Intent, nil)
		if err != nil {
			return err
		}
		if err = save(); err != nil {
			return err
		}
	}
	page := origin + "/enroll#" + enrollmentText(session.Start["locator"])
	fmt.Fprintf(cmd.ErrOrStderr(), "Your issuer names approval service %s (RP ID %s).\nOpen %s\n", origin, rp, page)
	_ = openBrowser(page)
	if session.Binding == nil {
		yes, err := awid.TerminalConfirmPrompt()("Register your key in that browser, then type yes to continue [y/N]: ")
		if err != nil {
			return err
		}
		if !yes {
			return usageError("enrollment saved; run the same command when ready")
		}
		text, err := awid.TerminalTextPrompt()("How many keys did you personally register in this enrollment (1-8)? ")
		if err != nil {
			return err
		}
		expected, err := enrollmentKeyCount(text)
		if err != nil {
			return err
		}
		material, err := humanEnrollmentExchange(ctx, client, "enrollment_material", base, session.Intent, nil)
		if err != nil {
			return err
		}
		if err = reviewEnrollmentKeys(material, expected, cmd.ErrOrStderr(), awid.TerminalConfirmPrompt()); err != nil {
			return err
		}

		answer, err := humanIssuerRequest(ctx, h, issuer, "/v1/enrollments/"+url.PathEscape(h.record.StableID)+"/binding", map[string]any{"material": material, "registration_count": expected})
		if err != nil {
			return err
		}
		if !sameEnrollmentValue(answer["intent"], session.Intent) {
			return usageError("issuer changed your pending intent")
		}
		session.Binding = enrollmentObject(answer["binding"])
		session.RequestBytes = enrollmentText(answer["request_bytes"])
		if err := save(); err != nil {
			return err
		}
	}
	requestBytes, err := base64.RawURLEncoding.Strict().DecodeString(session.RequestBytes)
	if err != nil {
		return err
	}
	confirmation := humanEnrollmentConfirmation(session, client.Admission)
	if session.Receipt == nil {
		input.Now = time.Now().Unix()
		if input.Trust != nil {
			trust, err := proof.ReadTrust(ctx, status, h.chain["certificates"].([]any), h.record.StableID, h.record.DIDKey, h.record.Domain)
			if err != nil {
				return err
			}
			input.Trust = &trust
		}
		if _, err := proof.ReadEnrollmentRequest("enrollment_confirm", confirmation, session.Intent, input); err != nil {
			return err
		}
		for {
			answer, err := humanEnrollmentExchange(ctx, client, "enrollment_confirm", confirmation, session.Intent, requestBytes)
			if err != nil {
				return err
			}
			if answer["state"] != "pending" {
				session.Receipt, err = proof.AssembleReceipt(requestBytes, answer, proof.AnswerInput{Status: http.StatusOK, Intent: session.Intent})
				if err != nil {
					return err
				}
				if err = save(); err != nil {
					return err
				}
				break
			}
			yes, err := awid.TerminalConfirmPrompt()("Confirm your enrollment in that browser, then type yes to continue [y/N]: ")
			if err != nil {
				return err
			}
			if !yes {
				return usageError("enrollment saved; run the same command when ready")
			}
		}
	}
	if session.Activation == nil {
		session.Activation, err = humanIssuerRequest(ctx, h, issuer, "/v1/enrollments/"+url.PathEscape(h.record.StableID)+"/finish", session.Receipt)
		if err != nil {
			return err
		}
		if err = save(); err != nil {
			return err
		}
	}
	activation := session.Activation
	if !sameEnrollmentValue(activation["intent"], session.Intent) || !sameEnrollmentValue(activation["binding"], session.Binding) {
		return usageError("activation changed your saved intent or binding")
	}
	receiptField := "creation_receipt"
	if i["purpose"] == "enroll_existing_person" {
		receiptField = "confirmation_receipt"
	}
	if !sameEnrollmentValue(activation[receiptField], session.Receipt) {
		return usageError("activation changed your saved confirmation receipt")
	}
	if i["purpose"] != "enroll_existing_person" {
		packet, err := proof.Canonical(map[string]any{"state": "enrollment_pending", "intent": session.Intent})
		if err != nil {
			return err
		}
		chain, err := parseIssuedHumanChain(packet, h.record)
		if err != nil {
			return err
		}
		if _, err = registerHumanChain(ctx, h, chain, registryURL); err != nil {
			return err
		}
	}
	trust, err := proof.ReadTrust(ctx, status, h.chain["certificates"].([]any), h.record.StableID, h.record.DIDKey, h.record.Domain)
	if err != nil {
		return err
	}
	input.Trust, input.Now = &trust, time.Now().Unix()
	if _, err = proof.CheckActivation(activation, input); err != nil {
		return err
	}
	collection := map[string]any{"v": 1, "links": []any{map[string]any{"certificate": trust.Certificate, "statement": activation["evidence"], "receipt": session.Receipt}}}
	evidencePath := filepath.Join(h.dir, "approval-evidence.json")
	preserveEvidence := false
	if prior, readErr := readFileBounded(evidencePath, maxResponseBytes); readErr == nil {
		parsed, parseErr := proof.Parse(prior)
		if parseErr != nil {
			return parseErr
		}
		if !sameEnrollmentValue(parsed, collection) {
			return usageError("existing evidence is preserved; enrollment cannot replace its creation statement")
		}
		preserveEvidence = true
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if _, err = humanEnrollmentExchange(ctx, client, "enrollment_activate", activation, session.Intent, nil); err != nil {
		return err
	}
	if _, err = humanIssuerRequest(ctx, h, issuer, "/v1/enrollments/"+url.PathEscape(h.record.StableID)+"/activate", map[string]any{}); err != nil {
		return err
	}
	if err = saveHumanEnrollment(filepath.Join(h.dir, "approval-binding.json"), session.Binding); err != nil {
		return err
	}
	if !preserveEvidence {
		if err = saveHumanEnrollment(evidencePath, collection); err != nil {
			return err
		}
	}
	session.Completed = true
	if err = save(); err != nil {
		return err
	}
	fmt.Fprint(cmd.ErrOrStderr(), enrollmentKeyAdvice(enrolledKeyCount(session.Binding)))
	report := approval.CheckHumanEvidence(approval.Link{ID: h.record.StableID, Key: h.record.DIDKey, Certificate: trust.Certificate}, enrollmentObject(activation["evidence"]), session.Receipt, &trust, &trust, time.Now().Unix())
	printOutput(report, func(any) string {
		return approval.FormatEvidence(report) + "\nNext: aw id proof --message-file FILE --out proof.json; the recipient runs aw verify proof.json.\n"
	})
	return nil
}
