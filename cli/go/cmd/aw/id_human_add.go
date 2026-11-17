package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var humanAddIssuer, humanAddOrigin, humanAddPerson, humanAddKey, humanAddOut string
var humanAddRestart bool
var idHumanAddCmd = &cobra.Command{
	Use: "add", Short: "Ask an approved-mode issuer for a new person's pending enrollment",
	Long: `Run as an existing enrolled person with --human ID --human-domain DOMAIN.
The issuer's approved-mode endpoint asks for human approval through the existing
428 protocol. Review the exact act in your approval-service browser page. Every
identity signature uses your keychain key, unlocked once at this terminal for
this command, including the approval wait. The key is wiped at command exit.
An agent requester uses the generic aw id request command instead.

This command returns a pending intent; it never enrolls the new person. The new
person first prepares their own key with aw id human init and gives you its ID
and key. Give them the resulting FILE. They run aw id human enroll --intent FILE
--issuer URL with their own --human ID --human-domain DOMAIN, then register and
confirm their approval key in the browser named by that signed intent.

In operator mode, the organization's operator instead runs aweb-key-holder
issue-person on the holder host. The new person runs aw id human register FILE.
This command has no operator mode or operator network route.
An expired approval can be archived with --restart to ask for a fresh approval.
It never extends or reuses the old approval deadline.`,
	Args: cobra.NoArgs, Annotations: map[string]string{humanCommandAnnotation: "registered"}, RunE: runIDHumanAdd,
}

func init() {
	idHumanAddCmd.Flags().StringVar(&humanAddIssuer, "issuer", "", "Issuer HTTPS origin; defaults to your saved enrollment")
	idHumanAddCmd.Flags().StringVar(&humanAddOrigin, "approval-origin", "", "Optional equality pin for your enrolled approval service")
	idHumanAddCmd.Flags().StringVar(&humanAddPerson, "person", "", "New person's prepared did:aw")
	idHumanAddCmd.Flags().StringVar(&humanAddKey, "identity-key", "", "New person's prepared identity did:key")
	idHumanAddCmd.Flags().StringVar(&humanAddOut, "out", "", "New pending-intent file; default is JSON on stdout")
	_ = idHumanAddCmd.MarkFlagRequired("person")
	_ = idHumanAddCmd.MarkFlagRequired("identity-key")
	idHumanAddCmd.Flags().BoolVar(&humanAddRestart, "restart", false, "Archive an expired approval attempt and ask the issuer for a fresh request")
	idHumanCmd.AddCommand(idHumanAddCmd)
}

// This is the typed command's requested-act binding, not a receipt verifier.
func checkHumanAddRequest(request map[string]any, human *awconfig.HumanRecord, person, key, issuer string) error {
	act := enrollmentObject(request["act"])
	target := enrollmentObject(act["target"])
	expectedRequester := map[string]any{"kind": "identity", "id": human.StableID, "key": human.DIDKey}
	if act["operation"] != "human.add" || target["person"] != person || target["identity_key"] != key || request["approver"] != human.StableID || request["organisation"] != human.Domain || enrollmentObject(request["enforcer"])["audience"] != issuer || !sameEnrollmentValue(request["requester"], expectedRequester) {
		return usageError("issuer's approval request differs from the person and action you requested")
	}
	return proof.CheckDefinition(request)
}

func runIDHumanAdd(cmd *cobra.Command, args []string) error {
	h := activeHuman
	h.operation = "ask your issuer to add human " + humanAddPerson
	if !strings.HasPrefix(humanAddPerson, "did:aw:") {
		return usageError("--person must be the new person's prepared did:aw")
	}
	if _, err := awid.DecodeStableID(strings.TrimPrefix(humanAddPerson, "did:aw:")); err != nil {
		return err
	}
	if _, err := awid.ExtractPublicKey(humanAddKey); err != nil {
		return err
	}
	saved, err := loadHumanEnrollment(filepath.Join(h.dir, "enrollment-session.json"), h)
	if err != nil {
		return err
	}
	issuer := strings.TrimSpace(humanAddIssuer)
	if issuer == "" && saved != nil {
		issuer = saved.Issuer
	}
	if issuer == "" {
		return usageError("supply --issuer URL or finish your own enrollment first")
	}
	issuer, err = canonicalHumanIssuer(issuer)
	if err != nil {
		return err
	}
	raw, err := readFileBounded(filepath.Join(h.dir, "approval-binding.json"), maxResponseBytes)
	if err != nil {
		return fmt.Errorf("read your enrolled approval service (run aw id human enroll first): %w", err)
	}
	binding, err := proof.Parse(raw)
	if err != nil {
		return err
	}
	origin := enrollmentText(enrollmentObject(binding["binding"])["origin"])
	if humanAddOrigin != "" && humanAddOrigin != origin {
		return usageError("--approval-origin differs from your enrolled binding")
	}
	client := humanEnrollmentClient(h, origin)
	client.PollInterval = 5 * time.Second
	client.Notify = cmd.ErrOrStderr()
	body := map[string]any{"person": humanAddPerson, "identity_key": humanAddKey, "approver": h.record.StableID}
	canonical, err := proof.Canonical(body)
	if err != nil {
		return err
	}
	targetURL := issuer + "/v1/humans"
	digest := sha256.Sum256(append([]byte(targetURL+"\n"), canonical...))
	recordPath := filepath.Join(h.dir, fmt.Sprintf("human-add-%x.json", digest))
	client.Retain = approvalRecordWriter(recordPath, origin, targetURL)
	ctx := cmd.Context()
	var presentation []byte
	var result *idRequestExecutionResult
	var request map[string]any
	showApproval := func() {
		fmt.Fprintf(cmd.ErrOrStderr(), "Open %s/ and sign in as %s to review human.add for %s.\n", origin, h.record.StableID, humanAddPerson)
		_ = openBrowser(origin + "/")
	}
	var original []byte
	var receipt map[string]any
	if _, statErr := os.Stat(recordPath); statErr == nil {
		original, receipt, err = readApprovalRecord(recordPath, origin, targetURL)
		if err != nil {
			return err
		}
		request, err = proof.Parse(original)
		if err != nil {
			return err
		}
		if err = checkHumanAddRequest(request, h.record, humanAddPerson, humanAddKey, issuer); err != nil {
			return err
		}
		archive, err := restartHumanAttempt(recordPath, request, time.Now().Unix(), humanAddRestart, false)
		if err != nil {
			return err
		}
		if archive != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Expired approval preserved in %s. Asking for a fresh approval.\n", archive)
			original = nil
			receipt = nil
			request = nil
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if original != nil {
		if receipt == nil {
			showApproval()
		}
		presentation, err = client.Resume(ctx, original, receipt)
		if err != nil {
			return err
		}
	} else {
		result, err = humanIssuerHTTP(ctx, h, issuer, "/v1/humans", body)
		if err != nil {
			return err
		}
		if result.Status == http.StatusPreconditionRequired {
			pending, err := client.From428(result.Body, result.Status)
			if err != nil {
				return err
			}
			request = pending.Request
			if err = checkHumanAddRequest(request, h.record, humanAddPerson, humanAddKey, issuer); err != nil {
				return err
			}
			showApproval()
			presentation, err = client.Complete428(ctx, result.Body, result.Status)
			if err != nil {
				return err
			}
		}
	}
	if presentation != nil {
		packet, err := proof.Parse(presentation)
		if err != nil {
			return err
		}
		result, err = humanIssuerHTTP(ctx, h, issuer, "/v1/humans", packet)
		if err != nil {
			return err
		}
	}
	if result == nil || result.Status != http.StatusOK {
		if result == nil {
			return fmt.Errorf("issuer returned no pending intent")
		}
		return fmt.Errorf("approved add returned HTTP %d: %s", result.Status, result.Body)
	}
	answer, err := proof.Parse(result.Body)
	if err != nil {
		return err
	}
	i := enrollmentObject(enrollmentObject(answer["intent"])["intent"])
	if answer["state"] != "enrollment_pending" || i["person"] != humanAddPerson || i["identity_key"] != humanAddKey || i["organisation"] != h.record.Domain {
		return usageError("issuer returned a different person or no pending intent")
	}
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
	issuerKey, err := registry.IDNamespaceController(ctx, h.record.Domain, registryURL, authority)
	if err != nil {
		return err
	}
	if _, err = proof.CheckEnrollmentIntent(enrollmentObject(answer["intent"]), proof.EnrollmentInput{
		IssuerKey: issuerKey, Requester: map[string]any{"kind": "identity", "id": humanAddPerson, "key": humanAddKey},
		Origin: origin, RPID: enrollmentText(enrollmentObject(binding["binding"])["rp_id"]), Now: time.Now().Unix(),
	}); err != nil {
		return err
	}
	if request != nil {
		cert := enrollmentObject(enrollmentObject(i["pending_certificate"])["certificate"])
		certificate, err := awid.IDCertificateID(cert)
		if err != nil {
			return err
		}
		if enrollmentObject(enrollmentObject(request["act"])["target"])["certificate"] != certificate {
			return usageError("pending certificate differs from the approved act")
		}
	}
	if err = writeExchangeFile(humanAddOut, result.Body); err != nil {
		return err
	}
	file := humanAddOut
	if file == "" || file == "-" {
		file = "the saved intent file"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Pending acceptance by %s. Give %s to that person. They run aw id human enroll --intent FILE --issuer %s --human %s --human-domain %s, then register and confirm their key in the named browser.\n", humanAddPerson, file, issuer, humanAddPerson, h.record.Domain)
	return nil
}
