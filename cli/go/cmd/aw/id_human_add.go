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
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var humanAddIssuer, humanAddOrigin, humanAddPerson, humanAddKey, humanAddOut string
var humanAddRestart bool
var idHumanAddCmd = &cobra.Command{
	Use: "add", Short: "Ask your issuer to add a new person",
	Long: `Run as a current person with --human ID --human-domain DOMAIN.
With no human_approval requirement, the issuer returns a certificate without
contacting an approval service or requiring your enrollment. Give it to the new
person, who runs aw id human register FILE with their own human selector.
If the organisation requires approval, you must be enrolled; the issuer asks
for human approval through the existing 428 protocol. Review the exact act in your approval-service browser page. Every
identity signature uses your keychain key, unlocked once at this terminal for
this command, including the approval wait. The key is wiped at command exit.
When approval is required, an agent requester uses the generic aw id request
command instead; agents cannot use the unconfigured issuance path.

The configured approval path returns a pending intent; it never enrolls the new person. The new
person first prepares their own key with aw id human init and gives you its ID
and key. Give them the resulting FILE. They run aw id human enroll --intent FILE
--issuer URL with their own --human ID --human-domain DOMAIN, then register and
confirm their approval key in the browser named by that signed intent.

The first person is still bootstrapped by the organization's operator on the
holder host. There is no operator network route.
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

// This checks the handover result against the requested person and the namespace
// controller obtained independently from DNS and the registry, not its own key.
func checkHumanAddIssued(answer map[string]any, person, key, domain, controller string) error {
	if answer["state"] != "issued" || answer["person"] != person || answer["identity_key"] != key {
		return usageError("issuer returned a different person or identity key")
	}
	public, err := awid.ExtractPublicKey(key)
	if err != nil {
		return err
	}
	if awid.ComputeStableID(public) != person {
		return usageError("issued fresh person does not match the prepared identity key")
	}
	signed := enrollmentObject(answer["certificate"])
	cert := enrollmentObject(signed["certificate"])
	if cert["id"] != person || cert["domain"] != domain || cert["kind"] != "human" || cert["issuer_key"] != controller || !sameEnrollmentValue(cert["parent"], map[string]any{"kind": "namespace", "id": domain}) {
		return usageError("issued human certificate differs from the requested organisation or controller")
	}
	return awid.VerifyIDCertificate(signed, controller)
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
	issuer := strings.TrimSpace(humanAddIssuer)
	if issuer == "" {
		saved, err := loadHumanEnrollment(filepath.Join(h.dir, "enrollment-session.json"), h)
		if err != nil {
			return err
		}
		if saved != nil {
			issuer = saved.Issuer
		}
	}
	if issuer == "" {
		return usageError("supply --issuer URL or finish your own enrollment first")
	}
	issuer, err := canonicalHumanIssuer(issuer)
	if err != nil {
		return err
	}
	var origin string
	var binding map[string]any
	var client *approval.Client
	body := map[string]any{"person": humanAddPerson, "identity_key": humanAddKey, "approver": h.record.StableID}
	canonical, err := proof.Canonical(body)
	if err != nil {
		return err
	}
	targetURL := issuer + "/v1/humans"
	digest := sha256.Sum256(append([]byte(targetURL+"\n"), canonical...))
	recordPath := filepath.Join(h.dir, fmt.Sprintf("human-add-%x.json", digest))
	loadApproval := func() error {
		raw, e := readFileBounded(filepath.Join(h.dir, "approval-binding.json"), maxResponseBytes)
		if e != nil {
			return fmt.Errorf("this issuer requires approval; run aw id human enroll first: %w", e)
		}
		binding, e = proof.Parse(raw)
		if e != nil {
			return e
		}
		origin = enrollmentText(enrollmentObject(binding["binding"])["origin"])
		if humanAddOrigin != "" && humanAddOrigin != origin {
			return usageError("--approval-origin differs from your enrolled binding")
		}
		client = humanEnrollmentClient(h, origin)
		client.PollInterval = 5 * time.Second
		client.Notify = cmd.ErrOrStderr()
		client.Retain = approvalRecordWriter(recordPath, origin, targetURL)
		return nil
	}
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
		if err = loadApproval(); err != nil {
			return err
		}
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
			if err = loadApproval(); err != nil {
				return err
			}
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
			return fmt.Errorf("issuer returned no issuance result")
		}
		return fmt.Errorf("add returned HTTP %d: %s", result.Status, result.Body)
	}
	answer, err := proof.Parse(result.Body)
	if err != nil {
		return err
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
	if answer["state"] == "issued" {
		if err = checkHumanAddIssued(answer, humanAddPerson, humanAddKey, h.record.Domain, issuerKey); err != nil {
			return err
		}
		if request != nil {
			cert := enrollmentObject(enrollmentObject(answer["certificate"])["certificate"])
			id, e := awid.IDCertificateID(cert)
			if e != nil {
				return e
			}
			if enrollmentObject(enrollmentObject(request["act"])["target"])["certificate"] != id {
				return usageError("issued certificate differs from the approved act")
			}
		}
		if err = writeExchangeFile(humanAddOut, result.Body); err != nil {
			return err
		}
		file := humanAddOut
		if file == "" || file == "-" {
			file = "the saved certificate file"
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Issued %s without enrolling an approval key. Give %s to that person. They run aw id human register FILE --human %s --human-domain %s. Enrollment is optional.\n", humanAddPerson, file, humanAddPerson, h.record.Domain)
		return nil
	}
	if client == nil {
		if err = loadApproval(); err != nil {
			return err
		}
	}
	i := enrollmentObject(enrollmentObject(answer["intent"])["intent"])
	if answer["state"] != "enrollment_pending" || i["person"] != humanAddPerson || i["identity_key"] != humanAddKey || i["organisation"] != h.record.Domain {
		return usageError("issuer returned a different person or no pending intent")
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
