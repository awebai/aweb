package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/approval"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/atomicfile"
	"github.com/spf13/cobra"
)

var humanRefreshIssuer string
var idHumanRefreshBindingCmd = &cobra.Command{
	Use: "refresh-binding", Short: "Refresh your live approval binding after an issuer or controller change",
	Long: `Run this yourself with --human ID --human-domain DOMAIN at a terminal.
The holder re-signs your existing approval keys under its current authority.
The approval service checks your own-person packet; no new key is enrolled.

The new live binding is saved separately from the original enrollment and
historical proof evidence. A retry carries the same retained packet until the
service confirms it. While that packet exists, --issuer does not replace it.
A definitive refusal names the retained file to remove before requesting a new
packet. An uncertain failure keeps the exact packet for replay.
This command never replaces a lost approval key.`,
	Args: cobra.NoArgs, Annotations: map[string]string{humanCommandAnnotation: "registered"}, RunE: runIDHumanRefreshBinding,
}

func init() {
	idHumanRefreshBindingCmd.Flags().StringVar(&humanRefreshIssuer, "issuer", "", "Issuer HTTPS origin; defaults to your saved enrollment")
	idHumanCmd.AddCommand(idHumanRefreshBindingCmd)
}

type humanBindingRefreshSource uint8

const (
	bindingRefreshFromHolder humanBindingRefreshSource = iota
	bindingRefreshRetainedReplay
)

type humanBindingRefreshInput struct {
	Source  humanBindingRefreshSource
	Human   *humanParticipation
	Current map[string]any
}
type humanBindingRefreshPacket struct {
	Body    map[string]any
	Binding map[string]any
	Origin  string
}
type humanBindingRefreshAnswer struct {
	Status int
	Body   map[string]any
}

// loadHumanApprovalBinding selects live approval authority, never proof history.
// Initial enrollment's B remains available for its immutable proof commitments.
func loadHumanApprovalBinding(dir string) (map[string]any, error) {
	for _, name := range []string{"approval-live-binding.json", "approval-binding.json"} {
		raw, err := readFileBounded(filepath.Join(dir, name), maxResponseBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		binding, err := proof.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("The saved approval binding in %q is unreadable. Restore that file from your last successful enrollment or refresh before retrying: %w", filepath.Join(dir, name), err)
		}
		return binding, nil
	}
	return nil, fmt.Errorf("No approval binding is saved. Run aw id human enroll with your human identity first.")
}

func (in humanBindingRefreshInput) packetError(detail string, cause error) error {
	var message string
	if in.Source == bindingRefreshRetainedReplay {
		message = fmt.Sprintf("The retained refresh packet in %q is unreadable or does not match this person, binding or service. Restore the exact packet from the interrupted request; if the issuer confirms it cannot be used, remove that file and repeat refresh-binding with --issuer URL to request a new packet.", filepath.Join(in.Human.dir, "approval-binding-refresh.json"))
	} else {
		message = "The holder returned an unreadable or mismatched refresh packet. Check the selected issuer and this person's last successful live binding before retrying."
	}
	if cause != nil {
		return fmt.Errorf("%s %s: %w", message, detail, cause)
	}
	return fmt.Errorf("%s %s", message, detail)
}

func bindingRefreshBody(binding map[string]any) (map[string]any, error) {
	body, ok := binding["binding"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("The approval binding is unreadable. Restore the saved enrollment before refreshing.")
	}
	return body, nil
}

// readHumanBindingRefreshPacket correlates the holder's reply with this command.
// Current issuer, credential and signature checks belong to the service's
// binding-refresh-v1 owner (approval-service docs/protocol.md, Current-issuer binding refresh).
func readHumanBindingRefreshPacket(raw []byte, in humanBindingRefreshInput) (*humanBindingRefreshPacket, error) {
	packet, err := proof.Parse(raw)
	if err != nil {
		return nil, in.packetError("The packet is not valid JSON.", err)
	}
	refusal := in.packetError("The packet does not match the selected person, live binding or service.", nil)
	version, ok := packet["version"].(json.Number)
	if !ok || version.String() != "1" || len(packet) != 5 {
		return nil, refusal
	}
	requester := map[string]any{"kind": "identity", "id": in.Human.record.StableID, "key": in.Human.record.DIDKey}
	if !sameEnrollmentValue(packet["requester"], requester) {
		return nil, refusal
	}
	chain, ok := packet["id_chain"].([]any)
	if !ok || len(chain) == 0 {
		return nil, refusal
	}
	binding, ok := packet["binding"].(map[string]any)
	if !ok {
		return nil, refusal
	}
	body, err := bindingRefreshBody(binding)
	if err != nil {
		return nil, in.packetError("The packet's binding is unreadable.", err)
	}
	current, err := bindingRefreshBody(in.Current)
	if err != nil {
		return nil, err
	}
	origin, ok := body["origin"].(string)
	if !ok || origin == "" || current["origin"] != origin || body["person"] != in.Human.record.StableID || body["identity_key"] != in.Human.record.DIDKey || body["organisation"] != in.Human.record.Domain {
		return nil, refusal
	}
	live, err := proof.Commitment("binding_commitment", in.Current)
	if err != nil {
		return nil, err
	}
	candidate, err := proof.Commitment("binding_commitment", binding)
	if err != nil {
		return nil, err
	}
	// Saving live B can succeed before removal of the pending packet. Its exact
	// replay remains valid, without rolling back the successfully saved binding.
	if packet["previous_binding_commitment"] != live && (in.Source != bindingRefreshRetainedReplay || candidate != live) {
		return nil, refusal
	}
	return &humanBindingRefreshPacket{Body: packet, Binding: binding, Origin: origin}, nil
}

func bindingRefreshAnswerError(err error) error {
	var refusal *proof.BindingRefreshServiceError
	if errors.As(err, &refusal) {
		if advice := awid.SanitizeErrorText(refusal.Advice); advice != "" {
			return fmt.Errorf("%w. %s", err, advice)
		}
		return fmt.Errorf("%w. Ask the issuer to check this binding refresh.", err)
	}
	return fmt.Errorf("The service did not confirm this binding. Keep the retained packet and retry; if refusal persists, ask your issuer to check the active enrollment: %w", err)
}

// The shared answer reader establishes a service refusal. Unavailable or
// ambiguous answers retain exact replay (docs/id-certificates.md:105-112).
func bindingRefreshRecoveryError(err error, pendingPath string) error {
	var refusal *proof.BindingRefreshServiceError
	if errors.As(err, &refusal) {
		status := refusal.Service.HTTPStatus
		if status >= 400 && status < 500 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests {
			return fmt.Errorf("%w. The service definitively refused this packet. Restore your last successful live binding if it changed elsewhere. To ask the holder for a new packet, remove %q and repeat refresh-binding with --issuer URL for the current issuer.", err, pendingPath)
		}
	}
	return err
}

func saveCheckedHumanBindingRefresh(h *humanParticipation, packet *humanBindingRefreshPacket, answer humanBindingRefreshAnswer) error {
	if _, err := proof.ReadBindingRefreshAnswer(answer.Body, proof.BindingRefreshAnswerInput{Status: answer.Status, Binding: packet.Binding}); err != nil {
		return bindingRefreshAnswerError(err)
	}
	return saveHumanEnrollment(filepath.Join(h.dir, "approval-live-binding.json"), packet.Binding)
}

func humanBindingRefreshIssuer(h *humanParticipation, issuerOrigin string) (string, error) {
	if issuerOrigin != "" {
		return canonicalHumanIssuer(issuerOrigin)
	}
	session, err := loadHumanEnrollment(filepath.Join(h.dir, "enrollment-session.json"), h)
	if err != nil {
		return "", err
	}
	if session == nil {
		return "", usageError("Supply --issuer URL for your existing enrollment; ask your issuer for its HTTPS origin.")
	}
	return canonicalHumanIssuer(session.Issuer)
}

var humanHolderErrorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

// humanBindingRefreshHolderError preserves the holder's controlled next step.
// Holder enrollment errors use an error envelope, not the service answer profile.
func humanBindingRefreshHolderError(result *idRequestExecutionResult) error {
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(result.Body, &response); err == nil && humanHolderErrorCode.MatchString(response.Error.Code) && strings.TrimSpace(response.Error.Message) != "" {
		message := awid.SanitizeErrorText(response.Error.Message)
		if message != "" {
			refusal := &awid.APIError{StatusCode: result.Status, Body: string(result.Body)}
			return withErrorCode(response.Error.Code, &plainRefusal{text: message, jsonMessage: message, err: refusal})
		}
	}
	return fmt.Errorf("Holder refused binding refresh (HTTP %d). Check the person's current ID chain and active enrollment with the issuer.", result.Status)
}

func runIDHumanRefreshBinding(cmd *cobra.Command, args []string) error {
	h := activeHuman
	h.operation = "refresh your live approval binding"
	current, err := loadHumanApprovalBinding(h.dir)
	if err != nil {
		return err
	}
	pendingPath := filepath.Join(h.dir, "approval-binding-refresh.json")
	source := bindingRefreshRetainedReplay
	raw, err := readFileBounded(pendingPath, maxResponseBytes)
	if errors.Is(err, os.ErrNotExist) {
		source = bindingRefreshFromHolder
		issuer, issuerErr := humanBindingRefreshIssuer(h, humanRefreshIssuer)
		if issuerErr != nil {
			return issuerErr
		}
		commitment, commitmentErr := proof.Commitment("binding_commitment", current)
		if commitmentErr != nil {
			return commitmentErr
		}
		result, requestErr := humanIssuerHTTP(cmd.Context(), h, issuer, "/v1/enrollments/"+url.PathEscape(h.record.StableID)+"/refresh-binding", map[string]any{"previous_binding_commitment": commitment})
		if requestErr != nil {
			return fmt.Errorf("The holder could not prepare the refresh. Check its availability and retry: %w", requestErr)
		}
		if result.Status != http.StatusOK {
			return humanBindingRefreshHolderError(result)
		}
		raw = result.Body
	} else if err != nil {
		return fmt.Errorf("Cannot read the retained refresh packet in %q. Restore access to that exact packet before retrying: %w", pendingPath, err)
	}
	packet, err := readHumanBindingRefreshPacket(raw, humanBindingRefreshInput{Human: h, Current: current, Source: source})
	if err != nil {
		return err
	}
	if err = (atomicfile.Options{Mode: 0600, ParentMode: 0700}).Write(pendingPath, raw); err != nil {
		return err
	}
	client, err := humanEnrollmentClient(h, packet.Origin)
	if err != nil {
		return err
	}
	answer, err := client.RefreshBinding(cmd.Context(), approval.BindingRefreshInput{Packet: packet.Body})
	if err != nil {
		return bindingRefreshRecoveryError(bindingRefreshAnswerError(err), pendingPath)
	}
	if err = saveCheckedHumanBindingRefresh(h, packet, humanBindingRefreshAnswer{Status: answer.Status, Body: answer.Body}); err != nil {
		return bindingRefreshRecoveryError(err, pendingPath)
	}
	if err = os.Remove(pendingPath); err != nil {
		return fmt.Errorf("Live binding saved but the retained packet could not be removed. Repeat refresh-binding to complete the exact replay: %w", err)
	}
	printOutput(answer.Body, func(any) string {
		return "Approval binding refreshed. Your historical enrollment evidence is unchanged.\n"
	})
	return nil
}
