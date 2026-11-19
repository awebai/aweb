package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
service confirms it. This command never replaces a lost approval key.`,
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
		return proof.Parse(raw)
	}
	return nil, fmt.Errorf("No approval binding is saved. Run aw id human enroll with your human identity first.")
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
		return nil, fmt.Errorf("The holder returned an unreadable refresh packet. Check the issuer and retry: %w", err)
	}
	refusal := fmt.Errorf("The holder's packet does not match this person, live binding or service. Check the issuer and restore the last successful live binding before retrying.")
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
		return nil, err
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
	if errors.As(err, &refusal) && refusal.Advice != "" {
		return fmt.Errorf("%w. %s", err, refusal.Advice)
	}
	return fmt.Errorf("The service did not confirm this binding. Keep the retained packet and retry; if refusal persists, ask your issuer to check the active enrollment: %w", err)
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

// humanBindingRefreshHolderError preserves the holder's controlled next step.
// Holder enrollment errors use an error envelope, not the service answer profile.
func humanBindingRefreshHolderError(result *idRequestExecutionResult) error {
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(result.Body, &response); err == nil && strings.TrimSpace(response.Error.Code) != "" && strings.TrimSpace(response.Error.Message) != "" {
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
		return err
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
		return bindingRefreshAnswerError(err)
	}
	if err = saveCheckedHumanBindingRefresh(h, packet, humanBindingRefreshAnswer{Status: answer.Status, Body: answer.Body}); err != nil {
		return err
	}
	if err = os.Remove(pendingPath); err != nil {
		return fmt.Errorf("Live binding saved but the retained packet could not be removed. Repeat refresh-binding to complete the exact replay: %w", err)
	}
	printOutput(answer.Body, func(any) string {
		return "Approval binding refreshed. Your historical enrollment evidence is unchanged.\n"
	})
	return nil
}
