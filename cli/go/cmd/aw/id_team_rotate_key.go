package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw id team rotate-key replaces the team controller key at AWID on the atomic
// path of docs/principal-attestation.md §5: every team-key-signed record the
// team has stored (its aweb.team-server/1 record, custodian, member-custody and
// member-person records) is re-signed by the new key and swapped with the key in
// one transaction. A record is re-signed only after it verifies against the
// team's current key, so the registry cannot get arbitrary content signed by the
// new key. The records come from AWID's paginated same-team read
// (/signed-records), so the reads do not grow with the team. If AWID's 409 still
// names custodian records that were not sent, such as ones published during the
// run, those are read, verified and re-signed, and the rotation is retried
// exactly once.
//
// The new key is stored as pending before AWID sees it and promoted once AWID
// holds it, so an interruption never loses a key AWID may already have. Member
// certificates are signed by the team key and are not re-issued here.

type teamRotateKeyOptions struct {
	Domain      string
	Team        string
	RegistryURL string
	Now         func() time.Time
	// HTTPClient, when set, carries every AWID request.
	HTTPClient *http.Client
	// PageSize is the signed-records page size; zero is AWID's default.
	PageSize int
	// AfterRead runs after the records are read and before the first attempt.
	AfterRead func()
	// BeforeRetry runs between the refused first attempt and the retry.
	BeforeRetry func()
}

type teamRotateKeyOutput struct {
	Status             string   `json:"status"`
	TeamID             string   `json:"team_id"`
	OldTeamDIDKey      string   `json:"old_team_did_key"`
	NewTeamDIDKey      string   `json:"new_team_did_key"`
	RegistryURL        string   `json:"registry_url"`
	ResignedTeamServer bool     `json:"resigned_team_server"`
	ResignedCustodians int      `json:"resigned_custodians"`
	ResignedCustody    int      `json:"resigned_member_custody"`
	ResignedPerson     int      `json:"resigned_member_person"`
	LearnedCustodians  []string `json:"learned_custodians,omitempty"`
	Notice             string   `json:"notice"`
}

var (
	teamRotateKeyTeam        string
	teamRotateKeyNamespace   string
	teamRotateKeyRegistryURL string

	teamRotateKeyCmd = &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the team controller key, re-signing the team's AWID records with it",
		Long: "Replace the team controller key at AWID with a new local key, under the namespace\n" +
			"controller key. Every record the team key has signed at AWID (the team-server record,\n" +
			"custodian, member-custody and member-person records) is verified, re-signed by the\n" +
			"new key and swapped with the key in one atomic request.\n\n" +
			"Every member certificate is signed by the team key, so after a rotation all of them are\n" +
			"invalid: re-issue each with `aw id team reissue-cert`. If the command is interrupted,\n" +
			"run it again: it resumes with the same new key.",
		RunE: runTeamRotateKey,
	}
)

func init() {
	teamRotateKeyCmd.Flags().StringVar(&teamRotateKeyTeam, "team", "", "Team name")
	teamRotateKeyCmd.Flags().StringVar(&teamRotateKeyNamespace, "namespace", "", "Namespace domain")
	teamRotateKeyCmd.Flags().StringVar(&teamRotateKeyRegistryURL, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamRotateKeyCmd)
}

func runTeamRotateKey(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	out, err := executeTeamRotateKey(ctx, teamRotateKeyOptions{
		Domain:      teamRotateKeyNamespace,
		Team:        teamRotateKeyTeam,
		RegistryURL: teamRotateKeyRegistryURL,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatTeamRotateKey)
	return nil
}

func formatTeamRotateKey(v any) string {
	out := v.(teamRotateKeyOutput)
	var b strings.Builder
	if out.Status == "promoted" {
		fmt.Fprintf(&b, "AWID already held the new team key for %s; it is now the local team key.\n", out.TeamID)
	} else {
		fmt.Fprintf(&b, "Rotated the team key of %s.\n", out.TeamID)
		fmt.Fprintf(&b, "Re-signed: team server record %t, %d custodian, %d member-custody, %d member-person record(s).\n",
			out.ResignedTeamServer, out.ResignedCustodians, out.ResignedCustody, out.ResignedPerson)
	}
	if len(out.LearnedCustodians) > 0 {
		fmt.Fprintf(&b, "AWID named custodian records aw could not discover itself: %s.\n", strings.Join(out.LearnedCustodians, ", "))
	}
	fmt.Fprintf(&b, "Old team key: %s\nNew team key: %s\n", out.OldTeamDIDKey, out.NewTeamDIDKey)
	b.WriteString(out.Notice + "\n")
	return b.String()
}

func teamRotateKeyNotice(domain, team string) string {
	return fmt.Sprintf("Every member certificate of %s was signed by the old team key and is no longer valid. "+
		"Re-issue each member's certificate with `aw id team reissue-cert <alias> --team %s --namespace %s`.",
		awid.BuildTeamID(domain, team), team, domain)
}

func didOf(key ed25519.PrivateKey) string {
	return awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
}

// teamRotation holds what one rotation reads, verifies and re-signs.
type teamRotation struct {
	registry    *awid.RegistryClient
	registryURL string
	domain      string
	team        string
	teamID      string
	currentDID  string
	newKey      ed25519.PrivateKey
	now         time.Time
	pageSize    int
	resigned    awid.ResignedRecords
}

func (r *teamRotation) verifyStored(kind string, stored *awid.SignedAttestationRecord, keyField, key string) error {
	if stored.Record["type"] != kind || stored.Record["team_id"] != r.teamID || stored.Record[keyField] != key {
		return &awid.AttestationRecordError{Code: "record_invalid", Message: fmt.Sprintf("AWID served a %s record for another team or key", kind)}
	}
	if err := awid.VerifyAttestationRecord(stored.Record, stored.Signature, r.currentDID); err != nil {
		return fmt.Errorf("the stored %s record for %s does not verify against the team's current key, so aw will not re-sign it: %w", kind, key, err)
	}
	return nil
}

func (r *teamRotation) addCustodian(ctx context.Context, custodianID string) error {
	stored, err := r.registry.GetTeamCustodianRecord(ctx, r.registryURL, r.domain, r.team, custodianID)
	if err != nil {
		return fmt.Errorf("read custodian record %s: %w", custodianID, err)
	}
	if err := r.verifyStored(awid.TeamCustodianRecordType, stored, "custodian_id", custodianID); err != nil {
		return err
	}
	resigned, err := awid.ResignAttestationRecord(r.newKey, stored.Record, r.now)
	if err != nil {
		return err
	}
	r.resigned.TeamCustodians = append(r.resigned.TeamCustodians, resigned)
	return nil
}

// collect reads every record the team has stored at AWID, in pages, verifies
// each against the current key and re-signs it with the new key.
func (r *teamRotation) collect(ctx context.Context, currentKey ed25519.PrivateKey) error {
	items, err := r.registry.ListTeamSignedRecords(ctx, r.registryURL, r.domain, r.team, r.pageSize, currentKey)
	if err != nil {
		return fmt.Errorf("read the signed records of %s: %w", r.teamID, err)
	}
	keyed := map[string]struct {
		recordType string
		keyField   string
		into       *[]awid.SignedAttestationRecord
	}{
		"team_custodians": {awid.TeamCustodianRecordType, "custodian_id", &r.resigned.TeamCustodians},
		"member_custody":  {awid.MemberCustodyRecordType, "certificate_id", &r.resigned.MemberCustody},
		"member_person":   {awid.MemberPersonRecordType, "certificate_id", &r.resigned.MemberPerson},
	}
	for _, item := range items {
		if item.Kind == "team_server" {
			if r.resigned.TeamServer != nil {
				return fmt.Errorf("AWID returned more than one team server record for %s", r.teamID)
			}
			if _, err := awid.VerifyTeamServerRecord(item.Record, item.Signature, r.teamID, r.currentDID, r.now); err != nil {
				return fmt.Errorf("the stored team server record does not verify against the team's current key, so aw will not re-sign it: %w", err)
			}
			resigned, err := awid.ResignTeamServerRecord(r.newKey, item.Record, r.now)
			if err != nil {
				return err
			}
			r.resigned.TeamServer = &resigned
			continue
		}
		kind, ok := keyed[item.Kind]
		if !ok || item.Key == nil {
			return fmt.Errorf("AWID returned a signed record of unknown kind %q for %s", item.Kind, r.teamID)
		}
		stored := item.SignedAttestationRecord
		if err := r.verifyStored(kind.recordType, &stored, kind.keyField, *item.Key); err != nil {
			return err
		}
		resigned, err := awid.ResignAttestationRecord(r.newKey, stored.Record, r.now)
		if err != nil {
			return err
		}
		*kind.into = append(*kind.into, resigned)
	}
	return nil
}

// onlyMissingCustodians is the one 409 a retry can fix: AWID names custodian
// records aw could not discover, and nothing else is wrong.
func onlyMissingCustodians(detail *awid.ResignedRecordsIncomplete) bool {
	missing := detail.Missing
	return len(missing.TeamCustodians) > 0 && !missing.TeamServer && len(missing.MemberCustody) == 0 &&
		len(missing.MemberPerson) == 0 && detail.Extra.IsEmpty() && detail.Changed.IsEmpty()
}

func rotateRefusal(teamID string, err error) error {
	if code, ok := registryStatusCode(err); ok && code == http.StatusRequestEntityTooLarge {
		return fmt.Errorf("AWID refused the rotation of %s: the re-signed records exceed its rotate body limit (AWID_ROTATE_MAX_BODY_BYTES, at least 4 MiB); the team key is unchanged: %w", teamID, err)
	}
	return fmt.Errorf("AWID refused the rotation of %s; the team key is unchanged: %w", teamID, err)
}

func executeTeamRotateKey(ctx context.Context, opts teamRotateKeyOptions) (teamRotateKeyOutput, error) {
	registry, registryURL, domain, teamName, err := teamServerTarget(ctx, teamServerOptions{
		Domain: opts.Domain, Team: opts.Team, RegistryURL: opts.RegistryURL,
	})
	if err != nil {
		return teamRotateKeyOutput{}, err
	}
	if opts.HTTPClient != nil {
		registry = awid.NewAWIDRegistryClient(opts.HTTPClient, nil)
	}
	teamID := awid.BuildTeamID(domain, teamName)
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}

	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return teamRotateKeyOutput{}, fmt.Errorf("load the namespace controller key for %s: %w", domain, err)
	}
	namespace, _, err := registry.GetNamespaceAt(ctx, registryURL, domain)
	if err != nil {
		return teamRotateKeyOutput{}, fmt.Errorf("fetch namespace %s: %w", domain, err)
	}
	if strings.TrimSpace(namespace.ControllerDID) != didOf(controllerKey) {
		return teamRotateKeyOutput{}, fmt.Errorf("local controller key for %s does not match the registered namespace controller", domain)
	}

	currentKey, err := awconfig.LoadTeamKey(domain, teamName)
	if err != nil {
		return teamRotateKeyOutput{}, teamKeyLoadError(teamID, domain, err)
	}
	pendingKey, err := awconfig.LoadPendingTeamKey(domain, teamName)
	if err != nil {
		return teamRotateKeyOutput{}, fmt.Errorf("load the pending team key of %s: %w", teamID, err)
	}
	team, err := registry.GetTeam(ctx, registryURL, domain, teamName, currentKey)
	if err != nil && pendingKey != nil {
		team, err = registry.GetTeam(ctx, registryURL, domain, teamName, pendingKey)
	}
	if code, ok := registryStatusCode(err); ok && code == http.StatusForbidden {
		return teamRotateKeyOutput{}, fmt.Errorf("local team controller key does not match AWID team controller for %s: AWID refused a team read signed with it: %w", teamID, err)
	}
	if err != nil {
		return teamRotateKeyOutput{}, fmt.Errorf("load AWID team %s: %w", teamID, err)
	}
	currentDID := strings.TrimSpace(team.TeamDIDKey)
	out := teamRotateKeyOutput{TeamID: teamID, OldTeamDIDKey: didOf(currentKey), RegistryURL: registryURL, Notice: teamRotateKeyNotice(domain, teamName)}

	if pendingKey != nil && didOf(pendingKey) == currentDID {
		if err := awconfig.PromotePendingTeamKey(domain, teamName); err != nil {
			return teamRotateKeyOutput{}, fmt.Errorf("AWID holds the pending team key of %s, but saving it as the team key failed: %w", teamID, err)
		}
		out.Status, out.NewTeamDIDKey = "promoted", currentDID
		return out, nil
	}
	if didOf(currentKey) != currentDID {
		return teamRotateKeyOutput{}, fmt.Errorf("local team controller key does not match AWID team controller for %s (local=%s, awid=%s)", teamID, didOf(currentKey), currentDID)
	}
	newKey := pendingKey
	if newKey == nil {
		_, newKey, err = awid.GenerateKeypair()
		if err != nil {
			return teamRotateKeyOutput{}, err
		}
		if err := awconfig.SavePendingTeamKey(domain, teamName, newKey); err != nil {
			return teamRotateKeyOutput{}, fmt.Errorf("save the new team key of %s before rotating: %w", teamID, err)
		}
	}

	rotation := &teamRotation{
		registry: registry, registryURL: registryURL, domain: domain, team: teamName, teamID: teamID,
		currentDID: currentDID, newKey: newKey, now: now, pageSize: opts.PageSize,
	}
	if err := rotation.collect(ctx, currentKey); err != nil {
		return teamRotateKeyOutput{}, err
	}
	if opts.AfterRead != nil {
		opts.AfterRead()
	}
	newDID := didOf(newKey)
	_, err = registry.RotateTeamKey(ctx, registryURL, domain, teamName, newDID, &rotation.resigned, controllerKey)
	if detail, ok := awid.ResignedRecordsIncompleteDetail(err); ok && onlyMissingCustodians(detail) {
		learned := append([]string{}, detail.Missing.TeamCustodians...)
		sort.Strings(learned)
		if opts.BeforeRetry != nil {
			opts.BeforeRetry()
		}
		for _, custodianID := range learned {
			if err := rotation.addCustodian(ctx, custodianID); err != nil {
				return teamRotateKeyOutput{}, err
			}
		}
		out.LearnedCustodians = learned
		_, err = registry.RotateTeamKey(ctx, registryURL, domain, teamName, newDID, &rotation.resigned, controllerKey)
	}
	if err != nil {
		return teamRotateKeyOutput{}, rotateRefusal(teamID, err)
	}

	if err := awconfig.PromotePendingTeamKey(domain, teamName); err != nil {
		return teamRotateKeyOutput{}, fmt.Errorf("AWID now holds the new team key of %s, but saving it as the team key failed; it is kept as the pending key, and running aw id team rotate-key again finishes: %w", teamID, err)
	}
	out.Status, out.NewTeamDIDKey = "rotated", newDID
	out.ResignedTeamServer = rotation.resigned.TeamServer != nil
	out.ResignedCustodians = len(rotation.resigned.TeamCustodians)
	out.ResignedCustody = len(rotation.resigned.MemberCustody)
	out.ResignedPerson = len(rotation.resigned.MemberPerson)
	return out, nil
}
