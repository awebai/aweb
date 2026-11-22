package awid

import (
	"errors"
	"testing"
)

type legacyInvitationLookup struct {
	invitations []*IDInvitation
	listError   error
	lists       int
}

func (store *legacyInvitationLookup) Invitation(string) (*IDInvitation, error) { return nil, nil }
func (store *legacyInvitationLookup) PutInvitation(*IDInvitation) error        { return nil }
func (store *legacyInvitationLookup) Invitations() ([]*IDInvitation, error) {
	store.lists++
	return store.invitations, store.listError
}

type indexedInvitationLookup struct {
	*legacyInvitationLookup
	found       *IDInvitation
	lookupError error
}

func (store indexedInvitationLookup) InvitationForRequest(string) (*IDInvitation, error) {
	return store.found, store.lookupError
}

func TestInvitationRequestLookupRetainsReleasedStoreAndUsesIndex(t *testing.T) {
	wanted := &IDInvitation{InvitationID: "first", Request: &IDRequestRecord{RequestID: "request"}}
	legacy := &legacyInvitationLookup{invitations: []*IDInvitation{wanted}}
	if got, err := FindIDInvitationForRequest(legacy, "request"); err != nil || got != wanted || legacy.lists != 1 {
		t.Fatalf("legacy: %v %v lists=%d", got, err, legacy.lists)
	}
	legacy.lists = 0
	indexed := indexedInvitationLookup{legacyInvitationLookup: legacy, found: wanted}
	if got, err := FindIDInvitationForRequest(indexed, "request"); err != nil || got != wanted || legacy.lists != 0 {
		t.Fatalf("indexed: %v %v lists=%d", got, err, legacy.lists)
	}
	unavailable := errors.New("unreadable index")
	indexed.lookupError = unavailable
	if _, err := FindIDInvitationForRequest(indexed, "request"); !errors.Is(err, unavailable) || legacy.lists != 0 {
		t.Fatalf("index failure became fallback: %v lists=%d", err, legacy.lists)
	}
	legacy.listError = unavailable
	if _, err := FindIDInvitationForRequest(legacy, "request"); !errors.Is(err, unavailable) {
		t.Fatalf("legacy failure became absence: %v", err)
	}
	legacy.listError = nil
	legacy.invitations = append(legacy.invitations, &IDInvitation{InvitationID: "second", Request: &IDRequestRecord{RequestID: "request"}})
	if _, err := FindIDInvitationForRequest(legacy, "request"); err == nil {
		t.Fatal("duplicate request was ambiguous success")
	}
}
