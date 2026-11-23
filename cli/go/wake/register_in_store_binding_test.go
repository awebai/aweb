package wake

import (
	"path/filepath"
	"strings"
	"testing"
)

// The daemon-down registration path admits a receive binding as the running
// broker does: at most one registration owns an identity home's binding for a
// team (docs/terminal-wake-broker.md:85-88). A second terminal for the same
// identity is refused; a terminal for another identity registers.
func TestRegisterInStoreRefusesABindingAnotherRegistrationOwns(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	idHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, idHome, "team:one")
	otherIDHome := filepath.Join(tempHome(t, "other-identity"), ".aw")
	writeWakeTestTeamState(t, otherIDHome, "team:one")

	first := tempHome(t, "first")
	if err := RegisterInStore(store, Registration{Home: first, IdentityHome: idHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}

	second := tempHome(t, "second")
	err = RegisterInStore(store, Registration{Home: second, IdentityHome: idHome, Delivery: DeliverySession})
	if err == nil || !strings.Contains(err.Error(), "is already owned by registration") {
		t.Fatalf("second registration for the same binding: err=%v", err)
	}
	if _, ok, loadErr := store.LoadRegistration(second); loadErr != nil || ok {
		t.Fatalf("refused registration was saved: ok=%v err=%v", ok, loadErr)
	}

	if err := RegisterInStore(store, Registration{Home: second, IdentityHome: otherIDHome, Delivery: DeliverySession}); err != nil {
		t.Fatalf("registration for another identity: %v", err)
	}
	// Re-registering the owner keeps working.
	if err := RegisterInStore(store, Registration{Home: first, IdentityHome: idHome, Delivery: DeliverySession}); err != nil {
		t.Fatalf("owner re-registration: %v", err)
	}
}
