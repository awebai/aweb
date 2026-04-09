package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateContact(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	var gotBody ContactCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(ContactCreateResponse{
			ContactID:      "ct-1",
			ContactAddress: "alice@example.com",
			Label:          "Alice",
			CreatedAt:      "2026-02-08T10:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.CreateContact(context.Background(), &ContactCreateRequest{
		ContactAddress: "alice@example.com",
		Label:          "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method=%s", gotMethod)
	}
	if gotPath != "/v1/contacts" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotBody.ContactAddress != "alice@example.com" {
		t.Fatalf("contact_address=%s", gotBody.ContactAddress)
	}
	if gotBody.Label != "Alice" {
		t.Fatalf("label=%s", gotBody.Label)
	}
	if resp.ContactID != "ct-1" {
		t.Fatalf("contact_id=%s", resp.ContactID)
	}
	if resp.ContactAddress != "alice@example.com" {
		t.Fatalf("contact_address=%s", resp.ContactAddress)
	}
	if resp.Label != "Alice" {
		t.Fatalf("label=%s", resp.Label)
	}
	if resp.CreatedAt != "2026-02-08T10:00:00Z" {
		t.Fatalf("created_at=%s", resp.CreatedAt)
	}
}

func TestListContacts(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/contacts" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ContactListResponse{
			Contacts: []Contact{
				{ContactID: "ct-1", ContactAddress: "alice@example.com", Label: "Alice", CreatedAt: "2026-02-08T10:00:00Z"},
				{ContactID: "ct-2", ContactAddress: "bob@example.com", CreatedAt: "2026-02-08T11:00:00Z"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ListContacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Contacts) != 2 {
		t.Fatalf("contacts=%d", len(resp.Contacts))
	}
	if resp.Contacts[0].ContactID != "ct-1" {
		t.Fatalf("contact_id=%s", resp.Contacts[0].ContactID)
	}
	if resp.Contacts[0].Label != "Alice" {
		t.Fatalf("label=%s", resp.Contacts[0].Label)
	}
	if resp.Contacts[1].ContactAddress != "bob@example.com" {
		t.Fatalf("contact_address=%s", resp.Contacts[1].ContactAddress)
	}
	if resp.Contacts[1].Label != "" {
		t.Fatalf("label should be empty, got=%s", resp.Contacts[1].Label)
	}
}

func TestDeleteContact(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(ContactDeleteResponse{Deleted: true})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DeleteContact(context.Background(), "ct-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s", gotMethod)
	}
	if gotPath != "/v1/contacts/ct-1" {
		t.Fatalf("path=%s", gotPath)
	}
	if !resp.Deleted {
		t.Fatal("deleted=false")
	}
}
