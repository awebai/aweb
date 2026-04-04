package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAddExternalNamespace(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p-1/namespaces/external" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":          "ns-1",
			"slug":                  "acme-com",
			"full_name":             "acme.com",
			"display_name":          "acme.com",
			"is_default":            false,
			"is_external":           true,
			"published_agent_count": 0,
			"dns_txt_name":          "_awid.acme.com",
			"dns_txt_value":         "awid=v1; controller=did:key:z6Mkf; registry=https://api.awid.ai;",
			"dns_status":            "desired",
			"registration_status":   "unregistered",
			"created_at":            "2026-03-19T10:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.AddExternalNamespace(context.Background(), "p-1", &ExternalNamespaceRequest{
		Domain: "acme.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotBody["domain"] != "acme.com" {
		t.Fatalf("request domain=%v", gotBody["domain"])
	}
	if resp.NamespaceID != "ns-1" {
		t.Fatalf("namespace_id=%q", resp.NamespaceID)
	}
	if resp.FullName != "acme.com" {
		t.Fatalf("full_name=%q", resp.FullName)
	}
	if resp.DnsTxtName != "_awid.acme.com" {
		t.Fatalf("dns_txt_name=%q", resp.DnsTxtName)
	}
	if resp.DnsStatus != "desired" {
		t.Fatalf("dns_status=%q", resp.DnsStatus)
	}
	if resp.RegistrationStatus != "unregistered" {
		t.Fatalf("registration_status=%q", resp.RegistrationStatus)
	}
	if !resp.IsExternal {
		t.Fatal("is_external=false")
	}
}

func TestAddExternalNamespaceValidation(t *testing.T) {
	t.Parallel()

	c, err := NewWithAPIKey("http://localhost", "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.AddExternalNamespace(context.Background(), "p-1", &ExternalNamespaceRequest{})
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestVerifyNamespace(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p-1/namespaces/ns-1/verify" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":        "ns-1",
			"slug":                "acme-com",
			"full_name":           "acme.com",
			"dns_status":          "published",
			"registration_status": "registered",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.VerifyNamespace(context.Background(), "p-1", "ns-1")
	if err != nil {
		t.Fatal(err)
	}

	if resp.RegistrationStatus != "registered" {
		t.Fatalf("registration_status=%q", resp.RegistrationStatus)
	}
	if resp.DnsStatus != "published" {
		t.Fatalf("dns_status=%q", resp.DnsStatus)
	}
}

func TestListManagedNamespaces(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p-1/namespaces" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"namespace_id":            "ns-1",
				"full_name":               "myteam.aweb.ai",
				"is_external":             false,
				"registration_status":     "registered",
				"assigned_identity_count": 3,
			},
			{
				"namespace_id":            "ns-2",
				"full_name":               "acme.com",
				"is_external":             true,
				"registration_status":     "unregistered",
				"assigned_identity_count": 0,
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	list, err := c.ListManagedNamespaces(context.Background(), "p-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 2 {
		t.Fatalf("len=%d", len(list))
	}
	if list[0].FullName != "myteam.aweb.ai" {
		t.Fatalf("first full_name=%q", list[0].FullName)
	}
	if list[1].FullName != "acme.com" {
		t.Fatalf("second full_name=%q", list[1].FullName)
	}
}

func TestDeleteNamespace(t *testing.T) {
	t.Parallel()

	var gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/p-1/namespaces/ns-1" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	err = c.DeleteNamespace(context.Background(), "p-1", "ns-1")
	if err != nil {
		t.Fatal(err)
	}

	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s", gotMethod)
	}
}
