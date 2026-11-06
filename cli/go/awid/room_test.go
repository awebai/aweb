package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoomPostUsesChatEnvelopeAndExactRoomTarget(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	team, room := "ops:example.test", "a1111111-1111-4111-8111-111111111111"
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/v1/room" {
			json.NewEncoder(w).Encode(RoomMetadata{TeamID: team, RoomID: room, Confidentiality: "server_readable", HistoryVisibility: "current_and_future_members"})
			return
		}
		if r.Method != "POST" || r.URL.Path != "/v1/room/messages" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		posts++
		var req struct{ RoomID, SignedPayload, Signature, SigningKeyID string }
		var raw map[string]string
		json.NewDecoder(r.Body).Decode(&raw)
		req.RoomID, req.SignedPayload, req.Signature, req.SigningKeyID = raw["room_id"], raw["signed_payload"], raw["signature"], raw["signing_key_id"]
		var env MessageEnvelope
		json.Unmarshal([]byte(req.SignedPayload), &env)
		if env.Type != "chat" || env.To != "team-room:"+team || env.ToDID != "" || env.ConversationID != room || env.Body != "post body" || env.Subject != "subject" || req.RoomID != room {
			t.Errorf("wrong signed envelope: %+v", env)
		}
		status, err := VerifySignedPayload(req.SignedPayload, req.Signature, did, req.SigningKeyID)
		if status != Verified || err != nil {
			t.Errorf("signature: %s %v", status, err)
		}
		json.NewEncoder(w).Encode(RoomMessage{TeamID: team, RoomID: room, ConversationID: room, MessageID: env.MessageID, FromDID: did, FromAlias: env.From, Subject: env.Subject, Body: env.Body, Timestamp: env.Timestamp, SignedPayload: req.SignedPayload, Signature: req.Signature, SigningKeyID: did})
	}))
	defer server.Close()
	client, err := NewWithCertificate(server.URL, key, &TeamCertificate{Team: team, MemberDIDKey: did, Alias: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.PostRoom(context.Background(), RoomPostParams{Subject: "subject", Body: "post body"})
	if err != nil || got.MessageID == "" || posts != 1 {
		t.Fatalf("got=%+v err=%v posts=%d", got, err, posts)
	}
	if _, err := client.PostRoom(context.Background(), RoomPostParams{Body: "must not send", E2EE: true}); err == nil || posts != 1 {
		t.Fatal("explicit E2E intent did not fail before sending")
	}
}

func TestRoomReadRejectsUnsignedAndTamperedProjection(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	team, room := "ops:example.test", "a1111111-1111-4111-8111-111111111111"
	env := MessageEnvelope{Type: "chat", To: "team-room:" + team, ConversationID: room, MessageID: "b1111111-1111-4111-8111-111111111111", From: "alice", FromDID: did, Body: "original", Timestamp: "2026-10-30T00:00:00Z"}
	sig, _ := SignMessage(key, &env)
	for _, change := range []string{"none", "body", "team", "room", "unsigned"} {
		t.Run(change, func(t *testing.T) {
			row := RoomMessage{TeamID: team, RoomID: room, ConversationID: room, MessageID: env.MessageID, FromAlias: env.From, FromDID: did, Body: env.Body, Timestamp: env.Timestamp, SignedPayload: CanonicalJSON(&env), Signature: sig, SigningKeyID: did}
			switch change {
			case "body":
				row.Body = "changed"
			case "team":
				row.TeamID = "other:example.test"
			case "room":
				row.RoomID = "another"
			case "unsigned":
				row.Signature = ""
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.URL.Query().Get("after") != "cursor" {
					t.Error("lost cursor")
				}
				json.NewEncoder(w).Encode(RoomHistory{TeamID: team, RoomID: room, Messages: []RoomMessage{row}, HasMore: true, NextCursor: "next"})
			}))
			defer server.Close()
			client, _ := NewWithCertificate(server.URL, key, &TeamCertificate{Team: team, MemberDIDKey: did, Alias: "bob"})
			got, err := client.ReadRoom(context.Background(), RoomReadParams{After: "cursor", Limit: 1})
			if err != nil {
				t.Fatal(err)
			}
			if got.NextCursor != "next" || !got.HasMore {
				t.Fatal("lost paging metadata")
			}
			if change != "none" && got.Messages[0].VerificationStatus != Failed {
				t.Fatalf("tampered %s accepted: %+v", change, got.Messages[0])
			}
			if change == "none" && got.Messages[0].VerificationStatus == Failed {
				t.Fatal("valid signed post failed")
			}
		})
	}
}
