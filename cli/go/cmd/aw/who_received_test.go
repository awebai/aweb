package main

import (
	"context"
	"github.com/awebai/aw/awid"
	"testing"
)

type whoMessageFixture struct {
	inboxCalls []awid.InboxParams
	pages      map[string]*awid.InboxResponse
	exact      *awid.InboxResponse
	chat       *awid.ChatHistoryResponse
}

func (f *whoMessageFixture) Inbox(_ context.Context, p awid.InboxParams) (*awid.InboxResponse, error) {
	f.inboxCalls = append(f.inboxCalls, p)
	return f.pages[p.Cursor], nil
}
func (f *whoMessageFixture) Message(context.Context, string) (*awid.InboxResponse, error) {
	return f.exact, nil
}
func (f *whoMessageFixture) ChatHistory(context.Context, awid.ChatHistoryParams) (*awid.ChatHistoryResponse, error) {
	return f.chat, nil
}
func (f *whoMessageFixture) ListConversationsWithParams(context.Context, awid.ConversationListParams) (*awid.ConversationsResponse, error) {
	return &awid.ConversationsResponse{}, nil
}
func TestWhoFindsReadMailOnLaterPagesWithoutAcknowledging(t *testing.T) {
	f := &whoMessageFixture{pages: map[string]*awid.InboxResponse{
		"":     {Messages: []awid.InboxMessage{{FromAlias: "other"}}, HasMore: true, NextCursor: "next"},
		"next": {Messages: []awid.InboxMessage{{MessageID: "match", FromAlias: "sender"}}},
	}}
	got, err := findWhoSender(context.Background(), f, "sender", "", "")
	if err != nil || got.MessageID != "match" || len(f.inboxCalls) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	for _, p := range f.inboxCalls {
		if p.UnreadOnly {
			t.Fatal("who must include previously read messages")
		}
	}
}
func TestWhoExactSelectorsDoNotSubstituteAnotherSender(t *testing.T) {
	f := &whoMessageFixture{exact: &awid.InboxResponse{Messages: []awid.InboxMessage{{MessageID: "m", FromAlias: "other"}}}}
	if _, err := findWhoSender(context.Background(), f, "sender", "m", ""); err == nil {
		t.Fatal("wrong sender accepted")
	}
	f.chat = &awid.ChatHistoryResponse{Messages: []awid.ChatMessage{{MessageID: "m", FromAgent: "sender", FromDID: "did:key:one"}, {MessageID: "new", FromAgent: "sender", FromDID: "did:key:two"}}}
	got, err := findWhoSender(context.Background(), f, "sender", "m", "session")
	if err != nil || got.FromDID != "did:key:one" {
		t.Fatalf("got %+v err %v", got, err)
	}
	if len(f.inboxCalls) != 0 {
		t.Fatal("exact selectors must not scan inbox")
	}
}

type whoRoomFixture struct {
	whoMessageFixture
	status    int
	roomCalls int
	room      awid.RoomMessage
}

func (f *whoRoomFixture) Message(context.Context, string) (*awid.InboxResponse, error) {
	return nil, &awid.APIError{StatusCode: f.status, Body: `{"detail":"Not found"}`}
}
func (f *whoRoomFixture) RoomMessage(context.Context, string) (*awid.RoomMessage, error) {
	f.roomCalls++
	return &f.room, nil
}
func TestWhoFindsExactRoomPostOnlyAfterMailNotFound(t *testing.T) {
	for _, status := range []int{404, 403, 503} {
		f := &whoRoomFixture{status: status, room: awid.RoomMessage{MessageID: "m", FromAlias: "sender", FromDID: "did:key:sender", VerificationStatus: awid.Verified}}
		got, err := findWhoSender(context.Background(), f, "sender", "m", "")
		if status == 404 {
			if err != nil || got.MessageID != "m" || f.roomCalls != 1 {
				t.Fatalf("got=%+v err=%v calls=%d", got, err, f.roomCalls)
			}
		} else if err == nil || f.roomCalls != 0 {
			t.Fatalf("mail auth/dependency error was hidden: %d", status)
		}
	}
}
