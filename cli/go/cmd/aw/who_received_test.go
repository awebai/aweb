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
