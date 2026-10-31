package awid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const RoomDisclosure = "Team room posts are readable by the service operator and all current and future team members."

type RoomMetadata struct {
	TeamID            string `json:"team_id"`
	RoomID            string `json:"room_id"`
	Confidentiality   string `json:"confidentiality"`
	HistoryVisibility string `json:"history_visibility"`
	Notice            string `json:"notice"`
}

type RoomMessage struct {
	TeamID             string             `json:"team_id"`
	RoomID             string             `json:"room_id"`
	ConversationID     string             `json:"conversation_id"`
	MessageID          string             `json:"message_id"`
	Sequence           int64              `json:"sequence"`
	FromDID            string             `json:"from_did"`
	FromStableID       string             `json:"from_stable_id,omitempty"`
	FromAlias          string             `json:"from_alias"`
	FromAddress        string             `json:"from_address,omitempty"`
	Subject            string             `json:"subject"`
	Body               string             `json:"body"`
	Timestamp          string             `json:"timestamp"`
	CreatedAt          string             `json:"created_at"`
	Signature          string             `json:"signature"`
	SigningKeyID       string             `json:"signing_key_id"`
	SignedPayload      string             `json:"signed_payload"`
	IDChain            ReceivedIDChain    `json:"id_chain,omitempty"`
	SenderMembership   *SenderMembership  `json:"sender_membership,omitempty"`
	VerificationStatus VerificationStatus `json:"verification_status"`
	Confidentiality    string             `json:"confidentiality"`
	HistoryVisibility  string             `json:"history_visibility"`
	Notice             string             `json:"notice"`
}

type RoomHistory struct {
	TeamID            string        `json:"team_id"`
	RoomID            string        `json:"room_id"`
	Messages          []RoomMessage `json:"messages"`
	HasMore           bool          `json:"has_more"`
	NextCursor        string        `json:"next_cursor,omitempty"`
	Confidentiality   string        `json:"confidentiality"`
	HistoryVisibility string        `json:"history_visibility"`
	Notice            string        `json:"notice"`
}

type RoomReadParams struct {
	After string
	Limit int
}
type RoomPostParams struct {
	Subject string
	Body    string
	E2EE    bool
}

func (c *Client) Room(ctx context.Context) (*RoomMetadata, error) {
	var out RoomMetadata
	if err := c.Get(ctx, "/v1/room", &out); err != nil {
		return nil, err
	}
	if c.TeamID() == "" || out.TeamID != c.TeamID() || out.RoomID == "" || out.Confidentiality != "server_readable" || out.HistoryVisibility != "current_and_future_members" {
		return nil, errors.New("room metadata does not match the selected team or supported history policy")
	}
	return &out, nil
}

func (c *Client) ReadRoom(ctx context.Context, p RoomReadParams) (*RoomHistory, error) {
	values := url.Values{}
	if p.After != "" {
		values.Set("after", p.After)
	}
	if p.Limit > 0 {
		values.Set("limit", strconv.Itoa(p.Limit))
	}
	path := "/v1/room/messages"
	if len(values) > 0 {
		path += "?" + values.Encode()
	}
	var out RoomHistory
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	if c.TeamID() == "" || out.TeamID != c.TeamID() || out.RoomID == "" {
		return nil, errors.New("room history does not match the selected team")
	}
	for i := range out.Messages {
		c.verifyRoomMessage(ctx, &out.Messages[i], out.TeamID, out.RoomID)
	}
	return &out, nil
}

func (c *Client) RoomMessage(ctx context.Context, id string) (*RoomMessage, error) {
	room, err := c.Room(ctx)
	if err != nil {
		return nil, err
	}
	var out RoomMessage
	if err := c.Get(ctx, "/v1/room/messages/"+url.PathEscape(id), &out); err != nil {
		return nil, err
	}
	c.verifyRoomMessage(ctx, &out, room.TeamID, room.RoomID)
	if out.MessageID != id {
		out.VerificationStatus = Failed
	}
	return &out, nil
}

func (c *Client) PostRoom(ctx context.Context, p RoomPostParams) (*RoomMessage, error) {
	if p.E2EE {
		return nil, errors.New("room_e2ee_unsupported: team rooms are server-readable")
	}
	if strings.TrimSpace(p.Body) == "" {
		return nil, errors.New("room post body is required")
	}
	if !c.canAttachPlainMessageSignature() {
		return nil, errors.New("room posts require the member identity signer")
	}
	room, err := c.Room(ctx)
	if err != nil {
		return nil, err
	}
	env := &MessageEnvelope{Type: "chat", From: c.signedPayloadFrom(false, true), To: "team-room:" + room.TeamID, ConversationID: room.RoomID, Subject: p.Subject, Body: p.Body}
	sf, err := c.signEnvelope(ctx, env)
	if err != nil {
		return nil, err
	}
	if sf.Signature == "" || sf.SignedPayload == "" {
		return nil, errors.New("room posts require the member identity signer")
	}
	request := struct {
		RoomID        string `json:"room_id"`
		SignedPayload string `json:"signed_payload"`
		Signature     string `json:"signature"`
		SigningKeyID  string `json:"signing_key_id"`
	}{room.RoomID, sf.SignedPayload, sf.Signature, sf.SigningKeyID}
	var out RoomMessage
	if err := c.Post(ctx, "/v1/room/messages", request, &out); err != nil {
		return nil, err
	}
	c.verifyRoomMessage(ctx, &out, room.TeamID, room.RoomID)
	if out.SignedPayload != sf.SignedPayload || out.Signature != sf.Signature || out.MessageID != sf.MessageID || out.VerificationStatus == Failed {
		return nil, fmt.Errorf("room post response does not match the signed post; the post may already be stored")
	}
	return &out, nil
}

func (c *Client) verifyRoomMessage(ctx context.Context, m *RoomMessage, team, room string) {
	m.VerificationStatus = Failed
	if team == "" || team != c.TeamID() || room == "" || m.RoomID != room || m.TeamID != team || m.ConversationID != room || m.MessageID == "" {
		return
	}
	var env MessageEnvelope
	if json.Unmarshal([]byte(m.SignedPayload), &env) != nil {
		return
	}
	if env.Type != "chat" || env.To != "team-room:"+team || env.ToDID != "" || env.ToStableID != "" || env.ConversationID != room || env.MessageID != m.MessageID || env.FromDID != m.FromDID || m.SigningKeyID != m.FromDID || env.FromStableID != m.FromStableID || env.From == "" || env.From != m.FromAlias || env.Subject != m.Subject || env.Body != m.Body || env.Timestamp == "" || env.Timestamp != m.Timestamp {
		return
	}
	if m.FromAddress != "" && m.FromAddress != env.From {
		return
	}
	status, err := VerifySignedPayload(m.SignedPayload, m.Signature, m.FromDID, m.SigningKeyID)
	if err != nil || status != Verified {
		return
	}
	address := ""
	if strings.Contains(env.From, "/") {
		address = env.From
	}
	m.VerificationStatus, _ = c.NormalizeReceivedSenderTrust(ctx, status, address, env.From, m.FromDID, m.FromStableID, m.SenderMembership, nil, nil, nil, ReceivedSenderBinding{TeamID: team, ProjectedDID: m.FromDID})
}
