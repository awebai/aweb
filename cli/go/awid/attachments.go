package awid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const MaxAttachmentBytes = 5 * 1024 * 1024

var attachmentUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type AttachmentDescriptor struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	ExpiresAt string `json:"expires_at"`
}

func (d AttachmentDescriptor) Validate() error {
	invalid := errors.New("invalid attachment descriptor")
	if !attachmentUUID.MatchString(d.ID) {
		return invalid
	}
	if d.Size < 1 || d.Size > MaxAttachmentBytes || len(d.SHA256) != 64 || strings.ToLower(d.SHA256) != d.SHA256 {
		return invalid
	}
	if _, err := hex.DecodeString(d.SHA256); err != nil {
		return invalid
	}
	switch d.MediaType {
	case "text/plain", "text/markdown", "text/csv", "application/json", "application/pdf", "image/png", "image/jpeg", "image/webp":
	default:
		return invalid
	}
	if d.Filename == "" || d.Filename == "." || d.Filename == ".." || len(d.Filename) > 255 || !utf8.ValidString(d.Filename) || strings.TrimSpace(d.Filename) != d.Filename || strings.ContainsAny(d.Filename, "/\\") {
		return invalid
	}
	for _, r := range d.Filename {
		if unicode.Is(unicode.Cc, r) || strings.ContainsRune("\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c\u200b\u2060\ufeff", r) {
			return invalid
		}
	}
	expiry, err := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if err != nil {
		return invalid
	}
	_, offset := expiry.Zone()
	if offset != 0 {
		return invalid
	}
	return nil
}

func decodeAttachmentContent(raw json.RawMessage) ([]AttachmentDescriptor, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || string(raw) == "null" || len(entries) > 4 {
		return nil, false
	}
	out := make([]AttachmentDescriptor, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		var d AttachmentDescriptor
		decoder := json.NewDecoder(strings.NewReader(string(entry)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&d); err != nil || d.Validate() != nil || seen[d.ID] {
			return nil, false
		}
		seen[d.ID] = true
		out = append(out, d)
	}
	return out, true
}

// FetchAttachment uses the participant's ordinary identity/certificate/grant
// client. The descriptor must come from authenticated decrypted message content.
// It is never a URL or a bearer capability.
func (c *Client) FetchAttachment(ctx context.Context, kind, messageID string, d AttachmentDescriptor) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if !attachmentUUID.MatchString(messageID) {
		return nil, errors.New("invalid attachment message id")
	}
	prefix := "/v1/messages/"
	if kind == "chat" {
		prefix = "/v1/chat/messages/"
	} else if kind != "mail" {
		return nil, errors.New("invalid attachment message kind")
	}
	response, err := c.DoRaw(ctx, http.MethodGet, prefix+messageID+"/attachments/"+d.ID, "application/octet-stream", nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment fetch refused (HTTP %d)", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxAttachmentBytes+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if int64(len(body)) != d.Size || len(body) > MaxAttachmentBytes || hex.EncodeToString(sum[:]) != d.SHA256 {
		return nil, errors.New("attachment bytes do not match authenticated descriptor")
	}
	return body, nil
}

func isAttachmentFetchPath(path string) bool {
	return strings.Contains(path, "/v1/messages/") && strings.Contains(path, "/attachments/") || strings.Contains(path, "/v1/chat/messages/") && strings.Contains(path, "/attachments/")
}
