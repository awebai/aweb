package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// SetCertificateRefresher configures retrieval from the member's trusted
// registry and durable installation. A grant client never uses this path.
func (c *Client) SetCertificateRefresher(refresh func(context.Context, string) (*TeamCertificate, ed25519.PublicKey, error)) {
	c.certificateMu.Lock()
	defer c.certificateMu.Unlock()
	c.certificateRefresher = refresh
}

func (c *Client) recoverReplacedCertificate(ctx context.Context, resp *http.Response) (bool, error) {
	c.certificateMu.RLock()
	refresh, oldHeader := c.certificateRefresher, c.teamCertHeader
	c.certificateMu.RUnlock()
	if refresh == nil || c.grantID != "" || oldHeader == "" || resp.Body == nil {
		return false, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	_ = resp.Body.Close()
	if err != nil {
		return false, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if len(data) > 65536 {
		return false, nil
	}
	var refusal struct {
		Detail struct {
			Code          string `json:"code"`
			ReplacementID string `json:"replacement_certificate_id"`
		} `json:"detail"`
	}
	if json.Unmarshal(data, &refusal) != nil || refusal.Detail.Code != "certificate_replaced" || refusal.Detail.ReplacementID == "" {
		return false, nil
	}
	old, err := DecodeTeamCertificateHeader(oldHeader)
	if err != nil {
		return false, err
	}
	fresh, key, err := refresh(ctx, refusal.Detail.ReplacementID)
	if err != nil {
		return false, fmt.Errorf("recover replaced certificate: %w", err)
	}
	if fresh == nil || fresh.CertificateID != refusal.Detail.ReplacementID || fresh.CertificateID == old.CertificateID || fresh.Team != old.Team || fresh.MemberDIDKey != c.did || fresh.Alias != old.Alias || fresh.IdentityScope != old.IdentityScope || fresh.MemberDIDAW != old.MemberDIDAW || fresh.MemberAddress != old.MemberAddress || ComputeDIDKey(key) != fresh.TeamDIDKey {
		return false, fmt.Errorf("replacement certificate binding mismatch")
	}
	if err := VerifyTeamCertificate(fresh, key); err != nil {
		return false, err
	}
	header, err := EncodeTeamCertificateHeader(fresh)
	if err != nil {
		return false, err
	}
	c.certificateMu.Lock()
	c.teamCertHeader = header
	c.certificateMu.Unlock()
	_ = resp.Body.Close()
	return true, nil
}

func (c *Client) sendSSEWithCertificateRecovery(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt != 0 {
			req = req.Clone(req.Context())
			if err := c.signRequest(req, nil); err != nil {
				return nil, err
			}
		}
		response, err := DoNoRedirect(c.sseClient, req)
		if err != nil {
			return nil, err
		}
		if attempt == 0 && response.StatusCode == http.StatusUnauthorized {
			recovered, err := c.recoverReplacedCertificate(req.Context(), response)
			if err != nil {
				return nil, err
			}
			if recovered {
				continue
			}
		}
		return response, nil
	}
	return nil, fmt.Errorf("certificate retry limit reached")
}
