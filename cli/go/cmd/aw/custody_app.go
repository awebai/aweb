package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

func (s *custodyService) handleSignAppRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "unsupported_operation", 405)
		return
	}
	var req awid.AppRequestSignRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeCustodyError(w, 400, "bad_request")
		return
	}
	out, err := s.signAppRequest(r.Context(), &req)
	if err != nil {
		writeCustodyError(w, 403, err.Error())
		return
	}
	writeJSON(w, out)
}

// signAppRequest signs one installed-app tool call for a grant. Custody is
// authoritative: it re-interprets the call against the resident's mint-time
// snapshot of that exact tool, chooses origin/method/path/body itself and
// signs the ordinary team-auth v2 envelope with the resident key and the
// resident's team certificate. It never signs worker-supplied bytes.
func (s *custodyService) signAppRequest(ctx context.Context, req *awid.AppRequestSignRequest) (*awid.AppRequestSignResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("bad_request")
	}
	if strings.TrimSpace(req.Operation) != "sign_app_request" {
		return nil, fmt.Errorf("unsupported_operation")
	}
	if err := awid.VerifyAppRequestCustodyProof(req); err != nil {
		return nil, err
	}
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	if _, err := s.validateE2EECommon(ctx, req.Operation, fields, req.Nonce, req.Timestamp, ""); err != nil {
		return nil, err
	}
	key, cached, err := s.reserveCustodyReplay(req.GrantID, req.SessionDIDKey, req.Nonce, req.RequestDigest, &awid.AppRequestSignResponse{})
	if err != nil {
		return nil, err
	}
	if out, _ := cached.(*awid.AppRequestSignResponse); out != nil {
		return out, nil
	}
	snap, err := loadGrantAppToolsSnapshot(s.residentHome, req.GrantID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("app_tool_denied")
		}
		return nil, fmt.Errorf("app_tool_policy_unavailable")
	}
	if strings.TrimSpace(snap.TeamID) != strings.TrimSpace(req.TeamID) {
		return nil, fmt.Errorf("grant_team_mismatch")
	}
	app, ok := snap.Apps[strings.TrimSpace(req.AppID)]
	if !ok {
		return nil, fmt.Errorf("app_tool_denied")
	}
	var tool *appmanifest.Tool
	for i := range app.Tools {
		if strings.TrimSpace(app.Tools[i].Name) == strings.TrimSpace(req.Verb) {
			if tool != nil {
				return nil, fmt.Errorf("app_tool_policy_unavailable")
			}
			tool = &app.Tools[i]
		}
	}
	if tool == nil || strings.TrimSpace(tool.Auth) == "none" {
		return nil, fmt.Errorf("app_tool_denied")
	}
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	for _, param := range tool.Params {
		if strings.TrimSpace(param.In) != "path" {
			continue
		}
		value, _ := args[param.Name].(string)
		if v := strings.TrimSpace(value); v == "" || v == "." || v == ".." {
			return nil, fmt.Errorf("app_request_not_allowed")
		}
	}
	var rawBody []byte
	if strings.TrimSpace(req.RawBody) != "" {
		rawBody, err = base64.StdEncoding.DecodeString(req.RawBody)
		if err != nil {
			return nil, fmt.Errorf("bad_request")
		}
	}
	spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{
		Manifest:      appmanifest.Manifest{ManifestVersion: app.ManifestVersion, App: app.App, Tools: []appmanifest.Tool{*tool}},
		Verb:          tool.Name,
		Args:          args,
		RawBody:       rawBody,
		ReservedNames: reservedRootCommandNames(),
	})
	if err != nil {
		return nil, fmt.Errorf("app_request_not_allowed")
	}
	if strings.TrimSpace(spec.Auth) == "none" {
		return nil, fmt.Errorf("app_tool_denied")
	}
	target, err := url.Parse(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("app_request_not_allowed")
	}
	requestOrigin, err := canonicalAppOrigin(target.Scheme + "://" + target.Host)
	if err != nil {
		return nil, fmt.Errorf("app_request_not_allowed")
	}
	snapshotOrigin, err := canonicalAppOrigin(app.App.Origin)
	if err != nil || requestOrigin != snapshotOrigin {
		return nil, fmt.Errorf("app_request_not_allowed")
	}
	if canonicalOriginSet(s.appDeniedOrigins)[requestOrigin] {
		return nil, fmt.Errorf("app_request_not_allowed")
	}
	identity := &localSigningIdentity{
		DIDKey:       s.identity.DID,
		StableID:     s.identity.StableID,
		SigningKey:   s.signingKey,
		WorkingDir:   s.residentHome,
		IdentityHome: s.residentHome,
		TeamID:       strings.TrimSpace(snap.TeamID),
	}
	headers := make(http.Header)
	for k, v := range spec.Headers {
		headers.Set(k, v)
	}
	if err := signIDRequestHeaders(headers, spec.Method, target, identity, spec.Body, map[string]any{}, true, s.now().UTC().Format("2006-01-02T15:04:05Z07:00")); err != nil {
		return nil, fmt.Errorf("app_request_sign_failed")
	}
	out := &awid.AppRequestSignResponse{Method: spec.Method, URL: target.String(), Body: base64.StdEncoding.EncodeToString(spec.Body), Headers: map[string]string{}}
	for k := range headers {
		out.Headers[k] = headers.Get(k)
	}
	s.cacheCustodyReplayResult(key, out)
	return out, nil
}
