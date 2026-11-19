package main

import (
	"fmt"
	"github.com/awebai/aw/awid"
	"strings"
	"time"
)

func (s *custodyService) evictReplayLocked(cutoff time.Time) {
	for key, at := range s.replayAt {
		if at.Before(cutoff) {
			delete(s.replayAt, key)
			delete(s.replay, key)
			delete(s.results, key)
		}
	}
}

func (s *custodyService) reserveCustodyReplay(grantID, sessionDIDKey, nonce, digest string, resultType any) (string, any, error) {
	key := strings.TrimSpace(grantID) + "|" + strings.TrimSpace(sessionDIDKey) + "|" + strings.TrimSpace(nonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replay == nil {
		s.replay = map[string]string{}
	}
	if s.replayAt == nil {
		s.replayAt = map[string]time.Time{}
	}
	if s.results == nil {
		s.results = map[string]any{}
	}
	s.evictReplayLocked(s.now().Add(-2 * time.Minute))
	if old, exists := s.replay[key]; exists {
		if old != strings.TrimSpace(digest) {
			return "", nil, fmt.Errorf("replay_detected")
		}
		if res := s.results[key]; res != nil {
			switch resultType.(type) {
			case *awid.E2EEEnvelopeCreateResponse:
				if _, ok := res.(*awid.E2EEEnvelopeCreateResponse); ok {
					return key, res, nil
				}
			case *awid.E2EEUnwrapResponse:
				if _, ok := res.(*awid.E2EEUnwrapResponse); ok {
					return key, res, nil
				}
			case *awid.PlainMessageSignResponse:
				if _, ok := res.(*awid.PlainMessageSignResponse); ok {
					return key, res, nil
				}
			case *awid.AppRequestSignResponse:
				if _, ok := res.(*awid.AppRequestSignResponse); ok {
					return key, res, nil
				}
			}
		}
		return "", nil, fmt.Errorf("replay_detected")
	}
	s.replay[key] = strings.TrimSpace(digest)
	s.replayAt[key] = s.now()
	return key, nil, nil
}

func (s *custodyService) cacheCustodyReplayResult(key string, result any) {
	if strings.TrimSpace(key) == "" || result == nil {
		return
	}
	s.mu.Lock()
	if s.results == nil {
		s.results = map[string]any{}
	}
	s.results[key] = result
	s.mu.Unlock()
}
