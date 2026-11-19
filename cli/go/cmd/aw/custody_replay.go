package main

import (
	"fmt"
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

// custodyReplayRequest binds a nonce to one grant, session and exact request.
type custodyReplayRequest struct {
	grantID, sessionDIDKey, nonce, digest string
}

// custodyReplayReservation identifies this attempt, including its original time.
// A late failure cannot remove a newer reservation for the same nonce.
type custodyReplayReservation struct {
	key, digest string
	startedAt   time.Time
}

func reserveCustodyReplay[T any](s *custodyService, request custodyReplayRequest) (custodyReplayReservation, *T, error) {
	key := strings.TrimSpace(request.grantID) + "|" + strings.TrimSpace(request.sessionDIDKey) + "|" + strings.TrimSpace(request.nonce)
	digest := strings.TrimSpace(request.digest)
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
			return custodyReplayReservation{}, nil, fmt.Errorf("replay_detected")
		}
		if result, ok := s.results[key].(*T); ok && result != nil {
			return custodyReplayReservation{}, result, nil
		}
		return custodyReplayReservation{}, nil, fmt.Errorf("replay_detected")
	}
	s.replay[key] = strings.TrimSpace(digest)
	at := s.now()
	s.replayAt[key] = at
	return custodyReplayReservation{key: key, digest: digest, startedAt: at}, nil, nil
}

func (s *custodyService) cacheCustodyReplayResult(reservation custodyReplayReservation, result any) {
	key := reservation.key
	if key == "" || result == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ownsReplayReservation(reservation) {
		return
	}
	if s.results == nil {
		s.results = map[string]any{}
	}
	s.results[key] = result
}

// releaseFailedCustodyReplay keeps concurrent duplicates refused, but permits a
// retry after a failed attempt (docs/identity.md: local custody request failures).
func (s *custodyService) releaseFailedCustodyReplay(reservation custodyReplayReservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ownsReplayReservation(reservation) && s.results[reservation.key] == nil {
		delete(s.replay, reservation.key)
		delete(s.replayAt, reservation.key)
	}
}

func (s *custodyService) ownsReplayReservation(reservation custodyReplayReservation) bool {
	return reservation.key != "" && s.replay[reservation.key] == reservation.digest && s.replayAt[reservation.key].Equal(reservation.startedAt)
}
