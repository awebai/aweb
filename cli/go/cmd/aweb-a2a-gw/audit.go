package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/awebai/aw/a2agw"
)

type jsonlAuditSink struct {
	mu   sync.Mutex
	path string
}

func newJSONLAuditSink(path string) (*jsonlAuditSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &jsonlAuditSink{path: path}, nil
}

func (s *jsonlAuditSink) RecordA2A(event a2agw.AuditEvent) {
	if s == nil || s.path == "" {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}
