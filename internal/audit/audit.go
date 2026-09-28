// Package audit writes an append-only audit trail. Rotation is delegated to
// the external logrotate job; tokens and cookies are never recorded.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time   string `json:"time"`
	App    string `json:"app"`
	Sub    string `json:"sub"`
	Action string `json:"action"` // login | logout | denied | refresh
	Result string `json:"result"` // ok | error[:reason]
}

// Logger serialises events to a file.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// Open creates (or appends to) the audit log.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{f: f}, nil
}

// Log appends one event.
func (l *Logger) Log(app, sub, action, result string) {
	if l == nil {
		return
	}
	ev := Event{Time: time.Now().UTC().Format(time.RFC3339), App: app, Sub: sub, Action: action, Result: result}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.f, string(line))
}

// Close flushes and closes the log.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
