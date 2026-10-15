package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// sessionTable holds live sessions in memory, keyed by token hash. Sessions
// are short-lived, so losing them on restart only means devices re-sign.
type sessionTable struct {
	mu   sync.Mutex
	byID map[string]session
}

type session struct {
	deviceID string
	expires  time.Time
}

func newSessionTable() *sessionTable { return &sessionTable{byID: map[string]session{}} }

func (t *sessionTable) create(deviceID string, now time.Time, ttl time.Duration) (string, time.Time) {
	token := "lfs_" + randomToken()
	exp := now.Add(ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(now)
	t.byID[hashToken(token)] = session{deviceID: deviceID, expires: exp}
	return token, exp
}

func (t *sessionTable) lookup(token string, now time.Time) (string, bool) {
	if token == "" {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[hashToken(token)]
	if !ok || !now.Before(s.expires) {
		return "", false
	}
	return s.deviceID, true
}

func (t *sessionTable) remove(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, hashToken(token))
}

func (t *sessionTable) removeDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, s := range t.byID {
		if s.deviceID == deviceID {
			delete(t.byID, k)
		}
	}
}

func (t *sessionTable) prune(now time.Time) {
	for k, s := range t.byID {
		if !now.Before(s.expires) {
			delete(t.byID, k)
		}
	}
}

// challengeTable holds outstanding single-use challenges.
type challengeTable struct {
	mu    sync.Mutex
	items map[string]challenge
	max   int
}

type challenge struct {
	deviceID string
	expires  time.Time
}

func newChallengeTable(max int) *challengeTable {
	return &challengeTable{items: map[string]challenge{}, max: max}
}

func (t *challengeTable) issue(deviceID string, now time.Time, ttl time.Duration) (string, time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.items) >= t.max {
		for k, c := range t.items {
			if !now.Before(c.expires) {
				delete(t.items, k)
			}
		}
		if len(t.items) >= t.max {
			return "", time.Time{}, false
		}
	}
	value := encodeB64(randomBytes(32))
	exp := now.Add(ttl)
	t.items[value] = challenge{deviceID: deviceID, expires: exp}
	return value, exp, true
}

// consume removes the challenge whatever the outcome, so it can be tried once.
func (t *challengeTable) consume(value, deviceID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.items[value]
	if !ok {
		return false
	}
	delete(t.items, value)
	return c.deviceID == deviceID && now.Before(c.expires)
}

// failureLimiter blocks an IP after too many failed credentials in a window.
type failureLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	byIP   map[string]*failures
}

type failures struct {
	count int
	start time.Time
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	return &failureLimiter{limit: limit, window: window, byIP: map[string]*failures{}}
}

func (l *failureLimiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.byIP[ip]
	if !ok {
		return false
	}
	if now.Sub(f.start) >= l.window {
		delete(l.byIP, ip)
		return false
	}
	return f.count >= l.limit
}

func (l *failureLimiter) record(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.byIP) > 10000 {
		for k, f := range l.byIP {
			if now.Sub(f.start) >= l.window {
				delete(l.byIP, k)
			}
		}
	}
	f, ok := l.byIP[ip]
	if !ok || now.Sub(f.start) >= l.window {
		l.byIP[ip] = &failures{count: 1, start: now}
		return
	}
	f.count++
}

// auditLog appends one JSON object per line.
type auditLog struct {
	mu sync.Mutex
	f  *os.File
}

func openAuditLog(path string) (*auditLog, error) {
	if path == "" {
		return &auditLog{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &auditLog{f: f}, nil
}

func (a *auditLog) write(now time.Time, event string, fields map[string]any) {
	entry := map[string]any{"time": now.UTC().Format(time.RFC3339Nano), "event": event}
	for k, v := range fields {
		entry[k] = v
	}
	line, _ := json.Marshal(entry)
	log.Printf("audit %s", line)
	if a.f == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.f.Write(append(line, '\n'))
}

func (a *auditLog) Close() error {
	if a.f == nil {
		return nil
	}
	return a.f.Close()
}

// alerter posts Discord-compatible {"content": ...} messages to a webhook.
type alerter struct {
	url    string
	client *http.Client
}

func (a *alerter) send(msg string) {
	if a.url == "" {
		return
	}
	go func() {
		body, _ := json.Marshal(map[string]string{"content": msg})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
		if err != nil {
			log.Printf("alert: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			log.Printf("alert: %v", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("alert: webhook returned %s", resp.Status)
		}
	}()
}
