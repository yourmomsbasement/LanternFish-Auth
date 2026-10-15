package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// sessionTable holds live sessions in memory, keyed by token hash. Sessions
// are short-lived, so losing them on restart only means devices re-sign.
//
// SECURITY: each device keeps at most perDevice sessions; a new one replaces
// its oldest. That leaves room for several tabs and in-flight renewals, while
// a buggy or hostile client can't grow the table without bound. Expired
// sessions are swept at most once a minute instead of on every sign-in.
type sessionTable struct {
	mu        sync.Mutex
	byID      map[string]session
	byDevice  map[string][]string // token hashes, oldest first
	perDevice int
	nextSweep time.Time
}

type session struct {
	deviceID string
	expires  time.Time
}

// maxSessionsPerDevice bounds sessions per device; see sessionTable.
const maxSessionsPerDevice = 16

func newSessionTable(perDevice int) *sessionTable {
	return &sessionTable{byID: map[string]session{}, byDevice: map[string][]string{}, perDevice: perDevice}
}

func (t *sessionTable) create(deviceID string, now time.Time, ttl time.Duration) (string, time.Time) {
	token := "lfs_" + randomToken()
	h := hashToken(token)
	exp := now.Add(ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(now)
	t.byID[h] = session{deviceID: deviceID, expires: exp}
	list := append(t.byDevice[deviceID], h)
	for len(list) > t.perDevice {
		delete(t.byID, list[0])
		list = list[1:]
	}
	t.byDevice[deviceID] = list
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
	h := hashToken(token)
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[h]
	if !ok {
		return
	}
	delete(t.byID, h)
	list := t.byDevice[s.deviceID]
	for i, x := range list {
		if x == h {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(t.byDevice, s.deviceID)
	} else {
		t.byDevice[s.deviceID] = list
	}
}

func (t *sessionTable) removeDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, h := range t.byDevice[deviceID] {
		delete(t.byID, h)
	}
	delete(t.byDevice, deviceID)
}

func (t *sessionTable) sweep(now time.Time) {
	if now.Before(t.nextSweep) {
		return
	}
	t.nextSweep = now.Add(time.Minute)
	for dev, list := range t.byDevice {
		kept := list[:0]
		for _, h := range list {
			if s, ok := t.byID[h]; ok && now.Before(s.expires) {
				kept = append(kept, h)
			} else {
				delete(t.byID, h)
			}
		}
		if len(kept) == 0 {
			delete(t.byDevice, dev)
		} else {
			t.byDevice[dev] = kept
		}
	}
}

// streamTable tracks in-flight proxied requests per device, so revoking a
// device can cancel them (open WebSockets and media streams included).
type streamTable struct {
	mu       sync.Mutex
	next     uint64
	byDevice map[string]map[uint64]context.CancelFunc
}

func newStreamTable() *streamTable {
	return &streamTable{byDevice: map[string]map[uint64]context.CancelFunc{}}
}

// track returns a context that is cancelled when cancelDevice is called for
// deviceID, and a function to call when the request is finished.
func (t *streamTable) track(parent context.Context, deviceID string) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	t.mu.Lock()
	id := t.next
	t.next++
	m := t.byDevice[deviceID]
	if m == nil {
		m = map[uint64]context.CancelFunc{}
		t.byDevice[deviceID] = m
	}
	m[id] = cancel
	t.mu.Unlock()
	return ctx, func() {
		t.mu.Lock()
		if m := t.byDevice[deviceID]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(t.byDevice, deviceID)
			}
		}
		t.mu.Unlock()
		cancel()
	}
}

func (t *streamTable) cancelDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, cancel := range t.byDevice[deviceID] {
		cancel()
	}
	delete(t.byDevice, deviceID)
}

// challengeTable holds outstanding single-use challenges.
//
// SECURITY: challenges are handed out without authentication, so besides the
// global cap each source (an IPv4 address, or an IPv6 /64) may hold only
// maxPerSource at once. Without that, one client could fill the whole table
// and lock every device out of signing in.
type challengeTable struct {
	mu           sync.Mutex
	items        map[string]challenge
	bySource     map[string]int
	max          int
	maxPerSource int
}

type challenge struct {
	deviceID string
	source   string
	expires  time.Time
}

func newChallengeTable(max, maxPerSource int) *challengeTable {
	return &challengeTable{items: map[string]challenge{}, bySource: map[string]int{}, max: max, maxPerSource: maxPerSource}
}

func (t *challengeTable) drop(value string, c challenge) {
	delete(t.items, value)
	if n := t.bySource[c.source] - 1; n > 0 {
		t.bySource[c.source] = n
	} else {
		delete(t.bySource, c.source)
	}
}

func (t *challengeTable) issue(deviceID, source string, now time.Time, ttl time.Duration) (string, time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.items) >= t.max || t.bySource[source] >= t.maxPerSource {
		for k, c := range t.items {
			if !now.Before(c.expires) {
				t.drop(k, c)
			}
		}
		if len(t.items) >= t.max || t.bySource[source] >= t.maxPerSource {
			return "", time.Time{}, false
		}
	}
	value := encodeB64(randomBytes(32))
	exp := now.Add(ttl)
	t.items[value] = challenge{deviceID: deviceID, source: source, expires: exp}
	t.bySource[source]++
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
	t.drop(value, c)
	return c.deviceID == deviceID && now.Before(c.expires)
}

// sourceKey groups addresses one client is likely to control: an IPv4
// address, or the /64 an IPv6 address is in.
func sourceKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

// failureLimiter blocks a source after too many failed credentials in a
// window.
//
// SECURITY: sources are grouped like challenges (an IPv4 address, or an IPv6
// /64), so rotating addresses within one IPv6 subnet doesn't buy a new
// budget. The table is capped at max sources and swept at most once a
// minute: past the cap new sources go untracked rather than growing memory
// or making every failure scan the table. Many separate sources can still
// spread out guesses; SECURITY.md calls the limiter a speed bump.
type failureLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	max       int
	nextSweep time.Time
	bySource  map[string]*failures
}

type failures struct {
	count int
	start time.Time
}

func newFailureLimiter(limit int, window time.Duration, max int) *failureLimiter {
	return &failureLimiter{limit: limit, window: window, max: max, bySource: map[string]*failures{}}
}

func (l *failureLimiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.bySource[sourceKey(ip)]
	return ok && now.Sub(f.start) < l.window && f.count >= l.limit
}

func (l *failureLimiter) record(ip string, now time.Time) {
	key := sourceKey(ip)
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.bySource[key]
	if ok && now.Sub(f.start) < l.window {
		f.count++
		return
	}
	if !now.Before(l.nextSweep) {
		l.nextSweep = now.Add(time.Minute)
		for k, f := range l.bySource {
			if now.Sub(f.start) >= l.window {
				delete(l.bySource, k)
			}
		}
		_, ok = l.bySource[key]
	}
	if !ok && len(l.bySource) >= l.max {
		return
	}
	l.bySource[key] = &failures{count: 1, start: now}
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
		// SECURITY: device names come from whoever enrolls. Allow no
		// mentions, so a name like "@everyone" can't ping the whole server.
		body, _ := json.Marshal(map[string]any{
			"content":          msg,
			"allowed_mentions": map[string]any{"parse": []string{}},
		})
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
