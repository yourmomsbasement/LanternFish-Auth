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
	"strings"
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

// session is what a token hash maps to. It is bound to the network it was
// issued on (when the policy binds sessions to networks) and to the policy
// version that authorized it; a request under a newer policy is re-checked.
type session struct {
	deviceID string
	issued   time.Time
	expires  time.Time
	network  string    // "" when not bound
	version  int       // policy version that authorized it
	hardEnd  time.Time // next schedule end (zero: none within the horizon)
}

// maxSessionsPerDevice bounds sessions per device; see sessionTable.
const maxSessionsPerDevice = 16

func newSessionTable(perDevice int) *sessionTable {
	return &sessionTable{byID: map[string]session{}, byDevice: map[string][]string{}, perDevice: perDevice}
}

// create stores a new session and returns its token. perDevice (1..64)
// bounds the device's live sessions; 0 uses the table's default.
func (t *sessionTable) create(s session, now time.Time, perDevice int) string {
	token := "lfs_" + randomToken()
	h := hashToken(token)
	s.issued = now
	if perDevice <= 0 {
		perDevice = t.perDevice
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(now)
	t.byID[h] = s
	list := append(t.byDevice[s.deviceID], h)
	for len(list) > perDevice {
		delete(t.byID, list[0])
		list = list[1:]
	}
	t.byDevice[s.deviceID] = list
	return token
}

func (t *sessionTable) lookup(token string, now time.Time) (session, bool) {
	if token == "" {
		return session{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[hashToken(token)]
	if !ok || !now.Before(s.expires) {
		return session{}, false
	}
	return s, true
}

// reauthorize records that a live session was re-checked under policy
// version and may now last only until expires (never later than before). An
// unbound session becomes bound to network if the policy now binds sessions.
func (t *sessionTable) reauthorize(token string, version int, network string, expires, hardEnd time.Time) {
	h := hashToken(token)
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.byID[h]; ok {
		s.version = version
		if s.network == "" {
			s.network = network
		}
		if expires.Before(s.expires) {
			s.expires = expires
		}
		s.hardEnd = hardEnd
		t.byID[h] = s
	}
}

// removeDeviceNetworksExcept drops a device's sessions bound to a network
// not in keep (used when the device's approved networks change).
func (t *sessionTable) removeDeviceNetworksExcept(deviceID string, keep map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.byDevice[deviceID][:0]
	for _, h := range t.byDevice[deviceID] {
		if s, ok := t.byID[h]; ok && (s.network == "" || keep[s.network]) {
			kept = append(kept, h)
		} else {
			delete(t.byID, h)
		}
	}
	if len(kept) == 0 {
		delete(t.byDevice, deviceID)
	} else {
		t.byDevice[deviceID] = kept
	}
}

func (t *sessionTable) count(deviceID string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, h := range t.byDevice[deviceID] {
		if s, ok := t.byID[h]; ok && now.Before(s.expires) {
			n++
		}
	}
	return n
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

// grantTable holds short-lived access grants for client-certificate
// devices, keyed by device and network. A certificate proves possession of
// the device key; the grant records that the policy was checked for it.
type grantTable struct {
	mu        sync.Mutex
	byKey     map[string]grant
	nextSweep time.Time
}

type grant struct {
	expires time.Time
	version int
	hardEnd time.Time
}

func newGrantTable() *grantTable { return &grantTable{byKey: map[string]grant{}} }

func grantKey(deviceID, network string) string { return deviceID + "|" + network }

func (t *grantTable) lookup(deviceID, network string, now time.Time) (grant, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	g, ok := t.byKey[grantKey(deviceID, network)]
	return g, ok && now.Before(g.expires)
}

func (t *grantTable) put(deviceID, network string, g grant, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !now.Before(t.nextSweep) {
		t.nextSweep = now.Add(time.Minute)
		for k, x := range t.byKey {
			if !now.Before(x.expires) {
				delete(t.byKey, k)
			}
		}
	}
	t.byKey[grantKey(deviceID, network)] = g
}

func (t *grantTable) removeDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.byKey {
		if strings.HasPrefix(k, deviceID+"|") {
			delete(t.byKey, k)
		}
	}
}

// removeDeviceNetworksExcept drops a device's grants for networks not in keep.
func (t *grantTable) removeDeviceNetworksExcept(deviceID string, keep map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.byKey {
		if network, ok := strings.CutPrefix(k, deviceID+"|"); ok && network != "" && !keep[network] {
			delete(t.byKey, k)
		}
	}
}

// clear drops every grant, so the next request re-checks the policy.
func (t *grantTable) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.byKey = map[string]grant{}
}

// streamTable tracks in-flight proxied requests (WebSockets and media
// streams included), so they can be closed when their device is revoked,
// moves network, or loses access under a new policy, and at a deadline.
//
// SECURITY: a deadline only ever moves earlier. Re-checking a stream under a
// relaxed policy never extends it past what authorized it.
type streamTable struct {
	mu       sync.Mutex
	next     uint64
	byDevice map[string]map[uint64]*stream
	after    func(time.Duration, func()) func() bool // time.AfterFunc; replaced in tests
}

type stream struct {
	cancel   context.CancelFunc
	ip       string // client address, so a new policy can re-derive the network
	network  string
	deadline time.Time   // zero: none
	stop     func() bool // stops the deadline timer, if any
}

func newStreamTable() *streamTable {
	return &streamTable{
		byDevice: map[string]map[uint64]*stream{},
		after: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
	}
}

// arm (re)starts st's timer for its deadline. Caller holds t.mu.
func (t *streamTable) arm(st *stream, now time.Time) {
	if st.stop != nil {
		st.stop()
		st.stop = nil
	}
	if st.deadline.IsZero() {
		return
	}
	d := st.deadline.Sub(now)
	if d <= 0 {
		st.cancel()
		return
	}
	st.stop = t.after(d, st.cancel)
}

// track returns a context that is cancelled when the device's streams are
// cancelled, or at deadline (zero: none), and a function to call when the
// request is finished.
func (t *streamTable) track(parent context.Context, deviceID, ip, network string, deadline, now time.Time) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	st := &stream{cancel: cancel, ip: ip, network: network, deadline: deadline}
	t.mu.Lock()
	t.arm(st, now)
	id := t.next
	t.next++
	m := t.byDevice[deviceID]
	if m == nil {
		m = map[uint64]*stream{}
		t.byDevice[deviceID] = m
	}
	m[id] = st
	t.mu.Unlock()
	return ctx, func() {
		t.mu.Lock()
		if m := t.byDevice[deviceID]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(t.byDevice, deviceID)
			}
		}
		if st.stop != nil {
			st.stop()
		}
		t.mu.Unlock()
		cancel()
	}
}

func (t *streamTable) cancelDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, st := range t.byDevice[deviceID] {
		st.cancel()
	}
	delete(t.byDevice, deviceID)
}

// cancelDeviceNetworksExcept closes a device's streams bound to a network
// not in keep.
func (t *streamTable) cancelDeviceNetworksExcept(deviceID string, keep map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, st := range t.byDevice[deviceID] {
		if st.network != "" && !keep[st.network] {
			st.cancel()
			delete(t.byDevice[deviceID], id)
		}
	}
}

// devices lists the devices with open streams.
func (t *streamTable) devices() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.byDevice))
	for d := range t.byDevice {
		out = append(out, d)
	}
	return out
}

// recheck re-evaluates each of a device's open streams: check reports
// whether the stream's client address is still allowed and the deadline it must now
// end by (zero: none). Disallowed streams are closed; others keep the
// earlier of their old and new deadlines.
func (t *streamTable) recheck(deviceID string, now time.Time, check func(ip string) (bool, time.Time)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, st := range t.byDevice[deviceID] {
		ok, deadline := check(st.ip)
		if !ok {
			st.cancel()
			delete(t.byDevice[deviceID], id)
			continue
		}
		if !deadline.IsZero() && (st.deadline.IsZero() || deadline.Before(st.deadline)) {
			st.deadline = deadline
			t.arm(st, now)
		}
	}
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
