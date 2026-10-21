package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	country  string    // when location rules are enforced: where it was issued
	mac      string    // MAC evidence: "unavailable", "matched", "recorded", "changed_observed", ...
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

// setCountry records where a session is now used (see enforcedCountry).
func (t *sessionTable) setCountry(token, country string) {
	h := hashToken(token)
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.byID[h]; ok {
		s.country = country
		t.byID[h] = s
	}
}

// reauthorize records that a live session was re-checked under policy
// version and may now last only until expires (never later than before). An
// unbound session becomes bound to network if the policy now binds sessions.
// It reports whether the session still exists.
func (t *sessionTable) reauthorize(token string, version int, network string, expires, hardEnd time.Time) bool {
	h := hashToken(token)
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.byID[h]
	if !ok {
		return false
	}
	s.version = version
	if s.network == "" {
		s.network = network
	}
	if expires.Before(s.expires) {
		s.expires = expires
	}
	s.hardEnd = hardEnd
	t.byID[h] = s
	return true
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

// trimDevice ends a device's oldest sessions beyond max (0: the table's
// default), for when a policy lowers the cap.
func (t *sessionTable) trimDevice(deviceID string, max int) {
	if max <= 0 {
		max = t.perDevice
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	list := t.byDevice[deviceID]
	for len(list) > max {
		delete(t.byID, list[0])
		list = list[1:]
	}
	if len(list) == 0 {
		delete(t.byDevice, deviceID)
	} else {
		t.byDevice[deviceID] = list
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
	issued  time.Time
	expires time.Time
	version int
	hardEnd time.Time
	country string
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
	recheckMu sync.Mutex // one recheck at a time, so verdicts apply in order
	mu        sync.Mutex
	next      uint64
	byDevice  map[string]map[uint64]*stream
	after     func(time.Duration, func()) func() bool // time.AfterFunc; replaced in tests
}

type stream struct {
	streamAuth
	cancel context.CancelFunc
	stop   func() bool // stops the deadline timer, if any
}

// streamAuth is what authorized a stream: the client address (so a new
// policy can re-derive its network), its network key, and the credential's
// issue time and end, from which a stricter policy can work out a deadline.
type streamAuth struct {
	ip       string
	network  string    // "" when not bound
	issued   time.Time // zero: unknown (the stream's start is used)
	expires  time.Time // zero: unknown
	deadline time.Time // when the stream must close; zero: none
	session  string    // token hash of the session that opened it, if any
	app      string    // the application it goes to ("": Jellyfin)
}

// streamVerdict is a recheck's judgement on one stream.
type streamVerdict struct {
	allowed  bool
	deadline time.Time // zero: none
	network  string    // the stream's network key under the current policy
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
// cancelled, or at a.deadline (zero: none), and a function to call when the
// request is finished.
func (t *streamTable) track(parent context.Context, deviceID string, a streamAuth, now time.Time) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	if a.issued.IsZero() {
		a.issued = now
	}
	st := &stream{streamAuth: a, cancel: cancel}
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

// cancelWhere closes every stream whose application matches.
func (t *streamTable) cancelWhere(match func(app string) bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for dev, m := range t.byDevice {
		for id, st := range m {
			if match(st.app) {
				st.cancel()
				delete(m, id)
			}
		}
		if len(m) == 0 {
			delete(t.byDevice, dev)
		}
	}
}

// cancelSession closes the streams a session opened.
func (t *streamTable) cancelSession(sessionHash string) {
	if sessionHash == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, m := range t.byDevice {
		for id, st := range m {
			if st.session == sessionHash {
				st.cancel()
				delete(m, id)
			}
		}
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

// recheck re-evaluates each of a device's open streams with check.
// Disallowed streams are closed; the others take the network check reports
// and keep the earlier of their old and new deadlines.
//
// check runs without the table locked (it evaluates policy, which can be
// slow), on a snapshot; verdicts are applied to the streams still open.
// Streams that open meanwhile were authorized under the state check sees.
func (t *streamTable) recheck(deviceID string, now time.Time, check func(streamAuth) streamVerdict) {
	t.recheckMu.Lock()
	defer t.recheckMu.Unlock()
	t.mu.Lock()
	snapshot := make(map[uint64]streamAuth, len(t.byDevice[deviceID]))
	for id, st := range t.byDevice[deviceID] {
		snapshot[id] = st.streamAuth
	}
	t.mu.Unlock()

	verdicts := make(map[uint64]streamVerdict, len(snapshot))
	for id, a := range snapshot {
		verdicts[id] = check(a)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	m := t.byDevice[deviceID]
	for id, v := range verdicts {
		st := m[id]
		if st == nil {
			continue // finished meanwhile
		}
		if !v.allowed {
			st.cancel()
			delete(m, id)
			continue
		}
		st.network = v.network
		if !v.deadline.IsZero() && (st.deadline.IsZero() || v.deadline.Before(st.deadline)) {
			st.deadline = v.deadline
			t.arm(st, now)
		}
	}
	if len(m) == 0 {
		delete(t.byDevice, deviceID)
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
	// gatePage: requested by the Gate's own sign-in page (a browser).
	gatePage bool
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

func (t *challengeTable) issue(deviceID, source string, gatePage bool, now time.Time, ttl time.Duration) (string, time.Time, bool) {
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
	t.items[value] = challenge{deviceID: deviceID, source: source, expires: exp, gatePage: gatePage}
	t.bySource[source]++
	return value, exp, true
}

// consume removes the challenge whatever the outcome, so it can be tried once.
//
// SECURITY (L1): the signature covers the device and the challenge, not
// where it is sent from or what it is exchanged for. So a challenge is
// answered only from the source it was issued to, and one the Gate's own
// page asked for (a browser) can't be exchanged for a native client's bearer
// token. Someone who reads one sign-in request (a TLS-inspecting proxy)
// can't replay it elsewhere for a token.
func (t *challengeTable) consume(value, deviceID, source, client string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.items[value]
	if !ok {
		return false
	}
	t.drop(value, c)
	return c.deviceID == deviceID && now.Before(c.expires) && c.source == source && !(c.gatePage && client != "browser")
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
// It rotates at maxBytes, keeping three old files (audit.log.1 … .3).
type auditLog struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	size     int64
	maxBytes int64
}

func openAuditLog(path string, maxBytes ...int64) (*auditLog, error) {
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
	a := &auditLog{f: f, path: path, maxBytes: 20 << 20}
	if len(maxBytes) > 0 && maxBytes[0] > 0 {
		a.maxBytes = maxBytes[0]
	}
	if st, err := f.Stat(); err == nil {
		a.size = st.Size()
	}
	return a, nil
}

// rotate moves audit.log to audit.log.1 (and so on). Caller holds a.mu.
func (a *auditLog) rotate() {
	a.f.Close()
	for i := 2; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", a.path, i), fmt.Sprintf("%s.%d", a.path, i+1))
	}
	os.Rename(a.path, a.path+".1")
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("audit log: can't reopen after rotating: %v", err)
		a.f = nil
		return
	}
	a.f, a.size = f, 0
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
	if a.f == nil {
		return
	}
	if a.size+int64(len(line))+1 > a.maxBytes {
		a.rotate()
		if a.f == nil {
			return
		}
	}
	n, _ := a.f.Write(append(line, '\n'))
	a.size += int64(n)
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
