package gate

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The admin dashboard: a page at /_lanternfish/admin/ that drives the admin
// API from a browser on an allowed network.
//
// SECURITY: the page and its sign-in answer only from LANTERNFISH_ADMIN_ALLOW
// (404 elsewhere, like the API). Signing in exchanges the admin key for a
// session cookie the page's scripts can't read, scoped to the admin path,
// bound to the client address, ending after 15 minutes idle or 8 hours.
// Requests authenticated by that cookie must also carry the session's CSRF
// token in a header and must not come from another site, so another page
// open in the same browser can't act with it.

const (
	adminCookie      = "__Secure-lf_admin"
	adminPath        = "/_lanternfish/admin"
	csrfHeader       = "X-Lanternfish-CSRF"
	adminIdle        = 15 * time.Minute
	adminMaxLife     = 8 * time.Hour
	maxAdminSessions = 64
)

type adminSession struct {
	keyID      string
	csrf       string
	ip         string
	created    time.Time
	lastUsed   time.Time
	verifiedAt time.Time // last authenticator check (re-verification)
}

type adminSessionTable struct {
	mu     sync.Mutex
	byHash map[string]*adminSession
}

func newAdminSessionTable() *adminSessionTable {
	return &adminSessionTable{byHash: map[string]*adminSession{}}
}

func (t *adminSessionTable) create(keyID, ip string, now time.Time) (token, csrf string) {
	token, csrf = "lfas_"+randomToken(), randomToken()
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, s := range t.byHash {
		if !s.live(now) {
			delete(t.byHash, h)
		}
	}
	for len(t.byHash) >= maxAdminSessions { // drop the oldest
		var oldest string
		for h, s := range t.byHash {
			if oldest == "" || s.created.Before(t.byHash[oldest].created) {
				oldest = h
			}
		}
		delete(t.byHash, oldest)
	}
	t.byHash[hashToken(token)] = &adminSession{keyID: keyID, csrf: csrf, ip: ip, created: now, lastUsed: now}
	return token, csrf
}

func (s *adminSession) live(now time.Time) bool {
	return now.Sub(s.lastUsed) < adminIdle && now.Sub(s.created) < adminMaxLife
}

// use returns the live session for token from ip, refreshing its idle timer.
func (t *adminSessionTable) use(token, ip string, now time.Time) (adminSession, bool) {
	if token == "" {
		return adminSession{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h := hashToken(token)
	s, ok := t.byHash[h]
	if !ok || !s.live(now) {
		delete(t.byHash, h)
		return adminSession{}, false
	}
	if s.ip != ip {
		return adminSession{}, false
	}
	s.lastUsed = now
	return *s, true
}

// markVerified records a successful re-verification for a session.
func (t *adminSessionTable) markVerified(token string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.byHash[hashToken(token)]; ok {
		s.verifiedAt = now
	}
}

func (t *adminSessionTable) remove(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byHash, hashToken(token))
}

func (t *adminSessionTable) removeKey(keyID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, s := range t.byHash {
		if s.keyID == keyID {
			delete(t.byHash, h)
		}
	}
}

// crossSite reports whether the browser says the request came from another
// site. Clients that don't send Sec-Fetch-Site (curl, older browsers) pass;
// the CSRF token still protects cookie-authenticated changes.
func crossSite(r *http.Request) bool {
	s := r.Header.Get("Sec-Fetch-Site")
	return s != "" && s != "same-origin" && s != "none"
}

func (g *Gate) adminUIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+adminPath, func(w http.ResponseWriter, r *http.Request) {
		if !g.adminAllowed(clientIP(r)) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		http.Redirect(w, r, adminPath+"/", http.StatusFound)
	})
	mux.HandleFunc("GET "+adminPath+"/{$}", g.adminPage("admin.html"))
	mux.HandleFunc("GET "+adminPath+"/admin.js", g.adminPage("admin.js"))
	mux.HandleFunc("GET "+adminPath+"/admin.css", g.adminPage("admin.css"))
	mux.HandleFunc("POST "+adminPath+"/session", g.handleAdminSignIn)
	mux.HandleFunc("GET "+adminPath+"/session", g.admin(scopeAny, g.handleAdminWhoAmI))
	mux.HandleFunc("POST "+adminPath+"/logout", g.handleAdminSignOut)
	mux.HandleFunc("GET "+adminPath+"/v2/audit", g.admin(scopeAudit, g.handleAudit))
	mux.HandleFunc("POST "+adminPath+"/v2/qr", g.admin(scopeTickets, g.handleQR))
}

// adminPage serves a dashboard file, only on the admin networks.
func (g *Gate) adminPage(name string) http.HandlerFunc {
	serve := g.serveStatic(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.adminAllowed(clientIP(r)) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		serve(w, r)
	}
}

func (g *Gate) handleAdminSignIn(w http.ResponseWriter, r *http.Request) {
	if !g.adminAllowed(clientIP(r)) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if !g.guard(w, r) {
		return
	}
	// SECURITY: a JSON content type forces a CORS preflight for cross-site
	// requests, and Sec-Fetch-Site catches the rest: no signing a browser in
	// from another page.
	if crossSite(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusForbidden, "sign in from the dashboard page")
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	var key *AdminKey
	g.store.View(func(d *storeData) {
		if k := d.adminKeyByHash(hashToken(req.Key)); k != nil {
			c := *k
			key = &c
		}
	})
	if req.Key == "" || key == nil {
		g.fail(w, r, http.StatusUnauthorized, "admin_auth_failed", "admin key not accepted", map[string]any{"path": r.URL.Path})
		return
	}
	now := g.cfg.Now()
	ip := clientIP(r)
	token, csrf := g.adminSessions.create(key.ID, ip, now)
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: token, Path: adminPath, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(adminMaxLife.Seconds())})
	g.audit.write(now, "admin_signed_in", map[string]any{"admin_key": key.Name, "ip": ip})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"name": key.Name, "csrf": csrf, "idle_seconds": int(adminIdle.Seconds())})
}

func (g *Gate) handleAdminWhoAmI(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	out := map[string]any{"name": key.Name, "idle_seconds": int(adminIdle.Seconds())}
	if c, err := r.Cookie(adminCookie); err == nil {
		if s, ok := g.adminSessions.use(c.Value, clientIP(r), g.cfg.Now()); ok {
			out["csrf"] = s.csrf
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gate) handleAdminSignOut(w http.ResponseWriter, r *http.Request) {
	if !g.adminAllowed(clientIP(r)) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if c, err := r.Cookie(adminCookie); err == nil {
		g.adminSessions.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: "", Path: adminPath, MaxAge: -1, Secure: true,
		HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// adminFromCookie authenticates a dashboard request. Changes need the CSRF
// header too.
func (g *Gate) adminFromCookie(r *http.Request) (*AdminKey, *adminSession, string) {
	c, err := r.Cookie(adminCookie)
	if err != nil {
		return nil, nil, ""
	}
	s, ok := g.adminSessions.use(c.Value, clientIP(r), g.cfg.Now())
	if !ok {
		return nil, nil, "admin session expired; sign in again"
	}
	if crossSite(r) {
		return nil, nil, "cross-site request refused"
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		got := r.Header.Get(csrfHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.csrf)) != 1 {
			return nil, nil, "missing or wrong " + csrfHeader + " header"
		}
	}
	var key *AdminKey
	g.store.View(func(d *storeData) {
		if k := d.AdminKeys[s.keyID]; k != nil && k.RevokedAt == nil {
			c := *k
			key = &c
		}
	})
	if key == nil {
		g.adminSessions.removeKey(s.keyID)
		return nil, nil, "admin key revoked"
	}
	return key, &s, ""
}

// handleAudit returns recent audit entries, newest first, from the end of
// the audit log file.
func (g *Gate) handleAudit(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	filter := strings.ToLower(q.Get("q"))
	entries := []json.RawMessage{}
	if g.cfg.AuditPath == "" {
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "note": "LANTERNFISH_AUDIT_LOG is not set"})
		return
	}
	lines, err := tailLines(g.cfg.AuditPath, 4<<20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	for i := len(lines) - 1; i >= 0 && len(entries) < limit; i-- {
		line := lines[i]
		if !json.Valid(line) {
			continue
		}
		if filter != "" && !bytes.Contains(bytes.ToLower(line), []byte(filter)) {
			continue
		}
		entries = append(entries, json.RawMessage(line))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// tailLines returns the complete lines in the last max bytes of a file.
func tailLines(path string, max int64) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := st.Size() - max
	partial := start > 0
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if partial { // the first line is probably cut off
			partial = false
			continue
		}
		out = append(out, append([]byte(nil), sc.Bytes()...))
	}
	return out, sc.Err()
}

// handleQR encodes text (an enrollment link) as a QR code matrix, so the
// dashboard can draw it without a third-party library.
func (g *Gate) handleQR(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	var req struct {
		Text string `json:"text"`
	}
	if err := g.readJSON(w, r, &req); err != nil || req.Text == "" {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	rows, err := qrRows(req.Text)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"size": len(rows), "rows": rows})
}

// qrRows encodes text as QR modules, one "0101…" string per row.
func qrRows(text string) ([]string, error) {
	m, err := qrEncode([]byte(text))
	if err != nil {
		return nil, err
	}
	rows := make([]string, len(m))
	for y, row := range m {
		b := make([]byte, len(row))
		for x, dark := range row {
			b[x] = '0'
			if dark {
				b[x] = '1'
			}
		}
		rows[y] = string(b)
	}
	return rows, nil
}
