package gate

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Network settings the dashboard can change without editing gate.env:
// where Jellyfin is, where the admin API answers from, the host browsers
// sign in on, and more applications behind the Gate.
//
// Each setting left empty falls back to the environment, so a Gate nobody
// configured from the dashboard behaves exactly as before. Changes apply to
// the next request, without a restart. The listen address and the TLS
// certificate stay in gate.env: changing them needs a restart.
//
// Applications are routed by hostname (sonarr.example.com), never by path:
// most web applications break when moved under a sub-path. A request for a
// host that isn't an application goes to Jellyfin, as before.

type GateSettings struct {
	// Version counts saves; a save must name the version it was based on.
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`

	// Upstream is Jellyfin's address ("" = LANTERNFISH_UPSTREAM).
	Upstream string `json:"upstream,omitempty"`
	// AdminAllow is where the admin API answers from (empty =
	// LANTERNFISH_ADMIN_ALLOW, or private networks).
	AdminAllow []string `json:"admin_allow,omitempty"`
	// PrimaryHost is the hostname browsers enroll and sign in on (Jellyfin's
	// public name). Applications send browsers there to link them.
	PrimaryHost string `json:"primary_host,omitempty"`
	Apps        []App  `json:"apps,omitempty"`
}

// App is another web application behind the Gate.
type App struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  bool     `json:"enabled"`
	Hosts    []string `json:"hosts"`    // public hostnames, e.g. sonarr.example.com
	Upstream string   `json:"upstream"` // e.g. http://10.20.0.5:8989
	// Owners limits the app to these owners' devices (empty: every owner).
	Owners []string `json:"owners,omitempty"`
	// PreserveHost sends the public hostname to the app (what most apps
	// behind a reverse proxy expect) instead of the upstream's address.
	PreserveHost bool `json:"preserve_host"`
	// IdentityHeaders sends the device ID and a Gate signature, like Jellyfin
	// gets. Off: the app sees no Lanternfish headers.
	IdentityHeaders bool `json:"identity_headers"`
	// InjectRenewal adds the session-renewal script to the app's HTML pages,
	// so single-page apps keep working past a session's lifetime.
	InjectRenewal bool `json:"inject_renewal"`
}

const (
	maxApps        = 32
	maxHostsPerApp = 10
)

// routing is the compiled, effective settings.
type routing struct {
	jellyfin    *url.URL
	adminAllow  []netip.Prefix
	primaryHost string
	apps        map[string]*appRoute // by hostname
	byID        map[string]*appRoute
}

type appRoute struct {
	App
	target *url.URL
	owners map[string]bool
}

func (a *appRoute) allows(subjectID string) bool {
	return a == nil || len(a.owners) == 0 || a.owners[subjectID]
}

var hostnameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// requestHost is r's hostname, lower-case, without a port.
func requestHost(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func parseUpstream(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%q must be an address like http://10.20.0.5:8989", s)
	}
	return u, nil
}

// compileRouting validates settings (nil: none) against the environment's
// defaults and builds the routing table.
func compileRouting(s *GateSettings, cfg Config) (*routing, error) {
	rt := &routing{jellyfin: cfg.Upstream, adminAllow: cfg.AdminAllow, apps: map[string]*appRoute{}, byID: map[string]*appRoute{}}
	rt.primaryHost = defaultPrimaryHost(cfg)
	if s == nil {
		return rt, nil
	}
	var probs []string
	bad := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }
	if s.Upstream != "" {
		if u, err := parseUpstream(s.Upstream); err != nil {
			bad("Jellyfin address: %v", err)
		} else {
			rt.jellyfin = u
		}
	}
	if len(s.AdminAllow) > 0 {
		if p, err := ParseAdminAllow(strings.Join(s.AdminAllow, ",")); err != nil {
			bad("admin networks: %v", err)
		} else {
			rt.adminAllow = p
		}
	}
	if s.PrimaryHost != "" {
		h := strings.ToLower(strings.TrimSpace(s.PrimaryHost))
		if !hostnameRE.MatchString(h) {
			bad("sign-in host %q isn't a hostname", s.PrimaryHost)
		}
		rt.primaryHost = h
	}
	if len(s.Apps) > maxApps {
		bad("at most %d applications", maxApps)
	}
	for i, a := range s.Apps {
		label := fmt.Sprintf("application %d", i+1)
		if a.Name = strings.TrimSpace(a.Name); a.Name == "" || len(a.Name) > 64 {
			bad("%s needs a name (up to 64 characters)", label)
		} else {
			label = fmt.Sprintf("application %q", a.Name)
		}
		if a.ID == "" {
			bad("%s has no id", label)
		} else if rt.byID[a.ID] != nil {
			bad("%s: duplicate id", label)
		}
		u, err := parseUpstream(a.Upstream)
		if err != nil {
			bad("%s: %v", label, err)
		}
		if len(a.Hosts) == 0 || len(a.Hosts) > maxHostsPerApp {
			bad("%s needs 1 to %d hostnames", label, maxHostsPerApp)
		}
		route := &appRoute{App: a, target: u, owners: map[string]bool{}}
		for _, o := range a.Owners {
			route.owners[o] = true
		}
		for j, h := range a.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			route.Hosts[j] = h
			switch {
			case !hostnameRE.MatchString(h):
				bad("%s: %q isn't a hostname (no ports, paths or wildcards)", label, h)
			case h == rt.primaryHost:
				bad("%s: %q is the sign-in host (Jellyfin)", label, h)
			case rt.apps[h] != nil:
				bad("%s: %q is already used by %q", label, h, rt.apps[h].Name)
			}
			if a.Enabled {
				rt.apps[h] = route
			}
		}
		rt.byID[a.ID] = route
	}
	if len(probs) > 0 {
		return nil, &PolicyError{Problems: probs}
	}
	return rt, nil
}

// defaultPrimaryHost: the WebAuthn relying party's first origin, if any.
func defaultPrimaryHost(cfg Config) string {
	for _, o := range cfg.WebAuthnOrigins {
		if u, err := url.Parse(o); err == nil && u.Hostname() != "" {
			return strings.ToLower(u.Hostname())
		}
	}
	return ""
}

func (g *Gate) loadRouting() error {
	var s *GateSettings
	g.store.View(func(d *storeData) {
		if d.Settings != nil {
			c := *d.Settings
			s = &c
		}
	})
	rt, err := compileRouting(s, g.cfg)
	if err != nil {
		return fmt.Errorf("saved network settings (fix them with `lanternfish-gate settings reset`): %w", err)
	}
	g.routing.Store(rt)
	return nil
}

// appFor is the application r is for (nil: Jellyfin).
func (g *Gate) appFor(r *http.Request) *appRoute {
	return g.routing.Load().apps[requestHost(r)]
}

// ---- Admin API ----

type settingsView struct {
	Settings GateSettings   `json:"settings"`
	Env      map[string]any `json:"environment"`
	Live     map[string]any `json:"effective"`
	TLS      map[string]any `json:"tls"`
	Warnings []string       `json:"warnings"`
}

func (g *Gate) handleGetSettings(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	var s GateSettings
	g.store.View(func(d *storeData) {
		if d.Settings != nil {
			s = *d.Settings
		}
	})
	if s.Apps == nil {
		s.Apps = []App{}
	}
	rt := g.routing.Load()
	env := map[string]any{"listen": g.cfg.Listen, "upstream": urlString(g.cfg.Upstream),
		"admin_allow": prefixStrings(g.cfg.AdminAllow), "primary_host": defaultPrimaryHost(g.cfg)}
	live := map[string]any{"upstream": urlString(rt.jellyfin), "admin_allow": prefixStrings(rt.adminAllow),
		"primary_host": rt.primaryHost, "client_address": clientIP(r)}
	tlsInfo, names := certInfo(g.cfg.TLSCertFile)
	var warnings []string
	for _, a := range s.Apps {
		if !a.Enabled {
			continue
		}
		for _, h := range a.Hosts {
			if names != nil && !certCovers(names, h) {
				warnings = append(warnings, fmt.Sprintf("the TLS certificate doesn't cover %s (%s): add it to the certificate", h, a.Name))
			}
		}
	}
	if len(s.Apps) > 0 && rt.primaryHost == "" {
		warnings = append(warnings, "set the sign-in host so browsers can be linked to applications")
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusOK, settingsView{Settings: s, Env: env, Live: live, TLS: tlsInfo, Warnings: warnings})
}

func (g *Gate) handlePutSettings(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req GateSettings
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	// New applications get IDs here; existing ones keep theirs.
	for i := range req.Apps {
		if req.Apps[i].ID == "" {
			req.Apps[i].ID = newID("app_")
		}
		if req.Apps[i].Owners == nil {
			req.Apps[i].Owners = []string{}
		}
	}
	rt, err := compileRouting(&req, g.cfg)
	if err != nil {
		var pe *PolicyError
		errors.As(err, &pe)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_settings", "problems": pe.Problems})
		return
	}
	// SECURITY: never lock the administrator out from where they are.
	ip := clientIP(r)
	allowed := false
	if a, err := netip.ParseAddr(ip); err == nil {
		for _, p := range rt.adminAllow {
			allowed = allowed || p.Contains(a.Unmap())
		}
	}
	if !allowed {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_settings",
			"problems": []string{fmt.Sprintf("the admin networks must include your address (%s), or you'd lock yourself out", ip)}})
		return
	}
	errStale := errors.New("stale")
	var problems []string
	err = g.store.Update(func(d *storeData) error {
		cur := 0
		if d.Settings != nil {
			cur = d.Settings.Version
		}
		if req.Version != cur {
			return errStale
		}
		for _, a := range req.Apps {
			for _, o := range a.Owners {
				if d.Subjects[o] == nil {
					problems = append(problems, fmt.Sprintf("application %q: no owner %s", a.Name, o))
				}
			}
		}
		if len(problems) > 0 {
			return errInvalid
		}
		req.Version, req.UpdatedAt, req.UpdatedBy = cur+1, now, key.Name
		s := req
		d.Settings = &s
		return nil
	})
	switch {
	case errors.Is(err, errStale):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "version_conflict",
			"detail": "the settings were changed meanwhile; reload them"})
		return
	case errors.Is(err, errInvalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_settings", "problems": problems})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	old := g.routing.Swap(rt)
	g.settingsChanged(old, rt)
	g.audit.write(now, "settings_changed", map[string]any{"version": req.Version, "admin_key": key.Name, "ip": ip,
		"upstream": urlString(rt.jellyfin), "admin_allow": prefixStrings(rt.adminAllow), "primary_host": rt.primaryHost,
		"apps": len(req.Apps)})
	g.alerts.send(fmt.Sprintf("⚙️ Gate network settings changed by %s (version %d)", key.Name, req.Version))
	writeJSON(w, http.StatusOK, map[string]any{"version": req.Version})
}

var errInvalid = errors.New("invalid")

// settingsChanged closes what the new settings no longer allow: streams to
// an application that was removed, disabled, moved to another address or
// restricted to other owners. They reconnect through the new route.
func (g *Gate) settingsChanged(old, rt *routing) {
	changed := map[string]bool{}
	for id, a := range old.byID {
		n := rt.byID[id]
		if n == nil || !n.Enabled || n.Upstream != a.Upstream || !sameSet(n.Owners, a.Owners) ||
			!sameSet(n.Hosts, a.Hosts) || n.PreserveHost != a.PreserveHost || n.IdentityHeaders != a.IdentityHeaders {
			changed[id] = true
		}
	}
	jellyfinMoved := urlString(old.jellyfin) != urlString(rt.jellyfin)
	if len(changed) == 0 && !jellyfinMoved {
		return
	}
	g.accessChanged()
	g.streams.cancelWhere(func(app string) bool {
		if app == "" {
			return jellyfinMoved
		}
		return changed[app]
	})
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// handleTestUpstream checks that the Gate can reach an address (for the
// dashboard's "Test" button). It reports only whether and how it answered.
func (g *Gate) handleTestUpstream(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	var req struct {
		URL string `json:"url"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	u, err := parseUpstream(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Do(out)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"reachable": false, "error": err.Error(), "ms": ms})
		return
	}
	resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]any{"reachable": true, "status": resp.StatusCode, "ms": ms,
		"server": resp.Header.Get("Server")})
}

// ---- helpers ----

func urlString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func prefixStrings(ps []netip.Prefix) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// certInfo describes the serving certificate (nil names: unknown).
func certInfo(path string) (map[string]any, []string) {
	if path == "" {
		return map[string]any{"available": false}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}, nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return map[string]any{"available": false, "error": "no PEM certificate"}, nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}, nil
	}
	names := append([]string{}, c.DNSNames...)
	return map[string]any{"available": true, "names": names, "not_after": c.NotAfter.UTC(), "issuer": c.Issuer.CommonName}, names
}

func certCovers(names []string, host string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			if i := strings.IndexByte(host, '.'); i > 0 && host[i+1:] == n[2:] {
				return true
			}
		}
	}
	return false
}
