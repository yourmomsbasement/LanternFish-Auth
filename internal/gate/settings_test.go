package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// appServer is another application behind the Gate; it records requests.
type appServer struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	page string
}

func newAppServer(t *testing.T) *appServer {
	a := &appServer{page: "app home"}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.reqs = append(a.reqs, r.Clone(r.Context()))
		a.mu.Unlock()
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><head><title>app</title></head><body>"+a.page+"</body></html>")
			return
		}
		io.WriteString(w, a.page)
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *appServer) last() *http.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.reqs) == 0 {
		return nil
	}
	return a.reqs[len(a.reqs)-1]
}

// doHost is doFrom for a given hostname.
func (h *harness) doHost(remote, host, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "https://"+host+path, rd)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.g.Handler().ServeHTTP(rec, req)
	return rec
}

func (h *harness) settings() GateSettings {
	h.t.Helper()
	rec := h.admin2("GET", "settings", nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	return decode[settingsView](h.t, rec).Settings
}

func (h *harness) saveSettings(s GateSettings) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.admin2("PUT", "settings", s)
}

const appHost = "sonarr.example.com"

func (h *harness) addApp(a *appServer, mutate func(*App)) {
	h.t.Helper()
	s := h.settings()
	s.PrimaryHost = "gate.example"
	app := App{Name: "Sonarr", Enabled: true, Hosts: []string{appHost}, Upstream: a.URL, PreserveHost: true, InjectRenewal: true}
	if mutate != nil {
		mutate(&app)
	}
	s.Apps = append(s.Apps, app)
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		h.t.Fatalf("save settings: %d %s", rec.Code, rec.Body)
	}
}

// newSubject creates an owner (or admin) and returns its ID.
func (h *harness) newSubject(name, role string) string {
	h.t.Helper()
	rec := h.admin2("POST", "subjects", map[string]string{"name": name, "role": role})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create subject: %d %s", rec.Code, rec.Body)
	}
	return decode[Subject](h.t, rec).ID
}

// enrollFor enrolls a fresh device owned by subjectID, through an admin ticket.
func (h *harness) enrollFor(platform, subjectID string) (*ecdsa.PrivateKey, enrollResponse) {
	h.t.Helper()
	rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": platform, "subject_id": subjectID},
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("ticket for %s: %d %s", subjectID, rec.Code, rec.Body)
	}
	ticket, _ := decode[map[string]any](h.t, rec)["ticket"].(string)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	rec = h.do("POST", "/_lanternfish/v1/enroll", map[string]string{"ticket": ticket, "public_key": b64(spki),
		"proof": b64(rawSign(key, enrollMessage(ticket)))}, nil)
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("enroll for %s: %d %s", subjectID, rec.Code, rec.Body)
	}
	return key, decode[enrollResponse](h.t, rec)
}

// appGET requests an application host with an existing session token.
func (h *harness) appGET(host, token string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doHost(testClientAddr, host, "GET", "/", nil, map[string]string{sessionHeader: token})
}

func TestSettingsMoveJellyfin(t *testing.T) {
	h := newHarness(t)
	moved := newAppServer(t)
	key, enr := h.enrollECDSA("android")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))

	s := h.settings()
	s.Upstream = moved.URL
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if rec := h.get(testClientAddr, tok); rec.Code != http.StatusOK || rec.Body.String() != "app home" {
		t.Fatalf("after moving Jellyfin: %d %q", rec.Code, rec.Body)
	}
	// Jellyfin still gets its identity headers.
	if moved.last().Header.Get(deviceHeader) != enr.DeviceID || moved.last().Header.Get(gateSignatureHeader) == "" {
		t.Fatal("Jellyfin lost its identity headers")
	}
	// Saving needs the current version.
	if rec := h.saveSettings(s); rec.Code != http.StatusConflict {
		t.Fatalf("stale save: %d", rec.Code)
	}
}

func TestSettingsValidation(t *testing.T) {
	h := newHarness(t)
	for name, mutate := range map[string]func(*GateSettings){
		"locks the admin out": func(s *GateSettings) { s.AdminAllow = []string{"10.9.0.0/16"} },
		"bad address":         func(s *GateSettings) { s.Upstream = "ftp://x" },
		"bad hostname": func(s *GateSettings) {
			s.Apps = []App{{ID: "a", Name: "A", Hosts: []string{"*.example.com"}, Upstream: "http://10.0.0.1"}}
		},
		"duplicate host": func(s *GateSettings) {
			s.Apps = []App{{ID: "a", Name: "A", Enabled: true, Hosts: []string{"a.example.com"}, Upstream: "http://10.0.0.1"},
				{ID: "b", Name: "B", Enabled: true, Hosts: []string{"a.example.com"}, Upstream: "http://10.0.0.2"}}
		},
		"app on the sign-in host": func(s *GateSettings) {
			s.PrimaryHost = "flix.example.com"
			s.Apps = []App{{ID: "a", Name: "A", Hosts: []string{"flix.example.com"}, Upstream: "http://10.0.0.1"}}
		},
		"unknown owner": func(s *GateSettings) {
			s.Apps = []App{{ID: "a", Name: "A", Hosts: []string{"a.example.com"}, Upstream: "http://10.0.0.1", Owners: []string{"sub_nobody"}}}
		},
	} {
		s := h.settings()
		mutate(&s)
		if rec := h.saveSettings(s); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// Admin networks apply at once.
	s := h.settings()
	s.AdminAllow = []string{"192.168.1.0/24"}
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	auth := map[string]string{"Authorization": "Bearer " + h.adminKey}
	if rec := h.doFrom("10.1.2.3:1", "GET", "/_lanternfish/admin/v1/devices", nil, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("admin from a network no longer allowed: %d", rec.Code)
	}
}

func TestApplicationRouting(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, nil)
	key, enr := h.enrollECDSA("android")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	hdr := map[string]string{sessionHeader: tok, deviceHeader: "forged", gateSignatureHeader: "forged", gateNonceHeader: "n"}

	rec := h.doHost(testClientAddr, appHost, "GET", "/api/series", nil, hdr)
	if rec.Code != http.StatusOK || rec.Body.String() != "app home" {
		t.Fatalf("app: %d %q", rec.Code, rec.Body)
	}
	got := app.last()
	if got.Host != appHost {
		t.Errorf("host sent to the app: %q", got.Host)
	}
	for _, k := range []string{deviceHeader, authKindHeader, gateSignatureHeader, gateNonceHeader, sessionHeader} {
		if got.Header.Get(k) != "" {
			t.Errorf("app got %s", k)
		}
	}
	// Other hosts still go to Jellyfin; unauthenticated requests go nowhere.
	if rec := h.doHost(testClientAddr, "jellyfin.example.com", "GET", "/Items", nil, hdr); rec.Body.String() != "jellyfin" {
		t.Fatalf("other host: %q", rec.Body)
	}
	before := len(app.reqs)
	if rec := h.doHost(testClientAddr, appHost, "GET", "/api/series", nil, nil); rec.Code != http.StatusUnauthorized || len(app.reqs) != before {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}

	// Limited to another owner: refused.
	h.admin2("POST", "subjects", map[string]string{"name": "Kid", "role": "owner"})
	var kid string
	h.g.store.View(func(d *storeData) {
		for id, s := range d.Subjects {
			if s.Name == "Kid" {
				kid = id
			}
		}
	})
	s := h.settings()
	s.Apps[0].Owners = []string{kid}
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if rec := h.doHost(testClientAddr, appHost, "GET", "/api/series", nil, hdr); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "app_not_allowed" {
		t.Fatalf("owner not allowed: %d %s", rec.Code, rec.Body)
	}
}

func TestSettingsChangeClosesAppStreams(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, nil)
	_, enr := h.enrollECDSA("android")
	appID := h.settings().Apps[0].ID
	appCtx, done := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50", app: appID}, h.now)
	defer done()
	jfCtx, done2 := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50"}, h.now)
	defer done2()

	s := h.settings()
	s.Apps[0].Upstream = "http://10.20.0.9:8989"
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if appCtx.Err() == nil {
		t.Error("stream to the moved application still open")
	}
	if jfCtx.Err() != nil {
		t.Error("Jellyfin stream closed by an application change")
	}
}

// TestAppAccessModeLegacyUnchanged checks that apps saved without an access
// mode keep the original Owners behavior.
func TestAppAccessModeLegacyUnchanged(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, nil) // no access_mode, no owners: every owner
	key, enr := h.enrollECDSA("android")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	if rec := h.appGET(appHost, tok); rec.Code != http.StatusOK || rec.Body.String() != "app home" {
		t.Fatalf("legacy open app: %d %q", rec.Code, rec.Body)
	}
	// Naming an owner still limits the app to that owner, as before.
	kid := h.newSubject("Kid", "owner")
	s := h.settings()
	s.Apps[0].Owners = []string{kid}
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if rec := h.appGET(appHost, tok); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "app_not_allowed" {
		t.Fatalf("legacy restricted app: %d %s", rec.Code, rec.Body)
	}
}

// TestAppAccessModeSelectedEmptyDenies checks that an explicit "selected"
// mode with no owners named denies everyone, on request routing and on link
// code issuance, instead of falling back to everyone.
func TestAppAccessModeSelectedEmptyDenies(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, func(a *App) { a.AccessMode = accessSelected; a.Owners = []string{} })
	key, enr := h.enrollECDSA("web")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	if rec := h.appGET(appHost, tok); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "app_not_allowed" {
		t.Fatalf("selected with no owners: %d %s", rec.Code, rec.Body)
	}
	cookie, status := h.browserSignIn("gate.example", enr.DeviceID, key)
	if status != http.StatusOK {
		t.Fatalf("browser sign-in: %d", status)
	}
	rec := h.doHost(testClientAddr, "gate.example", "POST", "/_lanternfish/v2/link/code", map[string]string{"host": appHost},
		map[string]string{"Cookie": cookie.String()})
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "app_not_allowed" {
		t.Fatalf("link code for a denied application: %d %s", rec.Code, rec.Body)
	}
}

// TestAppAccessModeAdmins checks that "admins" allows an active admin owner's
// device and denies ordinary, unknown and disabled owners.
func TestAppAccessModeAdmins(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	adminID := h.newSubject("Boss", "admin")
	kidID := h.newSubject("Kid", "owner")
	h.addApp(app, func(a *App) { a.AccessMode = accessAdmins })

	adminKey, adminEnr := h.enrollFor("android", adminID)
	if rec := h.appGET(appHost, tokenOf(t, h.signInFrom(testClientAddr, adminEnr.DeviceID, adminKey))); rec.Code != http.StatusOK ||
		rec.Body.String() != "app home" {
		t.Fatalf("admin device: %d %q", rec.Code, rec.Body)
	}

	kidKey, kidEnr := h.enrollFor("android", kidID)
	if rec := h.appGET(appHost, tokenOf(t, h.signInFrom(testClientAddr, kidEnr.DeviceID, kidKey))); rec.Code != http.StatusForbidden {
		t.Fatalf("ordinary owner: %d %s", rec.Code, rec.Body)
	}

	// An owner no subject names is not an admin.
	ghostKey, ghostEnr := h.enrollECDSA("android")
	h.g.store.Update(func(d *storeData) error { d.Devices[ghostEnr.DeviceID].SubjectID = "sub_ghost"; return nil })
	if rec := h.appGET(appHost, tokenOf(t, h.signInFrom(testClientAddr, ghostEnr.DeviceID, ghostKey))); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown owner: %d %s", rec.Code, rec.Body)
	}

	// A disabled admin is not an admin.
	adminTok := tokenOf(t, h.signInFrom(testClientAddr, adminEnr.DeviceID, adminKey))
	h.g.store.Update(func(d *storeData) error { d.Subjects[adminID].Status = "disabled"; return nil })
	if rec := h.appGET(appHost, adminTok); rec.Code == http.StatusOK {
		t.Fatalf("disabled admin allowed: %d %s", rec.Code, rec.Body)
	}
}

// TestAppAccessModeAppliesToLinkRedeem checks that redeeming a link code
// re-checks the application's access mode, not only the state when the code
// was issued.
func TestAppAccessModeAppliesToLinkRedeem(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, func(a *App) { a.AccessMode = accessEveryone })
	key, enr := h.enrollECDSA("web")
	cookie, status := h.browserSignIn("gate.example", enr.DeviceID, key)
	if status != http.StatusOK {
		t.Fatalf("browser sign-in: %d", status)
	}
	rec := h.doHost(testClientAddr, "gate.example", "POST", "/_lanternfish/v2/link/code", map[string]string{"host": appHost},
		map[string]string{"Cookie": cookie.String()})
	if rec.Code != http.StatusOK {
		t.Fatalf("link code: %d %s", rec.Code, rec.Body)
	}
	code, _ := decode[map[string]any](t, rec)["code"].(string)

	// The application is re-scoped to no one between issue and redeem.
	s := h.settings()
	s.Apps[0].AccessMode = accessSelected
	s.Apps[0].Owners = []string{}
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	child, childPub := newKey(t)
	rec = h.doHost(testClientAddr, appHost, "POST", "/_lanternfish/v2/link/redeem", map[string]string{"code": code,
		"public_key": childPub, "proof": b64(rawSign(child, linkMessage(code)))}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("redeem after re-scoping: %d %s", rec.Code, rec.Body)
	}
}

// TestAppAccessModeChangeClosesStreams checks that changing an app's access
// mode closes its open streams, like its other limits do.
func TestAppAccessModeChangeClosesStreams(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, func(a *App) { a.AccessMode = accessEveryone })
	_, enr := h.enrollECDSA("android")
	appID := h.settings().Apps[0].ID
	appCtx, done := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50", app: appID}, h.now)
	defer done()
	jfCtx, done2 := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50"}, h.now)
	defer done2()

	s := h.settings()
	s.Apps[0].AccessMode = accessAdmins
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if appCtx.Err() == nil {
		t.Error("stream to the re-scoped application still open")
	}
	if jfCtx.Err() != nil {
		t.Error("Jellyfin stream closed by an access mode change")
	}
}

// TestAdminModeStreamsCloseWhenOwnerDisabled checks that the existing subject
// mutation (disable) closes an admin owner's open streams, so an admin-mode
// application does not keep a session whose admin rights ended.
func TestAdminModeStreamsCloseWhenOwnerDisabled(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	adminID := h.newSubject("Boss", "admin")
	h.addApp(app, func(a *App) { a.AccessMode = accessAdmins })
	_, enr := h.enrollFor("android", adminID)
	appID := h.settings().Apps[0].ID
	appCtx, done := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50", app: appID}, h.now)
	defer done()
	if rec := h.admin2("POST", "subjects/"+adminID+"/disable", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable admin: %d %s", rec.Code, rec.Body)
	}
	if appCtx.Err() == nil {
		t.Error("stream kept open after its admin owner was disabled")
	}
}

func TestAppAccessModeValidation(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, nil)
	for _, mode := range []string{accessLegacy, accessEveryone, accessSelected, accessAdmins} {
		s := h.settings()
		s.Apps[0].AccessMode = mode
		if rec := h.saveSettings(s); rec.Code != http.StatusOK {
			t.Fatalf("save %q: %d %s", mode, rec.Code, rec.Body)
		}
	}
	s := h.settings()
	s.Apps[0].AccessMode = "root"
	rec := h.saveSettings(s)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "access mode") {
		t.Fatalf("unknown access mode: %d %s", rec.Code, rec.Body)
	}
}

// newGate builds a Gate without a test upstream server, for unit tests of the
// routing rules that need no sockets.
func newGate(t *testing.T) *Gate {
	t.Helper()
	up, err := parseUpstream("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	g, err := New(Config{Upstream: up, DataPath: dir + "/gate.json", AuditPath: dir + "/audit.log",
		MasterKey: randomBytes(32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	return g
}

// TestAllowsAppUnit exercises the access-mode decision directly: legacy
// behavior, explicit "everyone" and "selected" (empty denies), and "admins"
// with active, ordinary, unknown and disabled owners.
func TestAllowsAppUnit(t *testing.T) {
	g := newGate(t)
	g.store.Update(func(d *storeData) error {
		d.Subjects["sub_admin"] = &Subject{ID: "sub_admin", Name: "Boss", Role: "admin", Status: "active"}
		d.Subjects["sub_owner"] = &Subject{ID: "sub_owner", Name: "Kid", Role: "owner", Status: "active"}
		d.Subjects["sub_off"] = &Subject{ID: "sub_off", Name: "Off", Role: "admin", Status: "disabled"}
		return nil
	})
	route := func(mode string, owners ...string) *appRoute {
		s := &GateSettings{Apps: []App{{ID: "a", Name: "A", Enabled: true, Hosts: []string{"a.example.com"},
			Upstream: "http://10.0.0.1", AccessMode: mode, Owners: owners}}}
		rt, err := compileRouting(s, Config{})
		if err != nil {
			t.Fatalf("compile %q: %v", mode, err)
		}
		return rt.byID["a"]
	}
	for _, tc := range []struct {
		name    string
		app     *appRoute
		subject string
		want    bool
	}{
		{"nil is Jellyfin", nil, "sub_owner", true},
		{"legacy open", route(accessLegacy), "sub_owner", true},
		{"legacy named owner", route(accessLegacy, "sub_owner"), "sub_owner", true},
		{"legacy other owner", route(accessLegacy, "sub_admin"), "sub_owner", false},
		{"everyone", route(accessEveryone), "sub_owner", true},
		{"selected empty denies", route(accessSelected), "sub_owner", false},
		{"selected empty denies admin", route(accessSelected), "sub_admin", false},
		{"selected owner", route(accessSelected, "sub_owner"), "sub_owner", true},
		{"selected other", route(accessSelected, "sub_owner"), "sub_admin", false},
		{"admins allows admin", route(accessAdmins), "sub_admin", true},
		{"admins denies ordinary", route(accessAdmins), "sub_owner", false},
		{"admins denies unknown", route(accessAdmins), "sub_ghost", false},
		{"admins denies disabled", route(accessAdmins), "sub_off", false},
		{"admins denies empty", route(accessAdmins), "", false},
	} {
		if got := g.allowsApp(tc.app, tc.subject); got != tc.want {
			t.Errorf("%s: allowsApp = %v, want %v", tc.name, got, tc.want)
		}
	}
	bad := &GateSettings{Apps: []App{{ID: "a", Name: "A", Enabled: true, Hosts: []string{"a.example.com"},
		Upstream: "http://10.0.0.1", AccessMode: "root"}}}
	if _, err := compileRouting(bad, Config{}); err == nil || !strings.Contains(err.Error(), "access mode") {
		t.Fatalf("unknown access mode accepted: %v", err)
	}
}

// browserSignIn signs a browser key in through v2 on host and returns its
// session cookie.
func (h *harness) browserSignIn(host, deviceID string, key *ecdsa.PrivateKey) (*http.Cookie, int) {
	h.t.Helper()
	rec := h.doHost(testClientAddr, host, "POST", "/_lanternfish/v2/challenge", map[string]string{"device_id": deviceID}, nil)
	c := decode[map[string]string](h.t, rec)["challenge"]
	rec = h.doHost(testClientAddr, host, "POST", "/_lanternfish/v2/session", map[string]string{"device_id": deviceID, "challenge": c,
		"signature": b64(rawSign(key, sessionMessage(deviceID, c))), "client": "browser"}, nil)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			return ck, rec.Code
		}
	}
	return nil, rec.Code
}

func TestLinkBrowserToApplication(t *testing.T) {
	h := newHarness(t)
	app := newAppServer(t)
	h.addApp(app, nil)
	key, enr := h.enrollECDSA("web")
	cookie, _ := h.browserSignIn("gate.example", enr.DeviceID, key)
	ck := map[string]string{"Cookie": cookie.String()}

	// The app host tells its page where to sign in.
	site := decode[map[string]any](t, h.doHost(testClientAddr, appHost, "GET", "/_lanternfish/v2/site", nil, nil))
	if site["app"] != true || site["sign_in_origin"] != "https://gate.example" {
		t.Fatalf("site: %v", site)
	}
	code := func() string {
		rec := h.doHost(testClientAddr, "gate.example", "POST", "/_lanternfish/v2/link/code", map[string]string{"host": appHost}, ck)
		if rec.Code != http.StatusOK {
			t.Fatalf("link code: %d %s", rec.Code, rec.Body)
		}
		return decode[map[string]any](t, rec)["code"].(string)
	}
	// Not for hosts that aren't applications, and not without signing in.
	if rec := h.doHost(testClientAddr, "gate.example", "POST", "/_lanternfish/v2/link/code", map[string]string{"host": "evil.example"}, ck); rec.Code != http.StatusNotFound {
		t.Fatalf("link code for another host: %d", rec.Code)
	}
	if rec := h.doHost(testClientAddr, "gate.example", "POST", "/_lanternfish/v2/link/code", map[string]string{"host": appHost}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("link code without a session: %d", rec.Code)
	}

	child, childPub := newKey(t)
	redeem := func(remote, host, c string, k *ecdsa.PrivateKey) *httptest.ResponseRecorder {
		pub := childPub
		return h.doHost(remote, host, "POST", "/_lanternfish/v2/link/redeem", map[string]string{"code": c, "public_key": pub,
			"proof": b64(rawSign(k, linkMessage(c)))}, nil)
	}
	c := code()
	if rec := redeem("203.0.113.9:1", appHost, c, child); rec.Code != http.StatusUnauthorized {
		t.Fatalf("redeemed from another address: %d", rec.Code)
	}
	if rec := redeem(testClientAddr, appHost, c, child); rec.Code != http.StatusUnauthorized {
		t.Fatalf("code reused after a failed redeem: %d", rec.Code)
	}
	c = code()
	if rec := redeem(testClientAddr, "other.example.com", c, child); rec.Code != http.StatusUnauthorized {
		t.Fatalf("redeemed on another host: %d", rec.Code)
	}
	c = code()
	rec := redeem(testClientAddr, appHost, c, child)
	if rec.Code != http.StatusCreated {
		t.Fatalf("redeem: %d %s", rec.Code, rec.Body)
	}
	childID := decode[map[string]enrollResponse](t, rec)["device"].DeviceID
	h.g.store.View(func(d *storeData) {
		cd := d.Devices[childID]
		if cd.ParentID != enr.DeviceID || cd.LinkedHost != appHost || cd.SubjectID != defaultSubjectID {
			t.Fatalf("linked device: %+v", cd)
		}
	})

	appCookie, code2 := h.browserSignIn(appHost, childID, child)
	if code2 != http.StatusOK {
		t.Fatalf("linked sign-in: %d", code2)
	}
	page := h.doHost(testClientAddr, appHost, "GET", "/", nil, map[string]string{"Cookie": appCookie.String(), "Accept": "text/html"})
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "/_lanternfish/gate-client.js") {
		t.Fatalf("app page with renewal: %d %s", page.Code, page.Body)
	}
	// The linked key is no use on Jellyfin's host.
	if rec := h.doHost(testClientAddr, "gate.example", "GET", "/Items", nil, map[string]string{"Cookie": appCookie.String()}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("linked device on Jellyfin: %d", rec.Code)
	}

	// Revoking the browser's device revokes the linked one, at once.
	auth := map[string]string{"Authorization": "Bearer " + h.adminKey}
	if rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, auth); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := h.doHost(testClientAddr, appHost, "GET", "/api", nil, map[string]string{"Cookie": appCookie.String()}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("linked session after parent revoked: %d", rec.Code)
	}
	if _, code := h.browserSignIn(appHost, childID, child); code == http.StatusOK {
		t.Fatal("linked device signed in after its parent was revoked")
	}
}
