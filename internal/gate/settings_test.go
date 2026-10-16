package gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
