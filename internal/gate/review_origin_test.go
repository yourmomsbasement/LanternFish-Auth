package gate

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression tests for H1 and L7 of the 2026-10-17 review.

// viaAdmin sends a request to the admin listener (LANTERNFISH_ADMIN_LISTEN).
func (h *harness) viaAdmin(method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "https://gate.example:9443"+path, rd)
	req.RemoteAddr = testClientAddr
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.g.AdminHandler().ServeHTTP(rec, req)
	return rec
}

// H1: with a separate admin origin, a script on Jellyfin's origin holding
// the admin's cookie gets neither the CSRF token nor the admin API.
func TestDashboardOnItsOwnOrigin(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.AdminListen = ":9443"

	rec := h.viaAdmin("POST", adminPath+"/session", map[string]string{"key": h.adminKey}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign in on the admin listener: %d %s", rec.Code, rec.Body)
	}
	cookie := adminCookie + "=" + rec.Result().Cookies()[0].Value
	csrf := decode[map[string]any](t, rec)["csrf"].(string)

	// The admin listener works with the cookie.
	if rec := h.viaAdmin("GET", adminPath+"/session", nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusOK {
		t.Fatalf("whoami on the admin listener: %d", rec.Code)
	}
	if rec := h.viaAdmin("GET", adminPath+"/v1/devices", nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusOK {
		t.Fatalf("admin API on the admin listener: %d %s", rec.Code, rec.Body)
	}

	// The review's probe, on the main listener: the token isn't served...
	same := map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin"}
	rec = h.do("GET", adminPath+"/session", nil, same)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), csrf) {
		t.Fatalf("main listener served the dashboard session: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{adminPath + "/", adminPath + "/admin.js"} {
		if rec := h.do("GET", p, nil, same); rec.Code != http.StatusNotFound {
			t.Errorf("main listener served %s: %d", p, rec.Code)
		}
	}
	// ...and the cookie, even with the token, authorizes nothing there.
	rec = h.do("POST", adminPath+"/v1/tickets", map[string]any{"platform": "android", "subject_id": "sub_default"},
		map[string]string{"Cookie": cookie, "Sec-Fetch-Site": "same-origin", "X-Lanternfish-CSRF": csrf})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie accepted on the main listener: %d %s", rec.Code, rec.Body)
	}
	// Admin keys still work there (the Builder uses them).
	if rec := h.do("GET", adminPath+"/v1/devices", nil, map[string]string{"Authorization": "Bearer " + h.adminKey}); rec.Code != http.StatusOK {
		t.Fatalf("admin key on the main listener: %d", rec.Code)
	}
	// The admin listener never proxies to Jellyfin.
	for _, p := range []string{"/", "/web/index.html", "/_lanternfish/v2/site", "/_lanternfish/adminx"} {
		if rec := h.viaAdmin("GET", p, nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusNotFound {
			t.Errorf("admin listener served %s: %d", p, rec.Code)
		}
	}
	if len(h.upstream) != 0 {
		t.Fatalf("requests reached Jellyfin: %d", len(h.upstream))
	}
}

// H1: the dashboard tells the admin whether it is isolated, and where
// devices connect.
func TestDashboardReportsOrigin(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.Listen = ":8443"
	cookie, _ := h.dashboardSignIn()
	out := decode[map[string]any](t, h.dashboard(testClientAddr, "GET", adminPath+"/session", nil, map[string]string{"Cookie": cookie}))
	if out["separate_origin"] != false || out["public_origin_hint"] != "https://gate.example:8443" {
		t.Fatalf("session: %v", out)
	}
}

// L7: sign-out can't be forced cross-site.
func TestDashboardSignOutRefusesCrossSite(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.dashboardSignIn()
	for _, hdr := range []map[string]string{
		{"Cookie": cookie, "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"},
		{"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"},
	} {
		h.dashboard(testClientAddr, "POST", adminPath+"/logout", nil, hdr)
		if rec := h.dashboard(testClientAddr, "GET", adminPath+"/session", nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusOK {
			t.Fatalf("forced sign-out (%v) ended the session: %d", hdr, rec.Code)
		}
	}
}
