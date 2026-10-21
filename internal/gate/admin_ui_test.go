package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (h *harness) dashboard(remote, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	if hdr == nil {
		hdr = map[string]string{}
	}
	if body != nil && hdr["Content-Type"] == "" {
		hdr["Content-Type"] = "application/json"
	}
	return h.doFrom(remote, method, path, body, hdr)
}

// dashboardSignIn returns the session cookie header and CSRF token.
func (h *harness) dashboardSignIn() (string, string) {
	h.t.Helper()
	rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/session", map[string]string{"key": h.adminKey}, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("sign in: %d %s", rec.Code, rec.Body)
	}
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].Name != adminCookie || !c[0].HttpOnly || !c[0].Secure || c[0].SameSite != http.SameSiteStrictMode || c[0].Path != adminPath {
		h.t.Fatalf("admin cookie: %+v", c)
	}
	return adminCookie + "=" + c[0].Value, decode[map[string]any](h.t, rec)["csrf"].(string)
}

func TestDashboardOnlyOnAdminNetworks(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/_lanternfish/admin/", "/_lanternfish/admin/admin.js", "/_lanternfish/admin"} {
		if rec := h.doFrom("203.0.113.9:1", "GET", p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s from the internet: %d", p, rec.Code)
		}
	}
	rec := h.do("GET", "/_lanternfish/admin/", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("dashboard page: %d %v", rec.Code, rec.Header())
	}
	if rec := h.dashboard("203.0.113.9:1", "POST", "/_lanternfish/admin/session", map[string]string{"key": h.adminKey}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("sign-in from the internet: %d", rec.Code)
	}
}

func TestDashboardSession(t *testing.T) {
	h := newHarness(t)

	// Wrong key: refused and counted; no JSON content type or a cross-site
	// request: refused before the key is looked at.
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/session", map[string]string{"key": "lfa_wrong"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/session", map[string]string{"key": h.adminKey},
		map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusForbidden {
		t.Fatalf("form-style sign-in: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/session", map[string]string{"key": h.adminKey},
		map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site sign-in: %d", rec.Code)
	}
	// Loading the page without a session doesn't count as a failure.
	for i := 0; i < 30; i++ {
		h.dashboard(testClientAddr, "GET", "/_lanternfish/admin/session", nil, nil)
	}

	cookie, csrf := h.dashboardSignIn()
	withCookie := func(extra map[string]string) map[string]string {
		m := map[string]string{"Cookie": cookie}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if rec := h.dashboard(testClientAddr, "GET", "/_lanternfish/admin/v1/devices", nil, withCookie(nil)); rec.Code != http.StatusOK {
		t.Fatalf("read with cookie: %d %s", rec.Code, rec.Body)
	}
	ticket := map[string]any{"platform": "web"}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/v1/tickets", ticket, withCookie(nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("change without CSRF header: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/v1/tickets", ticket, withCookie(map[string]string{csrfHeader: "nope"})); rec.Code != http.StatusUnauthorized {
		t.Fatalf("change with wrong CSRF header: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/v1/tickets", ticket,
		withCookie(map[string]string{csrfHeader: csrf, "Sec-Fetch-Site": "same-site"})); rec.Code != http.StatusUnauthorized {
		t.Fatalf("change from a sibling site: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/v1/tickets", ticket, withCookie(map[string]string{csrfHeader: csrf})); rec.Code != http.StatusCreated {
		t.Fatalf("change with CSRF header: %d %s", rec.Code, rec.Body)
	}
	if rec := h.dashboard("192.168.1.99:1", "GET", "/_lanternfish/admin/v1/devices", nil, withCookie(nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie from another address: %d", rec.Code)
	}

	// Idle timeout.
	h.now = h.now.Add(adminIdle + time.Minute)
	if rec := h.dashboard(testClientAddr, "GET", "/_lanternfish/admin/v1/devices", nil, withCookie(nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("idle session: %d", rec.Code)
	}

	// Revoking the admin key ends its dashboard sessions.
	cookie, _ = h.dashboardSignIn()
	h.g.store.Update(func(d *storeData) error {
		now := h.now
		d.AdminKeys["adm_test"].RevokedAt = &now
		return nil
	})
	if rec := h.dashboard(testClientAddr, "GET", "/_lanternfish/admin/v1/devices", nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key's session: %d", rec.Code)
	}
}

func TestDashboardSignOut(t *testing.T) {
	h := newHarness(t)
	cookie, _ := h.dashboardSignIn()
	h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/logout", map[string]any{}, map[string]string{"Cookie": cookie})
	if rec := h.dashboard(testClientAddr, "GET", "/_lanternfish/admin/session", nil, map[string]string{"Cookie": cookie}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after sign-out: %d", rec.Code)
	}
}

func TestAuditEndpoint(t *testing.T) {
	h := newHarness(t)
	h.enrollECDSA("web")
	h.ticket("roku")
	type auditPage struct {
		Entries []map[string]any `json:"entries"`
	}
	rec := h.admin2("GET", "audit?q=enrolled", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: %d %s", rec.Code, rec.Body)
	}
	out := decode[auditPage](t, rec)
	if len(out.Entries) != 1 || out.Entries[0]["event"] != "enrolled" {
		t.Fatalf("filtered audit: %+v", out.Entries)
	}
	all := decode[auditPage](t, h.admin2("GET", "audit", nil))
	if len(all.Entries) < 3 || all.Entries[0]["event"] != "ticket_created" {
		t.Fatalf("audit should be newest first: %+v", all.Entries)
	}
}

// The QR encoder's output for these inputs was checked module for module
// against an independent encoder (segno 1.6.6, with its padding corrected to
// the standard: it adds a spare 0x00 data codeword when the bit stream is
// already byte-aligned).
func TestQRMatchesReference(t *testing.T) {
	long := make([]byte, 200)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	cases := []struct {
		text []byte
		ver  int
		want []string
	}{
		{[]byte("hi"), 1, []string{"e89f4f948b7906c7", "b6f78ceac5ac15b4", "69f439bee9c38226", "d0057d96fb0bb89d",
			"b96212d526d6110f", "1cf578c9b947413f", "c2958289d5d73484", "a0310e5bf664f31e"}},
		{[]byte("https://flix.cindertrace.com/_lanternfish/#ticket=lft_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcdefg"), 6,
			[]string{"8f2f0f454a7c7ac2", "69d39d68c811fe36", "ad2544f37e370e63", "ec5c39783298ce94",
				"0b189fd24188ef49", "3b31fd23c8a24e19", "fcfb6e76e46728f3", "38f0c475157102c9"}},
		{long, 10, []string{"7047901c47238783", "53f3d50d6c57acd7", "c0311502b0e7f226", "b2a86f1e1ccc38d1",
			"3c9ab2aae958331b", "a3050aab613586a7", "324508326de28cee", "a295041759e5d128"}},
	}
	for _, c := range cases {
		for mask, want := range c.want {
			var b strings.Builder
			for _, row := range qrEncodeMask(c.text, c.ver, mask) {
				for _, d := range row {
					if d {
						b.WriteByte('1')
					} else {
						b.WriteByte('0')
					}
				}
			}
			sum := sha256.Sum256([]byte(b.String()))
			if got := hex.EncodeToString(sum[:])[:16]; got != want {
				t.Errorf("%d bytes, version %d, mask %d: %s, want %s", len(c.text), c.ver, mask, got, want)
			}
		}
		if m, err := qrEncode(c.text); err != nil || len(m) != 17+4*c.ver {
			t.Errorf("%d bytes: smallest version not chosen (%d modules, %v)", len(c.text), len(m), err)
		}
	}
	if _, err := qrEncode(make([]byte, 300)); err == nil {
		t.Error("text too long for version 10 accepted")
	}
}
