package gate

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const testIndex = "<!DOCTYPE html><html><HEAD><title>Jellyfin</title></HEAD><body>app</body></html>"

// fakeWeb serves a Jellyfin-like web client. With plugin set, it behaves like
// the Lanternfish plugin with session renewal on: it adds the script itself
// for cookie sessions and marks the response.
func fakeWeb(plugin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !webIndexPath.MatchString(r.URL.Path) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, testIndex) // HTML, but not the web client's index
			return
		}
		body := testIndex
		if plugin && r.Header.Get(authKindHeader) == authCookie {
			body = strings.Replace(body, "</HEAD>", renewalScript+"</HEAD>", 1)
			w.Header().Set(renewalHeader, "injected")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"abc"`)
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			io.WriteString(gz, body)
			gz.Close()
			return
		}
		io.WriteString(w, body)
	}
}

func (h *harness) cookieSession(t *testing.T) string {
	t.Helper()
	key, enr := h.enrollECDSA("web")
	return "lf_session=" + h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) }) + "; " + jellyfinCacheCookie + "=" + h.g.jellyfinCacheBuild([]byte(testIndex))
}

func TestRenewalInjectedForCookieSessions(t *testing.T) {
	h := newHarness(t)
	h.respond = fakeWeb(false)
	cookie := h.cookieSession(t)

	for _, path := range []string{"/web/", "/web/index.html", "/jellyfin/web/index.html"} {
		rec := h.do("GET", path, nil, map[string]string{"Cookie": cookie, "Accept-Encoding": "gzip", "If-None-Match": `"abc"`})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Count(body, renewalScript) != 1 || !strings.Contains(body, renewalScript+"</HEAD>") {
			t.Fatalf("%s: script not injected once before </head>:\n%s", path, body)
		}
		if rec.Header().Get("ETag") != "" || rec.Header().Get("Content-Length") != itoa(len(body)) {
			t.Fatalf("%s: headers %v", path, rec.Header())
		}
		up := h.lastUpstream()
		if up.Header.Get("Accept-Encoding") != "identity" || up.Header.Get("If-None-Match") != "" {
			t.Fatalf("%s: upstream asked for %q / %q", path, up.Header.Get("Accept-Encoding"), up.Header.Get("If-None-Match"))
		}
		if up.Header.Get(authKindHeader) != authCookie {
			t.Fatalf("Jellyfin was told auth=%q", up.Header.Get(authKindHeader))
		}
	}

	// Other HTML pages are left alone.
	rec := h.do("GET", "/web/ConfigurationPage", nil, map[string]string{"Cookie": cookie})
	if strings.Contains(rec.Body.String(), "gate-client.js") {
		t.Fatal("injected into a page that isn't the web client's index")
	}
}

func TestRenewalNotInjectedForApps(t *testing.T) {
	h := newHarness(t)
	h.respond = fakeWeb(false)
	key, enr := h.enrollECDSA("webos")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	// A spoofed auth kind from the client is overwritten.
	rec := h.do("GET", "/web/index.html", nil, map[string]string{sessionHeader: token, authKindHeader: authCookie})
	if strings.Contains(rec.Body.String(), "gate-client.js") {
		t.Fatal("injected for an app using the session header")
	}
	if got := h.lastUpstream().Header.Get(authKindHeader); got != authHeader {
		t.Fatalf("Jellyfin was told auth=%q", got)
	}
}

func TestPluginInjectionIsNotDoubled(t *testing.T) {
	h := newHarness(t)
	h.respond = fakeWeb(true)
	rec := h.do("GET", "/web/index.html", nil, map[string]string{"Cookie": h.cookieSession(t)})
	if n := strings.Count(rec.Body.String(), renewalScript); n != 1 {
		t.Fatalf("script appears %d times:\n%s", n, rec.Body.String())
	}
	if rec.Header().Get(renewalHeader) != "" {
		t.Fatal("plugin's marker header leaked to the browser")
	}
}

func TestRenewalInjectionCanBeDisabled(t *testing.T) {
	h := newHarness(t)
	h.respond = fakeWeb(false)
	h.g.cfg.DisableRenewalInjection = true
	rec := h.do("GET", "/web/index.html", nil, map[string]string{"Cookie": h.cookieSession(t)})
	if strings.Contains(rec.Body.String(), "gate-client.js") {
		t.Fatal("injected while disabled")
	}
}

func TestCompressedIndexPassesThrough(t *testing.T) {
	// If Jellyfin compresses anyway, the page is passed through untouched
	// rather than corrupted.
	h := newHarness(t)
	h.respond = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		io.WriteString(gz, testIndex)
		gz.Close()
	}
	rec := h.do("GET", "/web/index.html", nil, map[string]string{"Cookie": h.cookieSession(t)})
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("headers %v", rec.Header())
	}
	gz, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gz)
	if string(body) != testIndex {
		t.Fatalf("body changed: %q", body)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestJellyfinCachePreparationPrecedesApplication(t *testing.T) {
	for _, plugin := range []bool{false, true} {
		t.Run(strconv.FormatBool(plugin), func(t *testing.T) {
			h := newHarness(t)
			h.respond = fakeWeb(plugin)
			cookie := strings.Split(h.cookieSession(t), ";")[0]
			r := h.do("GET", "/web/", nil, map[string]string{"Cookie": cookie})
			if r.Code != 200 || !strings.Contains(r.Body.String(), "/_lanternfish/jellyfin-cache.js") || strings.Contains(r.Body.String(), renewalScript) {
				t.Fatal("application loaded before cache preparation", r.Body.String())
			}
			if r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("ETag") != "" {
				t.Fatal("maintenance page cached")
			}
			build := h.g.jellyfinCacheBuild([]byte(testIndex))
			if !strings.Contains(r.Body.String(), `data-build="`+build+`"`) {
				t.Fatal("missing build marker")
			}
			r = h.do("GET", "/web/", nil, map[string]string{"Cookie": cookie + "; " + jellyfinCacheCookie + "=" + build})
			if strings.Contains(r.Body.String(), "jellyfin-cache.js") || strings.Count(r.Body.String(), renewalScript) != 1 {
				t.Fatal("prepared browser did not load application", r.Body.String())
			}
			h.g.cfg.Version = "next-build"
			r = h.do("GET", "/web/", nil, map[string]string{"Cookie": cookie + "; " + jellyfinCacheCookie + "=" + build})
			if !strings.Contains(r.Body.String(), "jellyfin-cache.js") {
				t.Fatal("Gate upgrade did not invalidate cache")
			}
		})
	}
}
func TestJellyfinCacheBuildTracksFrontendAssets(t *testing.T) {
	h := newHarness(t)
	a := []byte(`<script defer src="/web/app.123.js"></script>`)
	b := []byte(`<script defer src="/web/app.456.js"></script>`)
	if h.g.jellyfinCacheBuild(a) == h.g.jellyfinCacheBuild(b) {
		t.Fatal("frontend upgrade did not invalidate cache")
	}
	withRenewal := append(append([]byte{}, a...), []byte(renewalScript)...)
	if h.g.jellyfinCacheBuild(a) != h.g.jellyfinCacheBuild(withRenewal) {
		t.Fatal("plugin renewal injection caused cache invalidation loop")
	}
}
