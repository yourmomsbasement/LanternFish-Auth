package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Session renewal for Jellyfin's web client.
//
// Browser sessions last 15 minutes. A page load past that silently signs in
// again, but the Jellyfin web app is a single page: its background requests
// would start failing until a reload. gate-client.js with data-autorenew
// renews the session before it expires, so it has to be loaded by Jellyfin's
// index.html.
//
// The Lanternfish Jellyfin plugin adds the script itself (its "session
// renewal" setting) and marks the response with X-Lanternfish-Renewal. When
// that mark is missing (no plugin, an older plugin, or the setting is off) the
// Gate adds the script as it passes the page through. Either way it appears
// once, and only for browsers that signed in with a cookie: apps using
// client certificates or the session header never get it.
const (
	authKindHeader = "X-Lanternfish-Auth"
	renewalHeader  = "X-Lanternfish-Renewal"
	renewalScript  = `<script src="/_lanternfish/gate-client.js" data-autorenew></script>`
	maxIndexSize   = 4 << 20
)

var webIndexPath = regexp.MustCompile(`(?i)(^|/)web/(index\.html)?$`)

// wantsRenewal: a browser (cookie) page load that gets the script: Jellyfin's
// web client page, or any HTML page of an application that asks for it.
func (g *Gate) wantsRenewal(r *http.Request) bool {
	a, _ := r.Context().Value(proxyAuthKey{}).(proxyAuth)
	if g.cfg.DisableRenewalInjection || r.Method != http.MethodGet || a.how != authCookie {
		return false
	}
	if a.app != nil {
		return a.app.InjectRenewal && acceptsHTML(r)
	}
	return webIndexPath.MatchString(r.URL.Path)
}

// prepareRenewal asks the upstream for the full, uncompressed page, so the
// script can be added to it.
func (g *Gate) prepareRenewal(out *http.Request) {
	if !g.wantsRenewal(out) {
		return
	}
	out.Header.Set("Accept-Encoding", "identity")
	out.Header.Del("If-None-Match")
	out.Header.Del("If-Modified-Since")
}

func (g *Gate) injectRenewal(resp *http.Response) error {
	pluginInjected := resp.Header.Get(renewalHeader) != ""
	resp.Header.Del(renewalHeader)
	if resp.Request == nil || !g.wantsRenewal(resp.Request) ||
		resp.StatusCode != http.StatusOK ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") ||
		resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexSize+1))
	if err != nil {
		return err
	}
	if len(body) > maxIndexSize {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	a, _ := resp.Request.Context().Value(proxyAuthKey{}).(proxyAuth)
	if a.app == nil && webIndexPath.MatchString(resp.Request.URL.Path) {
		build := g.jellyfinCacheBuild(body)
		cookie, err := resp.Request.Cookie(jellyfinCacheCookie)
		if err != nil || cookie.Value != build {
			body = []byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Preparing Jellyfin</title></head><body><p id="status">Preparing Jellyfin after an update…</p><button id="retry" hidden>Retry</button><script src="/_lanternfish/jellyfin-cache.js" data-build="` + html.EscapeString(build) + `"></script></body></html>`)
			resp.Header.Set("Content-Security-Policy", pageCSP)
			resp.Header.Set("Referrer-Policy", "no-referrer")
		}
		// Always obtain a fresh entry page; hashed application assets remain cacheable.
		resp.Header.Set("Cache-Control", "no-store")
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
	}
	if i := bytes.Index(asciiLower(body), []byte("</head>")); !pluginInjected && !bytes.Contains(body, []byte("/_lanternfish/jellyfin-cache.js")) && i >= 0 &&
		!bytes.Contains(body, []byte("/_lanternfish/gate-client.js")) {
		body = append(body[:i:i], append([]byte(renewalScript), body[i:]...)...)
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

// asciiLower lowercases ASCII letters only, so byte offsets stay the same.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

const jellyfinCacheCookie = "lf_jellyfin_cache_build"

var jellyfinScriptSources = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`)

// Gate upgrades and changes to Jellyfin's script bundles invalidate query state.
// Ignore our renewal script, which may be inserted by either side of the proxy.
func (g *Gate) jellyfinCacheBuild(body []byte) string {
	sum := sha256.New()
	sum.Write([]byte("jellyfin-query-cache/v1\n" + g.cfg.Version + "\n"))
	for _, match := range jellyfinScriptSources.FindAllSubmatch(body, -1) {
		src := string(match[1])
		if strings.Contains(src, "/_lanternfish/gate-client.js") {
			continue
		}
		sum.Write([]byte(src + "\n"))
	}
	return hex.EncodeToString(sum.Sum(nil))
}
