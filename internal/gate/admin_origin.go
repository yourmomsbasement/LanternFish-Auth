package gate

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// The dashboard's origin.
//
// SECURITY: the dashboard authenticates with a cookie, and a page on the
// same origin can use that cookie and read anything the dashboard can,
// its CSRF token included. Served from the same origin as Jellyfin, any
// script that runs in Jellyfin's web client (a stored XSS in metadata, a
// plugin, a theme) running in an administrator's browser could drive the
// admin API. CSRF tokens can't fix that: they stop other origins, not the
// same one.
//
// With LANTERNFISH_ADMIN_LISTEN set, the dashboard is served on its own
// port, which is a different origin:
//   - the admin listener serves only /_lanternfish/admin…, never Jellyfin;
//   - the main listener no longer serves the dashboard, and refuses
//     dashboard (cookie) authentication altogether, because browsers send
//     cookies regardless of port. Admin keys (Authorization: Bearer), as
//     the Builder uses, work on both.
// A script on Jellyfin's origin then can't read the dashboard's responses,
// and its requests to the admin port are cross-origin ("same-site"), which
// the dashboard refuses.

type adminListenerKey struct{}

// AdminHandler serves the dashboard and the admin API on the admin
// listener (LANTERNFISH_ADMIN_LISTEN). Nothing else is served there.
func (g *Gate) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != adminPath && !strings.HasPrefix(r.URL.Path, adminPath+"/") {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		g.handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminListenerKey{}, true)))
	})
}

func viaAdminListener(r *http.Request) bool {
	v, _ := r.Context().Value(adminListenerKey{}).(bool)
	return v
}

// dashboardCookiesAllowed reports whether r may authenticate with the
// dashboard's session cookie.
func (g *Gate) dashboardCookiesAllowed(r *http.Request) bool {
	return g.cfg.AdminListen == "" || viaAdminListener(r)
}

// isDashboardPath: the dashboard's pages and its sign-in and sign-out.
func isDashboardPath(p string) bool {
	switch p {
	case adminPath, adminPath + "/", adminPath + "/admin.js", adminPath + "/admin.css",
		adminPath + "/session", adminPath + "/logout":
		return true
	}
	return false
}

// publicOriginHint is the address devices use, as seen from a dashboard
// request: the same host name, on the main listener's port.
func (g *Gate) publicOriginHint(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	_, port, err := net.SplitHostPort(g.cfg.Listen)
	if err != nil || port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + host + ":" + port
}
