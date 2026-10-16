package gate

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/yourmomsbasement/lanternfish-auth/internal/update"
)

// Updates connects the dashboard to the root updater
// (lanternfish-gate-update.service). The Gate checks GitHub and verifies
// release signatures to show what is available, and asks for an update by
// writing a request naming a version. It never installs anything itself.
type Updates struct {
	Source      *update.Source // with the trusted keys; nil keys: updates off
	RequestPath string         // where the updater looks for requests
	StatusPath  string         // where the updater reports
	UnitPath    string         // present when the updater is installed
	KeysPath    string
	KeysError   string // why no keys were loaded
	AutoPolicy  string
	Prerelease  bool

	mu        sync.Mutex
	checked   time.Time
	latest    *update.Release
	seen      []update.Candidate
	checkErr  string
	lastCheck time.Time // throttles forced checks
}

const updateCacheTTL = time.Hour

// unavailable says why updates can't be installed from the dashboard, or "".
func (u *Updates) unavailable() string {
	switch {
	case u == nil:
		return "updates aren't configured"
	case u.KeysError != "":
		return u.KeysError
	case u.UnitPath != "" && !exists(u.UnitPath):
		return "the updater isn't installed (" + u.UnitPath + "); run install-gate.sh from a release"
	}
	return ""
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// check refreshes the cached release information when it is stale or force
// is set (at most once a minute).
func (u *Updates) check(ctx context.Context, force bool, now time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !(u.checked.IsZero() || now.Sub(u.checked) > updateCacheTTL || (force && now.Sub(u.lastCheck) > time.Minute)) {
		return
	}
	u.lastCheck = now
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rel, seen, err := u.Source.Find(ctx, u.Prerelease)
	u.checked = now
	u.latest, u.seen, u.checkErr = rel, seen, ""
	if err != nil {
		u.checkErr = err.Error()
	}
}

func (g *Gate) handleGetUpdate(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	u := g.cfg.Updates
	now := g.cfg.Now()
	out := map[string]any{"current": g.cfg.Version}
	why := u.unavailable()
	out["supported"] = why == ""
	if why != "" {
		out["reason"] = why
	}
	if u == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["auto_update"] = u.AutoPolicy
	out["prerelease"] = u.Prerelease
	out["keys_path"] = u.KeysPath
	if st, err := update.ReadStatus(u.StatusPath); err == nil {
		out["status"] = st
	}
	out["pending"] = exists(u.RequestPath)
	if u.KeysError == "" {
		u.check(r.Context(), r.URL.Query().Get("refresh") == "1", now)
		u.mu.Lock()
		out["checked_at"] = u.checked.UTC()
		out["candidates"] = u.seen
		if u.checkErr != "" {
			out["error"] = u.checkErr
		}
		if u.latest != nil {
			out["latest"] = map[string]any{"version": u.latest.Version.String(), "tag": u.latest.Tag,
				"published_at": u.latest.Published, "url": u.latest.URL, "signed_by": u.latest.SignedBy}
			out["update_available"] = newer(u.latest.Version, g.cfg.Version)
		}
		u.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, out)
}

// newer reports whether v is newer than the running version ("dev" builds
// accept any release).
func newer(v update.Version, running string) bool {
	cur, err := update.ParseVersion(running)
	return err != nil || v.Compare(cur) > 0
}

// handleRequestUpdate asks the updater to install the latest verified release.
func (g *Gate) handleRequestUpdate(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	u := g.cfg.Updates
	if why := u.unavailable(); why != "" {
		writeError(w, http.StatusConflict, why)
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	u.check(r.Context(), false, now)
	u.mu.Lock()
	latest := u.latest
	u.mu.Unlock()
	want, err := update.ParseVersion(req.Version)
	// Only the release the dashboard offers: the newest verified one.
	switch {
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case latest == nil || latest.Version.Compare(want) != 0:
		writeError(w, http.StatusConflict, "that isn't the latest verified release; check again")
		return
	case !newer(want, g.cfg.Version):
		writeError(w, http.StatusConflict, fmt.Sprintf("%s is not newer than the running %s", want, g.cfg.Version))
		return
	}
	if exists(u.RequestPath) {
		writeError(w, http.StatusConflict, "an update is already pending")
		return
	}
	if err := update.WriteRequest(u.RequestPath, update.Request{Version: want.String(), RequestedBy: key.Name,
		RequestedAt: now.UTC()}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not write the update request: "+err.Error())
		return
	}
	g.audit.write(now, "update_requested", map[string]any{"version": want.String(), "from": g.cfg.Version,
		"admin_key": key.Name, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("⬆️ Lanternfish Gate update to %s requested by %s", want, key.Name))
	writeJSON(w, http.StatusAccepted, map[string]any{"version": want.String(), "state": "pending"})
}
