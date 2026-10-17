package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JellyfinEnrollment is an immutable, administrator-selected account policy.
// Privileged operations (administration, deletion and device management) are never granted.
type JellyfinEnrollment struct {
	Libraries    []string `json:"libraries"`
	Playback     bool     `json:"playback"`
	RemoteAccess bool     `json:"remote_access"`
	Downloads    bool     `json:"downloads"`
	Transcoding  bool     `json:"transcoding"`
}
type JellyfinAdminSettings struct {
	URL       string `json:"url"`
	SealedKey string `json:"sealed_key"`
}

var jellyfinID = regexp.MustCompile(`^[a-fA-F0-9-]{32,36}$`)

func validateJellyfinEnrollment(p *JellyfinEnrollment) error {
	if p == nil {
		return nil
	}
	if len(p.Libraries) == 0 || len(p.Libraries) > 100 {
		return errors.New("select at least one Jellyfin library (maximum 100)")
	}
	for _, id := range p.Libraries {
		if !jellyfinID.MatchString(id) {
			return errors.New("invalid Jellyfin library ID")
		}
	}
	return nil
}
func (p *JellyfinEnrollment) policy(disabled bool) map[string]any {
	return map[string]any{"IsAdministrator": false, "IsHidden": true, "IsDisabled": disabled, "EnableAllFolders": false, "EnabledFolders": p.Libraries,
		"EnableMediaPlayback": p.Playback, "EnableRemoteAccess": p.RemoteAccess, "EnableContentDownloading": p.Downloads,
		"EnableAudioPlaybackTranscoding": p.Transcoding, "EnableVideoPlaybackTranscoding": p.Transcoding, "EnablePlaybackRemuxing": p.Transcoding,
		"EnableContentDeletion": false, "EnableContentDeletionFromFolders": []string{}, "EnableAllDevices": true, "EnableAllChannels": false, "EnabledChannels": []string{},
		"EnableLiveTvAccess": false, "EnableLiveTvManagement": false, "EnableSharedDeviceControl": false, "EnableRemoteControlOfOtherUsers": false, "EnablePublicSharing": false, "EnableSyncTranscoding": false}
}
func (g *Gate) jellyfinRoutes(m *http.ServeMux) {
	const p = "/_lanternfish/admin/v2/jellyfin"
	m.HandleFunc("GET "+p, g.admin(scopeSettings, g.getJellyfinAdmin))
	m.HandleFunc("PUT "+p, g.admin(scopeSettings, g.putJellyfinAdmin))
	m.HandleFunc("GET "+p+"/libraries", g.admin(scopeTickets, g.getJellyfinLibraries))
	m.HandleFunc("GET /_lanternfish/v2/jellyfin/account", g.jellyfinAccountInfo)
	m.HandleFunc("POST /_lanternfish/v2/jellyfin/account", g.createJellyfinAccount)
	m.HandleFunc("GET /_lanternfish/account/{$}", g.serveStatic("account.html"))
	m.HandleFunc("GET /_lanternfish/account.js", g.serveStatic("account.js"))
}
func (g *Gate) jellyfinConfig() JellyfinAdminSettings {
	var s JellyfinAdminSettings
	g.store.View(func(d *storeData) {
		if d.JellyfinAdmin != nil {
			s = *d.JellyfinAdmin
		}
	})
	return s
}
func (g *Gate) getJellyfinAdmin(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	s := g.jellyfinConfig()
	writeJSON(w, 200, map[string]any{"url": s.URL, "key_configured": s.SealedKey != ""})
}
func (g *Gate) putJellyfinAdmin(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	var req struct {
		URL    string `json:"url"`
		APIKey string `json:"api_key"`
	}
	if g.readJSON(w, r, &req) != nil {
		writeError(w, 400, "malformed request")
		return
	}
	u, e := url.Parse(strings.TrimRight(req.URL, "/"))
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		writeError(w, 400, "invalid Jellyfin server URL")
		return
	}
	s := g.jellyfinConfig()
	if req.APIKey != "" {
		if len(req.APIKey) > 1024 || strings.ContainsAny(req.APIKey, "\r\n") {
			writeError(w, 400, "invalid API key")
			return
		}
		s.SealedKey = g.sealer.Seal("jellyfin-admin-key", []byte(req.APIKey))
	} else if s.URL != u.String() {
		writeError(w, 400, "provide API key when changing server")
		return
	}
	s.URL = u.String()
	if s.SealedKey == "" {
		writeError(w, 400, "Jellyfin API key required")
		return
	}
	if g.store.Update(func(d *storeData) error { d.JellyfinAdmin = &s; return nil }) != nil {
		writeError(w, 500, "could not save settings")
		return
	}
	g.audit.write(g.cfg.Now(), "jellyfin_settings_changed", map[string]any{"actor": k.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// Errors deliberately contain no response bodies, request bodies or credentials.
func (g *Gate) jellyfinCall(ctx context.Context, s JellyfinAdminSettings, method, path string, body, out any) error {
	key, e := g.sealer.Open("jellyfin-admin-key", s.SealedKey)
	if e != nil {
		return errors.New("Jellyfin not configured")
	}
	var rd io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, s.URL+path, rd)
	if e != nil {
		return errors.New("invalid Jellyfin endpoint")
	}
	req.Header.Set("X-Emby-Token", string(key))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("Jellyfin connection failed")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("Jellyfin rejected request")
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
	}
	return nil
}
func (g *Gate) getJellyfinLibraries(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	var folders []struct {
		Name string `json:"Name"`
		ID   string `json:"ItemId"`
	}
	if g.jellyfinCall(r.Context(), g.jellyfinConfig(), "GET", "/Library/VirtualFolders", nil, &folders) != nil {
		writeError(w, 502, "could not load Jellyfin libraries")
		return
	}
	writeJSON(w, 200, map[string]any{"libraries": folders})
}
func (g *Gate) jellyfinAccountInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a := g.authorizeRequest(w, r)
	if a == nil {
		return
	}
	writeJSON(w, 200, map[string]any{"available": a.dev.JellyfinEnrollment != nil && a.dev.JellyfinUserID == "", "created": a.dev.JellyfinUserID != "", "state": a.dev.JellyfinSetupState})
}
func (g *Gate) createJellyfinAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Cookie authentication requires a same-origin request and an explicit header.
	if r.Header.Get("X-Lanternfish-Account") != "create" || r.Header.Get("Origin") != "https://"+r.Host {
		writeError(w, 403, "same-origin account request required")
		return
	}
	a := g.authorizeRequest(w, r)
	if a == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if g.readJSON(w, r, &req) != nil || len(req.Username) < 1 || len(req.Username) > 64 || strings.TrimSpace(req.Username) != req.Username || strings.ContainsAny(req.Username, "\r\n/\\") || len(req.Password) < 12 || len(req.Password) > 256 {
		writeError(w, 400, "choose a username and a password of 12–256 characters")
		return
	}
	var policy *JellyfinEnrollment
	if e := g.store.Update(func(d *storeData) error {
		dev := d.Devices[a.dev.ID]
		if dev == nil || !dev.Active() || dev.JellyfinEnrollment == nil || dev.JellyfinUserID != "" || dev.JellyfinSetupState != "" {
			return errors.New("unavailable")
		}
		dev.JellyfinSetupState = "creating"
		policy = dev.JellyfinEnrollment
		return nil
	}); e != nil {
		writeError(w, 409, "account setup unavailable or already in progress")
		return
	}
	s := g.jellyfinConfig()
	var user struct {
		ID string `json:"Id"`
	}
	// Start with an unguessable password. The chosen password is set only after restrictions apply.
	e := g.jellyfinCall(r.Context(), s, "POST", "/Users/New", map[string]any{"Name": req.Username, "Password": randomToken()}, &user)
	if e == nil && !jellyfinID.MatchString(user.ID) {
		e = errors.New("invalid Jellyfin user response")
	}
	if e == nil {
		e = g.jellyfinCall(r.Context(), s, "POST", "/Users/"+user.ID+"/Policy", policy.policy(true), nil)
	}
	if e == nil {
		e = g.jellyfinCall(r.Context(), s, "POST", "/Users/"+user.ID+"/Password", map[string]any{"NewPw": req.Password, "ResetPassword": false}, nil)
	}
	if e == nil {
		e = g.jellyfinCall(r.Context(), s, "POST", "/Users/"+user.ID+"/Policy", policy.policy(false), nil)
	}
	req.Password = ""
	if e != nil {
		// Ambiguous network failures stay locked for admin reconciliation; never create duplicates automatically.
		state := "needs_admin_review"
		if jellyfinID.MatchString(user.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if g.jellyfinCall(ctx, s, "DELETE", "/Users/"+user.ID, nil, nil) == nil {
				state = ""
			}
			cancel()
		}
		_ = g.store.Update(func(d *storeData) error {
			if dev := d.Devices[a.dev.ID]; dev != nil {
				dev.JellyfinSetupState = state
			}
			return nil
		})
		g.audit.write(g.cfg.Now(), "jellyfin_account_failed", map[string]any{"device_id": a.dev.ID, "state": state})
		writeError(w, 502, "account creation failed; contact the administrator if retry is unavailable")
		return
	}
	if e = g.store.Update(func(d *storeData) error {
		dev := d.Devices[a.dev.ID]
		if dev == nil {
			return errors.New("device missing")
		}
		dev.JellyfinUserID = user.ID
		dev.JellyfinSetupState = "created"
		return nil
	}); e != nil {
		writeError(w, 500, "account created; administrator must reconcile the device record")
		return
	}
	g.audit.write(g.cfg.Now(), "jellyfin_account_created", map[string]any{"device_id": a.dev.ID, "jellyfin_user_id": user.ID})
	writeJSON(w, 201, map[string]any{"ok": true})
}
