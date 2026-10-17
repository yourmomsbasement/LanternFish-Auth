package gate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const maxBody = 64 << 10

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON reads a small JSON request body.
//
// SECURITY: the body is bounded in time as well as size. The server has no
// overall read timeout (uploads and streams run long), so without this a
// client could send headers, trickle or stall the body, and hold a handler
// and connection open indefinitely without ever counting as a failure.
// readBody reads a small request body whole, bounded in size and in time
// like readJSON, for handlers that parse it themselves (WebAuthn).
func (g *Gate) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(g.cfg.BodyReadTimeout)); err == nil {
		defer rc.SetReadDeadline(time.Time{})
	}
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
}

func (g *Gate) readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(g.cfg.BodyReadTimeout)); err == nil {
		defer rc.SetReadDeadline(time.Time{})
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// guard rejects callers that have used up their failure budget.
func (g *Gate) guard(w http.ResponseWriter, r *http.Request) bool {
	if g.limiter.blocked(clientIP(r), g.cfg.Now()) {
		w.Header().Set("Retry-After", fmt.Sprint(int(g.cfg.FailureWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return false
	}
	return true
}

// fail records a failed credential against the caller and audits it.
func (g *Gate) fail(w http.ResponseWriter, r *http.Request, status int, event, reason string, fields map[string]any) {
	now := g.cfg.Now()
	ip := clientIP(r)
	g.limiter.record(ip, now)
	if fields == nil {
		fields = map[string]any{}
	}
	fields["ip"] = ip
	fields["reason"] = reason
	g.audit.write(now, event, fields)
	writeError(w, status, reason)
}

func cleanName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	for len(s) > 64 {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// ---- Device endpoints ----

func (g *Gate) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !g.guard(w, r) {
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := g.readJSON(w, r, &req); err != nil || req.DeviceID == "" || len(req.DeviceID) > 64 {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	// Issued for unknown IDs too, so this can't be used to probe for devices.
	value, exp, ok := g.challenges.issue(req.DeviceID, sourceKey(clientIP(r)), g.cfg.Now(), g.cfg.ChallengeTTL)
	if !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(g.cfg.ChallengeTTL.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many outstanding challenges")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": value, "expires_at": exp.UTC()})
}

// denySession answers a correctly signed sign-in the policy doesn't allow.
// It isn't a credential failure, so it doesn't count toward the IP's
// failure limit; the device is proven, so it gets the reason.
func (g *Gate) denySession(w http.ResponseWriter, r *http.Request, dev *Device, d decision, now time.Time) {
	fields := map[string]any{"device_id": dev.ID, "ip": clientIP(r), "reason": d.reason, "network": d.network}
	if d.pol != nil {
		fields["policy_version"] = d.pol.Version
	}
	g.audit.write(now, "session_denied", fields)
	switch d.outcome {
	case outUnavailable:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "reason": d.reason})
	case outReenroll:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature not accepted", "reason": d.reason})
	default:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "reason": d.reason})
	}
}

func (g *Gate) verifyDevice(dev *Device, msg, sig []byte) bool {
	switch dev.Kind {
	case KindECDSA:
		pub, err := parseP256PublicKey(dev.PublicKey)
		return err == nil && verifyP256(pub, msg, sig)
	case KindHMAC:
		secret, err := g.sealer.Open("device-secret:"+dev.ID, dev.SealedSecret)
		return err == nil && verifyHMAC(secret, msg, sig)
	}
	return false
}

// handleLogout ends the session it was called with, and closes the
// streams that session opened.
func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Same order as other changes that take access away (see accessChanged).
	var ended []string
	if t := r.Header.Get(sessionHeader); t != "" {
		g.sessions.remove(t)
		ended = append(ended, hashToken(t))
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.sessions.remove(c.Value)
		ended = append(ended, hashToken(c.Value))
	}
	if len(ended) > 0 {
		g.accessChanged()
		for _, h := range ended {
			g.streams.cancelSession(h)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Admin endpoints ----

type adminHandler func(w http.ResponseWriter, r *http.Request, key *AdminKey)

// Admin scopes. Keys made before scopes existed (no scopes stored) have all
// of them; sensitive ones need a recent re-verification in the dashboard
// once the key is linked to an owner with an authenticator app.
const (
	scopeAny            = ""
	scopeTickets        = "tickets"
	scopeDevices        = "devices"
	scopePolicyRead     = "policy-read"
	scopePolicyWrite    = "policy-write"
	scopeOwners         = "owners"
	scopeFactorRecovery = "factor-recovery"
	scopeAudit          = "audit"
	scopeUpdates        = "updates"
	scopeSettings       = "settings"
)

var allScopes = []string{scopeTickets, scopeDevices, scopePolicyRead, scopePolicyWrite, scopeOwners,
	scopeFactorRecovery, scopeAudit, scopeUpdates, scopeSettings}

var sensitiveScopes = map[string]bool{scopePolicyWrite: true, scopeOwners: true, scopeFactorRecovery: true, scopeUpdates: true,
	scopeSettings: true}

// recentVerification is how long a dashboard re-verification lasts.
const recentVerification = 5 * time.Minute

func (k *AdminKey) hasScope(scope string) bool {
	if scope == scopeAny || k.Scopes == nil {
		return true
	}
	return contains(k.Scopes, scope)
}

func (g *Gate) admin(scope string, h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Outside the allowed networks the admin API doesn't exist at all.
		if !g.adminAllowed(clientIP(r)) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if !g.guard(w, r) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		var key *AdminKey
		var sess *adminSession
		if auth == "" {
			// The dashboard: a session cookie plus, for changes, the CSRF header.
			var why string
			if key, sess, why = g.adminFromCookie(r); key == nil {
				// No credential at all guesses nothing, so it doesn't count
				// toward the failure limit (the dashboard asks on every load).
				if why == "" {
					why = "admin key required"
				}
				writeError(w, http.StatusUnauthorized, why)
				return
			}
		}
		if ok && token != "" {
			g.store.View(func(d *storeData) {
				if k := d.adminKeyByHash(hashToken(token)); k != nil {
					c := *k
					key = &c
				}
			})
		}
		if key == nil {
			g.fail(w, r, http.StatusUnauthorized, "admin_auth_failed", "admin key required", map[string]any{"path": r.URL.Path})
			return
		}
		if !key.hasScope(scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "scope_required", "scope": scope})
			return
		}
		// SECURITY: in the dashboard, weakening changes need the admin to
		// have proved their authenticator within the last five minutes.
		if sess != nil && sensitiveScopes[scope] && r.Method != http.MethodGet && g.adminHasFactor(key) &&
			g.cfg.Now().Sub(sess.verifiedAt) > recentVerification {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent_verification_required",
				"detail": "confirm with your authenticator code first"})
			return
		}
		h(w, r, key)
	}
}

func (g *Gate) handleCreateTicket(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		JellyfinEnrollment *JellyfinEnrollment `json:"jellyfin_enrollment"`
		Platform           string              `json:"platform"`
		Label              string              `json:"label"`
		TTLSeconds         int                 `json:"ttl_seconds"`
		SubjectID          string              `json:"subject_id"`
		ProfileID          string              `json:"profile_id"`
		// KeyFingerprint binds the ticket to one device key (the fingerprint
		// the device shows before enrolling); a stolen ticket is then useless.
		KeyFingerprint string `json:"key_fingerprint"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if _, ok := platformKinds[req.Platform]; !ok {
		writeError(w, http.StatusBadRequest, "platform must be one of android, firetv, webos, tizen, web, roku")
		return
	}
	if err := validateJellyfinEnrollment(req.JellyfinEnrollment); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	ttl := g.cfg.TicketTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > g.cfg.MaxTicketTTL {
		ttl = g.cfg.MaxTicketTTL
	}
	now := g.cfg.Now()
	value := "lft_" + randomToken()
	t := &Ticket{JellyfinEnrollment: req.JellyfinEnrollment,
		ID:        newID("tkt_"),
		Hash:      hashToken(value),
		Platform:  req.Platform,
		Label:     cleanName(req.Label),
		CreatedBy: key.Name,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		SubjectID: req.SubjectID,
		ProfileID: req.ProfileID,

		KeyFingerprint: strings.ToLower(strings.TrimSpace(req.KeyFingerprint)),
	}
	if t.SubjectID == "" {
		t.SubjectID = defaultSubjectID
	}
	if fp := t.KeyFingerprint; fp != "" && (len(fp) != 19 || strings.Count(fp, ":") != 3) {
		writeError(w, http.StatusBadRequest, "key_fingerprint must look like 1a2b:3c4d:5e6f:7a8b")
		return
	}
	errSubject := errors.New("no such subject")
	errProfile := errors.New("no such profile")
	if err := g.store.Update(func(d *storeData) error {
		if s := d.Subjects[t.SubjectID]; s == nil || s.Status != "active" {
			return errSubject
		}
		if t.ProfileID != "" && d.Profiles[t.ProfileID] == nil {
			return errProfile
		}
		d.pruneTickets(now)
		d.Tickets[t.ID] = t
		return nil
	}); errors.Is(err, errSubject) {
		writeError(w, http.StatusBadRequest, "subject_id is not an active subject")
		return
	} else if errors.Is(err, errProfile) {
		writeError(w, http.StatusBadRequest, "profile_id is not a profile")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save ticket")
		return
	}
	g.audit.write(now, "ticket_created", map[string]any{
		"ticket_id": t.ID, "platform": t.Platform, "label": t.Label, "admin_key": key.Name, "ip": clientIP(r),
		"expires_at": t.ExpiresAt.UTC(), "subject_id": t.SubjectID, "profile_id": t.ProfileID,
		"key_fingerprint": t.KeyFingerprint,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": t.ID, "ticket": value, "platform": t.Platform, "label": t.Label, "expires_at": t.ExpiresAt.UTC(),
		"subject_id": t.SubjectID, "profile_id": t.ProfileID, "key_fingerprint": t.KeyFingerprint,
	})
}

func (g *Gate) handleListTickets(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	now := g.cfg.Now()
	out := []map[string]any{}
	g.store.View(func(d *storeData) {
		for _, t := range d.Tickets {
			if now.Before(t.ExpiresAt) {
				out = append(out, map[string]any{
					"id": t.ID, "platform": t.Platform, "label": t.Label, "created_by": t.CreatedBy,
					"created_at": t.CreatedAt.UTC(), "expires_at": t.ExpiresAt.UTC(),
					"subject_id": t.SubjectID, "profile_id": t.ProfileID,
				})
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i]["created_at"].(time.Time).Before(out[j]["created_at"].(time.Time)) })
	writeJSON(w, http.StatusOK, map[string]any{"tickets": out})
}

func (g *Gate) handleDeleteTicket(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	errMissing := errors.New("missing")
	err := g.store.Update(func(d *storeData) error {
		if _, ok := d.Tickets[id]; !ok {
			return errMissing
		}
		delete(d.Tickets, id)
		return nil
	})
	if errors.Is(err, errMissing) {
		writeError(w, http.StatusNotFound, "no such ticket")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	g.audit.write(g.cfg.Now(), "ticket_cancelled", map[string]any{"ticket_id": id, "admin_key": key.Name, "ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

type deviceView struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Platform     string     `json:"platform"`
	Kind         string     `json:"kind"`
	CreatedAt    time.Time  `json:"created_at"`
	EnrolledFrom string     `json:"enrolled_from"`
	LastAuthAt   *time.Time `json:"last_auth_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	// RevocationUnsaved: revoked and locked out now, but the revocation
	// could not be saved and would be lost on restart. Revoke again.
	RevocationUnsaved bool `json:"revocation_unsaved,omitempty"`

	SubjectID     string            `json:"subject_id"`
	ProfileID     string            `json:"profile_id"`
	PolicyVersion int               `json:"policy_version"`
	Networks      []NetworkApproval `json:"networks"`
	LiveSessions  int               `json:"live_sessions"`

	ParentID       string            `json:"parent_id,omitempty"`
	LinkedHost     string            `json:"linked_host,omitempty"`
	KeyFingerprint string            `json:"key_fingerprint,omitempty"`
	Suspended      string            `json:"suspended,omitempty"`
	Countries      []CountryApproval `json:"countries"`
	MACs           []macView         `json:"macs"`
	Override       *DeviceOverride   `json:"override,omitempty"`
}

// macView describes a recorded MAC without its tag.
type macView struct {
	InterfaceKind string    `json:"interface_kind"`
	Randomized    string    `json:"randomized"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

func (g *Gate) handleListDevices(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	out := []deviceView{}
	now := g.cfg.Now()
	g.store.View(func(d *storeData) {
		for _, dev := range d.Devices {
			out = append(out, g.viewDevice(dev, now))
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (g *Gate) viewDevice(dev *Device, now time.Time) deviceView {
	v := deviceView{ID: dev.ID, Name: dev.Name, Platform: dev.Platform, Kind: dev.Kind, CreatedAt: dev.CreatedAt,
		EnrolledFrom: dev.EnrolledFrom, LastAuthAt: dev.LastAuthAt, RevokedAt: dev.RevokedAt,
		SubjectID: dev.SubjectID, ProfileID: dev.ProfileID, PolicyVersion: g.policyFor(dev).Version,
		Networks: []NetworkApproval{}, LiveSessions: g.sessions.count(dev.ID, now),
		KeyFingerprint: keyFingerprint(dev.PublicKey), ParentID: dev.ParentID, LinkedHost: dev.LinkedHost, Suspended: dev.Suspended, Override: dev.Override,
		Countries: []CountryApproval{}, MACs: []macView{}}
	for _, c := range dev.Countries {
		if now.Before(c.ExpiresAt) {
			v.Countries = append(v.Countries, c)
		}
	}
	for _, m := range dev.MACs {
		v.MACs = append(v.MACs, macView{InterfaceKind: m.InterfaceKind, Randomized: m.Randomized, FirstSeen: m.FirstSeen, LastSeen: m.LastSeen})
	}
	for _, a := range dev.Networks {
		if now.Before(a.ExpiresAt) {
			v.Networks = append(v.Networks, a)
		}
	}
	if t, ok := g.lastAuth.Load(dev.ID); ok && (v.LastAuthAt == nil || t.(time.Time).After(*v.LastAuthAt)) {
		lt := t.(time.Time)
		v.LastAuthAt = &lt
	}
	_, v.RevocationUnsaved = g.unsavedRevocations.Load(dev.ID)
	return v
}

func (g *Gate) handleRevokeDevice(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	now := g.cfg.Now()
	var name, platform string
	errMissing := errors.New("missing")
	// SECURITY: fail closed. Lock the device out before saving, and keep it
	// locked out (sessions dropped, streams closed) even if the save fails,
	// rather than leaving it working until someone notices the error.
	g.unsavedRevocations.Store(id, struct{}{})
	// Every way in (sessions, grants, certificates) checks activeDevice,
	// which already refuses this device, so nothing cached can authorize it.
	g.accessChanged()
	err := g.store.Update(func(d *storeData) error {
		dev, ok := d.Devices[id]
		if !ok {
			return errMissing
		}
		if dev.RevokedAt == nil {
			dev.RevokedAt = &now
		}
		name, platform = dev.Name, dev.Platform
		return nil
	})
	if errors.Is(err, errMissing) {
		g.unsavedRevocations.Delete(id)
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	g.endAccess(id) // and the devices linked to it
	if err != nil {
		log.Printf("revoke %s: could not save: %v", id, err)
		g.audit.write(now, "revoke_not_saved", map[string]any{"device_id": id, "admin_key": key.Name,
			"ip": clientIP(r), "error": err.Error()})
		writeError(w, http.StatusInternalServerError,
			"device locked out until restart, but the revocation could not be saved; fix the data file and revoke again")
		return
	}
	g.unsavedRevocations.Delete(id)
	g.audit.write(now, "revoked", map[string]any{"device_id": id, "name": name, "admin_key": key.Name, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("🔒 Device revoked on Lanternfish Gate: %q (%s, %s)", name, platform, id))
	w.WriteHeader(http.StatusNoContent)
}
