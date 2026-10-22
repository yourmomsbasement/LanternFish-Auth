package gate

import (
	"context"
	"errors"
	"fmt"
	mailer "github.com/yourmomsbasement/lanternfish-auth/internal/mail"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type emailSettings struct {
	mailer.Settings
	PublicOrigin string `json:"public_origin"`
}
type EnrollmentClaim struct {
	JellyfinEnrollment *JellyfinEnrollment `json:"jellyfin_enrollment,omitempty"`
	ID                 string              `json:"id"`
	Hash               string              `json:"hash"`
	Platform           string              `json:"platform"`
	Label              string              `json:"label"`
	SubjectID          string              `json:"subject_id"`
	ProfileID          string              `json:"profile_id"`
	CreatedBy          string              `json:"created_by"`
	CreatedAt          time.Time           `json:"created_at"`
	ExpiresAt          time.Time           `json:"expires_at"`
	Used               bool                `json:"used"`
	Revoked            bool                `json:"revoked"`
	Status             string              `json:"status"`
}

func (g *Gate) emailRoutes(m *http.ServeMux) {
	g.jellyfinRoutes(m)
	const p = "/_lanternfish/admin/v2/email"
	m.HandleFunc("GET "+p, g.admin(scopeSettings, g.getEmail))
	m.HandleFunc("PUT "+p, g.admin(scopeSettings, g.putEmail))
	m.HandleFunc("POST "+p+"/test", g.admin(scopeSettings, g.testEmail))
	m.HandleFunc("POST "+p+"/invitations", g.admin(scopeTickets, g.inviteEmail))
	m.HandleFunc("POST "+p+"/invitations/{id}/retry", g.admin(scopeTickets, g.inviteEmail))
	m.HandleFunc("GET "+p+"/invitations", g.admin(scopeTickets, g.listEmail))
	m.HandleFunc("DELETE "+p+"/invitations/{id}", g.admin(scopeTickets, g.revokeEmail))
	m.HandleFunc("POST /_lanternfish/v2/claim", g.exchangeClaim)
	m.HandleFunc("GET /_lanternfish/claim/{$}", g.serveStatic("claim.html"))
	m.HandleFunc("GET /_lanternfish/claim.js", g.serveStatic("claim.js"))
}
func (g *Gate) emailConfig() emailSettings {
	s := emailSettings{Settings: mailer.Settings{Port: 25, FromName: "LanternFish Enrollment", FromEmail: "enrollment.lanternfish@cindertrace.com"}}
	g.store.View(func(d *storeData) {
		if d.EmailSettings != nil {
			s = *d.EmailSettings
		}
	})
	return s
}
func (g *Gate) getEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	writeJSON(w, 200, g.emailConfig())
}
func (g *Gate) putEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	var s emailSettings
	if g.readJSON(w, r, &s) != nil {
		writeError(w, 400, "malformed request")
		return
	}
	s.PublicOrigin = strings.TrimRight(s.PublicOrigin, "/")
	// Only an explicitly configured HTTPS hostname can enter an invitation; never trust Host.
	u, err := url.Parse(s.PublicOrigin)
	validOrigin := err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Path == "" && !strings.ContainsAny(s.PublicOrigin, "\r\n\t ")
	if s.Validate() != nil || (s.Enabled && !validOrigin) {
		writeError(w, 400, "invalid email settings or HTTPS public origin")
		return
	}

	if g.store.Update(func(d *storeData) error { d.EmailSettings = &s; return nil }) != nil {
		writeError(w, 500, "could not save settings")
		return
	}
	g.audit.write(g.cfg.Now(), "email_settings_changed", map[string]any{"actor": k.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// Limits are reserved together, with bounded storage and a bounded number of workers.
func (g *Gate) reserveMail(keys map[string]int) bool {
	g.emailMu.Lock()
	defer g.emailMu.Unlock()
	now := g.cfg.Now()
	if g.emailLimits == nil {
		g.emailLimits = map[string][]time.Time{}
	}
	for key, ts := range g.emailLimits {
		kept := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < time.Hour {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(g.emailLimits, key)
		} else {
			g.emailLimits[key] = kept
		}
	}
	if g.emailClosed || g.emailActive >= 16 || len(g.emailLimits) > 10000 {
		return false
	}
	for key, n := range keys {
		if len(g.emailLimits[key]) >= n {
			return false
		}
	}
	for key := range keys {
		g.emailLimits[key] = append(g.emailLimits[key], now)
	}
	g.emailActive++
	g.emailWG.Add(1)
	return true
}
func (g *Gate) releaseMail() {
	g.emailMu.Lock()
	g.emailActive--
	g.emailWG.Done()
	g.emailMu.Unlock()
}
func (g *Gate) submitEmail(s emailSettings, msg mailer.Message, id, actor string) {
	defer g.releaseMail()
	err := (mailer.SMTPMailer{Settings: s.Settings}).Send(context.Background(), msg)
	status, event := "sent", "enrollment_email_sent"
	if err != nil {
		status, event = "email_failed", "enrollment_email_failed"
	}
	if id != "" {
		if e := g.store.Update(func(d *storeData) error {
			if c := d.Claims[id]; c != nil {
				c.Status = status
			}
			return nil
		}); e != nil {
			event = "enrollment_email_status_failed"
		}
	} else if err == nil {
		event = "email_test_sent"
	} else {
		event = "email_test_failed"
	}
	g.audit.write(g.cfg.Now(), event, map[string]any{"claim_id": id, "actor": actor})
}
func (g *Gate) testEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	var req struct {
		Recipient string `json:"recipient"`
	}
	s := g.emailConfig()
	if g.readJSON(w, r, &req) != nil || !mailer.Address(req.Recipient) {
		writeError(w, 400, "invalid recipient")
		return
	}
	if !s.Enabled {
		writeError(w, 409, "email disabled")
		return
	}
	if !g.reserveMail(map[string]int{"test:" + k.ID: 5}) {
		writeError(w, 429, "email rate or queue limit")
		return
	}
	go g.submitEmail(s, mailer.Message{To: req.Recipient, Subject: "LanternFish test email", TextBody: "LanternFish successfully submitted this test to your email relay."}, "", k.Name)
	writeJSON(w, 202, map[string]any{"ok": true, "status": "email_queued"})
}
func (g *Gate) inviteEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	var req struct {
		JellyfinEnrollment *JellyfinEnrollment `json:"jellyfin_enrollment"`
		Recipient          string              `json:"recipient"`
		Platform           string              `json:"platform"`
		Label              string              `json:"label"`
		TTL                int                 `json:"ttl_seconds"`
		SubjectID          string              `json:"subject_id"`
		ProfileID          string              `json:"profile_id"`
	}
	if g.readJSON(w, r, &req) != nil || !mailer.Address(req.Recipient) {
		writeError(w, 400, "invalid recipient")
		return
	}
	var retry *EnrollmentClaim
	if id := r.PathValue("id"); id != "" {
		g.store.View(func(d *storeData) {
			if old := d.Claims[id]; old != nil {
				x := *old
				retry = &x
			}
		})
		if retry == nil || retry.Used || retry.Revoked || !g.cfg.Now().Before(retry.ExpiresAt) {
			writeError(w, 409, "invitation unavailable")
			return
		}
		req.Platform, req.Label, req.SubjectID, req.ProfileID, req.JellyfinEnrollment = retry.Platform, retry.Label, retry.SubjectID, retry.ProfileID, retry.JellyfinEnrollment
		req.TTL = int(retry.ExpiresAt.Sub(g.cfg.Now()).Seconds())
	}
	if _, ok := platformKinds[req.Platform]; !ok {
		writeError(w, 400, "invalid platform")
		return
	}
	if err := validateJellyfinEnrollment(req.JellyfinEnrollment); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if req.TTL == 0 {
		req.TTL = 900
	}
	if req.TTL < 60 || req.TTL > 3600 {
		writeError(w, 400, "expiry must be 60–3600 seconds")
		return
	}
	s := g.emailConfig()
	if !s.Enabled {
		writeError(w, 409, "email disabled")
		return
	}
	if !g.reserveMail(map[string]int{"admin:" + k.ID: 20, "recipient:" + hashToken(strings.ToLower(req.Recipient)): 3, "ip:" + clientIP(r): 20}) {
		writeError(w, 429, "email rate or queue limit")
		return
	}
	now := g.cfg.Now()
	raw := "lfc_" + randomToken()
	c := &EnrollmentClaim{JellyfinEnrollment: req.JellyfinEnrollment, ID: newID("clm_"), Hash: hashToken(raw), Platform: req.Platform, Label: cleanName(req.Label), SubjectID: req.SubjectID, ProfileID: req.ProfileID, CreatedBy: k.Name, CreatedAt: now, ExpiresAt: now.Add(time.Duration(req.TTL) * time.Second), Status: "email_queued"}
	if retry != nil {
		c.ExpiresAt = retry.ExpiresAt
	}
	if c.SubjectID == "" {
		c.SubjectID = defaultSubjectID
	}
	var missing string
	err := g.store.Update(func(d *storeData) error {
		if retry != nil {
			old := d.Claims[retry.ID]
			if old == nil || old.Used || old.Revoked || !now.Before(old.ExpiresAt) {
				return errors.New("invitation unavailable")
			}
			old.Revoked = true
		}
		owner := d.Subjects[c.SubjectID]
		if owner == nil || owner.Status != "active" {
			return errors.New("invalid owner")
		}
		if c.ProfileID != "" && d.Profiles[c.ProfileID] == nil {
			return errors.New("invalid profile")
		}
		if missing = enrollmentScopeNeeded(k, owner, c.ProfileID); missing != "" {
			return &scopeError{missing}
		}
		if d.Claims == nil {
			d.Claims = map[string]*EnrollmentClaim{}
		}
		for id, old := range d.Claims {
			if !now.Before(old.ExpiresAt) {
				delete(d.Claims, id)
			}
		}
		if len(d.Claims) >= 10000 {
			return errors.New("claim capacity reached")
		}
		d.Claims[c.ID] = c
		return nil
	})
	if err != nil && missing != "" {
		g.releaseMail()
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "scope_required", "scope": missing})
		return
	}
	if err != nil {
		g.releaseMail()
		writeError(w, 400, "could not create invitation; check owner and profile")
		return
	}
	link := s.PublicOrigin + "/_lanternfish/claim/#token=" + raw
	for _, event := range []string{"enrollment_email_created", "enrollment_email_queued"} {
		g.audit.write(now, event, map[string]any{"claim_id": c.ID, "actor": k.Name})
	}
	go g.submitEmail(s, mailer.Message{To: req.Recipient, Subject: "Enroll your device with LanternFish", TextBody: fmt.Sprintf("A LanternFish device enrollment invitation was created for you.\n\nDevice: %s\n\nEnroll:\n%s\n\nThis invitation expires in %d minutes and can only be used once.\nIf you were not expecting it, ignore this email.", c.Label, link, req.TTL/60)}, c.ID, k.Name)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, map[string]any{"id": c.ID, "status": "email_queued", "link": link, "expires_at": c.ExpiresAt})
}
func (g *Gate) listEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	out := []EnrollmentClaim{}
	g.store.View(func(d *storeData) {
		for _, c := range d.Claims {
			x := *c
			x.Hash = ""
			if !g.cfg.Now().Before(x.ExpiresAt) {
				x.Status = "claim_expired"
			}
			if x.Used {
				x.Status = "claim_used"
			}
			if x.Revoked {
				x.Status = "revoked"
			}
			out = append(out, x)
		}
	})
	writeJSON(w, 200, map[string]any{"invitations": out})
}
func (g *Gate) revokeEmail(w http.ResponseWriter, r *http.Request, k *AdminKey) {
	err := g.store.Update(func(d *storeData) error {
		c := d.Claims[r.PathValue("id")]
		if c == nil {
			return errors.New("missing")
		}
		c.Revoked = true
		return nil
	})
	if err != nil {
		writeError(w, 404, "invitation unavailable")
		return
	}
	g.audit.write(g.cfg.Now(), "enrollment_claim_revoked", map[string]any{"claim_id": r.PathValue("id"), "actor": k.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}
func (g *Gate) consumeEmailClaim(raw string) (string, string, error) {
	now := g.cfg.Now()
	ticket := "lft_" + randomToken()
	id := ""
	if !strings.HasPrefix(raw, "lfc_") || len(raw) != 47 {
		return "", "", errors.New("invalid claim")
	}
	err := g.store.Update(func(d *storeData) error {
		for _, c := range d.Claims {
			if c.Hash != hashToken(raw) {
				continue
			}
			if c.Used || c.Revoked || !now.Before(c.ExpiresAt) {
				return errors.New("unavailable")
			}
			if s := d.Subjects[c.SubjectID]; s == nil || s.Status != "active" {
				return errors.New("owner unavailable")
			}
			if c.ProfileID != "" && d.Profiles[c.ProfileID] == nil {
				return errors.New("profile unavailable")
			}
			c.Used = true
			id = c.ID
			t := &Ticket{JellyfinEnrollment: c.JellyfinEnrollment, ID: newID("tkt_"), Hash: hashToken(ticket), Platform: c.Platform, Label: c.Label, SubjectID: c.SubjectID, ProfileID: c.ProfileID, CreatedBy: c.CreatedBy, CreatedAt: now, ExpiresAt: c.ExpiresAt}
			d.Tickets[t.ID] = t
			return nil
		}
		return errors.New("invalid claim")
	})
	return ticket, id, err
}
func (g *Gate) exchangeClaim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !g.guard(w, r) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if g.readJSON(w, r, &req) != nil {
		writeError(w, 400, "malformed request")
		return
	}
	ticket, id, err := g.consumeEmailClaim(req.Token)
	if err != nil {
		var expiredID string
		g.store.View(func(d *storeData) {
			for _, c := range d.Claims {
				if c.Hash == hashToken(req.Token) && !g.cfg.Now().Before(c.ExpiresAt) {
					expiredID = c.ID
					break
				}
			}
		})
		if expiredID != "" {
			g.audit.write(g.cfg.Now(), "enrollment_claim_expired", map[string]any{"claim_id": expiredID})
		}

		g.fail(w, r, 401, "enrollment_claim_failed", "invitation invalid, expired, revoked or already used", nil)
		return
	}
	g.audit.write(g.cfg.Now(), "enrollment_claim_used", map[string]any{"claim_id": id})
	writeJSON(w, 200, map[string]any{"ticket": ticket})
}
