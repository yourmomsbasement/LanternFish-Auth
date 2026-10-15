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

type enrollRequest struct {
	Ticket    string `json:"ticket"`
	PublicKey string `json:"public_key,omitempty"`
	Proof     string `json:"proof,omitempty"`
	Name      string `json:"name,omitempty"`
}

type enrollResponse struct {
	DeviceID      string `json:"device_id"`
	Kind          string `json:"kind"`
	Certificate   string `json:"certificate,omitempty"`
	CACertificate string `json:"ca_certificate,omitempty"`
	Secret        string `json:"secret,omitempty"`
}

func (g *Gate) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !g.guard(w, r) {
		return
	}
	var req enrollRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	ticketHash := hashToken(req.Ticket)

	var ticket Ticket
	found := false
	g.store.View(func(d *storeData) {
		if t := d.ticketByHash(ticketHash); t != nil && now.Before(t.ExpiresAt) {
			ticket, found = *t, true
		}
	})
	if !found {
		g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "ticket invalid, used or expired", nil)
		return
	}
	kind := platformKinds[ticket.Platform]
	fields := map[string]any{"ticket_id": ticket.ID, "platform": ticket.Platform}

	dev := &Device{
		ID:           newID("dev_"),
		Name:         ticket.Label,
		Platform:     ticket.Platform,
		Kind:         kind,
		CreatedAt:    now,
		EnrolledFrom: clientIP(r),
	}
	if dev.Name == "" {
		dev.Name = cleanName(req.Name)
	}
	resp := enrollResponse{DeviceID: dev.ID, Kind: kind}

	switch kind {
	case KindECDSA:
		spki, err := decodeB64(req.PublicKey)
		if err != nil {
			g.fail(w, r, http.StatusBadRequest, "enroll_failed", "public_key is not base64", fields)
			return
		}
		pub, err := parseP256PublicKey(spki)
		if err != nil {
			g.fail(w, r, http.StatusBadRequest, "enroll_failed", "public_key must be an ECDSA P-256 SubjectPublicKeyInfo", fields)
			return
		}
		proof, err := decodeB64(req.Proof)
		if err != nil || !verifyP256(pub, enrollMessage(req.Ticket), proof) {
			g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "proof signature invalid", fields)
			return
		}
		cert, err := g.ca.issue(dev.ID, pub, now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not issue certificate")
			return
		}
		dev.PublicKey = spki
		resp.Certificate = string(cert)
		resp.CACertificate = string(g.ca.certPEM)
	case KindHMAC:
		if req.PublicKey != "" || req.Proof != "" {
			writeError(w, http.StatusBadRequest, "roku tickets take no public_key or proof")
			return
		}
		secret := randomBytes(32)
		dev.SealedSecret = g.sealer.Seal("device-secret:"+dev.ID, secret)
		resp.Secret = encodeB64(secret)
	default:
		writeError(w, http.StatusInternalServerError, "ticket has unknown platform")
		return
	}

	errUsed := errors.New("ticket already used")
	errDup := errors.New("public key already enrolled")
	err := g.store.Update(func(d *storeData) error {
		if _, ok := d.Tickets[ticket.ID]; !ok {
			return errUsed
		}
		if dev.PublicKey != nil {
			for _, other := range d.Devices {
				if string(other.PublicKey) == string(dev.PublicKey) {
					return errDup
				}
			}
		}
		delete(d.Tickets, ticket.ID)
		d.Devices[dev.ID] = dev
		return nil
	})
	switch {
	case errors.Is(err, errUsed):
		g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "ticket invalid, used or expired", fields)
		return
	case errors.Is(err, errDup):
		g.fail(w, r, http.StatusConflict, "enroll_failed", err.Error(), fields)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save device")
		return
	}

	fields["device_id"] = dev.ID
	fields["name"] = dev.Name
	fields["ip"] = dev.EnrolledFrom
	g.audit.write(now, "enrolled", fields)
	g.alerts.send(fmt.Sprintf("🏮 New device enrolled on Lanternfish Gate: %q (%s, %s) from %s",
		dev.Name, dev.Platform, dev.ID, dev.EnrolledFrom))
	writeJSON(w, http.StatusCreated, resp)
}

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

func (g *Gate) handleSession(w http.ResponseWriter, r *http.Request) {
	if !g.guard(w, r) {
		return
	}
	var req struct {
		DeviceID  string `json:"device_id"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	fields := map[string]any{"device_id": req.DeviceID}
	if !g.challenges.consume(req.Challenge, req.DeviceID, now) {
		g.fail(w, r, http.StatusUnauthorized, "session_failed", "challenge invalid, used or expired", fields)
		return
	}
	dev := g.activeDevice(req.DeviceID)
	sig, sigErr := decodeB64(req.Signature)
	if dev == nil || sigErr != nil || !g.verifyDevice(dev, sessionMessage(req.DeviceID, req.Challenge), sig) {
		g.fail(w, r, http.StatusUnauthorized, "session_failed", "signature not accepted", fields)
		return
	}

	token, exp := g.sessions.create(dev.ID, now, g.cfg.SessionTTL)
	g.noteAuth(dev, now)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(g.cfg.SessionTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"session_token": token, "expires_at": exp.UTC()})
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

func (g *Gate) handleLogout(w http.ResponseWriter, r *http.Request) {
	if t := r.Header.Get(sessionHeader); t != "" {
		g.sessions.remove(t)
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.sessions.remove(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Admin endpoints ----

type adminHandler func(w http.ResponseWriter, r *http.Request, key *AdminKey)

func (g *Gate) admin(h adminHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Outside the allowed networks the admin API doesn't exist at all.
		if !g.adminAllowed(clientIP(r)) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if !g.guard(w, r) {
			return
		}
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		var key *AdminKey
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
		h(w, r, key)
	}
}

func (g *Gate) handleCreateTicket(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		Platform   string `json:"platform"`
		Label      string `json:"label"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if _, ok := platformKinds[req.Platform]; !ok {
		writeError(w, http.StatusBadRequest, "platform must be one of android, firetv, webos, tizen, web, roku")
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
	t := &Ticket{
		ID:        newID("tkt_"),
		Hash:      hashToken(value),
		Platform:  req.Platform,
		Label:     cleanName(req.Label),
		CreatedBy: key.Name,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	if err := g.store.Update(func(d *storeData) error {
		d.pruneTickets(now)
		d.Tickets[t.ID] = t
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save ticket")
		return
	}
	g.audit.write(now, "ticket_created", map[string]any{
		"ticket_id": t.ID, "platform": t.Platform, "label": t.Label, "admin_key": key.Name, "ip": clientIP(r),
		"expires_at": t.ExpiresAt.UTC(),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": t.ID, "ticket": value, "platform": t.Platform, "label": t.Label, "expires_at": t.ExpiresAt.UTC(),
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
}

func (g *Gate) handleListDevices(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	out := []deviceView{}
	g.store.View(func(d *storeData) {
		for _, dev := range d.Devices {
			v := deviceView{dev.ID, dev.Name, dev.Platform, dev.Kind, dev.CreatedAt,
				dev.EnrolledFrom, dev.LastAuthAt, dev.RevokedAt, false}
			if t, ok := g.lastAuth.Load(dev.ID); ok && (v.LastAuthAt == nil || t.(time.Time).After(*v.LastAuthAt)) {
				lt := t.(time.Time)
				v.LastAuthAt = &lt
			}
			_, v.RevocationUnsaved = g.unsavedRevocations.Load(dev.ID)
			out = append(out, v)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
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
	g.sessions.removeDevice(id)
	g.streams.cancelDevice(id)
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
