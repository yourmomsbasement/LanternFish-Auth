package gate

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

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

// pendingEnrollment is a checked ticket and device key, not yet activated.
type pendingEnrollment struct {
	ticket     Ticket
	ticketHash string
	dev        *Device
	pub        *ecdsa.PublicKey // ECDSA devices
	done       *enrollResponse  // set once activated (finish is idempotent)
}

func (g *Gate) lookupTicket(raw string, now time.Time) (Ticket, bool) {
	var t Ticket
	found := false
	h := hashToken(raw)
	g.store.View(func(d *storeData) {
		if x := d.ticketByHash(h); x != nil && now.Before(x.ExpiresAt) {
			t, found = *x, true
		}
	})
	return t, found
}

// prepareEnrollment checks the ticket and the key proof. On failure it
// writes the response and returns nil.
func (g *Gate) prepareEnrollment(w http.ResponseWriter, r *http.Request, req enrollRequest, now time.Time) *pendingEnrollment {
	ticket, ok := g.lookupTicket(req.Ticket, now)
	if !ok {
		g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "ticket invalid, used or expired", nil)
		return nil
	}
	kind := platformKinds[ticket.Platform]
	fields := map[string]any{"ticket_id": ticket.ID, "platform": ticket.Platform}
	dev := &Device{JellyfinEnrollment: ticket.JellyfinEnrollment, ID: newID("dev_"), Name: ticket.Label, Platform: ticket.Platform, Kind: kind, CreatedAt: now,
		EnrolledFrom: clientIP(r), SubjectID: ticket.SubjectID, ProfileID: ticket.ProfileID}
	if dev.SubjectID == "" {
		dev.SubjectID = defaultSubjectID
	}
	if dev.Name == "" {
		dev.Name = cleanName(req.Name)
	}
	pe := &pendingEnrollment{ticket: ticket, ticketHash: hashToken(req.Ticket), dev: dev}
	switch kind {
	case KindECDSA:
		spki, err := decodeB64(req.PublicKey)
		if err != nil {
			g.fail(w, r, http.StatusBadRequest, "enroll_failed", "public_key is not base64", fields)
			return nil
		}
		pub, err := parseP256PublicKey(spki)
		if err != nil {
			g.fail(w, r, http.StatusBadRequest, "enroll_failed", "public_key must be an ECDSA P-256 SubjectPublicKeyInfo", fields)
			return nil
		}
		proof, err := decodeB64(req.Proof)
		if err != nil || !verifyP256(pub, enrollMessage(req.Ticket), proof) {
			g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "proof signature invalid", fields)
			return nil
		}
		// SECURITY: a ticket bound to a key fingerprint works only with that
		// key, so a stolen ticket is useless to anyone else.
		if ticket.KeyFingerprint != "" && !strings.EqualFold(ticket.KeyFingerprint, keyFingerprint(spki)) {
			g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "this ticket is bound to a different device key", fields)
			return nil
		}
		dev.PublicKey, pe.pub = spki, pub
	case KindHMAC:
		if req.PublicKey != "" || req.Proof != "" {
			writeError(w, http.StatusBadRequest, "roku tickets take no public_key or proof")
			return nil
		}
		if ticket.KeyFingerprint != "" {
			writeError(w, http.StatusBadRequest, "this ticket is bound to a device key; roku devices have none")
			return nil
		}
	default:
		writeError(w, http.StatusInternalServerError, "ticket has unknown platform")
		return nil
	}
	return pe
}

var (
	errTicketUsed = errors.New("ticket already used")
	errKeyDup     = errors.New("public key already enrolled")
)

// activateEnrollment issues the credential and, in one transaction,
// consumes the ticket and stores the device with its approved network (and
// first country). Nothing is issued unless that save succeeds.
func (g *Gate) activateEnrollment(w http.ResponseWriter, r *http.Request, pe *pendingEnrollment, verified string, now time.Time) *enrollResponse {
	dev := *pe.dev
	fields := map[string]any{"ticket_id": pe.ticket.ID, "platform": pe.ticket.Platform}
	resp := &enrollResponse{DeviceID: dev.ID, Kind: dev.Kind}
	var secret []byte
	switch dev.Kind {
	case KindECDSA:
		cert, err := g.ca.issue(dev.ID, pe.pub, now)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not issue certificate")
			return nil
		}
		resp.Certificate, resp.CACertificate = string(cert), string(g.ca.certPEM)
	case KindHMAC:
		secret = randomBytes(32)
		dev.SealedSecret = g.sealer.Seal("device-secret:"+dev.ID, secret)
	}
	pol := g.policyFor(&dev)
	ip := clientIP(r)
	method := "enrollment"
	if verified != "" {
		method = "enrollment+" + verified
	}
	// The ticket was delivered to this network by the administrator, so
	// enrolling approves it (when the device's policy binds to networks).
	if pol.Policy.IP.Enabled {
		dev.Networks = []NetworkApproval{{ID: newID("net_"), Network: networkKey(ip, pol.Policy.IP), Method: method,
			Verified: verified != "", ApprovedAt: now, ExpiresAt: now.Add(pol.approvalTTL()), PolicyVersion: pol.Version}}
	}
	if pol.Policy.Geo.Mode != geoOff && !pol.geoExempted(ip) {
		if geo := g.geo.lookup(ip, now); geo.known() {
			dev.Countries = addCountry(nil, geo, "", method, pol.approvalTTL(), now)
		}
	}
	err := g.store.Update(func(d *storeData) error {
		if _, ok := d.Tickets[pe.ticket.ID]; !ok {
			return errTicketUsed
		}
		if dev.PublicKey != nil {
			for _, other := range d.Devices {
				if string(other.PublicKey) == string(dev.PublicKey) {
					return errKeyDup
				}
			}
		}
		if dev.ProfileID != "" && d.Profiles[dev.ProfileID] == nil {
			dev.ProfileID = "" // profile deleted since the ticket was made: global policy
		}
		delete(d.Tickets, pe.ticket.ID)
		stored := dev
		d.Devices[dev.ID] = &stored
		return nil
	})
	switch {
	case errors.Is(err, errTicketUsed):
		g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "ticket invalid, used or expired", fields)
		return nil
	case errors.Is(err, errKeyDup):
		g.fail(w, r, http.StatusConflict, "enroll_failed", err.Error(), fields)
		return nil
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save device")
		return nil
	}
	if secret != nil {
		resp.Secret = encodeB64(secret)
	}
	fields["device_id"], fields["name"], fields["ip"], fields["verified"] = dev.ID, dev.Name, ip, verified
	g.audit.write(now, "enrolled", fields)
	g.alerts.send(fmt.Sprintf("🏮 New device enrolled on Lanternfish Gate: %q (%s, %s) from %s",
		dev.Name, dev.Platform, dev.ID, ip))
	return resp
}

// handleEnroll is /v1/enroll. It can't bypass a policy that wants the owner
// to approve new devices: such tickets must use v2.
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
	pe := g.prepareEnrollment(w, r, req, now)
	if pe == nil {
		return
	}
	if req := g.policyFor(pe.dev).Policy.Verification.EnrollmentRequiredAll; len(req) > 0 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "enrollment_verification_required",
			"required_all": req, "detail": "this device's policy needs the owner to approve enrollment: use /_lanternfish/v2/enrollment/begin"})
		return
	}
	if resp := g.activateEnrollment(w, r, pe, "", now); resp != nil {
		writeJSON(w, http.StatusCreated, resp)
	}
}

// handleEnrollBegin is /v2/enrollment/begin: check the ticket and key, then
// either activate (no owner approval needed) or reserve the ticket for a
// pending verification. A reservation never consumes the ticket.
func (g *Gate) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if !g.guard(w, r) {
		return
	}
	var req enrollRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := g.cfg.Now()
	pe := g.prepareEnrollment(w, r, req, now)
	if pe == nil {
		return
	}
	pol := g.policyFor(pe.dev)
	required := pol.Policy.Verification.EnrollmentRequiredAll
	if len(required) == 0 {
		if resp := g.activateEnrollment(w, r, pe, "", now); resp != nil {
			writeJSON(w, http.StatusCreated, map[string]any{"status": "enrolled", "device": resp})
		}
		return
	}
	if missing := g.missingFactors(pe.dev.SubjectID, required); len(missing) > 0 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "access_denied", "reason": "factor_not_set_up",
			"missing": missing, "detail": "the owner must set up these factors before devices can be enrolled"})
		return
	}
	// One reservation per ticket at a time, and few attempts per ticket.
	if g.enrollLimiter.blocked("ticket:"+pe.ticket.ID, now) {
		writeError(w, http.StatusTooManyRequests, "too many attempts with this ticket; try again later")
		return
	}
	reserved := false
	g.verifications.mu.Lock()
	for _, v := range g.verifications.byHash {
		if v.enrollment != nil && v.enrollment.ticket.ID == pe.ticket.ID && now.Before(v.expires) && v.enrollment.done == nil {
			reserved = true
		}
	}
	g.verifications.mu.Unlock()
	if reserved {
		g.enrollLimiter.record("ticket:"+pe.ticket.ID, now)
		writeError(w, http.StatusConflict, "this ticket is reserved by another enrollment in progress; try again in a few minutes")
		return
	}
	g.enrollLimiter.record("ticket:"+pe.ticket.ID, now)
	ip := clientIP(r)
	pv := pol.Policy.Verification
	ttl := time.Duration(pv.PendingTTLSeconds) * time.Second
	exp := earliest(now.Add(ttl), pe.ticket.ExpiresAt)
	v := &verification{purpose: "enrollment", reason: "new_device", deviceID: pe.dev.ID, deviceName: pe.dev.Name,
		platform: pe.dev.Platform, subjectID: pe.dev.SubjectID, ip: ip, network: networkKey(ip, pol.Policy.IP),
		geo: g.geo.lookup(ip, now), policyVersion: pol.Version, required: append([]string(nil), required...),
		done: map[string]bool{}, maxAttempts: pv.MaxFailedCodeAttempts, expires: exp,
		fingerprint: keyFingerprint(pe.dev.PublicKey), enrollment: pe}
	handle := g.verifications.add(v, now)
	if handle == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	g.audit.write(now, "enrollment_pending", map[string]any{"ticket_id": pe.ticket.ID, "subject_id": pe.dev.SubjectID,
		"ip": ip, "required": required})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "verification_required", "verification_id": handle,
		"required_all": required, "expires_in_seconds": int(exp.Sub(now).Seconds())})
}

// handleEnrollFinish activates a verified enrollment, given the same ticket
// and a fresh proof by the same key. Repeating it returns the same result,
// so a lost response doesn't need a second ticket.
func (g *Gate) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req enrollRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	var done *enrollResponse
	err := g.verifications.with(handle, now, func(x *verification) error {
		if x.enrollment == nil {
			return errors.New("not an enrollment")
		}
		v, done = *x, x.enrollment.done
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	pe := v.enrollment
	if hashToken(req.Ticket) != pe.ticketHash {
		g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "ticket doesn't match this enrollment", nil)
		return
	}
	if pe.pub != nil {
		proof, err := decodeB64(req.Proof)
		if err != nil || !verifyP256(pe.pub, enrollMessage(req.Ticket), proof) {
			g.fail(w, r, http.StatusUnauthorized, "enroll_failed", "proof signature invalid", nil)
			return
		}
	}
	if done != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "enrolled", "device": done})
		return
	}
	if !v.allDone() {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "verification_incomplete", "required_all": v.required})
		return
	}
	pol := g.policyFor(pe.dev)
	ip := clientIP(r)
	if pol.Version != v.policyVersion || networkKey(ip, pol.Policy.IP) != v.network {
		g.verifications.remove(handle)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "verification_restart",
			"reason": "the policy or this device's network changed; begin again with the same ticket"})
		return
	}
	resp := g.activateEnrollment(w, r, pe, strings.Join(v.required, "+"), now)
	if resp == nil {
		return
	}
	g.verifications.with(handle, now, func(x *verification) error { x.enrollment.done = resp; return nil })
	writeJSON(w, http.StatusCreated, map[string]any{"status": "enrolled", "device": resp})
}
