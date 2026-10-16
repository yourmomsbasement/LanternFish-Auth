package gate

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Admin endpoints for owners' factors, device overrides and recovery.

func (g *Gate) adminFactorRoutes(mux *http.ServeMux) {
	const p = "/_lanternfish/admin/v2/"
	mux.HandleFunc("POST "+adminPath+"/verify", g.admin(scopeAny, g.handleAdminVerify))
	mux.HandleFunc("POST "+adminPath+"/link", g.admin(scopeAny, g.handleAdminLink))
	mux.HandleFunc("GET "+p+"admin-keys", g.admin(scopeAny, g.handleListAdminKeys))
	mux.HandleFunc("GET "+p+"status", g.admin(scopePolicyRead, g.handleDeploymentStatus))

	mux.HandleFunc("GET "+p+"subjects/{id}/factors", g.admin(scopeDevices, g.handleSubjectFactors))
	mux.HandleFunc("POST "+p+"subjects/{id}/setup-link", g.admin(scopeFactorRecovery, g.handleSetupLink))
	mux.HandleFunc("DELETE "+p+"subjects/{id}/factors/totp", g.admin(scopeFactorRecovery, g.handleDeleteTOTP))
	mux.HandleFunc("DELETE "+p+"subjects/{id}/factors/passkeys/{n}", g.admin(scopeFactorRecovery, g.handleDeletePasskey))

	mux.HandleFunc("PUT "+p+"devices/{id}/override", g.admin(scopePolicyWrite, g.handleSetOverride))
	mux.HandleFunc("DELETE "+p+"devices/{id}/override", g.admin(scopePolicyWrite, g.handleClearOverride))
	mux.HandleFunc("POST "+p+"devices/{id}/revoke", g.admin(scopeDevices, g.handleRevokeDevice))
	mux.HandleFunc("POST "+p+"devices/{id}/reset-enrollment", g.admin(scopeFactorRecovery, g.handleResetEnrollment))
	mux.HandleFunc("POST "+p+"devices/{id}/unsuspend", g.admin(scopeOwners, g.handleUnsuspend))
	mux.HandleFunc("DELETE "+p+"devices/{id}/network-approvals/{nid}", g.admin(scopeDevices, g.handleDeleteNetwork))
}

// adminHasFactor: the key is linked to an owner with an authenticator app,
// so sensitive dashboard actions need a recent re-verification.
func (g *Gate) adminHasFactor(key *AdminKey) bool {
	has := false
	if key.SubjectID != "" {
		g.store.View(func(d *storeData) {
			s := d.Subjects[key.SubjectID]
			has = s != nil && s.TOTP != nil
		})
	}
	return has
}

func (g *Gate) adminCookieToken(r *http.Request) string {
	if c, err := r.Cookie(adminCookie); err == nil {
		return c.Value
	}
	return ""
}

// handleAdminVerify re-verifies a dashboard session with the linked owner's
// authenticator code.
func (g *Gate) handleAdminVerify(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		Code string `json:"code"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	token := g.adminCookieToken(r)
	if token == "" || !g.adminHasFactor(key) {
		writeError(w, http.StatusConflict, "re-verification needs a dashboard session and an admin key linked to an owner with an authenticator app")
		return
	}
	now := g.cfg.Now()
	if g.factorLimiter.blocked("subject:"+key.SubjectID, now) {
		writeError(w, http.StatusTooManyRequests, "too many wrong codes; try again later")
		return
	}
	if err := g.consumeTOTP(key.SubjectID, req.Code, g.policies.Load().global, now); err != nil {
		g.factorLimiter.record("subject:"+key.SubjectID, now)
		g.audit.write(now, "admin_verify_failed", map[string]any{"admin_key": key.Name, "ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, "code not accepted")
		return
	}
	g.adminSessions.markVerified(token, now)
	g.audit.write(now, "admin_verified", map[string]any{"admin_key": key.Name, "ip": clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"verified_for_seconds": int(recentVerification.Seconds())})
}

// handleAdminLink links the signed-in admin key to an admin-role owner.
// Changing an existing link to an owner with factors needs re-verification.
func (g *Gate) handleAdminLink(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		SubjectID string `json:"subject_id"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	token := g.adminCookieToken(r)
	if g.adminHasFactor(key) {
		sess, ok := g.adminSessions.use(token, clientIP(r), now)
		if !ok || now.Sub(sess.verifiedAt) > recentVerification {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "recent_verification_required"})
			return
		}
	}
	err := g.store.Update(func(d *storeData) error {
		s := d.Subjects[req.SubjectID]
		if req.SubjectID != "" && (s == nil || s.Role != "admin" || s.Status != "active") {
			return errors.New("link to an active owner with the admin role")
		}
		k := d.AdminKeys[key.ID]
		if k == nil {
			return errMissing
		}
		k.SubjectID = req.SubjectID
		return nil
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	g.audit.write(now, "admin_key_linked", map[string]any{"admin_key": key.Name, "subject_id": req.SubjectID, "ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gate) handleListAdminKeys(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	out := []map[string]any{}
	g.store.View(func(d *storeData) {
		for _, k := range d.AdminKeys {
			scopes := k.Scopes
			if scopes == nil {
				scopes = allScopes
			}
			out = append(out, map[string]any{"id": k.ID, "name": k.Name, "created_at": k.CreatedAt.UTC(),
				"revoked": k.RevokedAt != nil, "scopes": scopes, "legacy_all_scopes": k.Scopes == nil,
				"subject_id": k.SubjectID, "current": k.ID == key.ID})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i]["created_at"].(time.Time).Before(out[j]["created_at"].(time.Time)) })
	writeJSON(w, http.StatusOK, map[string]any{"admin_keys": out, "you_have_factor": g.adminHasFactor(key)})
}

// handleDeploymentStatus reports what the deployment supports, so the
// dashboard can explain why a control is unavailable.
func (g *Gate) handleDeploymentStatus(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	now := g.cfg.Now()
	wa := map[string]any{"configured": g.passkeys != nil}
	if g.passkeys != nil {
		wa["rp_id"], wa["origins"] = g.passkeys.rpID, g.passkeys.origin
		wa["trusted_attestation_available"] = g.passkeys.strict != nil
		if g.passkeys.mdsErr != "" {
			wa["metadata_error"] = g.passkeys.mdsErr
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"server_time": now.UTC(), "webauthn": wa, "geoip": g.geo.health(now),
		"client_address": clientIP(r)})
}

// deploymentProblems lists what a policy needs that this Gate can't do.
func (g *Gate) deploymentProblems(scope string, p Policy) []string {
	p.normalize()
	var out []string
	if p.WebAuthn.Enabled && g.passkeys == nil {
		out = append(out, "webauthn.enabled needs LANTERNFISH_WEBAUTHN_RP_ID and LANTERNFISH_WEBAUTHN_ORIGINS")
	}
	if p.WebAuthn.Enabled && p.WebAuthn.Attestation == attRequired && (g.passkeys == nil || g.passkeys.strict == nil) {
		out = append(out, "webauthn.attestation \"require_trusted\" needs FIDO metadata (LANTERNFISH_WEBAUTHN_MDS)")
	}
	if p.Geo.Mode != geoOff && !g.geo.configured() {
		out = append(out, "geo needs a local country database (LANTERNFISH_GEOIP_DB)")
	}
	if p.MAC.RequireReport {
		if scope == scopeGlobal {
			out = append(out, "mac.require_report can only be set on a profile assigned to native devices, never globally")
		} else {
			g.store.View(func(d *storeData) {
				for _, dev := range d.Devices {
					if dev.Active() && dev.Platform == "web" && (dev.ProfileID == scope || "device:"+dev.ID == scope) {
						out = append(out, fmt.Sprintf("mac.require_report can't apply to browser device %q (browsers can't report a MAC)", dev.Name))
					}
				}
			})
		}
	}
	return out
}

// ---- Owners' factors ----

func (g *Gate) handleSubjectFactors(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	id := r.PathValue("id")
	var out map[string]any
	g.store.View(func(d *storeData) {
		s := d.Subjects[id]
		if s == nil {
			return
		}
		pk := []map[string]any{}
		for i, c := range s.Passkeys {
			pk = append(pk, map[string]any{"index": i, "name": c.Name, "created_at": c.CreatedAt.UTC(),
				"last_used_at": c.LastUsedAt, "attestation": c.AttestationResult,
				"aaguid":          fmt.Sprintf("%x", c.Credential.Authenticator.AAGUID),
				"backup_eligible": c.Credential.Flags.BackupEligible, "backup_state": c.Credential.Flags.BackupState,
				"clone_warning": c.Credential.Authenticator.CloneWarning})
		}
		unused := 0
		for _, rc := range s.RecoveryCodes {
			if rc.UsedAt == nil {
				unused++
			}
		}
		var totp any
		if s.TOTP != nil {
			totp = map[string]any{"activated_at": s.TOTP.ActivatedAt.UTC()}
		}
		out = map[string]any{"subject_id": s.ID, "name": s.Name, "role": s.Role, "totp": totp, "passkeys": pk,
			"recovery_codes_left": unused}
	})
	if out == nil {
		writeError(w, http.StatusNotFound, "no such subject")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetupLink issues a setup link for an owner. Whoever opens it can
// set up that owner's factors for 30 minutes: deliver it privately (show
// the QR in person, or a private message), and cancel by issuing another
// (or restarting the Gate) if it went astray.
func (g *Gate) handleSetupLink(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		ReplaceTOTP bool `json:"replace_totp"`
	}
	if r.ContentLength > 0 {
		if err := g.readJSON(w, r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed request")
			return
		}
	}
	id := r.PathValue("id")
	now := g.cfg.Now()
	ok := false
	g.store.View(func(d *storeData) {
		s := d.Subjects[id]
		ok = s != nil && s.Status == "active"
	})
	if !ok {
		writeError(w, http.StatusNotFound, "no such active owner")
		return
	}
	g.setupGrants.revokeSubject(id) // one live link per owner
	grant, exp := g.setupGrants.issue(id, key.Name, false, now)
	if req.ReplaceTOTP {
		g.setupGrants.with(grant, now, func(sg *setupGrant) error { sg.replaceTOTP = true; return nil })
	}
	g.audit.write(now, "setup_link_issued", map[string]any{"subject_id": id, "admin_key": key.Name,
		"replace_totp": req.ReplaceTOTP, "ip": clientIP(r)})
	writeJSON(w, http.StatusCreated, map[string]any{"path": "/_lanternfish/setup#grant=" + grant,
		"expires_at": exp.UTC()})
}

func (g *Gate) handleDeleteTOTP(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	err := g.store.Update(func(d *storeData) error {
		s := d.Subjects[id]
		if s == nil || s.TOTP == nil {
			return errMissing
		}
		s.TOTP, s.RecoveryCodes = nil, nil
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "no authenticator app to remove")
		return
	}
	g.audit.write(g.cfg.Now(), "totp_removed", map[string]any{"subject_id": id, "admin_key": key.Name, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("📱 Authenticator app removed for owner %s by %s", id, key.Name))
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gate) handleDeletePasskey(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	var n int
	if _, err := fmt.Sscan(r.PathValue("n"), &n); err != nil {
		writeError(w, http.StatusBadRequest, "bad index")
		return
	}
	var name string
	err := g.store.Update(func(d *storeData) error {
		s := d.Subjects[id]
		if s == nil || n < 0 || n >= len(s.Passkeys) {
			return errMissing
		}
		name = s.Passkeys[n].Name
		s.Passkeys = append(s.Passkeys[:n:n], s.Passkeys[n+1:]...)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "no such passkey")
		return
	}
	g.audit.write(g.cfg.Now(), "passkey_removed", map[string]any{"subject_id": id, "name": name, "admin_key": key.Name})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Devices ----

// handleSetOverride gives one device its own policy, ahead of its profile
// and the global policy, with a reason and an optional expiry.
func (g *Gate) handleSetOverride(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		Policy    Policy     `json:"policy"`
		Reason    string     `json:"reason"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	id := r.PathValue("id")
	now := g.cfg.Now()
	if strings.TrimSpace(req.Reason) == "" {
		writeError(w, http.StatusBadRequest, "an override needs a reason")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(now) {
		writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	if err := req.Policy.Validate(); err != nil {
		var pe *PolicyError
		errors.As(err, &pe)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_policy", "problems": pe.Problems})
		return
	}
	if probs := g.deploymentProblems("device:"+id, req.Policy); len(probs) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_policy", "problems": probs})
		return
	}
	g.policyMu.Lock()
	defer g.policyMu.Unlock()
	var version int
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil {
			return errMissing
		}
		rec := d.publish("device:"+id, req.Policy, key.Name, cleanReason(req.Reason), now)
		version = rec.Version
		dev.Override = &DeviceOverride{PolicyVersion: rec.Version, Reason: cleanReason(req.Reason), SetBy: key.Name,
			SetAt: now, ExpiresAt: req.ExpiresAt}
		return nil
	})
	if errors.Is(err, errMissing) {
		writeError(w, http.StatusNotFound, "no such device")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	g.policiesChanged()
	g.audit.write(now, "device_override_set", map[string]any{"device_id": id, "version": version, "reason": req.Reason,
		"admin_key": key.Name, "ip": clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"policy_version": version})
}

func (g *Gate) handleClearOverride(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	g.policyMu.Lock()
	defer g.policyMu.Unlock()
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil || dev.Override == nil {
			return errMissing
		}
		dev.Override = nil
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "no override on that device")
		return
	}
	g.policiesChanged()
	g.audit.write(g.cfg.Now(), "device_override_cleared", map[string]any{"device_id": id, "admin_key": key.Name})
	w.WriteHeader(http.StatusNoContent)
}

// handleResetEnrollment revokes a device's key and issues a ticket for its
// replacement (same owner, profile and label), bound to nothing: deliver it
// like any ticket.
func (g *Gate) handleResetEnrollment(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	now := g.cfg.Now()
	value := "lft_" + randomToken()
	var t *Ticket
	g.unsavedRevocations.Store(id, struct{}{})
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil {
			return errMissing
		}
		if dev.RevokedAt == nil {
			dev.RevokedAt = &now
		}
		t = &Ticket{ID: newID("tkt_"), Hash: hashToken(value), Platform: dev.Platform, Label: dev.Name,
			SubjectID: dev.SubjectID, ProfileID: dev.ProfileID, CreatedBy: key.Name, CreatedAt: now,
			ExpiresAt: now.Add(g.cfg.TicketTTL)}
		d.Tickets[t.ID] = t
		return nil
	})
	g.sessions.removeDevice(id)
	g.grants.removeDevice(id)
	g.streams.cancelDevice(id)
	g.verifications.removeDevice(id)
	if errors.Is(err, errMissing) {
		g.unsavedRevocations.Delete(id)
		writeError(w, http.StatusNotFound, "no such device")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "device locked out until restart, but the reset could not be saved")
		return
	}
	g.unsavedRevocations.Delete(id)
	g.audit.write(now, "enrollment_reset", map[string]any{"device_id": id, "ticket_id": t.ID, "admin_key": key.Name, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("♻️ Device %s was reset by %s; a replacement ticket was issued", id, key.Name))
	writeJSON(w, http.StatusCreated, map[string]any{"revoked_device_id": id, "ticket": value, "id": t.ID,
		"platform": t.Platform, "label": t.Label, "expires_at": t.ExpiresAt.UTC()})
}

func (g *Gate) handleUnsuspend(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil || dev.Suspended == "" {
			return errMissing
		}
		dev.Suspended = ""
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "that device isn't suspended")
		return
	}
	g.audit.write(g.cfg.Now(), "device_unsuspended", map[string]any{"device_id": id, "admin_key": key.Name})
	w.WriteHeader(http.StatusNoContent)
}
