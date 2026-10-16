package gate

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Admin API v2: access policies, profiles, subjects, and per-device policy
// state. Same guard as v1 (allowed networks, then an admin key).

func (g *Gate) adminV2Routes(mux *http.ServeMux) {
	const p = "/_lanternfish/admin/v2/"
	mux.HandleFunc("GET "+p+"policy", g.admin(g.handleGetPolicies))
	mux.HandleFunc("GET "+p+"policy/recommended", g.admin(g.handleRecommendedPolicy))
	mux.HandleFunc("GET "+p+"policy/history", g.admin(g.handlePolicyHistory))
	mux.HandleFunc("POST "+p+"policy/preview", g.admin(g.handlePreviewPolicy))
	mux.HandleFunc("PUT "+p+"policy", g.admin(g.handlePublishPolicy))

	mux.HandleFunc("GET "+p+"profiles", g.admin(g.handleListProfiles))
	mux.HandleFunc("POST "+p+"profiles", g.admin(g.handleCreateProfile))
	mux.HandleFunc("DELETE "+p+"profiles/{id}", g.admin(g.handleDeleteProfile))

	mux.HandleFunc("GET "+p+"subjects", g.admin(g.handleListSubjects))
	mux.HandleFunc("POST "+p+"subjects", g.admin(g.handleCreateSubject))
	mux.HandleFunc("POST "+p+"subjects/{id}/disable", g.admin(g.handleSubjectStatus("disabled")))
	mux.HandleFunc("POST "+p+"subjects/{id}/enable", g.admin(g.handleSubjectStatus("active")))

	mux.HandleFunc("GET "+p+"devices/{id}", g.admin(g.handleGetDevice))
	mux.HandleFunc("PUT "+p+"devices/{id}/profile", g.admin(g.handleAssignProfile))
	mux.HandleFunc("DELETE "+p+"devices/{id}/networks/{nid}", g.admin(g.handleDeleteNetwork))
}

func policyView(rec PolicyRecord) map[string]any {
	return map[string]any{"version": rec.Version, "scope": rec.Scope, "policy": rec.Policy,
		"editor": rec.Editor, "reason": rec.Reason, "published_at": rec.PublishedAt.UTC()}
}

func (g *Gate) handleGetPolicies(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	out := map[string]any{}
	profiles := []map[string]any{}
	g.store.View(func(d *storeData) {
		rec, _ := d.policyRecord(d.GlobalPolicyVersion)
		out["global"] = policyView(rec)
		for _, prof := range d.Profiles {
			rec, _ := d.policyRecord(prof.PolicyVersion)
			v := policyView(rec)
			v["profile"] = prof
			profiles = append(profiles, v)
		}
	})
	sort.Slice(profiles, func(i, j int) bool { return profiles[i]["scope"].(string) < profiles[j]["scope"].(string) })
	out["profiles"] = profiles
	writeJSON(w, http.StatusOK, out)
}

func (g *Gate) handleRecommendedPolicy(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	writeJSON(w, http.StatusOK, map[string]any{"policy": RecommendedPolicy()})
}

func (g *Gate) handlePolicyHistory(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	scope := r.URL.Query().Get("scope")
	out := []map[string]any{}
	g.store.View(func(d *storeData) {
		for i := len(d.PolicyHistory) - 1; i >= 0 && len(out) < 100; i-- {
			if rec := d.PolicyHistory[i]; scope == "" || rec.Scope == scope {
				out = append(out, policyView(rec))
			}
		}
	})
	writeJSON(w, http.StatusOK, map[string]any{"history": out})
}

type policyRequest struct {
	Scope           string `json:"scope"` // "global" (default) or a profile ID
	ExpectedVersion int    `json:"expected_version"`
	Reason          string `json:"reason"`
	Policy          Policy `json:"policy"`
}

// handlePreviewPolicy validates a policy and shows what publishing it would
// do, without changing anything.
func (g *Gate) handlePreviewPolicy(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	var req policyRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	scope := req.Scope
	if scope == "" {
		scope = scopeGlobal
	}
	if !g.scopeExists(scope) {
		writeError(w, http.StatusNotFound, "no such profile")
		return
	}
	cp, err := compilePolicy(0, scope, req.Policy)
	var pe *PolicyError
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "problems": pe.Problems})
		return
	} else if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "problems": []string{err.Error()}})
		return
	}
	now := g.cfg.Now()
	affected, blocked, reapprove := 0, []string{}, []string{}
	g.store.View(func(d *storeData) {
		for _, dev := range d.Devices {
			if !dev.Active() || !inScope(dev, scope, d) {
				continue
			}
			affected++
			if !cp.schedule.allowed(now) {
				blocked = append(blocked, dev.ID)
			}
			if cp.Policy.IP.Enabled && !hasApprovalUnder(dev, cp.Policy.IP, now) {
				reapprove = append(reapprove, dev.ID)
			}
		}
	})
	out := map[string]any{"valid": true, "devices_in_scope": affected,
		"devices_blocked_now_by_schedule": blocked, "devices_needing_network_approval": reapprove}
	if cp.schedule != nil {
		out["schedule_changes"] = cp.schedule.boundaries(now, 10, scheduleHorizon)
	}
	if req.Policy.IP.Enabled && req.Policy.IP.OnChange == onChangeDeny && len(reapprove) > 0 {
		out["warnings"] = []string{"with on_change \"deny\", the devices needing network approval can't sign in until they are re-enrolled"}
	}
	writeJSON(w, http.StatusOK, out)
}

// inScope reports whether a policy published to scope would govern dev.
func inScope(dev *Device, scope string, d *storeData) bool {
	if scope == scopeGlobal {
		return dev.ProfileID == "" || d.Profiles[dev.ProfileID] == nil
	}
	return dev.ProfileID == scope
}

// hasApprovalUnder reports whether one of dev's live approvals is still a
// network under ip (approvals are network keys, so changing the match or
// prefix lengths can turn them into keys that no longer occur).
func hasApprovalUnder(dev *Device, ip IPPolicy, now time.Time) bool {
	for _, a := range dev.Networks {
		if now.Before(a.ExpiresAt) && networkKey(addrOf(a.Network), ip) == a.Network {
			return true
		}
	}
	return false
}

// addrOf returns the address part of a network key ("1.2.3.0/24" -> "1.2.3.0").
func addrOf(network string) string {
	for i := 0; i < len(network); i++ {
		if network[i] == '/' {
			return network[:i]
		}
	}
	return network
}

func (g *Gate) scopeExists(scope string) bool {
	if scope == scopeGlobal {
		return true
	}
	ok := false
	g.store.View(func(d *storeData) { ok = d.Profiles[scope] != nil })
	return ok
}

var (
	errStale   = errors.New("stale")
	errMissing = errors.New("missing")
)

// handlePublishPolicy publishes a new policy version. expected_version must
// be the scope's current version, so two administrators can't silently
// overwrite each other.
func (g *Gate) handlePublishPolicy(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req policyRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Scope == "" {
		req.Scope = scopeGlobal
	}
	if _, err := compilePolicy(0, req.Scope, req.Policy); err != nil {
		var pe *PolicyError
		problems := []string{err.Error()}
		if errors.As(err, &pe) {
			problems = pe.Problems
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_policy", "problems": problems})
		return
	}
	now := g.cfg.Now()
	g.policyMu.Lock()
	defer g.policyMu.Unlock()
	var rec PolicyRecord
	current := 0
	err := g.store.Update(func(d *storeData) error {
		if req.Scope == scopeGlobal {
			current = d.GlobalPolicyVersion
		} else if prof := d.Profiles[req.Scope]; prof != nil {
			current = prof.PolicyVersion
		} else {
			return errMissing
		}
		if req.ExpectedVersion != current {
			return errStale
		}
		rec = d.publish(req.Scope, req.Policy, key.Name, cleanReason(req.Reason), now)
		return nil
	})
	switch {
	case errors.Is(err, errMissing):
		writeError(w, http.StatusNotFound, "no such profile")
		return
	case errors.Is(err, errStale):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "version_conflict", "current_version": current})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save policy")
		return
	}
	g.policiesChanged()
	g.audit.write(now, "policy_published", map[string]any{"scope": rec.Scope, "version": rec.Version,
		"previous_version": current, "admin_key": key.Name, "ip": clientIP(r), "reason": rec.Reason})
	g.alerts.send("📜 Lanternfish Gate access policy published: " + fmt.Sprintf("%s v%d by %s", rec.Scope, rec.Version, key.Name))
	writeJSON(w, http.StatusOK, policyView(rec))
}

// policiesChanged applies the stored policies: sessions re-check lazily (by
// version), grants are dropped, and open streams are re-checked now.
func (g *Gate) policiesChanged() {
	if err := g.reloadPolicies(); err != nil {
		// The new state was validated before saving, so this means the data
		// file is damaged; keep enforcing the previous policies.
		g.audit.write(g.cfg.Now(), "policy_reload_failed", map[string]any{"error": err.Error()})
		return
	}
	g.grants.clear()
	g.recheckStreams()
}

func cleanReason(s string) string {
	s = cleanName(s)
	if s == "" {
		return "(no reason given)"
	}
	return s
}

// ---- Profiles ----

func (g *Gate) handleListProfiles(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	out := []map[string]any{}
	g.store.View(func(d *storeData) {
		count := map[string]int{}
		for _, dev := range d.Devices {
			if dev.Active() {
				count[dev.ProfileID]++
			}
		}
		for _, p := range d.Profiles {
			out = append(out, map[string]any{"id": p.ID, "name": p.Name, "created_at": p.CreatedAt.UTC(),
				"policy_version": p.PolicyVersion, "devices": count[p.ID]})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

// handleCreateProfile creates a profile, starting from the given policy or a
// copy of the current global policy.
func (g *Gate) handleCreateProfile(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		Name   string  `json:"name"`
		Policy *Policy `json:"policy"`
	}
	if err := g.readJSON(w, r, &req); err != nil || cleanName(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "malformed request (name is required)")
		return
	}
	pol := g.policies.Load().global.Policy
	if req.Policy != nil {
		pol = *req.Policy
	}
	if err := pol.Validate(); err != nil {
		var pe *PolicyError
		errors.As(err, &pe)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_policy", "problems": pe.Problems})
		return
	}
	now := g.cfg.Now()
	prof := &Profile{ID: newID("prf_"), Name: cleanName(req.Name), CreatedAt: now}
	g.policyMu.Lock()
	defer g.policyMu.Unlock()
	if err := g.store.Update(func(d *storeData) error {
		if len(d.Profiles) >= 100 {
			return errors.New("too many profiles")
		}
		d.Profiles[prof.ID] = prof
		d.publish(prof.ID, pol, key.Name, "profile created", now)
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save profile: "+err.Error())
		return
	}
	g.policiesChanged()
	g.audit.write(now, "profile_created", map[string]any{"profile_id": prof.ID, "name": prof.Name, "admin_key": key.Name, "ip": clientIP(r)})
	writeJSON(w, http.StatusCreated, prof)
}

// handleDeleteProfile deletes a profile; its devices and pending tickets
// fall back to the global policy.
func (g *Gate) handleDeleteProfile(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	g.policyMu.Lock()
	defer g.policyMu.Unlock()
	moved := 0
	err := g.store.Update(func(d *storeData) error {
		if d.Profiles[id] == nil {
			return errMissing
		}
		delete(d.Profiles, id)
		for _, dev := range d.Devices {
			if dev.ProfileID == id {
				dev.ProfileID = ""
				moved++
			}
		}
		for _, t := range d.Tickets {
			if t.ProfileID == id {
				t.ProfileID = ""
			}
		}
		return nil
	})
	if errors.Is(err, errMissing) {
		writeError(w, http.StatusNotFound, "no such profile")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	g.policiesChanged()
	g.audit.write(g.cfg.Now(), "profile_deleted", map[string]any{"profile_id": id, "devices_moved_to_global": moved,
		"admin_key": key.Name, "ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

// ---- Subjects ----

func (g *Gate) handleListSubjects(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	out := []*Subject{}
	g.store.View(func(d *storeData) {
		for _, s := range d.Subjects {
			c := *s
			out = append(out, &c)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"subjects": out})
}

func (g *Gate) handleCreateSubject(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var req struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if err := g.readJSON(w, r, &req); err != nil || cleanName(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "malformed request (name is required)")
		return
	}
	if req.Role == "" {
		req.Role = "owner"
	}
	if req.Role != "owner" && req.Role != "admin" {
		writeError(w, http.StatusBadRequest, `role must be "owner" or "admin"`)
		return
	}
	now := g.cfg.Now()
	s := &Subject{ID: newID("sub_"), Name: cleanName(req.Name), Role: req.Role, Status: "active", CreatedAt: now}
	if err := g.store.Update(func(d *storeData) error {
		if len(d.Subjects) >= 1000 {
			return errors.New("too many subjects")
		}
		d.Subjects[s.ID] = s
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save subject: "+err.Error())
		return
	}
	g.audit.write(now, "subject_created", map[string]any{"subject_id": s.ID, "name": s.Name, "admin_key": key.Name, "ip": clientIP(r)})
	writeJSON(w, http.StatusCreated, s)
}

// handleSubjectStatus disables or re-enables a subject. Disabling ends its
// devices' sessions and streams at once.
func (g *Gate) handleSubjectStatus(status string) adminHandler {
	return func(w http.ResponseWriter, r *http.Request, key *AdminKey) {
		id := r.PathValue("id")
		var devices []string
		err := g.store.Update(func(d *storeData) error {
			s := d.Subjects[id]
			if s == nil {
				return errMissing
			}
			s.Status = status
			for _, dev := range d.Devices {
				if dev.SubjectID == id {
					devices = append(devices, dev.ID)
				}
			}
			return nil
		})
		if errors.Is(err, errMissing) {
			writeError(w, http.StatusNotFound, "no such subject")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "could not save")
			return
		}
		if status != "active" {
			for _, dev := range devices {
				g.sessions.removeDevice(dev)
				g.grants.removeDevice(dev)
				g.streams.cancelDevice(dev)
			}
		}
		g.audit.write(g.cfg.Now(), "subject_"+status, map[string]any{"subject_id": id, "devices": len(devices),
			"admin_key": key.Name, "ip": clientIP(r)})
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---- Devices ----

func (g *Gate) handleGetDevice(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	id := r.PathValue("id")
	var v *deviceView
	now := g.cfg.Now()
	g.store.View(func(d *storeData) {
		if dev := d.Devices[id]; dev != nil {
			dv := g.viewDevice(dev, now)
			v = &dv
		}
	})
	if v == nil {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (g *Gate) handleAssignProfile(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id := r.PathValue("id")
	var req struct {
		ProfileID string `json:"profile_id"` // "" for the global policy
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	errProfile := errors.New("no such profile")
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil {
			return errMissing
		}
		if req.ProfileID != "" && d.Profiles[req.ProfileID] == nil {
			return errProfile
		}
		dev.ProfileID = req.ProfileID
		return nil
	})
	switch {
	case errors.Is(err, errMissing):
		writeError(w, http.StatusNotFound, "no such device")
		return
	case errors.Is(err, errProfile):
		writeError(w, http.StatusBadRequest, "profile_id is not a profile")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	// The device's sessions now carry another policy's version, so they are
	// re-checked on their next request; grants and streams are re-checked now.
	g.grants.removeDevice(id)
	g.recheckStreams()
	g.audit.write(g.cfg.Now(), "device_profile_assigned", map[string]any{"device_id": id, "profile_id": req.ProfileID,
		"admin_key": key.Name, "ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteNetwork withdraws a network approval; the device's sessions,
// grants and streams on that network end now.
func (g *Gate) handleDeleteNetwork(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	id, nid := r.PathValue("id"), r.PathValue("nid")
	keep := map[string]bool{}
	var network string
	err := g.store.Update(func(d *storeData) error {
		dev := d.Devices[id]
		if dev == nil {
			return errMissing
		}
		out := dev.Networks[:0:0]
		for _, a := range dev.Networks {
			if a.ID == nid {
				network = a.Network
				continue
			}
			out = append(out, a)
			keep[a.Network] = true
		}
		if network == "" {
			return errMissing
		}
		dev.Networks = out
		return nil
	})
	if errors.Is(err, errMissing) {
		writeError(w, http.StatusNotFound, "no such device or network approval")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	g.sessions.removeDeviceNetworksExcept(id, keep)
	g.grants.removeDeviceNetworksExcept(id, keep)
	g.streams.cancelDeviceNetworksExcept(id, keep)
	g.audit.write(g.cfg.Now(), "network_approval_removed", map[string]any{"device_id": id, "network": network,
		"admin_key": key.Name, "ip": clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
