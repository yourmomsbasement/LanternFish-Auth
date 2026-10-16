package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

// Session issuance shared by /v1/session, /v2/session and verification.

type sessionRequest struct {
	DeviceID  string `json:"device_id"`
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
	// Client "browser" gets the session only as an HttpOnly cookie (v2);
	// "native" (or v1) gets it in the response body for the session header.
	Client string     `json:"client,omitempty"`
	MAC    *MACReport `json:"mac_report,omitempty"`
}

// keyFingerprint is a short, displayable fingerprint of a device key.
func keyFingerprint(spki []byte) string {
	if len(spki) == 0 {
		return ""
	}
	sum := sha256.Sum256(spki)
	h := hex.EncodeToString(sum[:8])
	return h[0:4] + ":" + h[4:8] + ":" + h[8:12] + ":" + h[12:16]
}

// proveDevice checks a signed challenge and returns the device, or writes
// the failure and returns nil.
func (g *Gate) proveDevice(w http.ResponseWriter, r *http.Request, req sessionRequest, now time.Time) *Device {
	fields := map[string]any{"device_id": req.DeviceID}
	if !g.challenges.consume(req.Challenge, req.DeviceID, now) {
		g.fail(w, r, http.StatusUnauthorized, "session_failed", "challenge invalid, used or expired", fields)
		return nil
	}
	dev := g.activeDevice(req.DeviceID)
	sig, sigErr := decodeB64(req.Signature)
	if dev == nil || sigErr != nil || !g.verifyDevice(dev, sessionMessage(req.DeviceID, req.Challenge), sig) {
		g.fail(w, r, http.StatusUnauthorized, "session_failed", "signature not accepted", fields)
		return nil
	}
	return dev
}

func (g *Gate) handleSession(w http.ResponseWriter, r *http.Request)   { g.sessionEndpoint(w, r, 1) }
func (g *Gate) handleSessionV2(w http.ResponseWriter, r *http.Request) { g.sessionEndpoint(w, r, 2) }

func (g *Gate) sessionEndpoint(w http.ResponseWriter, r *http.Request, apiVersion int) {
	if !g.guard(w, r) {
		return
	}
	var req sessionRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if apiVersion == 1 {
		req.Client, req.MAC = "", nil
	} else if req.Client != "browser" {
		req.Client = "native"
	}
	now := g.cfg.Now()
	dev := g.proveDevice(w, r, req, now)
	if dev == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")

	// The signed challenge is a fresh proof of the device key; the policy
	// decides whether that's enough here and now.
	d := g.authorizeKeyProof(dev, clientIP(r), now)
	macStatus, pending, md := g.checkMAC(dev, d, req, now)
	if md.outcome != "" {
		d = md
	}
	switch d.outcome {
	case outAllow:
		g.issueSession(w, r, dev, d, req.Client, macStatus, now)
	case outVerify:
		g.startVerification(w, r, dev, d, pending, macStatus, now)
	default:
		g.denySession(w, r, dev, d, now)
	}
}

// issueSession creates a session for an allowed decision.
//
// expires_at = min(now + TTL, network approval end, schedule end): a session
// never outlives what authorized it, and a new one never extends an old one.
//
// SECURITY: every way to a session (a plain sign-in, or completing a
// verification) comes through here, so the policy's prerequisites for a
// session are checked here, whatever path led here.
func (g *Gate) issueSession(w http.ResponseWriter, r *http.Request, dev *Device, d decision, client, mac string, now time.Time) {
	if d.pol.Policy.MAC.RequireReport && !validMACEvidence[mac] {
		g.denySession(w, r, dev, macRequiredDecision(dev, d), now)
		return
	}
	exp := earliest(now.Add(d.pol.sessionTTL()), d.expires)
	token := g.sessions.create(session{deviceID: dev.ID, expires: exp, network: d.network,
		version: d.pol.Version, hardEnd: d.hardEnd, country: g.enforcedCountry(d.pol, clientIP(r), now), mac: mac},
		now, d.pol.Policy.Session.MaxPerDevice)
	g.noteAuth(dev, now)
	maxAge := int(exp.Sub(now).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	out := map[string]any{"expires_at": exp.UTC()}
	if client != "" {
		out["expires_in_seconds"] = maxAge // v2 only: v1 replies keep their exact shape
	}
	if client != "browser" {
		out["session_token"] = token // v1 and native clients use the session header
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- MAC reports ----

// pendingMAC is a verified report waiting to be recorded.
type pendingMAC struct {
	tag, kind, randomized string
}

// validMACEvidence are the MAC statuses that count as a valid signed report
// (see session.mac): unchanged, first seen, a change the policy only
// observes, or a change approved by verification.
var validMACEvidence = map[string]bool{"matched": true, "recorded": true, "changed_observed": true, "verified_change": true}

func macRequiredDecision(dev *Device, d decision) decision {
	reason := "mac_report_required"
	if dev.Platform == "web" {
		reason = "mac_report_unsupported" // browsers can't; the profile is wrong for this device
	}
	return decision{outcome: outDeny, reason: reason, pol: d.pol, network: d.network}
}

// checkMAC handles a native client's MAC report. It returns the session's
// MAC evidence status, a report to record after verification, and a decision
// that overrides d (zero outcome: none).
func (g *Gate) checkMAC(dev *Device, d decision, req sessionRequest, now time.Time) (string, *pendingMAC, decision) {
	var none decision
	if d.pol == nil {
		return "unavailable", nil, none
	}
	mp := d.pol.Policy.MAC
	// A missing report is refused before a step-up too: verifying a factor
	// doesn't stand in for a report the policy requires.
	needed := mp.RequireReport && (d.outcome == outAllow || d.outcome == outVerify)
	if req.MAC == nil || !mp.Collect {
		if needed {
			return "missing", nil, macRequiredDecision(dev, d)
		}
		return "unavailable", nil, none
	}
	rep := req.MAC
	mac, err := parseMAC(rep.MAC)
	sig, sigErr := decodeB64(rep.Signature)
	if err != nil || sigErr != nil || !validInterfaceKind(rep.InterfaceKind) ||
		!g.verifyDevice(dev, macMessage(dev.ID, req.Challenge, rep, mac), sig) {
		g.audit.write(now, "mac_report_rejected", map[string]any{"device_id": dev.ID})
		if needed {
			return "invalid", nil, decision{outcome: outDeny, reason: "mac_report_invalid", pol: d.pol, network: d.network}
		}
		return "invalid", nil, none
	}
	rnd := "unknown"
	if rep.Randomized != nil {
		rnd = map[bool]string{true: "yes", false: "no"}[*rep.Randomized]
	}
	p := &pendingMAC{tag: macTag(g.macKey, dev.SubjectID, dev.ID, rep.InterfaceKind, mac), kind: rep.InterfaceKind, randomized: rnd}
	g.macSeen.Store(dev.ID, now)

	known, sameKind := false, false
	for _, o := range dev.MACs {
		if o.InterfaceKind == p.kind {
			sameKind = true
			if o.Tag == p.tag {
				known = true
			}
		}
	}
	switch {
	case known:
		return "matched", nil, none
	case !sameKind:
		// First report for this interface kind: record it.
		if d.outcome == outAllow {
			g.recordMAC(dev, p, now)
		}
		return "recorded", nil, none
	}
	// Changed.
	g.audit.write(now, "mac_changed", map[string]any{"device_id": dev.ID, "interface_kind": p.kind, "action": mp.OnChange})
	switch mp.OnChange {
	case actObserve:
		if d.outcome == outAllow {
			g.recordMAC(dev, p, now)
		}
		return "changed_observed", nil, none
	case actVerify:
		if d.outcome == outAllow || d.outcome == outVerify {
			return "changed", p, decision{outcome: outVerify, reason: "mac_changed", pol: d.pol, network: d.network,
				geo: d.geo, required: d.pol.Policy.Verification.NewNetworkRequiredAll}
		}
		return "changed", nil, none
	default: // reenroll
		g.suspendDevice(dev.ID, "reported_mac_changed", now)
		return "changed", nil, decision{outcome: outReenroll, reason: "reported_mac_changed", pol: d.pol, network: d.network}
	}
}

func (g *Gate) recordMAC(dev *Device, p *pendingMAC, now time.Time) {
	g.store.Update(func(sd *storeData) error {
		stored := sd.Devices[dev.ID]
		if stored == nil {
			return nil
		}
		out := stored.MACs[:0:0]
		for _, o := range stored.MACs {
			if o.InterfaceKind != p.kind {
				out = append(out, o)
			}
		}
		stored.MACs = append(out, MACObservation{ID: newID("mac_"), Tag: p.tag, TagKeyVersion: macTagKeyVersion,
			InterfaceKind: p.kind, Randomized: p.randomized, Source: "native_report", FirstSeen: now, LastSeen: now})
		return nil
	})
}

// macReportFresh: the device reported a valid MAC recently enough (for
// certificate clients under a require_report profile).
func (g *Gate) macReportFresh(deviceID string, pol *compiledPolicy, now time.Time) bool {
	t, ok := g.macSeen.Load(deviceID)
	return ok && now.Sub(t.(time.Time)) <= time.Duration(pol.Policy.MAC.MaxObservationAgeSeconds)*time.Second
}

// suspendDevice blocks a device until an administrator re-enrolls it (or
// lifts the suspension), ending its sessions and streams now.
func (g *Gate) suspendDevice(deviceID, reason string, now time.Time) {
	err := g.store.Update(func(sd *storeData) error {
		if dev := sd.Devices[deviceID]; dev != nil {
			dev.Suspended = reason
		}
		return nil
	})
	g.sessions.removeDevice(deviceID)
	g.grants.removeDevice(deviceID)
	g.accessChanged()
	g.streams.cancelDevice(deviceID)
	g.verifications.removeDevice(deviceID)
	fields := map[string]any{"device_id": deviceID, "reason": reason}
	if err != nil {
		fields["error"] = err.Error()
	}
	g.audit.write(now, "device_suspended", fields)
	g.alerts.send(fmt.Sprintf("⛔ Device %s suspended: %s; it must be re-enrolled", deviceID, reason))
}
