package gate

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Access decisions. Every way of authenticating (session cookie, session
// header, client certificate) goes through the same evaluator, both when a
// session or grant is issued and on every proxied request; there is no path
// to Jellyfin that skips it.

const (
	outAllow       = "allow"
	outDeny        = "deny"
	outNetwork     = "network_unapproved"    // valid device, network not approved
	outReenroll    = "reenrollment_required" // revoked or unusable device
	outUnavailable = "unavailable"           // couldn't decide safely (e.g. save failed)
)

// scheduleHorizon is how far ahead schedule ends are looked for.
const scheduleHorizon = 8 * 24 * time.Hour

type decision struct {
	outcome string
	reason  string
	pol     *compiledPolicy
	network string    // the request's network key under pol
	expires time.Time // the end of what is authorized (schedule close, approval expiry); zero: none
	hardEnd time.Time // schedule close only (or when to re-check it); zero: none
}

// policySet holds the compiled current policies, swapped atomically on publish.
type policySet struct {
	global   *compiledPolicy
	profiles map[string]*compiledPolicy
}

// reloadPolicies compiles the current global and profile policies.
func (g *Gate) reloadPolicies() error {
	set := &policySet{profiles: map[string]*compiledPolicy{}}
	var err error
	g.store.View(func(d *storeData) {
		rec, ok := d.policyRecord(d.GlobalPolicyVersion)
		if !ok {
			err = fmt.Errorf("global policy version %d is missing from the data file", d.GlobalPolicyVersion)
			return
		}
		if set.global, err = compilePolicy(rec.Version, scopeGlobal, rec.Policy); err != nil {
			err = fmt.Errorf("global policy version %d: %w", rec.Version, err)
			return
		}
		for id, prof := range d.Profiles {
			rec, ok := d.policyRecord(prof.PolicyVersion)
			if !ok {
				err = fmt.Errorf("profile %s policy version %d is missing", id, prof.PolicyVersion)
				return
			}
			if set.profiles[id], err = compilePolicy(rec.Version, id, rec.Policy); err != nil {
				err = fmt.Errorf("profile %s policy version %d: %w", id, rec.Version, err)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	g.policies.Store(set)
	return nil
}

// policyFor returns the policy in effect for a device: its profile's, or the
// global one.
func (g *Gate) policyFor(dev *Device) *compiledPolicy {
	set := g.policies.Load()
	if dev.ProfileID != "" {
		if p := set.profiles[dev.ProfileID]; p != nil {
			return p
		}
	}
	return set.global
}

func (g *Gate) subjectActive(id string) bool {
	active := true
	g.store.View(func(d *storeData) {
		if s := d.Subjects[id]; s != nil && s.Status != "active" {
			active = false
		}
	})
	return active
}

func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}

func approvedNetwork(dev *Device, network string, now time.Time) *NetworkApproval {
	for i := range dev.Networks {
		a := &dev.Networks[i]
		if a.Network == network && now.Before(a.ExpiresAt) {
			return a
		}
	}
	return nil
}

// evaluate decides whether dev may have access from client address ip now.
// It never changes anything; see authorizeKeyProof.
func (g *Gate) evaluate(dev *Device, ip string, now time.Time) decision {
	pol := g.policyFor(dev)
	return g.evaluateNetwork(dev, pol, networkKey(ip, pol.Policy.IP), now)
}

func (g *Gate) evaluateNetwork(dev *Device, pol *compiledPolicy, network string, now time.Time) decision {
	d := decision{pol: pol, network: network}
	switch {
	case !dev.Active():
		d.outcome, d.reason = outReenroll, "device_revoked"
		return d
	case !g.subjectActive(dev.SubjectID):
		d.outcome, d.reason = outDeny, "owner_disabled"
		return d
	case !pol.schedule.allowed(now):
		d.outcome, d.reason = outDeny, "outside_schedule"
		return d
	}
	if end, ok := pol.schedule.nextBoundary(now); ok {
		d.hardEnd, d.expires = end, end
	}
	if pol.Policy.IP.Enabled {
		a := approvedNetwork(dev, network, now)
		if a == nil {
			d.outcome, d.reason = outNetwork, "network_not_approved"
			return d
		}
		d.expires = earliest(d.expires, a.ExpiresAt)
	}
	d.outcome = outAllow
	return d
}

var errDeviceGone = errors.New("device revoked or removed")

// authorizeKeyProof decides after the device has freshly proved possession
// of its key (a signed challenge, or a client certificate on this TLS
// connection). Unlike evaluate, it may approve the request's network, when
// the policy allows a key proof to do that.
func (g *Gate) authorizeKeyProof(dev *Device, ip string, now time.Time) decision {
	d := g.evaluate(dev, ip, now)
	if d.outcome != outNetwork {
		return d
	}
	ipPol := d.pol.Policy.IP
	if ipPol.OnChange != onChangeKeyProof {
		d.outcome, d.reason = outDeny, "network_changed"
		return d
	}
	approval := NetworkApproval{ID: newID("net_"), Network: d.network, Method: onChangeKeyProof,
		ApprovedAt: now, ExpiresAt: now.Add(d.pol.approvalTTL()), PolicyVersion: d.pol.Version}
	keep := map[string]bool{}
	err := g.store.Update(func(sd *storeData) error {
		stored := sd.Devices[dev.ID]
		if !stored.Active() {
			return errDeviceGone
		}
		stored.Networks = addApproval(stored.Networks, approval, ipPol.RememberedNetworks, now)
		for _, a := range stored.Networks {
			keep[a.Network] = true
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errDeviceGone) {
			d.outcome, d.reason = outReenroll, "device_revoked"
		} else {
			d.outcome, d.reason = outUnavailable, "could_not_save_network_approval"
		}
		return d
	}
	// Sessions, grants and streams on networks the device is no longer
	// approved for end now (with one remembered network: everything on the
	// old one).
	g.sessions.removeDeviceNetworksExcept(dev.ID, keep)
	g.grants.removeDeviceNetworksExcept(dev.ID, keep)
	g.accessChanged()
	g.streams.cancelDeviceNetworksExcept(dev.ID, keep)
	g.audit.write(now, "network_approved", map[string]any{"device_id": dev.ID, "network": d.network,
		"ip": ip, "method": onChangeKeyProof, "policy_version": d.pol.Version, "expires_at": approval.ExpiresAt.UTC()})
	g.alerts.send(fmt.Sprintf("🌐 %q (%s) is now approved on a new network: %s", dev.Name, dev.ID, d.network))
	fresh := g.activeDevice(dev.ID)
	if fresh == nil {
		d.outcome, d.reason = outReenroll, "device_revoked"
		return d
	}
	return g.evaluate(fresh, ip, now)
}

// addApproval adds a, replacing any approval for the same network, dropping
// expired ones, and keeping at most limit (the newest).
func addApproval(list []NetworkApproval, a NetworkApproval, limit int, now time.Time) []NetworkApproval {
	out := make([]NetworkApproval, 0, len(list)+1)
	for _, x := range list {
		if x.Network != a.Network && now.Before(x.ExpiresAt) {
			out = append(out, x)
		}
	}
	out = append(out, a)
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// requestAuth is an authorized proxied request.
type requestAuth struct {
	dev     *Device
	how     string
	network string
	issued  time.Time // when the session or grant was issued
	expires time.Time // the session's or grant's end
	hardEnd time.Time
	pol     *compiledPolicy
}

// authorizeRequest checks a proxied request: credentials, then the device's
// current policy. On failure it writes the response and returns nil.
func (g *Gate) authorizeRequest(w http.ResponseWriter, r *http.Request) *requestAuth {
	now := g.cfg.Now()
	ip := clientIP(r)
	token, how := r.Header.Get(sessionHeader), authHeader
	if token == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			token, how = c.Value, authCookie
		}
	}

	if certDev := g.certificateDevice(r); certDev != nil {
		// SECURITY: a request can't present one device's certificate and
		// another device's session and get the more permissive of the two.
		if token != "" {
			if s, ok := g.sessions.lookup(token, now); ok && s.deviceID != certDev.ID {
				g.denyRequest(w, r, decision{outcome: outDeny, reason: "credential_mismatch"})
				return nil
			}
		}
		pol := g.policyFor(certDev)
		network := networkKey(ip, pol.Policy.IP)
		// A cached grant still needs an active owner (defence in depth: a
		// disable drops grants too).
		if gr, ok := g.grants.lookup(certDev.ID, network, now); ok && gr.version == pol.Version && g.subjectActive(certDev.SubjectID) {
			return &requestAuth{dev: certDev, how: authCertificate, network: network, issued: gr.issued,
				expires: gr.expires, hardEnd: gr.hardEnd, pol: pol}
		}
		// The certificate proved possession of the key on this connection.
		d := g.authorizeKeyProof(certDev, ip, now)
		if d.outcome != outAllow {
			g.denyRequest(w, r, d)
			return nil
		}
		exp := earliest(now.Add(d.pol.sessionTTL()), d.expires)
		g.grants.put(certDev.ID, d.network, grant{issued: now, expires: exp, version: d.pol.Version, hardEnd: d.hardEnd}, now)
		return &requestAuth{dev: certDev, how: authCertificate, network: d.network, issued: now, expires: exp,
			hardEnd: d.hardEnd, pol: d.pol}
	}

	s, ok := g.sessions.lookup(token, now)
	if !ok {
		g.unauthenticated(w, r, "")
		return nil
	}
	dev := g.activeDevice(s.deviceID)
	if dev == nil {
		g.unauthenticated(w, r, "")
		return nil
	}
	if !g.subjectActive(dev.SubjectID) {
		g.denyRequest(w, r, decision{outcome: outDeny, reason: "owner_disabled"})
		return nil
	}
	pol := g.policyFor(dev)
	network := networkKey(ip, pol.Policy.IP)
	// SECURITY: a session bound to one network is only good there. From
	// anywhere else the device must prove its key again (and the policy then
	// decides about the new network).
	if s.network != "" && s.network != network {
		g.unauthenticated(w, r, "network_changed")
		return nil
	}
	expires, hardEnd := s.expires, s.hardEnd
	if s.version != pol.Version || (s.network == "" && network != "") {
		// Issued under an older policy: re-check under the current one
		// before it authorizes anything.
		d := g.evaluateNetwork(dev, pol, network, now)
		switch d.outcome {
		case outAllow:
		case outNetwork:
			g.unauthenticated(w, r, "network_changed")
			return nil
		default:
			g.denyRequest(w, r, d)
			return nil
		}
		expires = earliest(earliest(s.expires, s.issued.Add(pol.sessionTTL())), d.expires)
		hardEnd = d.hardEnd
		// SECURITY: a shorter lifetime can leave the session already
		// expired under the new policy. End it now; don't let it through
		// once more because the check above used the old expiry.
		if !now.Before(expires) {
			g.sessions.remove(token)
			g.unauthenticated(w, r, "")
			return nil
		}
		// The session may have been removed (logout, revocation) since it
		// was looked up; then it authorizes nothing.
		if !g.sessions.reauthorize(token, pol.Version, network, expires, hardEnd) {
			g.unauthenticated(w, r, "")
			return nil
		}
	}
	return &requestAuth{dev: dev, how: how, network: network, issued: s.issued, expires: expires, hardEnd: hardEnd, pol: pol}
}

// certificateDevice returns the active device whose client certificate this
// connection presented, if any.
func (g *Gate) certificateDevice(r *http.Request) *Device {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	leaf := r.TLS.VerifiedChains[0][0]
	dev := g.activeDevice(leaf.Subject.CommonName)
	if dev == nil || dev.Kind != KindECDSA || string(dev.PublicKey) != string(leaf.RawSubjectPublicKeyInfo) {
		return nil
	}
	return dev
}

// streamDeadline is when a proxied connection must be closed: in strict
// mode when its session or grant ends; in continuity mode only at a hard
// schedule end. Revocation and policy changes close it in either mode.
func (a *requestAuth) streamDeadline() time.Time {
	if a.pol.Policy.Session.StreamExpiryMode == streamStrict {
		return a.expires
	}
	return a.hardEnd
}

func (g *Gate) unauthenticated(w http.ResponseWriter, r *http.Request, reason string) {
	if r.Method == http.MethodGet && acceptsHTML(r) {
		target := pathPrefix + "?next=" + url.QueryEscape(r.URL.RequestURI())
		if reason != "" {
			target += "&reason=" + url.QueryEscape(reason)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	body := map[string]string{"error": "lanternfish_auth_required"}
	if reason != "" {
		body["reason"] = reason
	}
	writeJSON(w, http.StatusUnauthorized, body)
}

// denyRequest answers a request the policy blocks: 403 with the reason (the
// device is known, so the reason isn't an enumeration leak), or 503 when the
// Gate couldn't decide safely.
func (g *Gate) denyRequest(w http.ResponseWriter, r *http.Request, d decision) {
	if d.outcome == outUnavailable {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "reason": d.reason})
		return
	}
	if d.outcome == outReenroll {
		g.unauthenticated(w, r, d.reason)
		return
	}
	if r.Method == http.MethodGet && acceptsHTML(r) {
		http.Redirect(w, r, pathPrefix+"?reason="+url.QueryEscape(d.reason)+"&next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "reason": d.reason})
}

// recheckStreams re-evaluates every open stream under the current policies,
// closing those no longer allowed and tightening deadlines.
func (g *Gate) recheckStreams() {
	for _, id := range g.streams.devices() {
		g.recheckDeviceStreams(id)
	}
}

// recheckDeviceStreams re-evaluates one device's open streams.
//
// SECURITY: each stream is judged as if it were a new request from its
// client address under the current policy, not by what was recorded when it
// opened:
//   - its network is re-derived and stored, so a stream opened while network
//     binding was off is bound once it is turned on, and removing that
//     network's approval closes it;
//   - in strict mode its deadline is its credential's end under the current
//     lifetime (issue time plus the policy's session lifetime), so switching
//     to strict, or shortening the lifetime, tightens streams that are
//     already open.
func (g *Gate) recheckDeviceStreams(id string) {
	now := g.cfg.Now()
	dev := g.activeDevice(id)
	if dev == nil {
		g.streams.cancelDevice(id)
		return
	}
	g.streams.recheck(id, now, func(sa streamAuth) streamVerdict {
		d := g.evaluate(dev, sa.ip, now)
		if d.outcome != outAllow {
			return streamVerdict{}
		}
		deadline := d.hardEnd
		if d.pol.Policy.Session.StreamExpiryMode == streamStrict {
			end := sa.issued.Add(d.pol.sessionTTL())
			if !sa.expires.IsZero() {
				end = earliest(end, sa.expires)
			}
			deadline = earliest(earliest(deadline, d.expires), end)
		}
		return streamVerdict{allowed: true, deadline: deadline, network: d.network}
	})
}
