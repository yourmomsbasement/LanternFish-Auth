package gate

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Additional verification ("step-up").
//
// When the policy needs more than a device key (a new network, an unknown or
// new country, a changed MAC report, or a new device's enrollment), a device
// that has just proved its key gets a pending verification instead of a
// session: 403 additional_verification_required with a random handle and the
// factors needed. The handle authorizes only the verification steps, never
// Jellyfin. Every listed factor must pass (WebAuthn AND authenticator code,
// never one instead of the other); then the device proves its key once more
// and only then is the network approved and a session issued.
//
// Pending verifications live in memory (a restart cancels them), expire after
// the policy's pending_ttl_seconds, and allow max_failed_code_attempts wrong
// codes; per-owner limits apply on top.

type verification struct {
	purpose       string // "access" or "enrollment"
	reason        string
	deviceID      string
	deviceName    string
	platform      string
	subjectID     string
	ip            string
	network       string
	geo           geoResult
	policyVersion int
	required      []string
	done          map[string]bool
	attempts      int
	maxAttempts   int
	expires       time.Time
	fingerprint   string // of the device key, for display when pairing

	pairHash    string // a TV's short pairing code, hashed
	pairExpires time.Time
	waSession   *webauthn.SessionData

	mac        *pendingMAC        // a MAC observation to record on completion
	macStatus  string             // the signed key proof's MAC evidence (see validMACEvidence)
	enrollment *pendingEnrollment // for purpose "enrollment"
}

type verificationTable struct {
	mu     sync.Mutex
	byHash map[string]*verification
	byPair map[string]string // pair code hash -> handle hash
}

const (
	maxVerifications          = 2000
	maxVerificationsPerDevice = 3
	pairCodeTTL               = 10 * time.Minute
)

func newVerificationTable() *verificationTable {
	return &verificationTable{byHash: map[string]*verification{}, byPair: map[string]string{}}
}

func (t *verificationTable) sweep(now time.Time) {
	for h, v := range t.byHash {
		if !now.Before(v.expires) {
			t.drop(h)
		}
	}
}

// drop removes a verification under every handle it has (a pairing
// gives the owner's phone a second one).
func (t *verificationTable) drop(h string) {
	v, ok := t.byHash[h]
	if !ok {
		return
	}
	if v.pairHash != "" {
		delete(t.byPair, v.pairHash)
	}
	for k, x := range t.byHash {
		if x == v {
			delete(t.byHash, k)
		}
	}
}

// add stores v and returns its handle. A device keeps at most a few pending
// verifications; a new one replaces its oldest.
func (t *verificationTable) add(v *verification, now time.Time) string {
	handle := "lfv_" + randomToken()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(now)
	var mine []string
	for h, x := range t.byHash {
		if x.deviceID == v.deviceID && x.deviceID != "" {
			mine = append(mine, h)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return t.byHash[mine[i]].expires.Before(t.byHash[mine[j]].expires) })
	for len(mine) >= maxVerificationsPerDevice {
		t.drop(mine[0])
		mine = mine[1:]
	}
	if len(t.byHash) >= maxVerifications {
		return "" // full: the caller answers 503
	}
	t.byHash[hashToken(handle)] = v
	return handle
}

// with runs fn on a live verification under the table lock.
func (t *verificationTable) with(handle string, now time.Time, fn func(v *verification) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := hashToken(handle)
	v, ok := t.byHash[h]
	if !ok || !now.Before(v.expires) {
		t.drop(h)
		return errNoVerification
	}
	return fn(v)
}

func (t *verificationTable) remove(handle string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drop(hashToken(handle))
}

// removeDevice cancels a device's pending verifications (revocation).
func (t *verificationTable) removeDevice(deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, v := range t.byHash {
		if v.deviceID == deviceID {
			t.drop(h)
		}
	}
}

// failed counts a wrong code; at the limit the verification is cancelled.
func (t *verificationTable) failed(handle string) (left int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := hashToken(handle)
	v, ok := t.byHash[h]
	if !ok {
		return 0
	}
	v.attempts++
	if v.attempts >= v.maxAttempts {
		t.drop(h)
		return 0
	}
	return v.maxAttempts - v.attempts
}

var errNoVerification = errors.New("verification not found or expired")

func (v *verification) allDone() bool {
	for _, f := range v.required {
		if !v.done[f] {
			return false
		}
	}
	return true
}

func (v *verification) needs(f string) bool {
	return contains(v.required, f) && !v.done[f]
}

// view is what the device (or the owner's phone) is shown.
func (v *verification) view(now time.Time) map[string]any {
	done := []string{}
	for _, f := range v.required {
		if v.done[f] {
			done = append(done, f)
		}
	}
	return map[string]any{"purpose": v.purpose, "reason": v.reason, "required_all": v.required, "done": done,
		"device_name": v.deviceName, "platform": v.platform, "network": v.network, "country": v.geo.Country,
		"key_fingerprint": v.fingerprint, "expires_in_seconds": int(v.expires.Sub(now).Seconds()),
		"attempts_left": v.maxAttempts - v.attempts}
}

// missingFactors lists required factors the owner hasn't set up.
func (g *Gate) missingFactors(subjectID string, required []string) []string {
	var missing []string
	g.store.View(func(d *storeData) {
		s := d.Subjects[subjectID]
		for _, f := range required {
			switch {
			case s == nil:
				missing = append(missing, f)
			case f == factorTOTP && s.TOTP == nil:
				missing = append(missing, f)
			case f == factorWebAuthn && len(s.Passkeys) == 0:
				missing = append(missing, f)
			}
		}
	})
	return missing
}

// startVerification answers a key proof that needs additional verification.
func (g *Gate) startVerification(w http.ResponseWriter, r *http.Request, dev *Device, d decision, mac *pendingMAC, macStatus string, now time.Time) {
	fields := map[string]any{"device_id": dev.ID, "ip": clientIP(r), "reason": d.reason, "required": d.required}
	if missing := g.missingFactors(dev.SubjectID, d.required); len(missing) > 0 {
		fields["missing"] = missing
		g.audit.write(now, "verification_unavailable", fields)
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "access_denied", "reason": "factor_not_set_up",
			"missing": missing, "detail": "the owner hasn't set up every factor this policy requires; ask the administrator for a setup link"})
		return
	}
	pv := d.pol.Policy.Verification
	v := &verification{purpose: "access", reason: d.reason, deviceID: dev.ID, deviceName: dev.Name, platform: dev.Platform,
		subjectID: dev.SubjectID, ip: clientIP(r), network: d.network, geo: d.geo, policyVersion: d.pol.Version,
		required: append([]string(nil), d.required...), done: map[string]bool{}, maxAttempts: pv.MaxFailedCodeAttempts,
		expires: now.Add(time.Duration(pv.PendingTTLSeconds) * time.Second), fingerprint: keyFingerprint(dev.PublicKey),
		mac: mac, macStatus: macStatus}
	handle := g.verifications.add(v, now)
	if handle == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable", "reason": "too_many_pending_verifications"})
		return
	}
	g.audit.write(now, "verification_started", fields)
	writeJSON(w, http.StatusForbidden, map[string]any{"error": "additional_verification_required",
		"verification_id": handle, "required_all": v.required, "reason": d.reason,
		"expires_in_seconds": pv.PendingTTLSeconds})
}

// stepRequest guards the verification step endpoints: JSON from this site
// only (the handle is the credential; no cookie can be borrowed).
func (g *Gate) stepRequest(w http.ResponseWriter, r *http.Request) bool {
	if !g.guard(w, r) {
		return false
	}
	if crossSite(r) {
		writeError(w, http.StatusForbidden, "cross-site request refused")
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}

func (g *Gate) handleVerificationStatus(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	now := g.cfg.Now()
	var out map[string]any
	err := g.verifications.with(r.PathValue("id"), now, func(v *verification) error {
		out = v.view(now)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleVerifyTOTP checks an authenticator code for one verification.
//
// SECURITY: the accepted time step is saved transactionally before success
// is reported, so a code works once, even if submitted twice at the same
// moment to two pending verifications.
func (g *Gate) handleVerifyTOTP(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	err := g.verifications.with(handle, now, func(x *verification) error {
		if !x.needs(factorTOTP) {
			return errors.New("no authenticator code is needed")
		}
		v = *x
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if g.factorLimiter.blocked("subject:"+v.subjectID, now) {
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, "too many wrong codes for this owner; try again later")
		return
	}
	pol := g.policyByVersion(v.policyVersion)
	if err := g.consumeTOTP(v.subjectID, req.Code, pol, now); err != nil {
		left := g.verifications.failed(handle)
		g.factorLimiter.record("subject:"+v.subjectID, now)
		g.audit.write(now, "totp_failed", map[string]any{"subject_id": v.subjectID, "device_id": v.deviceID,
			"ip": clientIP(r), "purpose": v.purpose})
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "code_not_accepted", "attempts_left": left})
		return
	}
	g.markDone(w, handle, factorTOTP, now)
	g.audit.write(now, "totp_verified", map[string]any{"subject_id": v.subjectID, "device_id": v.deviceID, "purpose": v.purpose})
}

var errCodeRefused = errors.New("code not accepted")

// consumeTOTP checks code against the owner's authenticator and, if it is
// right, records its time step so it can't be used again.
func (g *Gate) consumeTOTP(subjectID, code string, pol *compiledPolicy, now time.Time) error {
	drift := 1
	if pol != nil {
		drift = pol.Policy.TOTP.AllowedStepDrift
	}
	return g.store.Update(func(d *storeData) error {
		s := d.Subjects[subjectID]
		if s == nil || s.TOTP == nil {
			return errCodeRefused
		}
		secret, err := g.sealer.Open(totpPurpose(subjectID, s.TOTP.ID), s.TOTP.SealedSecret)
		if err != nil {
			return errCodeRefused
		}
		step, ok := totpMatch(secret, code, now, s.TOTP.Period, s.TOTP.Digits, drift, s.TOTP.LastStep)
		if !ok {
			return errCodeRefused
		}
		s.TOTP.LastStep = step
		return nil
	})
}

func (g *Gate) markDone(w http.ResponseWriter, handle, factor string, now time.Time) {
	var out map[string]any
	err := g.verifications.with(handle, now, func(v *verification) error {
		v.done[factor] = true
		out = v.view(now)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleVerifyRecovery redeems a recovery code during verification. It
// doesn't satisfy any factor: it issues a setup link to replace the lost
// authenticator, after which the owner verifies with the new one.
func (g *Gate) handleVerifyRecovery(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	if err := g.verifications.with(handle, now, func(x *verification) error { v = *x; return nil }); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	pol := g.policyByVersion(v.policyVersion)
	if pol == nil || !pol.Policy.TOTP.RecoveryCodes {
		writeError(w, http.StatusForbidden, "recovery codes are turned off; ask the administrator")
		return
	}
	if g.factorLimiter.blocked("subject:"+v.subjectID, now) {
		writeError(w, http.StatusTooManyRequests, "too many attempts for this owner; try again later")
		return
	}
	want := hashToken(normalizeRecovery(req.Code))
	errUsed := errors.New("not accepted")
	err := g.store.Update(func(d *storeData) error {
		s := d.Subjects[v.subjectID]
		if s == nil {
			return errUsed
		}
		for i := range s.RecoveryCodes {
			rc := &s.RecoveryCodes[i]
			if rc.UsedAt == nil && rc.Hash == want {
				t := now
				rc.UsedAt = &t
				return nil
			}
		}
		return errUsed
	})
	if err != nil {
		g.verifications.failed(handle)
		g.factorLimiter.record("subject:"+v.subjectID, now)
		g.audit.write(now, "recovery_code_failed", map[string]any{"subject_id": v.subjectID, "ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, "recovery code not accepted")
		return
	}
	grant, exp := g.setupGrants.issue(v.subjectID, "recovery code", true, now)
	g.audit.write(now, "recovery_code_used", map[string]any{"subject_id": v.subjectID, "device_id": v.deviceID, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("🛟 A recovery code was used for owner %s from %s (device %q)", v.subjectID, clientIP(r), v.deviceName))
	writeJSON(w, http.StatusOK, map[string]any{"setup_grant": grant, "expires_at": exp.UTC()})
}

// handleVerifyPairing gives a TV a short code to show, so the owner can
// approve the verification on a phone (/_lanternfish/pair). The code alone
// grants nothing: the phone still has to pass every required factor.
func (g *Gate) handleVerifyPairing(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	now := g.cfg.Now()
	code := pairCode()
	err := g.verifications.with(r.PathValue("id"), now, func(v *verification) error {
		g.verifications.byPair[hashToken(code)] = hashToken(r.PathValue("id"))
		if v.pairHash != "" {
			delete(g.verifications.byPair, v.pairHash)
		}
		v.pairHash, v.pairExpires = hashToken(code), earliest(now.Add(pairCodeTTL), v.expires)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pairing_code": code, "pair_url": "/_lanternfish/pair",
		"expires_in_seconds": int(pairCodeTTL.Seconds())})
}

// pairCode is 8 characters from a 31-letter alphabet (about 40 bits), shown
// as XXXX-XXXX.
func pairCode() string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	raw := randomBytes(8)
	var b strings.Builder
	for i, c := range raw {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return b.String()
}

// handlePairLookup exchanges a pairing code for the verification it belongs
// to, once. Wrong codes count against the caller's address.
func (g *Gate) handlePairLookup(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	code := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(req.Code))
	if len(code) == 8 {
		code = code[:4] + "-" + code[4:]
	}
	t := g.verifications
	t.mu.Lock()
	h, ok := t.byPair[hashToken(code)]
	var v *verification
	if ok {
		v = t.byHash[h]
		delete(t.byPair, hashToken(code)) // one use
	}
	if v != nil && (!now.Before(v.pairExpires) || !now.Before(v.expires)) {
		v = nil
	}
	if v != nil {
		v.pairHash = ""
	}
	var view map[string]any
	if v != nil {
		view = v.view(now)
	}
	t.mu.Unlock()
	if v == nil {
		g.fail(w, r, http.StatusNotFound, "pairing_failed", "pairing code invalid or expired", nil)
		return
	}
	// The handle travels to the owner's phone; it authorizes only the
	// verification steps, and completing still needs the TV's own key.
	handle := "lfv_" + randomToken()
	t.mu.Lock()
	if cur, ok := t.byHash[h]; ok && cur == v {
		t.byHash[hashToken(handle)] = v
	}
	t.mu.Unlock()
	view["verification_id"] = handle
	g.audit.write(now, "pairing_opened", map[string]any{"device_id": v.deviceID, "ip": clientIP(r)})
	writeJSON(w, http.StatusOK, view)
}

// handleVerifyComplete finishes an access verification: every factor done,
// a fresh device-key proof, the same network and policy as when it started,
// and the hard rules still allow it. Then the network (and country) are
// approved and a session is issued.
func (g *Gate) handleVerifyComplete(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req sessionRequest
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if req.Client != "browser" {
		req.Client = "native"
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	err := g.verifications.with(handle, now, func(x *verification) error {
		if x.purpose != "access" {
			return errors.New("use /_lanternfish/v2/enrollment/{id}/finish for an enrollment")
		}
		if !x.allDone() {
			return errors.New("not every required factor has been verified")
		}
		v = *x
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	dev := g.proveDevice(w, r, req, now)
	if dev == nil {
		return
	}
	if dev.ID != v.deviceID {
		writeError(w, http.StatusConflict, "this verification is for another device")
		return
	}
	pol := g.policyFor(dev)
	ip := clientIP(r)
	restart := func(why string) {
		g.verifications.remove(handle)
		g.audit.write(now, "verification_restarted", map[string]any{"device_id": dev.ID, "reason": why})
		writeJSON(w, http.StatusConflict, map[string]string{"error": "verification_restart", "reason": why})
	}
	switch {
	case pol.Version != v.policyVersion:
		restart("policy_changed")
		return
	case networkKey(ip, pol.Policy.IP) != v.network || ip != v.ip && pol.Policy.IP.Enabled && pol.Policy.IP.Match == "exact":
		restart("network_changed")
		return
	}
	d := g.evaluate(dev, ip, now)
	switch d.outcome {
	case outAllow, outNetwork, outVerify:
	default:
		g.verifications.remove(handle)
		g.denySession(w, r, dev, d, now)
		return
	}
	if d.geo.Country != v.geo.Country ||
		!d.geo.known() && d.geoSource != unknownLocationSource(v.ip, pol.Policy.IP) {
		// SECURITY: an unknown location is only the same if it's the same
		// source; verifying at one unplaceable address mustn't complete at
		// another.
		restart("location_changed")
		return
	}
	method := strings.Join(v.required, "+")
	if err := g.approveNetwork(dev, ip, d, method, true, now); err != nil {
		g.denySession(w, r, dev, failedApproval(d, err), now)
		return
	}
	if v.mac != nil {
		g.recordMAC(dev, v.mac, now)
	}
	g.verifications.remove(handle)
	g.audit.write(now, "verification_completed", map[string]any{"device_id": dev.ID, "subject_id": dev.SubjectID,
		"network": d.network, "country": d.geo.Country, "factors": v.required, "reason": v.reason})
	fresh := g.activeDevice(dev.ID)
	if fresh == nil {
		g.unauthenticated(w, r, "device_revoked")
		return
	}
	d = g.authorizeKeyProof(fresh, ip, now)
	if d.outcome != outAllow {
		g.denySession(w, r, fresh, d, now)
		return
	}
	mac := v.macStatus
	if v.mac != nil {
		mac = "verified_change"
	}
	g.issueSession(w, r, fresh, d, req.Client, mac, now)
}

// policyByVersion finds a compiled current policy by version (global,
// profile or override), or nil if it isn't current any more.
func (g *Gate) policyByVersion(version int) *compiledPolicy {
	set := g.policies.Load()
	if set.global.Version == version {
		return set.global
	}
	for _, p := range set.profiles {
		if p.Version == version {
			return p
		}
	}
	for _, p := range set.overrides {
		if p.Version == version {
			return p
		}
	}
	return nil
}
