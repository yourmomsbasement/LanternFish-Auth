package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/cached"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// Passkeys and security keys (WebAuthn), through go-webauthn (pinned).
// All CBOR/COSE parsing, attestation formats and signature checks are the
// library's; this file decides policy.
//
// What a passkey proves here: the owner approved this step with an
// authenticator they registered. It does not identify the computer the
// browser runs on (a synced passkey works on any of the owner's devices),
// and attestation describes the authenticator model, not the machine.

type passkeyRP struct {
	plain  *webauthn.WebAuthn // no metadata: "none" and "collect_if_available"
	strict *webauthn.WebAuthn // checks FIDO metadata: "require_trusted"; nil when not configured
	mds    metadata.Provider  // strict's metadata, to confirm an authenticator is listed
	rpID   string
	origin []string
	mdsErr string
}

func newPasskeyRP(cfg Config) (*passkeyRP, error) {
	if cfg.WebAuthnRPID == "" {
		return nil, nil
	}
	if len(cfg.WebAuthnOrigins) == 0 {
		return nil, errors.New("LANTERNFISH_WEBAUTHN_ORIGINS is required with LANTERNFISH_WEBAUTHN_RP_ID")
	}
	for _, o := range cfg.WebAuthnOrigins {
		u, err := url.Parse(o)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
			strings.Contains(o, "*") || u.User != nil {
			return nil, fmt.Errorf("webauthn origin %q must be an exact https origin like https://flix.example.com", o)
		}
	}
	name := cfg.WebAuthnRPName
	if name == "" {
		name = "Lanternfish"
	}
	base := webauthn.Config{
		RPID: cfg.WebAuthnRPID, RPDisplayName: name, RPOrigins: cfg.WebAuthnOrigins,
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired},
	}
	plain, err := webauthn.New(&base)
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	rp := &passkeyRP{plain: plain, rpID: cfg.WebAuthnRPID, origin: cfg.WebAuthnOrigins}
	if cfg.WebAuthnMDSPath != "" {
		mds, err := cached.New(cached.WithPath(cfg.WebAuthnMDSPath), cached.WithUpdate(true),
			cached.WithNew(func(m *metadata.Metadata) (metadata.Provider, error) {
				return memory.New(memory.WithMetadata(m.ToMap()), memory.WithValidateEntry(true),
					memory.WithValidateTrustAnchor(true), memory.WithValidateStatus(true))
			}))
		if err != nil {
			rp.mdsErr = err.Error() // require_trusted stays unavailable
		} else {
			sc := base
			sc.MDS = mds
			if rp.strict, err = webauthn.New(&sc); err != nil {
				rp.mdsErr = err.Error()
			} else {
				rp.mds = mds
			}
		}
	}
	return rp, nil
}

// Attestation types backed by a certificate chain, which the strict
// relying party checks against the FIDO metadata's trust anchors.
// "basic_surrogate" (self attestation) and "none" carry no such chain.
var chainAttestationTypes = map[string]bool{
	string(metadata.BasicFull): true, string(metadata.AttCA): true, string(metadata.AnonCA): true}

// attestationEvidence classifies what a registration offered, without
// trusting it: "not_provided" (no attestation), "unverified" (some
// statement, but nothing that could tie it to a trusted model), or
// "chain" (a certificate-chain statement for a known authenticator model).
func attestationEvidence(c *webauthn.Credential) string {
	if c.AttestationFormat == "" || c.AttestationFormat == string(protocol.AttestationFormatNone) ||
		c.AttestationType == "" || c.AttestationType == string(metadata.None) {
		return "not_provided"
	}
	aaguid, err := uuid.FromBytes(c.Authenticator.AAGUID)
	if !chainAttestationTypes[c.AttestationType] || err != nil || aaguid == uuid.Nil {
		return "unverified"
	}
	return "chain"
}

// trustedAttestation reports whether a credential that the strict relying
// party accepted really has verified provenance.
//
// SECURITY: the library's strict check accepts an attestation of format
// "none" (and self attestation, and a zero AAGUID when allowed) without
// consulting the metadata at all, so "the strict check passed" doesn't mean
// "a trusted authenticator". Only a certificate-chain attestation for an
// authenticator the metadata lists counts.
func (rp *passkeyRP) trustedAttestation(c *webauthn.Credential) bool {
	if rp.mds == nil || attestationEvidence(c) != "chain" {
		return false
	}
	aaguid, _ := uuid.FromBytes(c.Authenticator.AAGUID)
	entry, err := rp.mds.GetEntry(context.Background(), aaguid)
	return err == nil && entry != nil
}

// repairPasskeyTrust takes "verified" away from stored credentials that
// don't carry certificate-chain attestation (registered before the check
// above). Network and country approvals that a passkey helped grant for
// those owners' devices are withdrawn too, since a "require_trusted" policy
// may have relied on the wrong verdict. It returns the owners affected.
func repairPasskeyTrust(d *storeData) []string {
	var owners []string
	for _, s := range d.Subjects {
		changed := false
		for i := range s.Passkeys {
			p := &s.Passkeys[i]
			if p.AttestationResult == "verified" && attestationEvidence(&p.Credential) != "chain" {
				p.AttestationResult = attestationEvidence(&p.Credential)
				changed = true
			}
		}
		if !changed {
			continue
		}
		owners = append(owners, s.ID)
		for _, dev := range d.Devices {
			if dev.SubjectID != s.ID {
				continue
			}
			nets := dev.Networks[:0:0]
			for _, a := range dev.Networks {
				if !strings.Contains(a.Method, factorWebAuthn) {
					nets = append(nets, a)
				}
			}
			dev.Networks = nets
			countries := dev.Countries[:0:0]
			for _, a := range dev.Countries {
				if !strings.Contains(a.Method, factorWebAuthn) {
					countries = append(countries, a)
				}
			}
			dev.Countries = countries
		}
	}
	return owners
}

// subjectUser adapts an owner for the library. The user handle is the
// subject ID: random, and not personal data.
type subjectUser struct {
	id, name string
	creds    []webauthn.Credential
}

func (u subjectUser) WebAuthnID() []byte                         { return []byte(u.id) }
func (u subjectUser) WebAuthnName() string                       { return u.name }
func (u subjectUser) WebAuthnDisplayName() string                { return u.name }
func (u subjectUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// usablePasskeys are an owner's credentials that the policy accepts.
func usablePasskeys(s *Subject, wp WebAuthnPolicy) []webauthn.Credential {
	var out []webauthn.Credential
	for _, c := range s.Passkeys {
		if wp.Attestation == attRequired && c.AttestationResult != "verified" {
			continue
		}
		if !wp.AllowBackupEligible && c.Credential.Flags.BackupEligible {
			continue
		}
		out = append(out, c.Credential)
	}
	return out
}

func uvRequirement(wp WebAuthnPolicy) protocol.UserVerificationRequirement {
	if wp.UserVerification == "preferred" {
		return protocol.VerificationPreferred
	}
	return protocol.VerificationRequired
}

// ---- Verification step ----

func (g *Gate) handleVerifyPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	if g.passkeys == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn isn't configured on this Gate")
		return
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	if err := g.verifications.with(handle, now, func(x *verification) error {
		if !x.needs(factorWebAuthn) {
			return errors.New("no passkey is needed")
		}
		v = *x
		return nil
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	pol := g.policyByVersion(v.policyVersion)
	if pol == nil {
		writeError(w, http.StatusConflict, "the policy changed; start again")
		return
	}
	user, ok := g.passkeyUser(v.subjectID, pol.Policy.WebAuthn)
	if !ok || len(user.creds) == 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "reason": "no_acceptable_passkey",
			"detail": "none of the owner's passkeys meets this policy (attestation or backup rules)"})
		return
	}
	assertion, sess, err := g.passkeys.plain.BeginLogin(user, webauthn.WithUserVerification(uvRequirement(pol.Policy.WebAuthn)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start the passkey check")
		return
	}
	if err := g.verifications.with(handle, now, func(x *verification) error { x.waSession = sess; return nil }); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (g *Gate) passkeyUser(subjectID string, wp WebAuthnPolicy) (subjectUser, bool) {
	var u subjectUser
	ok := false
	g.store.View(func(d *storeData) {
		if s := d.Subjects[subjectID]; s != nil && s.Status == "active" {
			u = subjectUser{id: s.ID, name: s.Name, creds: usablePasskeys(s, wp)}
			ok = true
		}
	})
	return u, ok
}

// handleVerifyPasskeyFinish checks an assertion for this verification only:
// its challenge was issued for it and is used once.
func (g *Gate) handleVerifyPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	if g.passkeys == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn isn't configured on this Gate")
		return
	}
	body, err := g.readBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	handle := r.PathValue("id")
	var v verification
	var sess *webauthn.SessionData
	if err := g.verifications.with(handle, now, func(x *verification) error {
		if !x.needs(factorWebAuthn) || x.waSession == nil {
			return errors.New("ask for passkey options first")
		}
		v, sess, x.waSession = *x, x.waSession, nil // one use
		return nil
	}); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	pol := g.policyByVersion(v.policyVersion)
	user, ok := g.passkeyUser(v.subjectID, pol.Policy.WebAuthn)
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	var cred *webauthn.Credential
	if ok && err == nil {
		cred, err = g.passkeys.plain.ValidateLogin(user, *sess, parsed)
	}
	if !ok || err != nil {
		left := g.verifications.failed(handle)
		g.factorLimiter.record("subject:"+v.subjectID, now)
		g.audit.write(now, "passkey_failed", map[string]any{"subject_id": v.subjectID, "device_id": v.deviceID, "ip": clientIP(r)})
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "passkey_not_accepted", "attempts_left": left})
		return
	}
	g.passkeyUsed(v.subjectID, cred, now)
	g.markDone(w, handle, factorWebAuthn, now)
	g.audit.write(now, "passkey_verified", map[string]any{"subject_id": v.subjectID, "device_id": v.deviceID,
		"clone_warning": cred.Authenticator.CloneWarning})
}

// passkeyUsed saves the counter, flags and last use. A clone warning (a
// counter that didn't increase) is recorded and alerted, not treated as
// conclusive: many authenticators always report 0.
func (g *Gate) passkeyUsed(subjectID string, cred *webauthn.Credential, now time.Time) {
	g.store.Update(func(d *storeData) error {
		s := d.Subjects[subjectID]
		if s == nil {
			return nil
		}
		for i := range s.Passkeys {
			p := &s.Passkeys[i]
			if bytes.Equal(p.Credential.ID, cred.ID) {
				p.Credential.Authenticator = cred.Authenticator
				p.Credential.Flags = cred.Flags
				t := now
				p.LastUsedAt = &t
			}
		}
		return nil
	})
	if cred.Authenticator.CloneWarning {
		g.alerts.send(fmt.Sprintf("⚠️ A passkey of owner %s reported a signature counter that didn't increase (possible clone)", subjectID))
	}
}

// ---- Registration (with a setup grant) ----

func (g *Gate) handleSetupPasskeyOptions(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	if g.passkeys == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn isn't configured on this Gate (LANTERNFISH_WEBAUTHN_RP_ID)")
		return
	}
	var req struct {
		Grant string `json:"grant"`
		Name  string `json:"name"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	wp := g.policies.Load().global.Policy.WebAuthn
	var opts *protocol.CredentialCreation
	err := g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error {
		if sg.passkeys >= maxPasskeysEach {
			return errors.New("this setup link has registered enough passkeys")
		}
		var user subjectUser
		var exclude []protocol.CredentialDescriptor
		found := false
		g.store.View(func(d *storeData) {
			if s := d.Subjects[sg.subjectID]; s != nil {
				found = true
				user = subjectUser{id: s.ID, name: s.Name}
				for _, c := range s.Passkeys {
					exclude = append(exclude, c.Credential.Descriptor())
				}
			}
		})
		if !found {
			return errGrantInvalid
		}
		conveyance := protocol.PreferDirectAttestation
		if wp.Attestation == attNone {
			conveyance = protocol.PreferNoAttestation
		}
		var sess *webauthn.SessionData
		var err error
		opts, sess, err = g.passkeys.plain.BeginRegistration(user, webauthn.WithExclusions(exclude),
			webauthn.WithConveyancePreference(conveyance),
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: uvRequirement(wp)}))
		if err != nil {
			return err
		}
		sg.waSession = sess
		sg.passkeyName = cleanName(req.Name)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

// handleSetupPasskeyFinish registers a credential. The setup grant travels
// in the X-Lanternfish-Grant header (the body is the credential).
//
// SECURITY: the body is read (bounded in size and time) before the grant is
// looked at, and the credential is checked and saved under the grant table's
// lock, which revocation also takes. So a grant revoked (a new setup link,
// an owner disabled) while a request was in flight can't still register a
// passkey: either the revocation comes first and this fails, or the passkey
// was registered before it. The lock is never held across client I/O.
func (g *Gate) handleSetupPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	if g.passkeys == nil {
		writeError(w, http.StatusServiceUnavailable, "WebAuthn isn't configured on this Gate")
		return
	}
	body, err := g.readBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed credential")
		return
	}
	now := g.cfg.Now()
	grant := r.Header.Get("X-Lanternfish-Grant")
	wp := g.policies.Load().global.Policy.WebAuthn
	var subjectID, name, result string
	var cred *webauthn.Credential
	errPolicy := errors.New("policy")
	var policyDetail string
	err = g.setupGrants.with(grant, now, func(sg *setupGrant) error {
		if sg.waSession == nil {
			return errors.New("ask for passkey options first")
		}
		sess := sg.waSession
		sg.waSession = nil // one use
		subjectID, name = sg.subjectID, sg.passkeyName
		var user subjectUser
		g.store.View(func(d *storeData) {
			if s := d.Subjects[subjectID]; s != nil {
				user = subjectUser{id: s.ID, name: s.Name}
			}
		})
		// With FIDO metadata configured, first see whether the authenticator
		// is one it vouches for; otherwise (or if not) record what was offered.
		if g.passkeys.strict != nil && wp.Attestation != attNone {
			if c, err := g.passkeys.strict.CreateCredential(user, *sess, parsed); err == nil && g.passkeys.trustedAttestation(c) {
				cred, result = c, "verified"
			}
		}
		if cred == nil {
			if wp.Attestation == attRequired {
				policyDetail = "this policy accepts only authenticators the FIDO metadata service vouches for"
				return errPolicy
			}
			c, err := g.passkeys.plain.CreateCredential(user, *sess, parsed)
			if err != nil {
				return fmt.Errorf("%w: %v", errPasskeyRejected, err)
			}
			cred, result = c, attestationEvidence(c)
			if result == "chain" { // a chain the metadata didn't vouch for
				result = "unverified"
			}
		}
		if !wp.AllowBackupEligible && cred.Flags.BackupEligible {
			policyDetail = "this policy doesn't accept synced (backup-eligible) passkeys; use a security key or a device-bound passkey"
			return errPolicy
		}
		if sg.passkeys >= maxPasskeysEach {
			return errors.New("this setup link has registered enough passkeys")
		}
		if name == "" {
			name = "Passkey " + now.Format("2006-01-02")
		}
		rec := WebAuthnCredential{Name: name, CreatedAt: now, AttestationResult: result, Credential: *cred}
		if err := g.store.Update(func(d *storeData) error {
			s := d.Subjects[subjectID]
			if s == nil || s.Status != "active" {
				return errGrantInvalid
			}
			if len(s.Passkeys) >= maxPasskeysEach {
				return errors.New("this owner has the maximum number of passkeys")
			}
			s.Passkeys = append(s.Passkeys, rec)
			return nil
		}); err != nil {
			return err
		}
		sg.passkeys++
		return nil
	})
	switch {
	case errors.Is(err, errPolicy):
		g.audit.write(now, "passkey_rejected", map[string]any{"subject_id": subjectID, "reason": policyDetail})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "authenticator_policy_unsupported", "detail": policyDetail})
		return
	case errors.Is(err, errPasskeyRejected):
		g.audit.write(now, "passkey_rejected", map[string]any{"subject_id": subjectID, "reason": err.Error()})
		writeError(w, http.StatusBadRequest, "passkey not accepted")
		return
	case err != nil:
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	g.audit.write(now, "passkey_registered", map[string]any{"subject_id": subjectID, "name": name,
		"attestation": result, "backup_eligible": cred.Flags.BackupEligible, "aaguid": fmt.Sprintf("%x", cred.Authenticator.AAGUID)})
	g.alerts.send(fmt.Sprintf("🔑 A passkey %q was registered for owner %s", name, subjectID))
	writeJSON(w, http.StatusCreated, map[string]any{"name": name, "attestation": result,
		"backup_eligible": cred.Flags.BackupEligible})
}

var errPasskeyRejected = errors.New("passkey not accepted")
