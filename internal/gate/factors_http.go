package gate

import (
	"errors"
	"fmt"
	"net/http"
)

// Owner factor setup, through a setup link (grant). The page is
// /_lanternfish/setup#grant=...; the grant stays in the fragment and the
// request bodies, never a URL a server sees.

func (g *Gate) handleSetupInfo(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Grant string `json:"grant"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	var out map[string]any
	err := g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error {
		g.store.View(func(d *storeData) {
			s := d.Subjects[sg.subjectID]
			if s == nil {
				return
			}
			unused := 0
			for _, rc := range s.RecoveryCodes {
				if rc.UsedAt == nil {
					unused++
				}
			}
			out = map[string]any{"owner": s.Name, "has_totp": s.TOTP != nil, "passkeys": len(s.Passkeys),
				"recovery_codes_left": unused, "recovery": sg.recovery,
				"expires_in_seconds": int(sg.expires.Sub(now).Seconds()),
				"webauthn_available": g.passkeys != nil}
		})
		if out == nil {
			return errGrantInvalid
		}
		return nil
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSetupTOTP proposes a new authenticator secret. It isn't saved until
// a code from it is confirmed.
func (g *Gate) handleSetupTOTP(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Grant string `json:"grant"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	var uri string
	var secret []byte
	err := g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error {
		var name string
		var has bool
		g.store.View(func(d *storeData) {
			if s := d.Subjects[sg.subjectID]; s != nil {
				name, has = s.Name, s.TOTP != nil
			}
		})
		if name == "" {
			return errGrantInvalid
		}
		if has && !sg.recovery && !sg.replaceTOTP {
			return errors.New("this owner already has an authenticator app; an administrator can issue a link that replaces it")
		}
		sg.totpSecret = randomBytes(20)
		secret, uri = sg.totpSecret, totpURI(sg.totpSecret, name)
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	rows, _ := qrRows(uri)
	writeJSON(w, http.StatusOK, map[string]any{"otpauth_uri": uri, "secret": b32.EncodeToString(secret),
		"qr": map[string]any{"size": len(rows), "rows": rows}})
}

// handleConfirmTOTP saves the proposed secret once a code from it is
// right, replaces any previous authenticator, and returns new recovery codes
// (shown once; only their hashes are kept).
func (g *Gate) handleConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Grant string `json:"grant"`
		Code  string `json:"code"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	var subjectID string
	var secret []byte
	var replaced bool
	err := g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error {
		if sg.totpSecret == nil {
			return errors.New("start the authenticator setup first")
		}
		if g.factorLimiter.blocked("setup:"+req.Grant, now) {
			return errors.New("too many wrong codes; start again with a new setup link")
		}
		step, ok := totpMatch(sg.totpSecret, req.Code, now, 30, 6, 1, 0)
		if !ok {
			g.factorLimiter.record("setup:"+req.Grant, now)
			return errCodeRefused
		}
		subjectID, secret = sg.subjectID, sg.totpSecret
		factorID := newID("totp_")
		codes, recs := newRecoveryCodes(10, now)
		err := g.store.Update(func(d *storeData) error {
			s := d.Subjects[sg.subjectID]
			if s == nil {
				return errGrantInvalid
			}
			replaced = s.TOTP != nil
			s.TOTP = &TOTPFactor{ID: factorID, SealedSecret: g.sealer.Seal(totpPurpose(s.ID, factorID), secret),
				Digits: 6, Period: 30, ActivatedAt: now, LastStep: step}
			s.RecoveryCodes = recs
			return nil
		})
		if err != nil {
			return err
		}
		sg.totpSecret, sg.recovery, sg.replaceTOTP = nil, false, false
		sg.recoveryCodes = codes
		return nil
	})
	if errors.Is(err, errCodeRefused) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "code_not_accepted",
			"detail": "check the phone's clock is set automatically, then try the current code"})
		return
	} else if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	var codes []string
	g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error { codes, sg.recoveryCodes = sg.recoveryCodes, nil; return nil })
	event := "totp_enrolled"
	if replaced {
		event = "totp_replaced"
	}
	g.audit.write(now, event, map[string]any{"subject_id": subjectID, "ip": clientIP(r)})
	g.alerts.send(fmt.Sprintf("📱 Authenticator app %s for owner %s", map[bool]string{true: "replaced", false: "set up"}[replaced], subjectID))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "recovery_codes": codes})
}

// handleNewRecoveryCodes replaces an owner's recovery codes (setup link
// only; a media session can never do this).
func (g *Gate) handleNewRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Grant string `json:"grant"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	now := g.cfg.Now()
	var codes []string
	var subjectID string
	err := g.setupGrants.with(req.Grant, now, func(sg *setupGrant) error {
		subjectID = sg.subjectID
		var recs []RecoveryCode
		codes, recs = newRecoveryCodes(10, now)
		return g.store.Update(func(d *storeData) error {
			s := d.Subjects[sg.subjectID]
			if s == nil || s.TOTP == nil {
				return errors.New("set up an authenticator app first")
			}
			s.RecoveryCodes = recs
			return nil
		})
	})
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	g.audit.write(now, "recovery_codes_replaced", map[string]any{"subject_id": subjectID, "ip": clientIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleSetupDone ends a setup link early.
func (g *Gate) handleSetupDone(w http.ResponseWriter, r *http.Request) {
	if !g.stepRequest(w, r) {
		return
	}
	var req struct {
		Grant string `json:"grant"`
	}
	if err := g.readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	g.setupGrants.revoke(req.Grant)
	w.WriteHeader(http.StatusNoContent)
}
