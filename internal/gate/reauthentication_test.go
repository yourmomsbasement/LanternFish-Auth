package gate

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func periodicPolicy() Policy {
	p := LegacyPolicy(time.Hour)
	p.TOTP.Enabled = true
	p.Verification.ReauthenticateAfterSeconds = 60
	p.Verification.ReauthenticateRequiredAll = []string{factorTOTP}
	p.normalize()
	return p
}
func TestReauthenticationValidation(t *testing.T) {
	p := periodicPolicy()
	if _, e := compilePolicy(1, scopeGlobal, p); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Policy){func(p *Policy) { p.Verification.ReauthenticateAfterSeconds = -1 }, func(p *Policy) { p.Verification.ReauthenticateAfterSeconds = 31536001 }, func(p *Policy) { p.Verification.ReauthenticateRequiredAll = nil }, func(p *Policy) { p.TOTP.Enabled = false }, func(p *Policy) { p.Verification.ReauthenticateRequiredAll = []string{"email"} }} {
		bad := periodicPolicy()
		mutate(&bad)
		if _, e := compilePolicy(1, scopeGlobal, bad); e == nil {
			t.Fatal("invalid periodic policy accepted")
		}
	}
}
func TestPeriodicReauthenticationDoesNotRenewWithDeviceKey(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, periodicPolicy())
	key, enr := h.enrollECDSA("web")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	id := h.startStepUp(testClientAddr, enr.DeviceID, key)
	if r := h.step(testClientAddr, id, "/totp", map[string]string{"code": h.code(secret)}); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	token := tokenOf(t, h.complete(testClientAddr, id, enr.DeviceID, key))
	verifiedAt := h.now
	if r := h.get(testClientAddr, token); r.Code != 200 {
		t.Fatal(r.Code)
	}
	h.now = h.now.Add(30 * time.Second)
	renewed := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	h.g.store.View(func(d *storeData) {
		if !d.Devices[enr.DeviceID].FactorVerifiedAt[factorTOTP].Equal(verifiedAt) {
			t.Error("device key renewal reset factor clock")
		}
	})
	h.now = h.now.Add(30 * time.Second)
	if r := h.get(testClientAddr, renewed); r.Code == 200 {
		t.Fatal("cached session survived maximum factor age")
	}
	id = h.startStepUp(testClientAddr, enr.DeviceID, key)
	if r := h.step(testClientAddr, id, "/totp", map[string]string{"code": h.code(secret)}); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	token = tokenOf(t, h.complete(testClientAddr, id, enr.DeviceID, key))
	if r := h.get(testClientAddr, token); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	// Factor verification is per device, not shared with another device of the same owner.
	key2, enr2 := h.enrollECDSA("web")
	h.startStepUp(testClientAddr, enr2.DeviceID, key2)
}
func TestReauthenticationTracksEachRequiredFactor(t *testing.T) {
	h := newHarness(t)
	p := periodicPolicy()
	p.WebAuthn.Enabled = true
	p.Verification.ReauthenticateRequiredAll = []string{factorTOTP, factorWebAuthn}
	pol, e := compilePolicy(1, scopeGlobal, p)
	if e != nil {
		t.Fatal(e)
	}
	dev := &Device{FactorVerifiedAt: map[string]time.Time{factorTOTP: h.now, factorWebAuthn: h.now.Add(-time.Minute)}}
	d := h.g.reauthenticationDecision(dev, decision{pol: pol, outcome: outAllow}, h.now)
	if d.outcome != outVerify || !contains(d.required, factorTOTP) || !contains(d.required, factorWebAuthn) {
		t.Fatal("fresh TOTP bypassed stale passkey")
	}
	recordFactorVerification(dev, []string{factorTOTP}, h.now)
	if d = h.g.reauthenticationDecision(dev, decision{pol: pol, outcome: outAllow}, h.now); d.outcome != outVerify {
		t.Fatal("unverified passkey made fresh")
	}
	recordFactorVerification(dev, []string{factorWebAuthn}, h.now)
	if d = h.g.reauthenticationDecision(dev, decision{pol: pol, outcome: outAllow}, h.now); d.outcome != outAllow || !d.hardEnd.Equal(h.now.Add(time.Minute)) {
		t.Fatal("fresh verification did not cap access", d)
	}
}
func TestReauthenticationDeadlineEndsSessionsCertificatesAndStreams(t *testing.T) {
	for _, mode := range []string{streamContinuity, streamStrict} {
		for _, via := range []string{"session", "certificate"} {
			t.Run(mode+"/"+via, func(t *testing.T) {
				h := newHarness(t)
				p := periodicPolicy()
				p.Session.StreamExpiryMode = mode
				h.publish(scopeGlobal, p)
				key, enr := h.enrollECDSA("android")
				if e := h.g.store.Update(func(d *storeData) error {
					recordFactorVerification(d.Devices[enr.DeviceID], []string{factorTOTP}, h.now)
					return nil
				}); e != nil {
					t.Fatal(e)
				}
				req := httptest.NewRequest("GET", "https://gate.example/Items", nil)
				req.RemoteAddr = testClientAddr
				if via == "session" {
					req.Header.Set(sessionHeader, tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key)))
				} else {
					req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leafOf(t, enr)}}}
				}
				timers := &recordingTimers{}
				h.g.streams.after = timers.arm
				auth, _, ctx, done := h.g.authorizeAndTrack(httptest.NewRecorder(), req)
				if auth == nil {
					t.Fatal("fresh factor denied")
				}
				defer done()
				if !auth.hardEnd.Equal(h.now.Add(time.Minute)) || len(timers.after) == 0 || timers.after[0] > time.Minute {
					t.Fatal("stream outlived authentication age")
				}
				h.now = h.now.Add(time.Minute)
				timers.fire[0]()
				select {
				case <-ctx.Done():
				default:
					t.Fatal("stream not cancelled")
				}
				rec := httptest.NewRecorder()
				if h.g.authorizeRequest(rec, req) != nil || rec.Code == http.StatusOK {
					t.Fatal("expired authentication authorized")
				}
			})
		}
	}
}
