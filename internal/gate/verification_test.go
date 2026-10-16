package gate

import (
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- helpers ----

// stepUpPolicy: sessions bound to the exact address, and a new network
// needs the owner's authenticator code.
func stepUpPolicy() Policy {
	p := RecommendedPolicy()
	p.IP.OnChange = onChangeVerify
	p.TOTP.Enabled = true
	p.Verification.NewNetworkRequiredAll = []string{factorTOTP}
	p.normalize()
	return p
}

// setUpTOTP gives an owner an authenticator through a setup link and
// returns its secret and recovery codes.
func (h *harness) setUpTOTP(subjectID string) ([]byte, []string) {
	h.t.Helper()
	rec := h.admin2("POST", "subjects/"+subjectID+"/setup-link", nil)
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("setup link: %d %s", rec.Code, rec.Body)
	}
	path := decode[map[string]any](h.t, rec)["path"].(string)
	grant := path[strings.Index(path, "grant=")+len("grant="):]
	rec = h.do("POST", "/_lanternfish/v2/factors/totp/setup", map[string]string{"grant": grant}, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("totp setup: %d %s", rec.Code, rec.Body)
	}
	secret, err := b32.DecodeString(decode[map[string]any](h.t, rec)["secret"].(string))
	if err != nil {
		h.t.Fatal(err)
	}
	rec = h.do("POST", "/_lanternfish/v2/factors/totp/confirm", map[string]string{"grant": grant,
		"code": totpCode(secret, h.now.Unix()/30, 6)}, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("totp confirm: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Codes []string `json:"recovery_codes"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	h.now = h.now.Add(30 * time.Second) // the confirmation code's step is used up
	return secret, out.Codes
}

func (h *harness) code(secret []byte) string { return totpCode(secret, h.now.Unix()/30, 6) }

// startStepUp signs in from remote and expects a pending verification.
func (h *harness) startStepUp(remote, deviceID string, key *ecdsa.PrivateKey) string {
	h.t.Helper()
	rec := h.signInFrom(remote, deviceID, key)
	body := decode[map[string]any](h.t, rec)
	if rec.Code != http.StatusForbidden || body["error"] != "additional_verification_required" {
		h.t.Fatalf("expected step-up, got %d %s", rec.Code, rec.Body)
	}
	if len(rec.Result().Cookies()) != 0 {
		h.t.Fatal("a pending verification set a cookie")
	}
	return body["verification_id"].(string)
}

func (h *harness) step(remote, id, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doFrom(remote, "POST", "/_lanternfish/v2/verification/"+id+path, body, map[string]string{"Content-Type": "application/json"})
}

func (h *harness) complete(remote, id, deviceID string, key *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.doFrom(remote, "POST", "/_lanternfish/v2/challenge", map[string]string{"device_id": deviceID}, nil)
	c := decode[map[string]string](h.t, rec)["challenge"]
	return h.step(remote, id, "/complete", map[string]string{"device_id": deviceID, "challenge": c,
		"signature": b64(rawSign(key, sessionMessage(deviceID, c)))})
}

// ---- tests ----

func TestNewNetworkNeedsAuthenticatorCode(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("web") // approves testClientAddr's network
	secret, _ := h.setUpTOTP(defaultSubjectID)

	home := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	if rec := h.get(testClientAddr, home); rec.Code != http.StatusOK {
		t.Fatalf("enrolled network: %d", rec.Code)
	}

	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	// The pending handle authorizes nothing upstream; the old token doesn't
	// work from the new network either.
	if rec := h.doFrom(otherAddr, "GET", "/Items", nil, map[string]string{sessionHeader: id}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("handle used as a token: %d", rec.Code)
	}
	if rec := h.get(otherAddr, home); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token from new network: %d", rec.Code)
	}
	// Completing before the factor is refused.
	if rec := h.complete(otherAddr, id, enr.DeviceID, key); rec.Code != http.StatusConflict {
		t.Fatalf("complete without factor: %d %s", rec.Code, rec.Body)
	}
	// A wrong code counts; the right one passes.
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": "000000"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("right code: %d %s", rec.Code, rec.Body)
	}
	// Completing from yet another network restarts.
	if rec := h.complete("198.18.0.9:1", id, enr.DeviceID, key); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "network_changed") {
		t.Fatalf("complete from another network: %d %s", rec.Code, rec.Body)
	}

	// Start again, verify, complete: now a session, and the old network's ends.
	id = h.startStepUp(otherAddr, enr.DeviceID, key)
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code accepted: %d", rec.Code)
	}
	h.now = h.now.Add(30 * time.Second)
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("next code: %d %s", rec.Code, rec.Body)
	}
	rec := h.complete(otherAddr, id, enr.DeviceID, key)
	tok := tokenOf(t, rec)
	if r := h.get(otherAddr, tok); r.Code != http.StatusOK {
		t.Fatalf("after verification: %d", r.Code)
	}
	if r := h.get(testClientAddr, home); r.Code != http.StatusUnauthorized {
		t.Fatalf("old network's session survived: %d", r.Code)
	}
	dev := decode[deviceView](t, h.admin2("GET", "devices/"+enr.DeviceID, nil))
	if len(dev.Networks) != 1 || !dev.Networks[0].Verified || dev.Networks[0].Method != "totp" {
		t.Fatalf("approval: %+v", dev.Networks)
	}
}

func TestTOTPCodeWorksOnceUnderRace(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("web")
	key2, enr2 := h.enrollECDSA("web")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	a := h.startStepUp(otherAddr, enr.DeviceID, key)
	b := h.startStepUp(otherAddr, enr2.DeviceID, key2)
	code := h.code(secret)
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i, id := range []string{a, b} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			results[i] = h.step(otherAddr, id, "/totp", map[string]string{"code": code}).Code
		}(i, id)
	}
	wg.Wait()
	ok := 0
	for _, c := range results {
		if c == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("one code accepted %d times: %v", ok, results)
	}
}

func TestVerificationAttemptsAreBounded(t *testing.T) {
	h := newHarness(t)
	p := stepUpPolicy()
	p.Verification.MaxFailedCodeAttempts = 3
	h.publish(scopeGlobal, p)
	key, enr := h.enrollECDSA("web")
	h.setUpTOTP(defaultSubjectID)
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	for i := 0; i < 3; i++ {
		h.step(otherAddr, id, "/totp", map[string]string{"code": "000000"})
	}
	if rec := h.doFrom(otherAddr, "GET", "/_lanternfish/v2/verification/"+id, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("verification survived its attempt limit: %d", rec.Code)
	}
}

func TestStepUpNeedsSetUpFactors(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("web")
	rec := h.signInFrom(otherAddr, enr.DeviceID, key)
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "factor_not_set_up" {
		t.Fatalf("no authenticator set up: %d %s", rec.Code, rec.Body)
	}
	// The preview says so beforehand.
	prev := h.admin2("POST", "policy/preview", map[string]any{"policy": stepUpPolicy()})
	if !strings.Contains(prev.Body.String(), "owners_missing_factors") || !strings.Contains(prev.Body.String(), defaultSubjectID) {
		t.Fatalf("preview: %s", prev.Body)
	}
}

func TestStepUpPolicyValidation(t *testing.T) {
	p := RecommendedPolicy()
	p.IP.OnChange = onChangeVerify
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "new_network_required_all") {
		t.Fatalf("step-up with no factors: %v", err)
	}
	p.Verification.NewNetworkRequiredAll = []string{factorTOTP}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "doesn't enable") {
		t.Fatalf("factor required but disabled: %v", err)
	}
	p.TOTP.Enabled = true
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryCodeReplacesAuthenticator(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("web")
	oldSecret, codes := h.setUpTOTP(defaultSubjectID)
	if len(codes) != 10 {
		t.Fatalf("recovery codes: %v", codes)
	}
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	rec := h.step(otherAddr, id, "/recovery", map[string]string{"code": codes[0]})
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery: %d %s", rec.Code, rec.Body)
	}
	grant := decode[map[string]any](t, rec)["setup_grant"].(string)
	if rec := h.step(otherAddr, id, "/recovery", map[string]string{"code": codes[0]}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("recovery code reused: %d", rec.Code)
	}
	// The grant sets up a replacement; the old authenticator stops working.
	rec = h.do("POST", "/_lanternfish/v2/factors/totp/setup", map[string]string{"grant": grant}, nil)
	newSecret, _ := b32.DecodeString(decode[map[string]any](t, rec)["secret"].(string))
	if rec := h.do("POST", "/_lanternfish/v2/factors/totp/confirm", map[string]string{"grant": grant, "code": h.code(newSecret)}, nil); rec.Code != http.StatusOK {
		t.Fatalf("replacement confirm: %d %s", rec.Code, rec.Body)
	}
	h.now = h.now.Add(30 * time.Second)
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(oldSecret)}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old authenticator still works: %d", rec.Code)
	}
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(newSecret)}); rec.Code != http.StatusOK {
		t.Fatalf("new authenticator: %d %s", rec.Code, rec.Body)
	}
}

func TestPhonePairingApprovesTV(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("android")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	pair := decode[map[string]any](t, h.step(otherAddr, id, "/pairing", map[string]string{}))
	code := pair["pairing_code"].(string)

	phone := "198.18.5.5:1"
	if rec := h.doFrom(phone, "POST", "/_lanternfish/v2/pair", map[string]string{"code": "ZZZZ-ZZZZ"}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("wrong pairing code: %d", rec.Code)
	}
	rec := h.doFrom(phone, "POST", "/_lanternfish/v2/pair", map[string]string{"code": strings.ToLower(strings.ReplaceAll(code, "-", ""))}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("pairing: %d %s", rec.Code, rec.Body)
	}
	view := decode[map[string]any](t, rec)
	if view["device_name"] != "Living room" || view["key_fingerprint"] == "" {
		t.Fatalf("pairing view: %v", view)
	}
	if rec := h.doFrom(phone, "POST", "/_lanternfish/v2/pair", map[string]string{"code": code}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("pairing code reused: %d", rec.Code)
	}
	phoneID := view["verification_id"].(string)
	if rec := h.step(phone, phoneID, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("phone approval: %d %s", rec.Code, rec.Body)
	}
	// The phone can't finish it: that needs the TV's key.
	if rec := h.step(phone, phoneID, "/complete", map[string]string{"device_id": enr.DeviceID}); rec.Code == http.StatusOK {
		t.Fatal("phone completed without the device key")
	}
	if tok := tokenOf(t, h.complete(otherAddr, id, enr.DeviceID, key)); h.get(otherAddr, tok).Code != http.StatusOK {
		t.Fatal("TV not signed in after phone approval")
	}
}

func TestClientCertificateStepsUpLikeSessions(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("android")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	leaf := leafOf(t, enr)
	if rec := h.doCert(testClientAddr, leaf, ""); rec.Code != http.StatusOK {
		t.Fatalf("cert on enrolled network: %d", rec.Code)
	}
	rec := h.doCert(otherAddr, leaf, "")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "additional_verification_required") {
		t.Fatalf("cert from new network: %d %s", rec.Code, rec.Body)
	}
	// The app starts verification with a key proof, then the certificate works.
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)})
	tokenOf(t, h.complete(otherAddr, id, enr.DeviceID, key))
	if rec := h.doCert(otherAddr, leaf, ""); rec.Code != http.StatusOK {
		t.Fatalf("cert after verification: %d %s", rec.Code, rec.Body)
	}
}

func TestRevocationCancelsPendingVerification(t *testing.T) {
	h := newHarness(t)
	h.publish(scopeGlobal, stepUpPolicy())
	key, enr := h.enrollECDSA("web")
	h.setUpTOTP(defaultSubjectID)
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec := h.doFrom(otherAddr, "GET", "/_lanternfish/v2/verification/"+id, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("pending verification survived revocation: %d", rec.Code)
	}
}
