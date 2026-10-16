package gate

import (
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A5: a policy that requires a MAC report requires it whatever path leads
// to a session, step-up included.

func (h *harness) signInFromWithMAC(remote, deviceID string, key *ecdsa.PrivateKey, mac string) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.doFrom(remote, "POST", "/_lanternfish/v2/challenge", map[string]string{"device_id": deviceID}, nil)
	c := decode[map[string]string](h.t, rec)["challenge"]
	body := map[string]any{"device_id": deviceID, "challenge": c, "signature": b64(rawSign(key, sessionMessage(deviceID, c))),
		"client": "native"}
	if mac != "" {
		rep := &MACReport{InterfaceKind: "wifi", MAC: mac, CollectedAt: h.now.Unix()}
		hw, _ := parseMAC(mac)
		rep.Signature = b64(rawSign(key, macMessage(deviceID, c, rep, hw)))
		body["mac_report"] = rep
	}
	return h.doFrom(remote, "POST", "/_lanternfish/v2/session", body, nil)
}

// macStepUpDevice is an Android device on a profile that needs both a TOTP
// step-up on new networks and a MAC report.
func macStepUpDevice(t *testing.T, h *harness) (*ecdsa.PrivateKey, enrollResponse, []byte) {
	t.Helper()
	key, enr := h.enrollECDSA("android")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	p := stepUpPolicy()
	p.MAC = MACPolicy{Collect: true, RequireReport: true, OnChange: actObserve, MaxObservationAgeSeconds: 600}
	rec := h.admin2("POST", "profiles", map[string]any{"name": "Native required report", "policy": p})
	if rec.Code != http.StatusCreated {
		t.Fatalf("profile: %d %s", rec.Code, rec.Body)
	}
	profile := decode[Profile](t, rec)
	if rec := h.admin2("PUT", "devices/"+enr.DeviceID+"/profile", map[string]string{"profile_id": profile.ID}); rec.Code != http.StatusNoContent {
		t.Fatalf("assignment: %d", rec.Code)
	}
	return key, enr, secret
}

func TestStepUpStillNeedsMACReport(t *testing.T) {
	h := newHarness(t)
	key, enr, _ := macStepUpDevice(t, h)
	rec := h.signInFromWithMAC(otherAddr, enr.DeviceID, key, "")
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "mac_report_required" {
		t.Fatalf("step-up without a MAC report: %d %s", rec.Code, rec.Body)
	}
}

func TestStepUpWithMACReportCompletes(t *testing.T) {
	h := newHarness(t)
	key, enr, secret := macStepUpDevice(t, h)
	rec := h.signInFromWithMAC(otherAddr, enr.DeviceID, key, "02:11:22:33:44:55")
	body := decode[map[string]any](t, rec)
	if rec.Code != http.StatusForbidden || body["error"] != "additional_verification_required" {
		t.Fatalf("expected a step-up: %d %s", rec.Code, rec.Body)
	}
	id := body["verification_id"].(string)
	if rec := h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("totp: %d", rec.Code)
	}
	if rec := h.get(otherAddr, tokenOf(t, h.complete(otherAddr, id, enr.DeviceID, key))); rec.Code != http.StatusOK {
		t.Fatalf("proxy: %d", rec.Code)
	}
}

// The check also sits where sessions are issued, so a verification that
// somehow lacks the evidence can't produce a session.
func TestSessionIssuanceChecksMACEvidence(t *testing.T) {
	h := newHarness(t)
	key, enr, secret := macStepUpDevice(t, h)
	rec := h.signInFromWithMAC(otherAddr, enr.DeviceID, key, "02:11:22:33:44:55")
	id := decode[map[string]any](t, rec)["verification_id"].(string)
	h.g.verifications.with(id, h.now, func(v *verification) error { v.macStatus = "unavailable"; return nil })
	h.step(otherAddr, id, "/totp", map[string]string{"code": h.code(secret)})
	if rec := h.complete(otherAddr, id, enr.DeviceID, key); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "mac_report_required" {
		t.Fatalf("completion without MAC evidence: %d %s", rec.Code, rec.Body)
	}
}
