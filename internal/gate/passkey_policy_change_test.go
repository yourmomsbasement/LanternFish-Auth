package gate

import (
	"net/http"
	"testing"
)

func TestPasskeyFinishAfterPolicyChange(t *testing.T) {
	h := newHarness(t)
	h.enablePasskeys()
	h.publish(scopeGlobal, passkeyPolicy())
	key, enr := h.enrollECDSA("web")
	auth := newSoftAuthenticator()
	if res := h.registerPasskey(defaultSubjectID, auth); res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	rec := h.step(otherAddr, id, "/webauthn/options", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("options: %d %s", rec.Code, rec.Body)
	}
	challenge := challengeOf(t, rec.Body.Bytes())
	h.publish(scopeGlobal, passkeyPolicy())
	rec = h.step(otherAddr, id, "/webauthn/finish", auth.get(challenge, defaultSubjectID))
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale policy assertion: %d %s", rec.Code, rec.Body)
	}
	if err := h.g.verifications.with(id, h.now, func(*verification) error { return nil }); err == nil {
		t.Fatal("stale verification remained usable")
	}
}
