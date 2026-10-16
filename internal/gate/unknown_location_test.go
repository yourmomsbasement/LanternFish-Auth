package gate

import (
	"net/http"
	"testing"
	"time"
)

// A3: with IP binding off, verifying from one address GeoIP can't place
// doesn't approve other unplaceable addresses.

func unknownLocationPolicy() Policy {
	p := geoPolicy(geoEnforce) // IP binding off (legacy policy)
	p.Geo.UnknownAction = actVerify
	p.TOTP.Enabled = true
	p.Verification.NewNetworkRequiredAll = []string{factorTOTP}
	p.normalize()
	return p
}

func TestUnknownLocationApprovalIsBoundToItsSource(t *testing.T) {
	h := newHarness(t)
	h.fakeGeo(map[string]string{}) // nothing can be placed
	h.publish(scopeGlobal, unknownLocationPolicy())
	key, enr := h.enrollECDSA("web")
	secret, _ := h.setUpTOTP(defaultSubjectID)

	id := h.startStepUp(homeAddr, enr.DeviceID, key)
	if rec := h.step(homeAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("totp: %d %s", rec.Code, rec.Body)
	}
	token := tokenOf(t, h.complete(homeAddr, id, enr.DeviceID, key))
	if rec := h.get(homeAddr, token); rec.Code != http.StatusOK {
		t.Fatalf("token where it was verified: %d", rec.Code)
	}
	// The same device elsewhere, also unplaceable.
	if rec := h.get(otherAddr, token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token at a second unknown address: %d %s", rec.Code, rec.Body)
	}
	h.startStepUp(otherAddr, enr.DeviceID, key) // a fresh sign-in there needs verifying again
	// Back home, still approved without another factor.
	tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key))
}

func TestUnknownLocationVerificationCompletesOnlyAtItsSource(t *testing.T) {
	h := newHarness(t)
	h.fakeGeo(map[string]string{})
	h.publish(scopeGlobal, unknownLocationPolicy())
	key, enr := h.enrollECDSA("web")
	secret, _ := h.setUpTOTP(defaultSubjectID)
	id := h.startStepUp(homeAddr, enr.DeviceID, key)
	if rec := h.step(homeAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("totp: %d", rec.Code)
	}
	if rec := h.complete(otherAddr, id, enr.DeviceID, key); rec.Code == http.StatusOK {
		t.Fatal("verification started at one unknown address completed at another")
	}
}

// Unknown-location approvals saved by earlier versions without a source
// don't count any more.
func TestLegacyUnknownLocationApprovalIgnored(t *testing.T) {
	h := newHarness(t)
	h.fakeGeo(map[string]string{})
	h.publish(scopeGlobal, unknownLocationPolicy())
	key, enr := h.enrollECDSA("web")
	h.setUpTOTP(defaultSubjectID)
	h.g.store.Update(func(d *storeData) error {
		dev := d.Devices[enr.DeviceID]
		dev.Countries = append(dev.Countries, CountryApproval{Country: "", Network: "", Method: "totp", ExpiresAt: h.now.Add(time.Hour)})
		return nil
	})
	h.startStepUp(otherAddr, enr.DeviceID, key)
}
