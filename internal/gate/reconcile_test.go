package gate

import (
	"net/http"
	"testing"
	"time"
)

// N1: tightening a policy applies to existing approvals and sessions.

func TestShorterApprovalLifetimeAppliesToExistingApprovals(t *testing.T) {
	h := newHarness(t)
	p := RecommendedPolicy() // approvals last a day
	h.publish(scopeGlobal, p)
	key, enr := h.enrollECDSA("web")
	token := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	h.now = h.now.Add(2 * time.Hour)
	p.IP.ApprovalTTLSeconds = 3600
	h.publish(scopeGlobal, p)
	h.g.store.View(func(d *storeData) {
		if n := len(d.Devices[enr.DeviceID].Networks); n != 0 {
			t.Errorf("%d approval(s) older than the new lifetime kept", n)
		}
	})
	if rec := h.get(testClientAddr, token); rec.Code == http.StatusOK {
		t.Fatal("session on a network whose approval the new lifetime ended still works")
	}
}

func TestFewerRememberedNetworksDropsOldest(t *testing.T) {
	h := newHarness(t)
	p := RecommendedPolicy()
	p.IP.RememberedNetworks = 3
	h.publish(scopeGlobal, p)
	key, enr := h.enrollECDSA("web") // approves testClientAddr's network
	old := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	h.now = h.now.Add(time.Minute)
	newer := tokenOf(t, h.signInFrom(otherAddr, enr.DeviceID, key)) // key proof approves a second network
	p.IP.RememberedNetworks = 1
	h.publish(scopeGlobal, p)
	h.g.store.View(func(d *storeData) {
		if n := len(d.Devices[enr.DeviceID].Networks); n != 1 {
			t.Errorf("%d approvals kept, want 1", n)
		}
	})
	if rec := h.get(testClientAddr, old); rec.Code == http.StatusOK {
		t.Error("session on the dropped (older) network still works")
	}
	if rec := h.get(otherAddr, newer); rec.Code != http.StatusOK {
		t.Errorf("session on the kept network: %d", rec.Code)
	}
}

func TestLowerSessionCapEndsOldestSessions(t *testing.T) {
	h := newHarness(t)
	p := RecommendedPolicy()
	h.publish(scopeGlobal, p)
	key, enr := h.enrollECDSA("web")
	var tokens []string
	for i := 0; i < 5; i++ {
		tokens = append(tokens, tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key)))
	}
	p.Session.MaxPerDevice = 2
	h.publish(scopeGlobal, p)
	if n := h.g.sessions.count(enr.DeviceID, h.now); n != 2 {
		t.Fatalf("%d sessions after lowering the cap to 2", n)
	}
	if rec := h.get(testClientAddr, tokens[0]); rec.Code == http.StatusOK {
		t.Error("oldest session still works")
	}
	if rec := h.get(testClientAddr, tokens[4]); rec.Code != http.StatusOK {
		t.Errorf("newest session: %d", rec.Code)
	}
}
