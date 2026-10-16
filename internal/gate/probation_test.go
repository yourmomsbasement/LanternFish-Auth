package gate

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// U2: while an update is on probation, nothing the Gate saves can be undone
// by a rollback, because it saves nothing: changes are refused. Devices can
// still sign in and use Jellyfin.
func TestProbationRefusesChanges(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	ticket := h.ticket("web")

	marker := filepath.Join(t.TempDir(), "probation")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := h.g.cfg
	cfg.ProbationPath = marker
	g, err := New(cfg) // the new version starting up
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h.g = g

	auth := map[string]string{"Authorization": "Bearer " + h.adminKey}
	for name, rec := range map[string]int{
		"revoke":        h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, auth).Code,
		"enroll":        h.do("POST", "/_lanternfish/v1/enroll", map[string]string{"ticket": ticket}, nil).Code,
		"enroll v2":     h.do("POST", "/_lanternfish/v2/enrollment/begin", map[string]string{"ticket": ticket}, nil).Code,
		"disable owner": h.admin2("POST", "subjects/"+defaultSubjectID+"/disable", nil).Code,
		"publish policy": h.do("PUT", "/_lanternfish/admin/v2/policy",
			map[string]any{"expected_version": 1, "policy": RecommendedPolicy()}, auth).Code,
	} {
		if rec != http.StatusServiceUnavailable {
			t.Errorf("%s during probation: %d, want 503", name, rec)
		}
	}
	if err := g.store.Update(func(*storeData) error { return nil }); err != ErrProbation {
		t.Errorf("store write during probation: %v", err)
	}
	// Signing in and using Jellyfin still work.
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	if rec := h.get(testClientAddr, tok); rec.Code != http.StatusOK {
		t.Fatalf("proxied request during probation: %d", rec.Code)
	}
	// So does the v2 sign-in the web client uses.
	if rec := h.signInWithMAC(enr.DeviceID, key, ""); rec.Code != http.StatusOK {
		t.Fatalf("v2 sign-in during probation: %d %s", rec.Code, rec.Body)
	}

	// Once the update is confirmed (marker gone), changes are allowed again.
	os.Remove(marker)
	deadline := time.Now().Add(5 * time.Second)
	for g.store.readOnly.Load() && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, auth); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke after probation: %d %s", rec.Code, rec.Body)
	}
}
