package gate

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// F1: a stalled request body must not hold a handler open past the deadline.
func TestStalledBodyTimesOut(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	dir := t.TempDir()
	cfg.DataPath, cfg.AuditPath = filepath.Join(dir, "gate.json"), filepath.Join(dir, "audit.log")
	cfg.BodyReadTimeout = 300 * time.Millisecond
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	server := httptest.NewUnstartedServer(g.Handler())
	server.Config.ReadHeaderTimeout = 10 * time.Second
	server.Start()
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /_lanternfish/v1/challenge HTTP/1.1\r\nHost: gate.example\r\n"+
		"Content-Type: application/json\r\nContent-Length: 19\r\n\r\n{")
	time.Sleep(time.Second)
	fmt.Fprint(conn, `"device_id":"dev"}`)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("body stalled past the read deadline was still accepted")
		}
	}
}

// F2: addresses in one IPv6 /64 share a budget, and the table is capped.
func TestFailureLimiterGroupsAndCaps(t *testing.T) {
	l := newFailureLimiter(10, 10*time.Minute, 100)
	now := time.Now()
	for i := 0; i < 10050; i++ {
		l.record(fmt.Sprintf("2001:db8:1:2::%x", i), now)
	}
	if !l.blocked("2001:db8:1:2::ffff", now) {
		t.Fatal("fresh address in the same /64 is not blocked")
	}
	for i := 0; i < 500; i++ {
		l.record(fmt.Sprintf("198.51.%d.%d", i/256, i%256), now)
	}
	if len(l.bySource) > 100 {
		t.Fatalf("limiter grew to %d entries past its cap of 100", len(l.bySource))
	}
	later := now.Add(11 * time.Minute)
	l.record("203.0.113.1", later)
	if len(l.bySource) != 1 {
		t.Fatalf("expired entries not swept: %d left", len(l.bySource))
	}
}

// F3: a renewal does not rewrite the data file when the saved time is recent,
// but the admin API still shows the latest sign-in.
func TestLastAuthIsSavedSparingly(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	sign := func(m []byte) []byte { return rawSign(key, m) }
	h.signIn(enr.DeviceID, sign)
	first := h.now
	h.now = h.now.Add(time.Minute)
	h.signIn(enr.DeviceID, sign)

	h.g.store.View(func(d *storeData) {
		if got := d.Devices[enr.DeviceID].LastAuthAt; got == nil || !got.Equal(first) {
			t.Errorf("stored last_auth_at = %v, want the first sign-in %v", got, first)
		}
	})
	rec := h.do("GET", "/_lanternfish/admin/v1/devices", nil, map[string]string{"Authorization": "Bearer " + h.adminKey})
	devs := decode[map[string][]deviceView](t, rec)["devices"]
	if len(devs) != 1 || devs[0].LastAuthAt == nil || !devs[0].LastAuthAt.Equal(h.now) {
		t.Fatalf("listed last_auth_at = %+v, want %v", devs, h.now)
	}

	h.now = h.now.Add(lastAuthSaveInterval)
	h.signIn(enr.DeviceID, sign)
	h.g.store.View(func(d *storeData) {
		if got := d.Devices[enr.DeviceID].LastAuthAt; got == nil || !got.Equal(h.now) {
			t.Errorf("stale last_auth_at not saved: %v", got)
		}
	})
}

// F4: one device can't pile up sessions; the newest ones stay valid.
func TestSessionsPerDeviceAreBounded(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	var tokens []string
	for i := 0; i < 100; i++ {
		tokens = append(tokens, h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) }))
	}
	if n := len(h.g.sessions.byID); n != maxSessionsPerDevice {
		t.Fatalf("%d sessions for one device, want %d", n, maxSessionsPerDevice)
	}
	if _, ok := h.g.sessions.lookup(tokens[len(tokens)-1], h.now); !ok {
		t.Error("newest session not valid")
	}
	if _, ok := h.g.sessions.lookup(tokens[0], h.now); ok {
		t.Error("oldest session still valid")
	}
	h.g.sessions.remove(tokens[len(tokens)-1])
	if n := len(h.g.sessions.byDevice[enr.DeviceID]); n != maxSessionsPerDevice-1 {
		t.Errorf("device index has %d sessions after a logout", n)
	}
}

// F5: a failed save changes nothing in memory.
func TestFailedUpdateChangesNothing(t *testing.T) {
	h := newHarness(t)
	breakSaves(t, h.g.store)
	err := h.g.store.Update(func(d *storeData) error {
		d.Tickets["tkt_x"] = &Ticket{ID: "tkt_x"}
		return nil
	})
	if err == nil {
		t.Fatal("save into a directory succeeded")
	}
	h.g.store.View(func(d *storeData) {
		if _, ok := d.Tickets["tkt_x"]; ok {
			t.Error("failed update left a ticket in memory")
		}
	})
}

// F5: if a revocation can't be saved, the device is still locked out and its
// open streams are closed, and the admin API says the revocation is unsaved.
// Revoking again once the disk is fixed saves it.
func TestUnsavedRevocationFailsClosed(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID)
	defer done()

	restore := breakSaves(t, h.g.store)
	auth := map[string]string{"Authorization": "Bearer " + h.adminKey}
	rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, auth)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("revoke with a broken disk: %d", rec.Code)
	}
	if h.g.activeDevice(enr.DeviceID) != nil {
		t.Error("device still active after an unsaved revocation")
	}
	if rec := h.do("GET", "/Items", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusUnauthorized {
		t.Errorf("session still works: %d", rec.Code)
	}
	select {
	case <-ctx.Done():
	default:
		t.Error("open stream survived an unsaved revocation")
	}
	devs := decode[map[string][]deviceView](t, h.do("GET", "/_lanternfish/admin/v1/devices", nil, auth))["devices"]
	if len(devs) != 1 || !devs[0].RevocationUnsaved || devs[0].RevokedAt != nil {
		t.Errorf("device list doesn't show the unsaved revocation: %+v", devs)
	}

	restore()
	if rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil, auth); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke after fixing the disk: %d %s", rec.Code, rec.Body)
	}
	s, err := OpenStore(h.cfg.DataPath, h.g.sealer, h.now)
	if err != nil {
		t.Fatal(err)
	}
	s.View(func(d *storeData) {
		if d.Devices[enr.DeviceID].Active() {
			t.Error("revocation not on disk")
		}
	})
	if _, ok := h.g.unsavedRevocations.Load(enr.DeviceID); ok {
		t.Error("revocation still marked unsaved")
	}
}

// breakSaves points the store at a directory, so saving fails. It returns a
// function that undoes this.
func breakSaves(t *testing.T, s *Store) func() {
	t.Helper()
	original := s.path
	s.path = filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(s.path, 0o700); err != nil {
		t.Fatal(err)
	}
	return func() { s.path = original }
}

// F6: a second process can't take the data file's lock, and releasing a
// failed attempt doesn't release the holder's lock.
func TestDataLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.json")
	first, err := LockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockFile(path); err == nil {
		second()
		t.Fatal("second lock acquired while the first is held")
	}
	if again, err := LockFile(path); err == nil {
		again()
		t.Fatal("lock acquired after a failed attempt")
	}
	first()
	third, err := LockFile(path)
	if err != nil {
		t.Fatalf("lock not available after release: %v", err)
	}
	third()
}
