package gate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A4: when a temporary override expires, connections it authorized end too,
// without waiting for a new request.

// recordingTimers records each armed deadline and lets a test fire it.
type recordingTimers struct {
	after []time.Duration
	fire  []func()
}

func (r *recordingTimers) arm(d time.Duration, f func()) func() bool {
	r.after, r.fire = append(r.after, d), append(r.fire, f)
	return func() bool { return true }
}

// overrideOverFallback gives dev a one-minute exception (mode: stream
// expiry mode) over fallback.
func overrideOverFallback(t *testing.T, h *harness, deviceID string, fallback Policy, mode string) time.Time {
	t.Helper()
	h.publish(scopeGlobal, fallback)
	expires := h.now.Add(time.Minute)
	override := LegacyPolicy(15 * time.Minute)
	override.Session.StreamExpiryMode = mode
	if rec := h.admin2("PUT", "devices/"+deviceID+"/override", map[string]any{"policy": override,
		"reason": "one minute exception", "expires_at": expires}); rec.Code != http.StatusOK {
		t.Fatalf("override: %d %s", rec.Code, rec.Body)
	}
	return expires
}

func closedFallback(h *harness) Policy {
	p := LegacyPolicy(15 * time.Minute)
	p.Schedule = closedSchedule(h.now)
	return p
}

func TestOverrideExpiryEndsOpenStreams(t *testing.T) {
	for _, mode := range []string{streamContinuity, streamStrict} {
		for _, via := range []string{"session", "certificate"} {
			t.Run(mode+"/"+via, func(t *testing.T) {
				h := newHarness(t)
				key, enr := h.enrollECDSA("android")
				expires := overrideOverFallback(t, h, enr.DeviceID, closedFallback(h), mode)
				req := httptest.NewRequest("GET", "https://gate.example/Items", nil)
				req.RemoteAddr = homeAddr
				if via == "session" {
					req.Header.Set(sessionHeader, tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key)))
				} else {
					req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leafOf(t, enr)}}}
				}
				timers := &recordingTimers{}
				h.g.streams.after = timers.arm
				auth, _, ctx, done := h.g.authorizeAndTrack(httptest.NewRecorder(), req)
				if auth == nil {
					t.Fatal("not authorized during the exception")
				}
				defer done()
				if len(timers.after) != 1 || timers.after[0] != expires.Sub(h.now) {
					t.Fatalf("deadline timers %v, want one at the override's end (%v)", timers.after, expires.Sub(h.now))
				}
				h.now = expires
				timers.fire[0]()
				if ctx.Err() == nil {
					t.Fatal("stream still open after the override expired")
				}
			})
		}
	}
}

// Sessions issued under an override end with it.
func TestOverrideExpiryEndsSessions(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	expires := overrideOverFallback(t, h, enr.DeviceID, LegacyPolicy(15*time.Minute), streamContinuity)
	token := tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key))
	s, _ := h.g.sessions.lookup(token, h.now)
	if !s.expires.Equal(expires) {
		t.Fatalf("session ends %v, want the override's end %v", s.expires, expires)
	}
	// Afterwards the fallback, which allows access, takes over on a new sign-in.
	h.now = expires.Add(time.Second)
	tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key))
}

// Removing an override re-checks open streams under the fallback.
func TestOverrideRemovalRechecksStreams(t *testing.T) {
	h := newHarness(t)
	_, enr := h.enrollECDSA("web")
	overrideOverFallback(t, h, enr.DeviceID, closedFallback(h), streamContinuity)
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: homeAddr}, h.now)
	defer done()
	if rec := h.admin2("DELETE", "devices/"+enr.DeviceID+"/override", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("remove override: %d %s", rec.Code, rec.Body)
	}
	if ctx.Err() == nil {
		t.Fatal("stream kept after the override was removed under a closed fallback")
	}
}
