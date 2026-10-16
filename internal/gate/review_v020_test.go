package gate

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Regression tests for the v0.2.0 follow-up review (R2–R7). Each started as
// the reviewer's reproduction of the bug, with its assertion turned around.

// pauseBeforeTracking makes the next proxied request stop right after it is
// authorized, before its stream is registered: authorizeRequest reads the
// clock once, and authorizeAndTrack reads it again just before track. It
// returns a channel closed when the request is paused, and a resume function.
func (h *harness) pauseBeforeTracking() (paused chan struct{}, resume func()) {
	paused, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	h.g.cfg.Now = func() time.Time {
		if calls.Add(1) == 2 {
			close(paused)
			<-release
		}
		return h.now
	}
	return paused, func() { close(release) }
}

func (h *harness) upstreamCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.upstream)
}

// raceChange runs send, pauses it between authorization and stream
// registration, applies change, and checks the request did not reach
// Jellyfin.
func raceChange(t *testing.T, h *harness, send func() *httptest.ResponseRecorder, change func()) {
	t.Helper()
	before := h.upstreamCount()
	paused, resume := h.pauseBeforeTracking()
	result := make(chan int, 1)
	go func() { result <- send().Code }()
	select {
	case <-paused:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not pause")
	}
	change()
	resume()
	select {
	case code := <-result:
		if code == http.StatusOK || h.upstreamCount() != before {
			t.Fatalf("request authorized before the change still reached Jellyfin (%d)", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request stuck")
	}
}

// racePolicy binds access to approved networks and doesn't let a key proof
// approve a new one. (Under on_change=key_proof a client certificate, being a
// fresh key proof, would rightly re-approve a removed network.)
func racePolicy() Policy {
	p := RecommendedPolicy()
	p.IP.OnChange = onChangeDeny
	return p
}

// R2: a change that takes access away can't miss a request that was
// authorized just before it but registers its stream just after.
func TestAccessChangeCannotMissARequestBeingTracked(t *testing.T) {
	changes := map[string]func(t *testing.T, h *harness, deviceID string){
		"owner disabled": func(t *testing.T, h *harness, _ string) {
			if rec := h.admin2("POST", "subjects/"+defaultSubjectID+"/disable", nil); rec.Code != http.StatusNoContent {
				t.Fatalf("disable: %d", rec.Code)
			}
		},
		"network approval removed": func(t *testing.T, h *harness, deviceID string) {
			var nid string
			h.g.store.View(func(d *storeData) { nid = d.Devices[deviceID].Networks[0].ID })
			if rec := h.admin2("DELETE", "devices/"+deviceID+"/networks/"+nid, nil); rec.Code != http.StatusNoContent {
				t.Fatalf("delete approval: %d %s", rec.Code, rec.Body)
			}
		},
		"policy restricted": func(t *testing.T, h *harness, _ string) {
			p := racePolicy()
			p.Schedule = closedSchedule(h.now)
			h.publish(scopeGlobal, p)
		},
	}
	for name, change := range changes {
		t.Run(name+"/session", func(t *testing.T) {
			h := newHarness(t)
			h.publish(scopeGlobal, racePolicy())
			key, enr := h.enrollECDSA("web")
			tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
			raceChange(t, h, func() *httptest.ResponseRecorder { return h.get(testClientAddr, tok) },
				func() { change(t, h, enr.DeviceID) })
		})
		t.Run(name+"/certificate", func(t *testing.T) {
			h := newHarness(t)
			h.publish(scopeGlobal, racePolicy())
			_, enr := h.enrollECDSA("android")
			leaf := leafOf(t, enr)
			if rec := h.doCert(testClientAddr, leaf, ""); rec.Code != http.StatusOK {
				t.Fatalf("certificate: %d %s", rec.Code, rec.Body)
			}
			raceChange(t, h, func() *httptest.ResponseRecorder { return h.doCert(testClientAddr, leaf, "") },
				func() { change(t, h, enr.DeviceID) })
		})
	}
}

// R3: once a shorter lifetime makes a session expired, its very next request
// is refused.
func TestShortenedLifetimeEndsExpiredSessionAtOnce(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	h.now = h.now.Add(2 * time.Minute)
	h.publish(scopeGlobal, LegacyPolicy(time.Minute))
	before := h.upstreamCount()
	if rec := h.get(testClientAddr, tok); rec.Code != http.StatusUnauthorized || h.upstreamCount() != before {
		t.Fatalf("request with a session already past the new lifetime: %d", rec.Code)
	}
	if _, ok := h.g.sessions.lookup(tok, h.now); ok {
		t.Error("expired session not removed")
	}
}

// R4: switching to strict expiry, or shortening a strict lifetime, puts a
// deadline on streams that are already open.
func TestStrictExpiryTightensOpenStreams(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	tok := tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))
	s, _ := h.g.sessions.lookup(tok, h.now)
	ft := &fakeTimers{}
	h.g.streams.after = ft.after
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID,
		streamAuth{ip: "192.168.1.50", issued: s.issued, expires: s.expires}, h.now)
	defer done()
	if len(ft.fired) != 0 {
		t.Fatal("continuity stream without a schedule end has a deadline")
	}

	p := LegacyPolicy(15 * time.Minute)
	p.Session.StreamExpiryMode = streamStrict
	h.publish(scopeGlobal, p)
	if len(ft.fired) != 1 {
		t.Fatalf("switching to strict armed %d timers, want 1", len(ft.fired))
	}

	// Shortening the strict lifetime past the stream's age closes it.
	h.now = h.now.Add(2 * time.Minute)
	p.Session.TTLSeconds = 60
	h.publish(scopeGlobal, p)
	if ctx.Err() == nil {
		t.Fatal("stream older than the new strict lifetime still open")
	}
}

// R5: a stream opened while network binding was off is bound to its network
// once binding is turned on, so withdrawing that network's approval closes it.
func TestReboundStreamClosesWhenNetworkApprovalIsRemoved(t *testing.T) {
	h := newHarness(t)
	p := RecommendedPolicy()
	h.publish(scopeGlobal, p)
	_, enr := h.enrollECDSA("web")
	var nid string
	h.g.store.View(func(d *storeData) { nid = d.Devices[enr.DeviceID].Networks[0].ID })

	p.IP.Enabled = false
	h.publish(scopeGlobal, p)
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID, streamAuth{ip: "192.168.1.50"}, h.now)
	defer done()
	p.IP.Enabled = true
	p.IP.OnChange = onChangeDeny
	h.publish(scopeGlobal, p)
	if ctx.Err() != nil {
		t.Fatal("stream on an approved network closed when binding was turned on")
	}
	if rec := h.admin2("DELETE", "devices/"+enr.DeviceID+"/networks/"+nid, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete approval: %d %s", rec.Code, rec.Body)
	}
	if ctx.Err() == nil {
		t.Fatal("stream survived the removal of its network's approval")
	}
}

// R6: a date cutoff beyond the schedule search horizon still ends
// continuity streams.
func TestCutoffBeyondHorizonEndsStreams(t *testing.T) {
	h := newHarness(t)
	end := h.now.Add(9 * 24 * time.Hour)
	p := LegacyPolicy(5 * time.Minute)
	p.Schedule = openUntil(end)
	h.publish(scopeGlobal, p)
	_, enr := h.enrollECDSA("web")
	d := h.g.evaluate(h.g.activeDevice(enr.DeviceID), "192.168.1.50", h.now)
	a := &requestAuth{pol: d.pol, expires: h.now.Add(5 * time.Minute), hardEnd: d.hardEnd}
	if d.outcome != outAllow || !a.streamDeadline().Equal(end) {
		t.Fatalf("continuity stream deadline = %v, want the cutoff %v", a.streamDeadline(), end)
	}

	// The same through a real stream, with the clock moved across the cutoff.
	ft := &fakeTimers{}
	h.g.streams.after = ft.after
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID,
		streamAuth{ip: "192.168.1.50", deadline: a.streamDeadline()}, h.now)
	defer done()
	if len(ft.fired) != 1 {
		t.Fatalf("no timer for a cutoff 9 days away")
	}
	ft.fired[0]()
	if ctx.Err() == nil {
		t.Fatal("stream open past the cutoff")
	}
}

// R6: a weekly schedule with no change for a whole horizon (only possible
// around clock changes) gets the horizon as its boundary, never "no end".
func TestNoBoundaryWithinHorizonIsNeverUnlimited(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	until := now.Add(30 * 24 * time.Hour)
	cs, err := compileSchedule(SchedulePolicy{Enabled: true, Timezone: "UTC", ValidUntil: &until,
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, Start: "00:00", End: "24:00"}}})
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := cs.nextBoundary(now); !ok || !at.Equal(until) {
		t.Fatalf("24/7 schedule ending in 30 days: boundary %v %v", at, ok)
	}
	// Memoised: asking again from later on gives the same answer.
	if at, ok := cs.nextBoundary(now.Add(48 * time.Hour)); !ok || !at.Equal(until) {
		t.Fatalf("memoised boundary %v %v", at, ok)
	}
	// Past the cutoff the memo doesn't apply; access never comes back.
	if _, ok := cs.nextBoundary(until.Add(time.Hour)); ok {
		t.Fatal("a boundary after the schedule's end")
	}
}

// R7: merging blackouts and skipping the minute scan don't change what the
// schedule allows, or where it changes.
func TestFastScheduleMatchesNaive(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for trial := 0; trial < 40; trial++ {
		sp := SchedulePolicy{Enabled: true, Timezone: "America/Chicago",
			WeeklyWindows: []WeeklyWindow{{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, Start: "00:00", End: "24:00"}}}
		if trial%2 == 1 {
			sp.WeeklyWindows = []WeeklyWindow{{Days: []string{"mon", "wed", "fri"}, Start: "18:00", End: "23:30"}}
		}
		for i := 0; i < 1+rng.Intn(30); i++ {
			start := base.Add(time.Duration(rng.Intn(20*24*60)) * time.Minute).Add(time.Duration(rng.Intn(60)) * time.Second)
			sp.Blackouts = append(sp.Blackouts, Interval{Start: start, End: start.Add(time.Duration(1+rng.Intn(36*60)) * time.Minute)})
		}
		cs, err := compileSchedule(sp)
		if err != nil {
			t.Fatal(err)
		}
		naive := func(at time.Time) bool {
			for _, b := range sp.Blackouts {
				if !at.Before(b.Start) && at.Before(b.End) {
					return false
				}
			}
			local := at.In(cs.loc)
			m := local.Hour()*60 + local.Minute()
			for _, s := range cs.byDay[local.Weekday()] {
				if m >= s.start && m < s.end {
					return true
				}
			}
			return false
		}
		for i := 0; i < 300; i++ {
			at := base.Add(time.Duration(rng.Int63n(int64(24 * 24 * time.Hour))))
			if cs.allowed(at) != naive(at) {
				t.Fatalf("trial %d: allowed(%v) = %v, naive %v", trial, at, cs.allowed(at), naive(at))
			}
		}
		from := base.Add(time.Duration(rng.Intn(5*24*60)) * time.Minute)
		at, ok := cs.nextChange(from, scheduleHorizon)
		if ok {
			for c := from.Truncate(time.Minute).Add(time.Minute); c.Before(at); c = c.Add(time.Minute) {
				if naive(c) != naive(from) {
					t.Fatalf("trial %d: change at %v missed (reported %v)", trial, c, at)
				}
			}
			if naive(at) == naive(from) {
				t.Fatalf("trial %d: reported change at %v isn't one", trial, at)
			}
		}
	}
}

func BenchmarkScheduleBoundary(b *testing.B) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	for _, count := range []int{0, 256} {
		b.Run(map[int]string{0: "all_day", 256: "all_day_256_future_blackouts"}[count], func(b *testing.B) {
			p := LegacyPolicy(5 * time.Minute)
			p.Schedule = openUntil(now.Add(30 * 24 * time.Hour))
			for i := 0; i < count; i++ {
				start := now.Add(time.Duration(40+i) * 24 * time.Hour)
				p.Schedule.Blackouts = append(p.Schedule.Blackouts, Interval{Start: start, End: start.Add(time.Hour)})
			}
			cp, err := compilePolicy(1, scopeGlobal, p)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cp.schedule.nextChange(now, scheduleHorizon)
			}
		})
	}
}
