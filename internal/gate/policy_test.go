package gate

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- Policy validation ----

func TestPolicyValidation(t *testing.T) {
	for name, p := range map[string]Policy{"legacy": LegacyPolicy(15 * time.Minute), "recommended": RecommendedPolicy()} {
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(p *Policy){
		"ttl too short":              func(p *Policy) { p.Session.TTLSeconds = 30 },
		"unknown stream mode":        func(p *Policy) { p.Session.StreamExpiryMode = "forever" },
		"verification not built yet": func(p *Policy) { p.IP.OnChange = onChangeVerify },
		"prefix too wide":            func(p *Policy) { p.IP.IPv4PrefixLen = 4 },
		"bad match":                  func(p *Policy) { p.IP.Match = "fuzzy" },
		"Local time zone":            func(p *Policy) { p.Schedule.Timezone = "Local" },
		"unknown time zone":          func(p *Policy) { p.Schedule.Timezone = "Mars/Olympus" },
		"enabled with no windows":    func(p *Policy) { p.Schedule.Enabled = true },
		"signed hour": func(p *Policy) {
			p.Schedule.WeeklyWindows = []WeeklyWindow{{Days: []string{"mon"}, Start: "+1:30", End: "05:00"}}
		},
		"24:00 as a start": func(p *Policy) {
			p.Schedule.WeeklyWindows = []WeeklyWindow{{Days: []string{"mon"}, Start: "24:00", End: "05:00"}}
		},
		"empty window": func(p *Policy) {
			p.Schedule.WeeklyWindows = []WeeklyWindow{{Days: []string{"mon"}, Start: "05:00", End: "05:00"}}
		},
		"unknown day": func(p *Policy) {
			p.Schedule.WeeklyWindows = []WeeklyWindow{{Days: []string{"monday"}, Start: "05:00", End: "06:00"}}
		},
		"reversed date range": func(p *Policy) {
			a, b := time.Now(), time.Now().Add(-time.Hour)
			p.Schedule.ValidFrom, p.Schedule.ValidUntil = &a, &b
		},
		"wrong schema": func(p *Policy) { p.SchemaVersion = 1 },
	}
	for name, mutate := range bad {
		p := RecommendedPolicy()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- Schedules ----

func mustSchedule(t *testing.T, sp SchedulePolicy) *compiledSchedule {
	t.Helper()
	sp.Enabled = true
	p := LegacyPolicy(time.Hour)
	p.Schedule = sp
	cp, err := compilePolicy(1, scopeGlobal, p)
	if err != nil {
		t.Fatal(err)
	}
	return cp.schedule
}

func at(t *testing.T, loc, s string) time.Time {
	t.Helper()
	l, err := time.LoadLocation(loc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := time.ParseInLocation("2006-01-02 15:04", s, l)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestScheduleCrossesMidnight(t *testing.T) {
	cs := mustSchedule(t, SchedulePolicy{Timezone: "America/Chicago",
		WeeklyWindows: []WeeklyWindow{{Days: []string{"fri"}, Start: "22:00", End: "02:00"}}})
	// 2026-10-16 is a Friday.
	for s, want := range map[string]bool{
		"2026-10-16 21:59": false, "2026-10-16 22:00": true, "2026-10-17 01:59": true,
		"2026-10-17 02:00": false, "2026-10-15 23:00": false, // Thursday night
	} {
		if got := cs.allowed(at(t, "America/Chicago", s)); got != want {
			t.Errorf("%s: allowed=%v, want %v", s, got, want)
		}
	}
	end, ok := cs.nextChange(at(t, "America/Chicago", "2026-10-16 23:30"), scheduleHorizon)
	if !ok || !end.Equal(at(t, "America/Chicago", "2026-10-17 02:00")) {
		t.Fatalf("next change: %v %v", end, ok)
	}
}

func TestScheduleDaylightSaving(t *testing.T) {
	// 2026-03-08: Chicago clocks jump from 02:00 to 03:00, so a 02:00-03:00
	// window never occurs and grants nothing.
	cs := mustSchedule(t, SchedulePolicy{Timezone: "America/Chicago",
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun"}, Start: "02:00", End: "03:00"}}})
	for m := time.Date(2026, 3, 8, 6, 0, 0, 0, time.UTC); m.Before(time.Date(2026, 3, 8, 10, 0, 0, 0, time.UTC)); m = m.Add(time.Minute) {
		if cs.allowed(m) {
			t.Fatalf("skipped hour granted access at %v", m)
		}
	}

	// 2026-11-01: 01:00-02:00 happens twice (CDT, then CST); both count.
	cs = mustSchedule(t, SchedulePolicy{Timezone: "America/Chicago",
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun"}, Start: "01:00", End: "02:00"}}})
	for s, want := range map[string]bool{
		"2026-11-01T05:59:00Z": false, // 00:59 CDT
		"2026-11-01T06:30:00Z": true,  // 01:30 CDT
		"2026-11-01T07:30:00Z": true,  // 01:30 CST
		"2026-11-01T08:00:00Z": false, // 02:00 CST
	} {
		tm, _ := time.Parse(time.RFC3339, s)
		if got := cs.allowed(tm); got != want {
			t.Errorf("%s: allowed=%v, want %v", s, got, want)
		}
	}
	start, _ := time.Parse(time.RFC3339, "2026-11-01T06:30:00Z")
	end, ok := cs.nextChange(start, scheduleHorizon)
	if want, _ := time.Parse(time.RFC3339, "2026-11-01T08:00:00Z"); !ok || !end.Equal(want) {
		t.Fatalf("window across the repeated hour should close at 08:00Z, got %v %v", end, ok)
	}
}

func TestScheduleBlackoutsAndDateRange(t *testing.T) {
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	from, until := base.Add(-time.Hour), base.Add(48*time.Hour)
	bStart := base.Add(10*time.Minute + 30*time.Second) // not on a minute boundary
	cs := mustSchedule(t, SchedulePolicy{Timezone: "UTC",
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, Start: "00:00", End: "24:00"}},
		ValidFrom:     &from, ValidUntil: &until,
		Blackouts: []Interval{{Start: bStart, End: bStart.Add(time.Hour), Reason: "maintenance"}}})
	if !cs.allowed(base) || cs.allowed(from.Add(-time.Second)) || cs.allowed(until) || cs.allowed(bStart) {
		t.Fatal("blackout or date range not applied")
	}
	if !cs.allowed(bStart.Add(time.Hour)) {
		t.Fatal("blackout end is exclusive")
	}
	if end, ok := cs.nextChange(base, scheduleHorizon); !ok || !end.Equal(bStart) {
		t.Fatalf("next change should be the exact blackout start, got %v", end)
	}
	if end, ok := cs.nextChange(bStart.Add(time.Hour), scheduleHorizon); !ok || !end.Equal(until) {
		t.Fatalf("next change should be valid_until, got %v", end)
	}
}

// ---- Network keys ----

func TestNetworkKey(t *testing.T) {
	rec := RecommendedPolicy().IP
	exact := rec
	exact.Match = "exact"
	off := rec
	off.Enabled = false
	cases := []struct {
		ip   string
		p    IPPolicy
		want string
	}{
		{"203.0.113.9", rec, "203.0.113.9/32"},
		{"::ffff:203.0.113.9", rec, "203.0.113.9/32"},
		{"2001:db8:1:2:aaaa::1", rec, "2001:db8:1:2::/64"},
		{"2001:db8:1:2:aaaa::1", exact, "2001:db8:1:2:aaaa::1/128"},
		{"203.0.113.9", off, ""},
	}
	for _, c := range cases {
		if got := networkKey(c.ip, c.p); got != c.want {
			t.Errorf("networkKey(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
	if networkKey("garbage", rec) == "" {
		t.Error("an unparseable address must not look like an unbound session")
	}
}

// ---- Through the Gate ----

func (h *harness) admin2(method, path string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.do(method, "/_lanternfish/admin/v2/"+path, body, map[string]string{"Authorization": "Bearer " + h.adminKey})
}

func (h *harness) globalVersion() int {
	h.t.Helper()
	rec := h.admin2("GET", "policy", nil)
	var v struct {
		Global struct {
			Version int `json:"version"`
		} `json:"global"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		h.t.Fatal(err)
	}
	return v.Global.Version
}

func (h *harness) publish(scope string, p Policy) {
	h.t.Helper()
	version := h.globalVersion()
	if scope != scopeGlobal {
		h.g.store.View(func(d *storeData) { version = d.Profiles[scope].PolicyVersion })
	}
	rec := h.admin2("PUT", "policy", map[string]any{"scope": scope, "expected_version": version, "reason": "test", "policy": p})
	if rec.Code != http.StatusOK {
		h.t.Fatalf("publish: %d %s", rec.Code, rec.Body)
	}
}

func (h *harness) signInFrom(remote, deviceID string, key *ecdsa.PrivateKey) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.doFrom(remote, "POST", "/_lanternfish/v1/challenge", map[string]string{"device_id": deviceID}, nil)
	c := decode[map[string]string](h.t, rec)["challenge"]
	return h.doFrom(remote, "POST", "/_lanternfish/v1/session", map[string]string{"device_id": deviceID, "challenge": c,
		"signature": b64(rawSign(key, sessionMessage(deviceID, c)))}, nil)
}

func tokenOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	return decode[map[string]string](t, rec)["session_token"]
}

func (h *harness) get(remote, token string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doFrom(remote, "GET", "/Items", nil, map[string]string{sessionHeader: token})
}

func reasonOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	return decode[map[string]string](t, rec)["reason"]
}

// closedSchedule allows no access now; openUntil allows it until end.
func closedSchedule(now time.Time) SchedulePolicy {
	past := now.Add(-time.Hour)
	return SchedulePolicy{Enabled: true, Timezone: "UTC", ValidUntil: &past,
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, Start: "00:00", End: "24:00"}}}
}

func openUntil(end time.Time) SchedulePolicy {
	return SchedulePolicy{Enabled: true, Timezone: "UTC", ValidUntil: &end,
		WeeklyWindows: []WeeklyWindow{{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, Start: "00:00", End: "24:00"}}}
}

const (
	homeAddr  = "198.51.100.7:4000"
	otherAddr = "203.0.113.20:4000"
)

func TestPublishNeedsCurrentVersion(t *testing.T) {
	h := newHarness(t)
	v := h.globalVersion()
	rec := h.admin2("PUT", "policy", map[string]any{"expected_version": v + 5, "policy": RecommendedPolicy()})
	if rec.Code != http.StatusConflict {
		t.Fatalf("stale publish: %d", rec.Code)
	}
	bad := RecommendedPolicy()
	bad.IP.OnChange = onChangeVerify
	if rec := h.admin2("PUT", "policy", map[string]any{"expected_version": v, "policy": bad}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid publish: %d", rec.Code)
	}
	if rec := h.admin2("POST", "policy/preview", map[string]any{"policy": bad}); !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Fatalf("preview of invalid policy: %s", rec.Body)
	}
	h.publish(scopeGlobal, RecommendedPolicy())
	if h.globalVersion() <= v {
		t.Fatal("version did not advance")
	}
}

func TestNetworkBindingWithKeyProof(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	h.publish(scopeGlobal, RecommendedPolicy())

	// Enrolled before network binding, so the first sign-in approves the
	// network on the strength of the key proof.
	home := tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key))
	if rec := h.get(homeAddr, home); rec.Code != http.StatusOK {
		t.Fatalf("home: %d %s", rec.Code, rec.Body)
	}
	// The same token from elsewhere is refused, with the reason.
	rec := h.get(otherAddr, home)
	if rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != "network_changed" {
		t.Fatalf("token from another network: %d %s", rec.Code, rec.Body)
	}
	// A browser navigation goes to the sign-in page with the reason.
	nav := h.doFrom(otherAddr, "GET", "/web/", nil, map[string]string{sessionHeader: home, "Accept": "text/html"})
	if nav.Code != http.StatusFound || !strings.Contains(nav.Header().Get("Location"), "reason=network_changed") {
		t.Fatalf("navigation: %d %s", nav.Code, nav.Header().Get("Location"))
	}

	// A fresh key proof from the new network approves it; with one
	// remembered network, the old network's sessions end.
	other := tokenOf(t, h.signInFrom(otherAddr, enr.DeviceID, key))
	if rec := h.get(otherAddr, other); rec.Code != http.StatusOK {
		t.Fatalf("new network: %d", rec.Code)
	}
	if rec := h.get(homeAddr, home); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old network's session survived: %d", rec.Code)
	}
	dev := h.admin2("GET", "devices/"+enr.DeviceID, nil)
	view := decode[deviceView](t, dev)
	if len(view.Networks) != 1 || view.Networks[0].Network != "203.0.113.20/32" {
		t.Fatalf("approvals: %+v", view.Networks)
	}

	// Withdrawing the approval ends the session at once.
	if rec := h.admin2("DELETE", "devices/"+enr.DeviceID+"/networks/"+view.Networks[0].ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete approval: %d", rec.Code)
	}
	if rec := h.get(otherAddr, other); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived its network approval: %d", rec.Code)
	}
}

func TestNetworkBindingDeny(t *testing.T) {
	h := newHarness(t)
	p := RecommendedPolicy()
	p.IP.OnChange = onChangeDeny
	h.publish(scopeGlobal, p)
	// Enrolling approves the network the ticket was used from.
	key, enr := h.enrollECDSA("web")
	if rec := h.get(testClientAddr, tokenOf(t, h.signInFrom(testClientAddr, enr.DeviceID, key))); rec.Code != http.StatusOK {
		t.Fatalf("enrollment network: %d", rec.Code)
	}
	rec := h.signInFrom(otherAddr, enr.DeviceID, key)
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "network_changed" {
		t.Fatalf("new network with deny: %d %s", rec.Code, rec.Body)
	}
	// A policy denial isn't a credential failure: it doesn't use up the
	// address's failure budget.
	for i := 0; i < 20; i++ {
		h.signInFrom(otherAddr, enr.DeviceID, key)
	}
	if rec := h.doFrom(otherAddr, "POST", "/_lanternfish/v1/challenge", map[string]string{"device_id": enr.DeviceID}, nil); rec.Code != http.StatusOK {
		t.Fatalf("policy denials counted as failures: %d", rec.Code)
	}
}

func TestPolicyChangeRechecksExistingSessions(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	p := LegacyPolicy(15 * time.Minute)
	p.Schedule = closedSchedule(h.now)
	h.publish(scopeGlobal, p)
	rec := h.get(testClientAddr, token)
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "outside_schedule" {
		t.Fatalf("session issued under the old policy: %d %s", rec.Code, rec.Body)
	}
	if rec := h.signInFrom(testClientAddr, enr.DeviceID, key); rec.Code != http.StatusForbidden {
		t.Fatalf("sign-in outside schedule: %d", rec.Code)
	}

	// Open again, until 10 minutes from now: the session works, and ends
	// when the schedule does even though its TTL is longer.
	p.Schedule = openUntil(h.now.Add(10 * time.Minute))
	h.publish(scopeGlobal, p)
	if rec := h.get(testClientAddr, token); rec.Code != http.StatusOK {
		t.Fatalf("reopened: %d", rec.Code)
	}
	h.now = h.now.Add(11 * time.Minute)
	if rec := h.get(testClientAddr, token); rec.Code == http.StatusOK {
		t.Fatal("session outlived the schedule")
	}
}

func TestProfilesAndSubjects(t *testing.T) {
	h := newHarness(t)
	kidKey, kid := h.enrollECDSA("web")
	adultKey, adult := h.enrollECDSA("web")
	kidToken := h.signIn(kid.DeviceID, func(m []byte) []byte { return rawSign(kidKey, m) })
	adultToken := h.signIn(adult.DeviceID, func(m []byte) []byte { return rawSign(adultKey, m) })

	p := LegacyPolicy(15 * time.Minute)
	p.Schedule = closedSchedule(h.now)
	rec := h.admin2("POST", "profiles", map[string]any{"name": "Kids", "policy": p})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", rec.Code, rec.Body)
	}
	prof := decode[Profile](t, rec)
	if rec := h.admin2("PUT", "devices/"+kid.DeviceID+"/profile", map[string]string{"profile_id": prof.ID}); rec.Code != http.StatusNoContent {
		t.Fatalf("assign: %d", rec.Code)
	}
	if rec := h.get(testClientAddr, kidToken); rec.Code != http.StatusForbidden {
		t.Fatalf("profile policy not applied: %d", rec.Code)
	}
	if rec := h.get(testClientAddr, adultToken); rec.Code != http.StatusOK {
		t.Fatalf("global device affected by a profile: %d", rec.Code)
	}
	// Deleting the profile returns its devices to the global policy.
	if rec := h.admin2("DELETE", "profiles/"+prof.ID, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete profile: %d", rec.Code)
	}
	if rec := h.get(testClientAddr, kidToken); rec.Code != http.StatusOK {
		t.Fatalf("after profile deleted: %d", rec.Code)
	}

	// Disabling the owner ends their devices' sessions and blocks sign-in.
	if rec := h.admin2("POST", "subjects/"+defaultSubjectID+"/disable", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := h.get(testClientAddr, adultToken); rec.Code == http.StatusOK {
		t.Fatal("disabled owner's session still works")
	}
	if rec := h.signInFrom(testClientAddr, adult.DeviceID, adultKey); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "owner_disabled" {
		t.Fatalf("disabled owner's sign-in: %d %s", rec.Code, rec.Body)
	}
	// Tickets can't be made for a disabled owner.
	if rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "web", "subject_id": defaultSubjectID},
		map[string]string{"Authorization": "Bearer " + h.adminKey}); rec.Code != http.StatusBadRequest {
		t.Fatalf("ticket for disabled owner: %d", rec.Code)
	}
}

// doCert sends a request as if over a TLS connection that presented leaf.
func (h *harness) doCert(remote string, leaf *x509.Certificate, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "https://gate.example/Items", nil)
	req.RemoteAddr = remote
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if token != "" {
		req.Header.Set(sessionHeader, token)
	}
	rec := httptest.NewRecorder()
	h.g.Handler().ServeHTTP(rec, req)
	return rec
}

func leafOf(t *testing.T, enr enrollResponse) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(enr.Certificate))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientCertificateGoesThroughPolicy(t *testing.T) {
	h := newHarness(t)
	_, enr := h.enrollECDSA("android")
	leaf := leafOf(t, enr)
	if rec := h.doCert(homeAddr, leaf, ""); rec.Code != http.StatusOK {
		t.Fatalf("cert: %d", rec.Code)
	}

	// A certificate alone no longer authorizes: the policy is applied, and
	// publishing drops the grant so the change is immediate.
	p := LegacyPolicy(15 * time.Minute)
	p.Schedule = closedSchedule(h.now)
	h.publish(scopeGlobal, p)
	if rec := h.doCert(homeAddr, leaf, ""); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "outside_schedule" {
		t.Fatalf("cert outside schedule: %d %s", rec.Code, rec.Body)
	}

	// Network binding applies to certificates too (key_proof: a new network
	// is approved by the TLS handshake's proof of the key).
	rp := RecommendedPolicy()
	rp.IP.OnChange = onChangeDeny
	h.publish(scopeGlobal, rp)
	if rec := h.doCert(homeAddr, leaf, ""); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "network_changed" {
		t.Fatalf("cert from unapproved network with deny: %d %s", rec.Code, rec.Body)
	}
	h.publish(scopeGlobal, RecommendedPolicy())
	if rec := h.doCert(homeAddr, leaf, ""); rec.Code != http.StatusOK {
		t.Fatalf("cert with key_proof: %d %s", rec.Code, rec.Body)
	}
}

func TestCertificateAndSessionMustAgree(t *testing.T) {
	h := newHarness(t)
	_, certDev := h.enrollECDSA("android")
	otherKey, other := h.enrollECDSA("web")
	token := h.signIn(other.DeviceID, func(m []byte) []byte { return rawSign(otherKey, m) })
	rec := h.doCert(testClientAddr, leafOf(t, certDev), token)
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "credential_mismatch" {
		t.Fatalf("mixed credentials: %d %s", rec.Code, rec.Body)
	}
}

// ---- Streams ----

type fakeTimers struct{ fired []func() }

func (f *fakeTimers) after(d time.Duration, fn func()) func() bool {
	f.fired = append(f.fired, fn)
	return func() bool { return true }
}

func TestStreamDeadlinesOnlyTighten(t *testing.T) {
	st := newStreamTable()
	ft := &fakeTimers{}
	st.after = ft.after
	now := time.Now()

	// A deadline in the past closes the stream at once.
	ctx, done := st.track(context.Background(), "dev", "1.2.3.4", "1.2.3.4/32", now.Add(-time.Second), now)
	if ctx.Err() == nil {
		t.Fatal("stream with a past deadline is open")
	}
	done()

	ctx, done = st.track(context.Background(), "dev", "1.2.3.4", "1.2.3.4/32", now.Add(time.Hour), now)
	defer done()
	// A later deadline doesn't extend it; an earlier one re-arms it.
	st.recheck("dev", now, func(string) (bool, time.Time) { return true, now.Add(2 * time.Hour) })
	if len(ft.fired) != 1 {
		t.Fatalf("re-armed for a later deadline: %d timers", len(ft.fired))
	}
	st.recheck("dev", now, func(string) (bool, time.Time) { return true, now.Add(time.Minute) })
	if len(ft.fired) != 2 {
		t.Fatalf("not re-armed for an earlier deadline: %d timers", len(ft.fired))
	}
	ft.fired[1]()
	if ctx.Err() == nil {
		t.Fatal("deadline timer did not close the stream")
	}

	// A stream the policy no longer allows is closed.
	ctx2, done2 := st.track(context.Background(), "dev", "1.2.3.4", "", time.Time{}, now)
	defer done2()
	st.recheck("dev", now, func(string) (bool, time.Time) { return false, time.Time{} })
	if ctx2.Err() == nil {
		t.Fatal("disallowed stream left open")
	}
}

func TestStreamDeadlineModes(t *testing.T) {
	exp, hard := time.Now().Add(5*time.Minute), time.Now().Add(time.Hour)
	cont := &compiledPolicy{Policy: LegacyPolicy(time.Hour)}
	strict := &compiledPolicy{Policy: LegacyPolicy(time.Hour)}
	strict.Policy.Session.StreamExpiryMode = streamStrict
	if d := (&requestAuth{pol: cont, expires: exp, hardEnd: hard}).streamDeadline(); !d.Equal(hard) {
		t.Errorf("continuity: %v", d)
	}
	if d := (&requestAuth{pol: cont, expires: exp}).streamDeadline(); !d.IsZero() {
		t.Errorf("continuity with no schedule end should have no deadline: %v", d)
	}
	if d := (&requestAuth{pol: strict, expires: exp, hardEnd: hard}).streamDeadline(); !d.Equal(exp) {
		t.Errorf("strict: %v", d)
	}
}

func TestPublishClosesStreamsThePolicyBlocks(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	ctx, done := h.g.streams.track(context.Background(), enr.DeviceID, "192.168.1.50", "", time.Time{}, h.now)
	defer done()
	p := LegacyPolicy(15 * time.Minute)
	p.Schedule = closedSchedule(h.now)
	h.publish(scopeGlobal, p)
	if ctx.Err() == nil {
		t.Fatal("stream survived a policy that blocks its device")
	}
}

// ---- Migration ----

func TestMigrationFromV1(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	// Make the data file look like it was written before schema 2.
	h.g.store.Update(func(d *storeData) error {
		d.Version = 1
		d.Subjects = map[string]*Subject{}
		d.Profiles = map[string]*Profile{}
		d.GlobalPolicyVersion, d.LastPolicyVersion, d.PolicyHistory = 0, 0, nil
		for _, dev := range d.Devices {
			dev.SubjectID = ""
		}
		return nil
	})
	h.g.Close()
	cfg := h.cfg
	cfg.SessionTTL = 20 * time.Minute
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h.g = g
	g.store.View(func(d *storeData) {
		if d.Version != 2 || d.Subjects[defaultSubjectID] == nil || d.Devices[enr.DeviceID].SubjectID != defaultSubjectID {
			t.Fatalf("not migrated: version %d", d.Version)
		}
		rec, ok := d.policyRecord(d.GlobalPolicyVersion)
		if !ok || rec.Policy.Session.TTLSeconds != 1200 || rec.Policy.IP.Enabled || rec.Policy.Schedule.Enabled {
			t.Fatalf("legacy policy: %+v", rec)
		}
	})
	// Behaviour is unchanged: any network, the configured TTL.
	tok := tokenOf(t, h.signInFrom(otherAddr, enr.DeviceID, key))
	if rec := h.get(homeAddr, tok); rec.Code != http.StatusOK {
		t.Fatalf("after migration: %d", rec.Code)
	}
}
