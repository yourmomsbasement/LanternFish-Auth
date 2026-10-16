package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- Enrollment v2 ----

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return key, b64(spki)
}

func (h *harness) begin(ticket string, key *ecdsa.PrivateKey, pub string) (int, map[string]any) {
	h.t.Helper()
	rec := h.do("POST", "/_lanternfish/v2/enrollment/begin", map[string]string{"ticket": ticket, "public_key": pub,
		"proof": b64(rawSign(key, enrollMessage(ticket)))}, nil)
	return rec.Code, decode[map[string]any](h.t, rec)
}

func (h *harness) finish(id, ticket string, key *ecdsa.PrivateKey) (int, map[string]any) {
	h.t.Helper()
	r := h.do("POST", "/_lanternfish/v2/enrollment/"+id+"/finish", map[string]string{"ticket": ticket,
		"proof": b64(rawSign(key, enrollMessage(ticket)))}, map[string]string{"Content-Type": "application/json"})
	return r.Code, decode[map[string]any](h.t, r)
}

func TestEnrollmentNeedsOwnerApproval(t *testing.T) {
	h := newHarness(t)
	p := stepUpPolicy()
	p.Verification.EnrollmentRequiredAll = []string{factorTOTP}
	h.publish(scopeGlobal, p)
	secret, _ := h.setUpTOTP(defaultSubjectID)

	ticket := h.ticket("web")
	key, pub := newKey(t)
	// v1 can't bypass the approval.
	if rec := h.do("POST", "/_lanternfish/v1/enroll", map[string]string{"ticket": ticket, "public_key": pub,
		"proof": b64(rawSign(key, enrollMessage(ticket)))}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("v1 enroll under an approval policy: %d %s", rec.Code, rec.Body)
	}
	code, body := h.begin(ticket, key, pub)
	if code != http.StatusAccepted || body["status"] != "verification_required" {
		t.Fatalf("begin: %d %v", code, body)
	}
	id := body["verification_id"].(string)
	// Another attempt with the same ticket waits for the reservation.
	key2, pub2 := newKey(t)
	if code, _ := h.begin(ticket, key2, pub2); code != http.StatusConflict {
		t.Fatalf("second reservation: %d", code)
	}
	if code, _ := h.finish(id, ticket, key); code != http.StatusConflict {
		t.Fatalf("finish before approval: %d", code)
	}
	if code, _ := h.finish(id, ticket, key2); code != http.StatusUnauthorized {
		t.Fatalf("finish with another key: %d", code)
	}
	if rec := h.step(testClientAddr, id, "/totp", map[string]string{"code": h.code(secret)}); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	code, body = h.finish(id, ticket, key)
	if code != http.StatusCreated {
		t.Fatalf("finish: %d %v", code, body)
	}
	devID := body["device"].(map[string]any)["device_id"].(string)
	// A lost response can be fetched again; the ticket isn't spent twice.
	if code, again := h.finish(id, ticket, key); code != http.StatusOK || again["device"].(map[string]any)["device_id"] != devID {
		t.Fatalf("repeat finish: %d %v", code, again)
	}
	if rec := h.signInFrom(testClientAddr, devID, key); rec.Code != http.StatusOK {
		t.Fatalf("sign-in after enrollment: %d %s", rec.Code, rec.Body)
	}
	dev := decode[deviceView](t, h.admin2("GET", "devices/"+devID, nil))
	if len(dev.Networks) != 1 || !dev.Networks[0].Verified || dev.Networks[0].Method != "enrollment+totp" {
		t.Fatalf("enrollment approval: %+v", dev.Networks)
	}
}

func TestTicketBoundToKey(t *testing.T) {
	h := newHarness(t)
	key, pub := newKey(t)
	other, otherPub := newKey(t)
	spki, _ := decodeB64(pub)
	rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "web", "key_fingerprint": keyFingerprint(spki)},
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	ticket := decode[map[string]any](t, rec)["ticket"].(string)
	if code, body := h.begin(ticket, other, otherPub); code != http.StatusUnauthorized {
		t.Fatalf("other key with a bound ticket: %d %v", code, body)
	}
	if code, body := h.begin(ticket, key, pub); code != http.StatusCreated || body["status"] != "enrolled" {
		t.Fatalf("bound key: %d %v", code, body)
	}
}

// ---- Location ----

func geoPolicy(mode string) Policy {
	p := LegacyPolicy(15 * time.Minute)
	p.Geo = GeoPolicy{Mode: mode, CountryAllowlist: []string{"US", "CA"}, CountryDenylist: []string{"KP"},
		UnknownAction: actDeny, NewCountryAction: actDeny, ExemptNetworks: []string{"192.168.0.0/16"}}
	p.normalize()
	return p
}

func (h *harness) fakeGeo(m map[string]string) {
	h.g.geo = &geoResolver{cache: map[netip.Addr]geoCached{}, lookupFn: func(a netip.Addr) (string, bool) {
		c, ok := m[a.String()]
		return c, ok
	}}
}

func TestCountryRules(t *testing.T) {
	h := newHarness(t)
	h.fakeGeo(map[string]string{"198.51.100.7": "US", "203.0.113.20": "DE", "203.0.113.21": "KP", "203.0.113.22": "CA"})
	h.publish(scopeGlobal, geoPolicy(geoEnforce))
	key, enr := h.enrollECDSA("web") // from the exempt LAN: no country recorded

	for addr, want := range map[string]string{
		"203.0.113.20:1": "country_not_allowed", // allowlist
		"203.0.113.21:1": "country_denied",      // denylist wins
		"198.18.0.1:1":   "location_unknown",    // unknown is never assumed home
	} {
		if rec := h.signInFrom(addr, enr.DeviceID, key); rec.Code != http.StatusForbidden || reasonOf(t, rec) != want {
			t.Errorf("%s: %d %s", addr, rec.Code, rec.Body)
		}
	}
	// The exempt network skips country rules.
	if rec := h.signInFrom(testClientAddr, enr.DeviceID, key); rec.Code != http.StatusOK {
		t.Fatalf("exempt network: %d %s", rec.Code, rec.Body)
	}
	// First country is recorded; a second one is "new" (deny here).
	us := tokenOf(t, h.signInFrom(homeAddr, enr.DeviceID, key))
	if rec := h.signInFrom("203.0.113.22:1", enr.DeviceID, key); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "new_country" {
		t.Fatalf("new country: %d %s", rec.Code, rec.Body)
	}
	// A session doesn't follow its device to another country.
	if rec := h.get("203.0.113.22:1", us); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session used from another country: %d", rec.Code)
	}
	if rec := h.get(homeAddr, us); rec.Code != http.StatusOK {
		t.Fatalf("session at home: %d", rec.Code)
	}
}

func TestGeoNeedsDatabaseAndValidLists(t *testing.T) {
	h := newHarness(t)
	rec := h.admin2("PUT", "policy", map[string]any{"expected_version": h.globalVersion(), "policy": geoPolicy(geoObserve)})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "LANTERNFISH_GEOIP_DB") {
		t.Fatalf("geo without a database: %d %s", rec.Code, rec.Body)
	}
	p := geoPolicy(geoEnforce)
	p.Geo.CountryAllowlist, p.Geo.CountryDenylist = nil, nil
	if err := p.Validate(); err == nil {
		t.Fatal("enforce with no lists accepted")
	}
	p = geoPolicy(geoEnforce)
	p.Geo.CountryAllowlist = []string{"usa"}
	if err := p.Validate(); err == nil {
		t.Fatal("three-letter country accepted")
	}
}

// A real database file: geo.go reads MaxMind's format.
func TestGeoReadsMaxMindDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, testMMDB(t, map[string]string{"203.0.113.0/24": "DE", "198.51.100.0/24": "US"}, time.Now()), 0o644); err != nil {
		t.Fatal(err)
	}
	g := newGeoResolver(path, 0)
	now := time.Now()
	if r := g.lookup("203.0.113.9", now); r.Country != "DE" || r.Status != "ok" {
		t.Fatalf("lookup: %+v", r)
	}
	if r := g.lookup("198.51.100.200", now); r.Country != "US" {
		t.Fatalf("lookup: %+v", r)
	}
	if r := g.lookup("8.8.8.8", now); r.known() {
		t.Fatalf("unlisted address resolved: %+v", r)
	}
	if r := g.lookup("10.0.0.1", now); r.Status != "private" {
		t.Fatalf("private address: %+v", r)
	}
	// A stale database answers "stale", never a country.
	old := newGeoResolver(path, 0)
	if r := old.lookup("203.0.113.9", now.Add(60*24*time.Hour)); r.Status != "stale" || r.known() {
		t.Fatalf("stale database: %+v", r)
	}
}

// ---- MAC reports ----

func macPolicy(onChange string) Policy {
	p := LegacyPolicy(15 * time.Minute)
	p.MAC = MACPolicy{Collect: true, RequireReport: true, OnChange: onChange, MaxObservationAgeSeconds: 600}
	p.normalize()
	return p
}

func (h *harness) signInWithMAC(deviceID string, key *ecdsa.PrivateKey, mac string) *httptest.ResponseRecorder {
	h.t.Helper()
	rec := h.do("POST", "/_lanternfish/v2/challenge", map[string]string{"device_id": deviceID}, nil)
	c := decode[map[string]string](h.t, rec)["challenge"]
	body := map[string]any{"device_id": deviceID, "challenge": c, "signature": b64(rawSign(key, sessionMessage(deviceID, c))),
		"client": "native"}
	if mac != "" {
		rep := &MACReport{InterfaceKind: "wifi", MAC: mac, CollectedAt: h.now.Unix()}
		hw, _ := parseMAC(mac)
		rep.Signature = b64(rawSign(key, macMessage(deviceID, c, rep, hw)))
		body["mac_report"] = rep
	}
	return h.do("POST", "/_lanternfish/v2/session", body, nil)
}

func TestMACReports(t *testing.T) {
	h := newHarness(t)
	rec := h.admin2("POST", "profiles", map[string]any{"name": "TVs", "policy": macPolicy(actReenrol)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("profile: %d %s", rec.Code, rec.Body)
	}
	prof := decode[Profile](t, rec)
	key, tv := h.enrollECDSA("android")
	_, browser := h.enrollECDSA("web")
	if rec := h.admin2("PUT", "devices/"+browser.DeviceID+"/profile", map[string]string{"profile_id": prof.ID}); rec.Code != http.StatusBadRequest {
		t.Fatalf("browser assigned to a MAC-required profile: %d", rec.Code)
	}
	h.admin2("PUT", "devices/"+tv.DeviceID+"/profile", map[string]string{"profile_id": prof.ID})

	if rec := h.signInWithMAC(tv.DeviceID, key, ""); rec.Code != http.StatusForbidden || reasonOf(t, rec) != "mac_report_required" {
		t.Fatalf("no report: %d %s", rec.Code, rec.Body)
	}
	if rec := h.signInWithMAC(tv.DeviceID, key, "00:00:00:00:00:00"); rec.Code == http.StatusOK {
		t.Fatal("placeholder MAC accepted")
	}
	if rec := h.signInWithMAC(tv.DeviceID, key, "3c:22:fb:01:02:03"); rec.Code != http.StatusOK {
		t.Fatalf("first report: %d %s", rec.Code, rec.Body)
	}
	if rec := h.signInWithMAC(tv.DeviceID, key, "3c:22:fb:01:02:03"); rec.Code != http.StatusOK {
		t.Fatalf("same report: %d %s", rec.Code, rec.Body)
	}
	// Stored as a keyed tag, not the address.
	h.g.store.View(func(d *storeData) {
		m := d.Devices[tv.DeviceID].MACs
		if len(m) != 1 || strings.Contains(m[0].Tag, "3c22fb") || len(m[0].Tag) != 64 {
			t.Fatalf("stored MAC: %+v", m)
		}
	})
	// Changed, under "reenroll": suspended until the admin acts.
	if rec := h.signInWithMAC(tv.DeviceID, key, "3c:22:fb:09:09:09"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("changed MAC: %d %s", rec.Code, rec.Body)
	}
	if rec := h.signInWithMAC(tv.DeviceID, key, "3c:22:fb:01:02:03"); rec.Code == http.StatusOK {
		t.Fatal("suspended device signed in")
	}
	if rec := h.admin2("POST", "devices/"+tv.DeviceID+"/unsuspend", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unsuspend: %d", rec.Code)
	}
	// require_report is never global.
	if rec := h.admin2("PUT", "policy", map[string]any{"expected_version": h.globalVersion(), "policy": macPolicy(actObserve)}); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("global require_report: %d", rec.Code)
	}
}

// ---- Admin ----

func TestAdminScopes(t *testing.T) {
	h := newHarness(t)
	tickets := "lfa_" + randomToken()
	h.g.store.Update(func(d *storeData) error {
		d.AdminKeys["adm_t"] = &AdminKey{ID: "adm_t", Name: "builder-tickets", Hash: hashToken(tickets),
			CreatedAt: h.now, Scopes: []string{scopeTickets}}
		return nil
	})
	auth := map[string]string{"Authorization": "Bearer " + tickets}
	if rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "web"}, auth); rec.Code != http.StatusCreated {
		t.Fatalf("scoped ticket: %d", rec.Code)
	}
	if rec := h.do("PUT", "/_lanternfish/admin/v2/policy", map[string]any{"expected_version": 1, "policy": RecommendedPolicy()}, auth); rec.Code != http.StatusForbidden {
		t.Fatalf("ticket-only key published a policy: %d", rec.Code)
	}
	if rec := h.do("GET", "/_lanternfish/admin/v1/devices", nil, auth); rec.Code != http.StatusForbidden {
		t.Fatalf("ticket-only key listed devices: %d", rec.Code)
	}
}

func TestDashboardSensitiveChangesNeedRecentVerification(t *testing.T) {
	h := newHarness(t)
	// An admin owner with an authenticator, linked to the key.
	h.admin2("POST", "subjects", map[string]string{"name": "Me", "role": "admin"})
	var adminID string
	h.g.store.View(func(d *storeData) {
		for id, s := range d.Subjects {
			if s.Role == "admin" {
				adminID = id
			}
		}
	})
	secret, _ := h.setUpTOTP(adminID)
	h.g.store.Update(func(d *storeData) error { d.AdminKeys["adm_test"].SubjectID = adminID; return nil })

	cookie, csrf := h.dashboardSignIn()
	hdr := map[string]string{"Cookie": cookie, csrfHeader: csrf}
	publish := map[string]any{"expected_version": h.globalVersion(), "policy": RecommendedPolicy()}
	rec := h.dashboard(testClientAddr, "PUT", "/_lanternfish/admin/v2/policy", publish, hdr)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "recent_verification_required") {
		t.Fatalf("unverified publish: %d %s", rec.Code, rec.Body)
	}
	// Reading and non-sensitive changes still work.
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "web"}, hdr); rec.Code != http.StatusCreated {
		t.Fatalf("ticket: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/verify", map[string]string{"code": "000000"}, hdr); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d", rec.Code)
	}
	if rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/verify", map[string]string{"code": h.code(secret)}, hdr); rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body)
	}
	if rec := h.dashboard(testClientAddr, "PUT", "/_lanternfish/admin/v2/policy", publish, hdr); rec.Code != http.StatusOK {
		t.Fatalf("verified publish: %d %s", rec.Code, rec.Body)
	}
	h.now = h.now.Add(recentVerification + time.Minute)
	cookie, csrf = h.dashboardSignIn() // the old session went idle
	publish["expected_version"] = h.globalVersion()
	if rec := h.dashboard(testClientAddr, "PUT", "/_lanternfish/admin/v2/policy", publish, map[string]string{"Cookie": cookie, csrfHeader: csrf}); rec.Code != http.StatusForbidden {
		t.Fatalf("stale verification: %d", rec.Code)
	}
}

func TestDeviceOverride(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	tok := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	closed := LegacyPolicy(15 * time.Minute)
	closed.Schedule = closedSchedule(h.now)
	exp := h.now.Add(time.Hour)
	if rec := h.admin2("PUT", "devices/"+enr.DeviceID+"/override", map[string]any{"policy": closed, "reason": "grounded", "expires_at": exp}); rec.Code != http.StatusOK {
		t.Fatalf("override: %d %s", rec.Code, rec.Body)
	}
	if rec := h.get(testClientAddr, tok); rec.Code != http.StatusForbidden {
		t.Fatalf("override not applied: %d", rec.Code)
	}
	h.now = exp.Add(time.Second)
	if rec := h.get(testClientAddr, tok); rec.Code == http.StatusForbidden {
		t.Fatal("expired override still applied")
	}
	if rec := h.admin2("PUT", "devices/"+enr.DeviceID+"/override", map[string]any{"policy": closed}); rec.Code != http.StatusBadRequest {
		t.Fatalf("override without a reason: %d", rec.Code)
	}
}

func TestResetEnrollment(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	tok := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	rec := h.admin2("POST", "devices/"+enr.DeviceID+"/reset-enrollment", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if h.get(testClientAddr, tok).Code != http.StatusUnauthorized {
		t.Fatal("old device still works")
	}
	ticket := decode[map[string]any](t, rec)["ticket"].(string)
	k2, pub2 := newKey(t)
	if code, body := h.begin(ticket, k2, pub2); code != http.StatusCreated {
		t.Fatalf("replacement enroll: %d %v", code, body)
	}
}

func TestAuditLogRotates(t *testing.T) {
	dir := t.TempDir()
	a, err := openAuditLog(filepath.Join(dir, "audit.log"), 400)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for i := 0; i < 40; i++ {
		a.write(time.Now(), "test_event", map[string]any{"n": i})
	}
	for _, name := range []string{"audit.log", "audit.log.1", "audit.log.2", "audit.log.3"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() > 400 {
			t.Fatalf("%s: %v %v", name, st, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.4")); err == nil {
		t.Fatal("kept more than three old files")
	}
}
