package gate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type harness struct {
	t        *testing.T
	g        *Gate
	cfg      Config
	now      time.Time
	adminKey string

	mu       sync.Mutex
	upstream []*http.Request
	respond  http.HandlerFunc // stands in for Jellyfin when set
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, now: time.Now().UTC()}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.upstream = append(h.upstream, r.Clone(r.Context()))
		respond := h.respond
		h.mu.Unlock()
		if respond != nil {
			respond(w, r)
			return
		}
		io.WriteString(w, "jellyfin")
	}))
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)
	dir := t.TempDir()
	h.cfg = Config{
		Upstream:  upURL,
		DataPath:  filepath.Join(dir, "gate.json"),
		AuditPath: filepath.Join(dir, "audit.log"),
		MasterKey: randomBytes(32),
		Now:       func() time.Time { return h.now },
	}
	g, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	h.g = g

	h.adminKey = "lfa_" + randomToken()
	g.store.Update(func(d *storeData) error {
		d.AdminKeys["adm_test"] = &AdminKey{ID: "adm_test", Name: "builder", Hash: hashToken(h.adminKey), CreatedAt: h.now}
		return nil
	})
	return h
}

// testClientAddr is on a private network, where the admin API answers.
const testClientAddr = "192.168.1.50:5555"

func (h *harness) do(method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	return h.doFrom(testClientAddr, method, path, body, hdr)
}

func (h *harness) doFrom(remote, method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "https://gate.example"+path, rd)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.g.Handler().ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func (h *harness) ticket(platform string) string {
	h.t.Helper()
	rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": platform, "label": "Living room"},
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("create ticket: %d %s", rec.Code, rec.Body)
	}
	return decode[map[string]any](h.t, rec)["ticket"].(string)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// rawSign produces a WebCrypto-style r||s signature.
func rawSign(key *ecdsa.PrivateKey, msg []byte) []byte {
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// derSign produces an Android/Java-style ASN.1 signature.
func derSign(key *ecdsa.PrivateKey, msg []byte) []byte {
	d := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		panic(err)
	}
	return sig
}

func (h *harness) enrollECDSA(platform string) (*ecdsa.PrivateKey, enrollResponse) {
	h.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ticket := h.ticket(platform)
	rec := h.do("POST", "/_lanternfish/v1/enroll", map[string]string{
		"ticket": ticket, "public_key": b64(spki), "proof": b64(rawSign(key, enrollMessage(ticket))),
	}, nil)
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	return key, decode[enrollResponse](h.t, rec)
}

func (h *harness) challenge(deviceID string) string {
	h.t.Helper()
	rec := h.do("POST", "/_lanternfish/v1/challenge", map[string]string{"device_id": deviceID}, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("challenge: %d %s", rec.Code, rec.Body)
	}
	return decode[map[string]string](h.t, rec)["challenge"]
}

func (h *harness) session(deviceID, challenge string, sig []byte) *httptest.ResponseRecorder {
	return h.do("POST", "/_lanternfish/v1/session",
		map[string]string{"device_id": deviceID, "challenge": challenge, "signature": b64(sig)}, nil)
}

func (h *harness) signIn(deviceID string, sign func([]byte) []byte) string {
	h.t.Helper()
	c := h.challenge(deviceID)
	rec := h.session(deviceID, c, sign(sessionMessage(deviceID, c)))
	if rec.Code != http.StatusOK {
		h.t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	return decode[map[string]string](h.t, rec)["session_token"]
}

func (h *harness) lastUpstream() *http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.upstream) == 0 {
		return nil
	}
	return h.upstream[len(h.upstream)-1]
}

func TestBrowserFlowAndProxy(t *testing.T) {
	h := newHarness(t)

	if rec := h.do("GET", "/Items", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API call: got %d", rec.Code)
	}
	rec := h.do("GET", "/web/index.html?x=1", nil, map[string]string{"Accept": "text/html"})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/_lanternfish/?next=%2Fweb%2Findex.html%3Fx%3D1" {
		t.Fatalf("unauthenticated navigation: %d %q", rec.Code, rec.Header().Get("Location"))
	}

	key, enr := h.enrollECDSA("web")
	if enr.Kind != KindECDSA || enr.Certificate == "" || enr.Secret != "" {
		t.Fatalf("unexpected enroll response %+v", enr)
	}

	c := h.challenge(enr.DeviceID)
	rec = h.session(enr.DeviceID, c, rawSign(key, sessionMessage(enr.DeviceID, c)))
	if rec.Code != http.StatusOK {
		t.Fatalf("session: %d %s", rec.Code, rec.Body)
	}
	cookie := rec.Result().Cookies()[0]
	if cookie.Name != sessionCookie || !cookie.HttpOnly || !cookie.Secure {
		t.Fatalf("bad cookie %+v", cookie)
	}

	rec = h.do("GET", "/Items", nil, map[string]string{
		"Cookie":               "lf_session=" + cookie.Value + "; jellyfin=keep",
		"X-Lanternfish-Device": "dev_spoofed",
	})
	if rec.Code != http.StatusOK || rec.Body.String() != "jellyfin" {
		t.Fatalf("proxied request: %d %s", rec.Code, rec.Body)
	}
	up := h.lastUpstream()
	if got := up.Header.Get(deviceHeader); got != enr.DeviceID {
		t.Errorf("upstream device header = %q", got)
	}
	if got := up.Header.Get("Cookie"); strings.Contains(got, "lf_session") || !strings.Contains(got, "jellyfin=keep") {
		t.Errorf("upstream cookie = %q", got)
	}
	if got := rec.Header().Values("Strict-Transport-Security"); len(got) != 1 {
		t.Errorf("HSTS header sent %d times: %q", len(got), got)
	}

	// Header token works too and is stripped.
	token := decode[map[string]string](t, h.session(enr.DeviceID, h.challenge(enr.DeviceID),
		nil))["session_token"]
	if token != "" {
		t.Fatal("session without signature must fail")
	}
	token = h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	if rec := h.do("GET", "/Items", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusOK {
		t.Fatalf("header token: %d", rec.Code)
	}
	if h.lastUpstream().Header.Get(sessionHeader) != "" {
		t.Error("session header leaked upstream")
	}
}

func TestTicketsAreSingleUseAndExpire(t *testing.T) {
	h := newHarness(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	enroll := func(ticket string) int {
		return h.do("POST", "/_lanternfish/v1/enroll", map[string]string{
			"ticket": ticket, "public_key": b64(spki), "proof": b64(derSign(key, enrollMessage(ticket))),
		}, nil).Code
	}

	ticket := h.ticket("android")
	if code := enroll(ticket); code != http.StatusCreated {
		t.Fatalf("first use: %d", code)
	}
	if code := enroll(ticket); code != http.StatusUnauthorized {
		t.Fatalf("second use: %d", code)
	}

	expired := h.ticket("android")
	h.now = h.now.Add(7 * time.Hour)
	if code := enroll(expired); code != http.StatusUnauthorized {
		t.Fatalf("expired ticket: %d", code)
	}
}

func TestBadProofKeepsTicket(t *testing.T) {
	h := newHarness(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ticket := h.ticket("firetv")

	rec := h.do("POST", "/_lanternfish/v1/enroll", map[string]string{
		"ticket": ticket, "public_key": b64(spki), "proof": b64(rawSign(other, enrollMessage(ticket))),
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad proof: %d", rec.Code)
	}
	rec = h.do("POST", "/_lanternfish/v1/enroll", map[string]string{
		"ticket": ticket, "public_key": b64(spki), "proof": b64(rawSign(key, enrollMessage(ticket))),
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("good proof after bad: %d", rec.Code)
	}
}

func TestChallengesCannotBeReplayed(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("android")
	other, enr2 := h.enrollECDSA("web")

	c := h.challenge(enr.DeviceID)
	sig := derSign(key, sessionMessage(enr.DeviceID, c))
	if rec := h.session(enr.DeviceID, c, sig); rec.Code != http.StatusOK {
		t.Fatalf("first: %d", rec.Code)
	}
	if rec := h.session(enr.DeviceID, c, sig); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", rec.Code)
	}

	// A challenge issued for one device can't be used by another.
	c = h.challenge(enr.DeviceID)
	if rec := h.session(enr2.DeviceID, c, rawSign(other, sessionMessage(enr2.DeviceID, c))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-device challenge: %d", rec.Code)
	}

	// Expired challenge.
	c = h.challenge(enr.DeviceID)
	h.now = h.now.Add(2 * time.Minute)
	if rec := h.session(enr.DeviceID, c, derSign(key, sessionMessage(enr.DeviceID, c))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired challenge: %d", rec.Code)
	}

	// An enroll proof is not a session proof.
	c = h.challenge(enr.DeviceID)
	if rec := h.session(enr.DeviceID, c, derSign(key, enrollMessage(c))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong context: %d", rec.Code)
	}
}

func TestSessionsExpire(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("tizen")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	h.now = h.now.Add(14 * time.Minute)
	if rec := h.do("GET", "/Items", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusOK {
		t.Fatalf("before expiry: %d", rec.Code)
	}
	h.now = h.now.Add(2 * time.Minute)
	if rec := h.do("GET", "/Items", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after expiry: %d", rec.Code)
	}
}

func TestRokuHMAC(t *testing.T) {
	h := newHarness(t)
	ticket := h.ticket("roku")
	rec := h.do("POST", "/_lanternfish/v1/enroll", map[string]string{"ticket": ticket}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	enr := decode[enrollResponse](t, rec)
	secret, _ := base64.StdEncoding.DecodeString(enr.Secret)
	if enr.Kind != KindHMAC || len(secret) != 32 || enr.Certificate != "" {
		t.Fatalf("unexpected roku enroll %+v", enr)
	}

	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return signHMAC(secret, m) })
	if rec := h.do("GET", "/Videos/1/stream", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusOK {
		t.Fatalf("roku proxied: %d", rec.Code)
	}

	c := h.challenge(enr.DeviceID)
	if rec := h.session(enr.DeviceID, c, signHMAC([]byte("wrong"), sessionMessage(enr.DeviceID, c))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rec.Code)
	}

	// The secret is sealed: it must not appear in the data file.
	raw, _ := os.ReadFile(h.cfg.DataPath)
	if bytes.Contains(raw, []byte(enr.Secret)) {
		t.Fatal("roku secret stored in the clear")
	}
}

func TestRevocationIsImmediate(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("webos")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil,
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	if rec := h.do("GET", "/Items", nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session: %d", rec.Code)
	}
	c := h.challenge(enr.DeviceID)
	if rec := h.session(enr.DeviceID, c, rawSign(key, sessionMessage(enr.DeviceID, c))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked sign-in: %d", rec.Code)
	}

	rec = h.do("GET", "/_lanternfish/admin/v1/devices", nil, map[string]string{"Authorization": "Bearer " + h.adminKey})
	devs := decode[map[string][]deviceView](t, rec)["devices"]
	if len(devs) != 1 || devs[0].RevokedAt == nil {
		t.Fatalf("device list %+v", devs)
	}
}

func TestAdminAuthAndRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 10; i++ {
		rec := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]string{"platform": "web"},
			map[string]string{"Authorization": "Bearer lfa_wrong"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	// Now even the right key is refused from this IP until the window passes.
	rec := h.do("GET", "/_lanternfish/admin/v1/devices", nil, map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after failures: %d", rec.Code)
	}
	h.now = h.now.Add(11 * time.Minute)
	rec = h.do("GET", "/_lanternfish/admin/v1/devices", nil, map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusOK {
		t.Fatalf("after window: %d", rec.Code)
	}

	audit, _ := os.ReadFile(h.cfg.AuditPath)
	if bytes.Count(audit, []byte(`"admin_auth_failed"`)) != 10 {
		t.Fatalf("audit log:\n%s", audit)
	}
}

func TestGatePathsAreNeverProxied(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	for _, p := range []string{"/_lanternfish/v1/enroll", "/_lanternfish/admin/v1/nope", "/_lanternfish/x"} {
		if rec := h.do("GET", p, nil, map[string]string{sessionHeader: token}); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if h.lastUpstream() != nil {
		t.Fatal("gate path reached upstream")
	}
	if rec := h.do("GET", "/_lanternfish/", nil, nil); rec.Code != http.StatusOK || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("login page: %d", rec.Code)
	}
}

func TestWrongMasterKeyRefused(t *testing.T) {
	h := newHarness(t)
	sealer, _ := NewSealer(randomBytes(32))
	if _, err := OpenStore(h.cfg.DataPath, sealer, h.now); err == nil {
		t.Fatal("opened data file with the wrong master key")
	}
	sealer, _ = NewSealer(h.cfg.MasterKey)
	if _, err := OpenStore(h.cfg.DataPath, sealer, h.now); err != nil {
		t.Fatalf("right key: %v", err)
	}
}

func TestClientCertificate(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("android")

	srv := httptest.NewUnstartedServer(h.g.Handler())
	srv.TLS = h.g.TLSConfig(nil)
	srv.StartTLS()
	defer srv.Close()

	block, _ := pem.Decode([]byte(enr.Certificate))
	client := srv.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{block.Bytes}, PrivateKey: key}}
	client.Transport = tr

	get := func() int {
		resp, err := client.Get(srv.URL + "/Items")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusOK {
		t.Fatalf("with client cert: %d", code)
	}

	rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil,
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", rec.Code)
	}
	tr.CloseIdleConnections()
	if code := get(); code != http.StatusUnauthorized {
		t.Fatalf("revoked client cert: %d", code)
	}

	// No certificate at all: plain 401, the handshake still succeeds.
	resp, err := srv.Client().Get(srv.URL + "/Items")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no cert: %d", resp.StatusCode)
	}
}

func TestAdminAPIOnlyFromAllowedNetworks(t *testing.T) {
	h := newHarness(t)
	auth := map[string]string{"Authorization": "Bearer " + h.adminKey}

	// From the internet the admin API doesn't exist, even with the right key,
	// and probing it doesn't count against the rate limit.
	for _, remote := range []string{"203.0.113.7:4000", "[2001:db8::1]:4000", "[::ffff:203.0.113.7]:4000"} {
		for i := 0; i < 12; i++ {
			rec := h.doFrom(remote, "GET", "/_lanternfish/admin/v1/devices", nil, auth)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: got %d", remote, rec.Code)
			}
		}
	}
	// Device endpoints still work from the internet.
	if rec := h.doFrom("203.0.113.7:4000", "POST", "/_lanternfish/v1/challenge", map[string]string{"device_id": "dev_x"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("challenge from internet: %d", rec.Code)
	}
	for _, remote := range []string{"192.168.1.50:1", "127.0.0.1:1", "[::1]:1", "[::ffff:10.1.2.3]:1"} {
		if rec := h.doFrom(remote, "GET", "/_lanternfish/admin/v1/devices", nil, auth); rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", remote, rec.Code)
		}
	}

	// A custom list replaces the default.
	nets, err := ParseAdminAllow(" 100.64.0.0/10 , 203.0.113.7 ")
	if err != nil {
		t.Fatal(err)
	}
	h.g.cfg.AdminAllow = nets
	if err := h.g.loadRouting(); err != nil { // as at start-up
		t.Fatal(err)
	}
	if rec := h.doFrom("203.0.113.7:4000", "GET", "/_lanternfish/admin/v1/devices", nil, auth); rec.Code != http.StatusOK {
		t.Fatalf("explicitly allowed host: %d", rec.Code)
	}
	if rec := h.doFrom("192.168.1.50:1", "GET", "/_lanternfish/admin/v1/devices", nil, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("no longer allowed LAN host: %d", rec.Code)
	}
	for _, bad := range []string{"", "nonsense", "10.0.0.0/33"} {
		if _, err := ParseAdminAllow(bad); err == nil {
			t.Errorf("ParseAdminAllow(%q) accepted", bad)
		}
	}
}
