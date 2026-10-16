package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServicePermissionBoundaries(t *testing.T) {
	rules := []ServicePermission{{Methods: []string{"GET"}, PathPrefix: "/Items"}, {Methods: []string{"POST"}, Path: "/Users/AuthenticateByName"}}
	client := ServiceClient{Permissions: &rules}
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{
		{"GET", "/Items", true}, {"GET", "/Items/abc?api_key=token", true}, {"POST", "/Items/abc", false}, {"GET", "/ItemsEvil", false},
		{"POST", "/Users/AuthenticateByName", true}, {"POST", "/Users/AuthenticateByName/other", false}, {"GET", "/Users", false},
		{"GET", "/Items/%2e%2e/Users", false}, {"GET", "/Items%2f..%2fUsers", false}, {"GET", "/Items/%252e%252e/Users", false}, {"GET", "/Items//abc", false}, {"GET", "/Items/abc;path", false},
	} {
		r := serviceRequest(tc.method, "http://10.20.0.2:8096"+tc.path, nil)
		if got := servicePermitted(client, r); got != tc.allowed {
			t.Errorf("%s %s: %v", tc.method, tc.path, got)
		}
	}
	empty := []ServicePermission{}
	client.Permissions = &empty
	if servicePermitted(client, serviceRequest("GET", "http://10.20.0.2:8096/Items", nil)) {
		t.Fatal("empty explicit policy allowed")
	}
	client.Permissions = nil
	if !servicePermitted(client, serviceRequest("GET", "http://10.20.0.2:8096/Users", nil)) {
		t.Fatal("legacy policy denied")
	}
}

func TestServiceOptionalConfigurationRejectsUnsafeValues(t *testing.T) {
	tests := []func(*Config){
		func(c *Config) { c.ServiceAuth = "token" }, func(c *Config) { c.ServiceAuth = "mtls" },
		func(c *Config) { c.ServiceTLSCertFile = "server.pem" }, func(c *Config) { c.ServiceTimeout = -time.Second },
		func(c *Config) { c.ServiceMaxConcurrent = -1 }, func(c *Config) { c.ServiceMaxBodyBytes = 1 << 31 },
		func(c *Config) { c.ServiceClients[0].MaxConcurrent = -1 },
		func(c *Config) {
			r := []ServicePermission{{Methods: []string{"GET"}, PathPrefix: "/Items/../Users"}}
			c.ServiceClients[0].Permissions = &r
		},
		func(c *Config) {
			r := []ServicePermission{{Methods: []string{"CONNECT"}, Path: "/Users"}}
			c.ServiceClients[0].Permissions = &r
		},
		func(c *Config) {
			r := []ServicePermission{{Methods: []string{"GET"}, Path: "/Users", PathPrefix: "/Users"}}
			c.ServiceClients[0].Permissions = &r
		},
		func(c *Config) { c.ServiceClients[0].CertificateURI = "spiffe://lanternfish/service/seerr" },
	}
	for i, mutate := range tests {
		cfg := serviceConfig()
		mutate(&cfg)
		if validateServiceConfig(cfg) == nil {
			t.Errorf("accepted invalid optional config %d", i)
		}
	}
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := os.WriteFile(file, []byte(`[{"name":"seerr","ip":"10.20.0.4","permissions":[],"max_concurrent":2}]`), 0600); err != nil {
		t.Fatal(err)
	}
	clients, err := LoadServiceClients(file)
	if err != nil || len(clients) != 1 || clients[0].Permissions == nil || len(*clients[0].Permissions) != 0 {
		t.Fatalf("policy file: %+v %v", clients, err)
	}
	for _, value := range []string{`[{"name":"seerr","typo":true}]`, `[] []`, strings.Repeat(" ", 128<<10) + `[]`, `[]` + strings.Repeat(" ", 128<<10)} {
		os.WriteFile(file, []byte(value), 0600)
		if _, err := LoadServiceClients(file); err == nil {
			t.Fatal("invalid policy file accepted")
		}
	}
}

func TestServicePermissionsLimitsAndRevocation(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	rules := []ServicePermission{{Methods: []string{"GET"}, PathPrefix: "/Items"}}
	h.g.cfg.ServiceClients = []ServiceClient{{Name: "seerr", IP: "10.20.0.4", Permissions: &rules, RequestsPerMinute: 1}}
	handler := h.g.ServiceHandler()
	request := func(method, path string, body *strings.Reader) int {
		var req *http.Request
		if body != nil {
			req = serviceRequest(method, "http://10.20.0.2:8096"+path, body)
		} else {
			req = serviceRequest(method, "http://10.20.0.2:8096"+path, nil)
		}
		req.RemoteAddr = "10.20.0.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := request("GET", "/Users", nil); code != 403 {
		t.Fatalf("policy denial: %d", code)
	}
	if code := request("GET", "/Items", nil); code != 200 {
		t.Fatalf("allowed request: %d", code)
	}
	if code := request("GET", "/Items", nil); code != 429 {
		t.Fatalf("rate limit: %d", code)
	}
	h.g.cfg.ServiceClients[0].Disabled = true
	handler = h.g.ServiceHandler()
	if code := request("GET", "/Items", nil); code != 403 {
		t.Fatalf("disabled service: %d", code)
	}
	h.g.cfg.ServiceClients = []ServiceClient{{Name: "seerr", IP: "10.20.0.4", MaxBodyBytes: 3}}
	handler = h.g.ServiceHandler()
	if code := request("POST", "/Users", strings.NewReader("long-body")); code != 413 {
		t.Fatalf("body limit: %d", code)
	}
	req := serviceRequest("POST", "http://10.20.0.2:8096/Users", strings.NewReader("unknown-length-body"))
	req.ContentLength = -1
	req.RemoteAddr = "10.20.0.4:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("unknown-length body limit: %d", rec.Code)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.upstream) != 1 {
		t.Fatalf("denied requests reached upstream: %d", len(h.upstream))
	}
}

func TestServiceConcurrencyLimit(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = []ServiceClient{{Name: "seerr", IP: "10.20.0.4", MaxConcurrent: 1}}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h.respond = func(w http.ResponseWriter, r *http.Request) { close(started); <-release }
	handler := h.g.ServiceHandler()
	request := func() *httptest.ResponseRecorder {
		req := serviceRequest("GET", "http://10.20.0.2:8096/Items", nil)
		req.RemoteAddr = "10.20.0.4:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	go func() { defer close(done); request() }()
	<-started
	second := request()
	close(release)
	<-done
	if second.Code != 429 {
		t.Fatalf("concurrency limit: %d", second.Code)
	}
}

type servicePKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	pool   *x509.CertPool
	dir    string
	server tls.Certificate
}

func testServicePKI(t *testing.T, now time.Time) *servicePKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-service-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := &servicePKI{ca: ca, caKey: key, pool: x509.NewCertPool(), dir: t.TempDir()}
	p.pool.AddCert(ca)
	os.WriteFile(filepath.Join(p.dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	p.server = p.issue(t, now, 2, "", true)
	os.WriteFile(filepath.Join(p.dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.server.Certificate[0]}), 0600)
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(p.dir, "server-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	return p
}
func (p *servicePKI) issue(t *testing.T, now time.Time, serial int64, uri string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.20.0.2")}
	} else {
		u, _ := url.Parse(uri)
		cert.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestServiceMTLSHandshakeAndIdentity(t *testing.T) {
	h := newHarness(t)
	pki := testServicePKI(t, h.now)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	h.g.cfg.ServiceAuth = "mtls"
	h.g.cfg.ServiceTLSCertFile = filepath.Join(pki.dir, "server.pem")
	h.g.cfg.ServiceTLSKeyFile = filepath.Join(pki.dir, "server-key.pem")
	h.g.cfg.ServiceClientCAFile = filepath.Join(pki.dir, "ca.pem")
	if err := validateServiceConfig(h.g.cfg); err != nil {
		t.Fatal(err)
	}
	config, err := h.g.ServiceTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("service TLS did not require mutual authentication")
	}
	handler := h.g.ServiceHandler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.RemoteAddr = "10.20.0.4:1234"; handler.ServeHTTP(w, r) }))
	config.Certificates = []tls.Certificate{pki.server}
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	good := pki.issue(t, h.now, 3, "spiffe://lanternfish/service/seerr", false)
	wrong := pki.issue(t, h.now, 4, "spiffe://lanternfish/service/sonarr", false)
	untrusted := testServicePKI(t, h.now).issue(t, h.now, 5, "spiffe://lanternfish/service/seerr", false)
	for _, tc := range []struct {
		name string
		cert *tls.Certificate
		want int
	}{{"missing", nil, 0}, {"untrusted CA", &untrusted, 0}, {"wrong identity", &wrong, 403}, {"valid", &good, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			tlsConfig := &tls.Config{RootCAs: pki.pool, MinVersion: tls.VersionTLS13}
			if tc.cert != nil {
				tlsConfig.Certificates = []tls.Certificate{*tc.cert}
			}
			transport := &http.Transport{TLSClientConfig: tlsConfig}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			req, _ := http.NewRequest("GET", server.URL+"/Items", nil)
			req.Host = h.g.cfg.ServiceListen
			response, err := client.Do(req)
			if tc.want == 0 {
				if err == nil {
					response.Body.Close()
					t.Fatal("missing client certificate accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("status %d", response.StatusCode)
			}
		})
	}
	req := serviceRequest("GET", "http://10.20.0.2:8096/Items", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{good.Leaf}, VerifiedChains: [][]*x509.Certificate{{good.Leaf, pki.ca}}}
	client := h.g.cfg.ServiceClients[0]
	if !serviceCertificateAllowed(client, req, h.now) {
		t.Fatal("valid certificate rejected before revocation")
	}
	client.RevokedSerials = []string{"0003"}
	if serviceCertificateAllowed(client, req, h.now) {
		t.Fatal("revoked serial accepted")
	}
	client.RevokedSerials = nil
	if serviceCertificateAllowed(client, req, good.Leaf.NotAfter) {
		t.Fatal("expired certificate accepted on existing connection")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.upstream) != 1 {
		t.Fatalf("unauthenticated requests reached upstream: %d", len(h.upstream))
	}
}

func TestServiceAlertsAreOptionalAndDeduplicated(t *testing.T) {
	messages := make(chan string, 10)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		messages <- body.Content
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	h := newHarness(t)
	h.g.alerts = &alerter{url: webhook.URL, client: webhook.Client()}
	state := newServiceState(ServiceClient{Name: "seerr"}, h.g.cfg)
	req := serviceRequest("GET", "http://10.20.0.2:8096/Items?api_key=private-token", nil)
	h.g.serviceAlerts(state, req, 403, h.now)
	select {
	case <-messages:
		t.Fatal("disabled alert fired")
	default:
	}
	h.g.cfg.ServiceAlertFailures = 2
	h.g.cfg.ServiceAlertWindow = 5 * time.Minute
	h.g.serviceAlerts(state, req, 403, h.now)
	h.g.serviceAlerts(state, req, 403, h.now)
	select {
	case message := <-messages:
		if !strings.Contains(message, "seerr") || strings.Contains(message, "private-token") {
			t.Fatalf("unsafe alert: %s", message)
		}
	case <-time.After(time.Second):
		t.Fatal("failure alert missing")
	}
	h.g.serviceAlerts(state, req, 403, h.now)
	// The state records deduplication synchronously, so repeated failures
	// cannot enqueue another asynchronous delivery in this window.
	state.mu.Lock()
	count := state.failures
	alerted := state.alerted
	state.mu.Unlock()
	if count != 3 || !alerted {
		t.Fatal("failure alert state not retained")
	}
	h.g.cfg.ServiceAlertFailures = 0
	h.g.cfg.ServiceCertWarnBefore = 24 * time.Hour
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: h.now.Add(time.Hour)}}}
	h.g.serviceAlerts(state, req, 200, h.now)
	h.g.serviceAlerts(state, req, 200, h.now)
	select {
	case message := <-messages:
		if !strings.Contains(message, "certificate expires") {
			t.Fatalf("wrong alert %s", message)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry alert missing")
	}
	select {
	case message := <-messages:
		t.Fatalf("duplicate alert %s", message)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestServiceClientTrustFileRejectsLeafCertificate(t *testing.T) {
	h := newHarness(t)
	pki := testServicePKI(t, h.now)
	h.g.cfg.ServiceAuth = "mtls"
	h.g.cfg.ServiceClientCAFile = filepath.Join(pki.dir, "server.pem")
	h.g.cfg.ServiceTLSCertFile = filepath.Join(pki.dir, "server.pem")
	h.g.cfg.ServiceTLSKeyFile = filepath.Join(pki.dir, "server-key.pem")
	if _, err := h.g.ServiceTLSConfig(); err == nil {
		t.Fatal("non-CA certificate accepted as service trust file")
	}
}

func TestServicePlanDriftAlertsAreOptional(t *testing.T) {
	messages := make(chan string, 4)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content string `json:"content"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		messages <- body.Content
		w.WriteHeader(http.StatusNoContent)
	}))
	defer webhook.Close()
	h := newHarness(t)
	h.g.alerts = &alerter{url: webhook.URL, client: webhook.Client()}
	h.g.alertServiceConfigDrift([]string{"mismatch"})
	select {
	case <-messages:
		t.Fatal("disabled drift alert fired")
	default:
	}
	h.g.cfg.ServiceAlertConfigDrift = true
	h.g.alertServiceConfigDrift([]string{"mismatch"})
	h.g.alertServiceConfigDrift([]string{"mismatch"})
	select {
	case message := <-messages:
		if !strings.Contains(message, "plan/configuration drift") {
			t.Fatal(message)
		}
	case <-time.After(time.Second):
		t.Fatal("drift alert missing")
	}
	select {
	case <-messages:
		t.Fatal("drift alert was not deduplicated")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestServiceRequestDeadline(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	h.g.cfg.ServiceTimeout = time.Second
	h.respond = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	req := serviceRequest("GET", "http://10.20.0.2:8096/Items", nil)
	req.RemoteAddr = "10.20.0.4:1234"
	rec := httptest.NewRecorder()
	started := time.Now()
	h.g.ServiceHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway || time.Since(started) > 3*time.Second {
		t.Fatalf("deadline not applied: status %d elapsed %s", rec.Code, time.Since(started))
	}
}

func TestServiceHostLiteralAndDefaultPorts(t *testing.T) {
	cfg := serviceConfig()
	for _, host := range []string{"10.20.0.2", "gate.internal:8096", "10.20.0.3:8096", "10.20.0.2:80"} {
		if serviceHostMatches(cfg, host) {
			t.Errorf("unexpected host accepted: %s", host)
		}
	}
	if !serviceHostMatches(cfg, "10.20.0.2:8096") {
		t.Fatal("configured host rejected")
	}
	cfg.ServiceListen = "10.20.0.2:443"
	cfg.ServiceAuth = "mtls"
	if !serviceHostMatches(cfg, "10.20.0.2") {
		t.Fatal("standard HTTPS port omission rejected")
	}
	cfg.ServiceListen = "[fd00::2]:443"
	if !serviceHostMatches(cfg, "[fd00::2]") {
		t.Fatal("standard IPv6 HTTPS host rejected")
	}
	if serviceHostMatches(cfg, "[fd00::3]") {
		t.Fatal("different IPv6 host accepted")
	}
}
