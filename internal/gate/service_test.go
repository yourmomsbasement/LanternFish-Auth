package gate

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func serviceRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.URL.Scheme, r.URL.Host = "", ""
	r.RequestURI = r.URL.RequestURI()
	return r
}

func serviceConfig() Config {
	return Config{ServiceNetwork: "10.20.0.0/24", ServiceListen: "10.20.0.2:8096", ServiceClients: []ServiceClient{{Name: "seerr", IP: "10.20.0.4"}}}
}

func TestServiceConfigFailsClosed(t *testing.T) {
	valid := serviceConfig()
	if err := validateServiceConfig(valid); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{":8096", "0.0.0.0:8096", "[::]:8096", "127.0.0.1:8096", "8.8.8.8:8096", "gate.internal:8096", "10.20.0.2:0", "10.20.0.2:65536", "[fe80::1%eth0]:8096"} {
		cfg := valid
		cfg.ServiceListen = address
		if err := validateServiceConfig(cfg); err == nil {
			t.Errorf("accepted listener %q", address)
		}
	}
	for _, ip := range []string{"192.168.1.50", "10.20.0.0/24", "0.0.0.0", "8.8.8.8", "127.0.0.1", "10.20.0.2", "fe80::1%eth0", "seerr.internal"} {
		cfg := valid
		cfg.ServiceClients = []ServiceClient{{Name: "seerr", IP: ip}}
		if err := validateServiceConfig(cfg); err == nil {
			t.Errorf("accepted peer %q", ip)
		}
	}
	for _, network := range []string{"", "10.20.0.4/24", "192.168.1.0/24", "10.0.0.0/7", "0.0.0.0/0"} {
		cfg := valid
		cfg.ServiceNetwork = network
		if err := validateServiceConfig(cfg); err == nil {
			t.Errorf("accepted service network %q", network)
		}
	}
	cases := []Config{
		{ServiceClients: valid.ServiceClients}, {ServiceListen: valid.ServiceListen},
		{ServiceNetwork: valid.ServiceNetwork, ServiceListen: valid.ServiceListen, ServiceClients: []ServiceClient{{Name: "seerr", IP: "10.20.0.4"}, {Name: "other", IP: "::ffff:10.20.0.4"}}},
		{ServiceNetwork: valid.ServiceNetwork, ServiceListen: valid.ServiceListen, ServiceClients: []ServiceClient{{Name: "seerr", IP: "10.20.0.4"}, {Name: "seerr", IP: "10.20.0.5"}}},
		{ServiceNetwork: valid.ServiceNetwork, ServiceListen: valid.ServiceListen, ServiceClients: []ServiceClient{{Name: "bad\nname", IP: "10.20.0.4"}}},
	}
	for i, cfg := range cases {
		if err := validateServiceConfig(cfg); err == nil {
			t.Errorf("accepted invalid config %d", i)
		}
	}
	if err := validateServiceConfig(Config{}); err != nil {
		t.Fatal(err)
	}
	clients, err := ParseServiceClients(" seerr=10.20.0.4, sonarr=10.20.0.5 ")
	if err != nil || len(clients) != 2 || clients[1].Name != "sonarr" {
		t.Fatalf("parse: %+v %v", clients, err)
	}
	if _, err := ParseServiceClients("10.20.0.4"); err == nil {
		t.Fatal("accepted unnamed peer")
	}
}

func TestServicePeerAuthorizationAndPublicIsolation(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	handler := h.g.ServiceHandler()
	for _, remote := range []string{"10.20.0.5:1234", "203.0.113.5:1234", "garbage", "10.20.0.4"} {
		req := serviceRequest("GET", "http://10.20.0.2:8096/Users", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", "10.20.0.4")
		req.Header.Set("Forwarded", "for=10.20.0.4")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", remote, rec.Code)
		}
	}
	req := serviceRequest("GET", "https://gate.example/Users", nil)
	req.RemoteAddr = "10.20.0.4:1234"
	rec := httptest.NewRecorder()
	h.g.Handler().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("service IP bypassed public authentication")
	}
	h.mu.Lock()
	count := len(h.upstream)
	h.mu.Unlock()
	if count != 0 {
		t.Fatal("unauthorized requests reached Jellyfin")
	}
	// Even a captured handler with configured clients refuses when disabled.
	h.g.cfg.ServiceListen = ""
	req = serviceRequest("GET", "http://10.20.0.2:8096/Users", nil)
	req.RemoteAddr = "10.20.0.4:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatal("disabled listener handler allowed access")
	}
}

func TestServiceSignsAndPreservesJellyfinAuthentication(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	body := `{"Username":"family","Pw":"private-password"}`
	req := serviceRequest("POST", "http://10.20.0.2:8096/Users/AuthenticateByName?api_key=secret-query", bytes.NewBufferString(body))
	req.RemoteAddr = "10.20.0.4:1234"
	req.Header.Set("Authorization", "MediaBrowser Token=secret-token")
	req.Header.Set("X-Emby-Token", "secret-emby")
	req.Header.Set("Cookie", "lf_session=gate-secret; jellyfin=app-secret")
	for _, header := range []string{deviceHeader, sessionHeader, authKindHeader, gateSignatureHeader, gateNonceHeader, gateTimestampHeader, "X-Lanternfish-Future"} {
		req.Header.Set(header, "forged")
	}
	req.Header.Set("Forwarded", "for=8.8.8.8")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	req.Header.Set("X-Real-IP", "8.8.8.8")
	req.Header.Set("Connection", deviceHeader+", "+gateSignatureHeader)
	rec := httptest.NewRecorder()
	h.g.ServiceHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("service: %d %s", rec.Code, rec.Body)
	}
	up := h.lastUpstream()
	if up.Header.Get(deviceHeader) != "service:seerr" || up.Header.Get(authKindHeader) != "service" {
		t.Fatal("service identity missing")
	}
	var pub []byte
	h.g.store.View(func(d *storeData) { pub = d.UpstreamPublicKey })
	if !verifyUpstream(t, pub, up) {
		t.Fatal("service signature invalid")
	}
	if up.Header.Get("Authorization") != "MediaBrowser Token=secret-token" || up.Header.Get("X-Emby-Token") != "secret-emby" {
		t.Fatal("Jellyfin credentials lost")
	}
	if up.Header.Get("Cookie") != "jellyfin=app-secret" || up.Header.Get(sessionHeader) != "" || up.Header.Get("X-Lanternfish-Future") != "" {
		t.Fatal("Gate credentials leaked")
	}
	if up.Header.Get("Forwarded") != "" || up.Header.Get("X-Real-IP") != "" || up.Header.Get("X-Forwarded-For") != "10.20.0.4" {
		t.Fatal("forwarded spoof survived")
	}
	log, err := os.ReadFile(h.cfg.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "service_request") || !strings.Contains(string(log), "seerr") {
		t.Fatal("service audit missing")
	}
	for _, secret := range []string{"secret-query", "secret-token", "private-password", "app-secret"} {
		if strings.Contains(string(log), secret) {
			t.Errorf("audit leaked %s", secret)
		}
	}
}

func TestServiceRejectsGateEndpointsAndUnexpectedHost(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	for _, target := range []string{"http://10.20.0.2:8096/_lanternfish/admin/v2/settings", "http://10.20.0.2:8096/%5flanternfish/admin/v2/settings", "http://evil.example/Users"} {
		req := serviceRequest("GET", target, nil)
		req.RemoteAddr = "10.20.0.4:1234"
		rec := httptest.NewRecorder()
		h.g.ServiceHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", target, rec.Code)
		}
	}
	h.mu.Lock()
	count := len(h.upstream)
	h.mu.Unlock()
	if count != 0 {
		t.Fatal("invalid request reached upstream")
	}
}

func TestServicePreservesJellyfinDenialAndBody(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	body := `{"Username":"family","Pw":"wrong"}`
	h.respond = func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil || string(got) != body {
			t.Errorf("body changed: %q %v", got, err)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	req := serviceRequest("POST", "http://10.20.0.2:8096/Users/AuthenticateByName", strings.NewReader(body))
	req.RemoteAddr = "10.20.0.4:1234"
	rec := httptest.NewRecorder()
	h.g.ServiceHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Jellyfin denial overridden: %d", rec.Code)
	}
	log, err := os.ReadFile(h.cfg.AuditPath)
	if err != nil || !strings.Contains(string(log), `"status":401`) {
		t.Fatalf("denial not audited: %s %v", log, err)
	}
}

func TestServiceAuditRecordsFinalStatus(t *testing.T) {
	recorder := &serviceResponse{ResponseWriter: httptest.NewRecorder()}
	recorder.WriteHeader(http.StatusEarlyHints)
	recorder.WriteHeader(http.StatusUnauthorized)
	if recorder.status != http.StatusUnauthorized {
		t.Fatalf("audit status was %d", recorder.status)
	}
}

func TestServiceForwardingRejectsSpoofWithoutConnectionHeader(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceNetwork = serviceConfig().ServiceNetwork
	h.g.cfg.ServiceListen = serviceConfig().ServiceListen
	h.g.cfg.ServiceClients = serviceConfig().ServiceClients
	req := serviceRequest("GET", "http://10.20.0.2:8096/Users", nil)
	req.RemoteAddr = "10.20.0.4:1234"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Forwarded", "for=8.8.8.8")
	req.Header.Set("X-Real-IP", "8.8.8.8")
	rec := httptest.NewRecorder()
	h.g.ServiceHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("service: %d", rec.Code)
	}
	up := h.lastUpstream()
	if up.Header.Get("X-Forwarded-For") != "10.20.0.4" || up.Header.Get("X-Forwarded-Host") != "10.20.0.2:8096" || up.Header.Get("X-Forwarded-Proto") != "http" || up.Header.Get("Forwarded") != "" || up.Header.Get("X-Real-IP") != "" {
		t.Fatalf("spoofed forwarding headers survived: %v", up.Header)
	}
}
