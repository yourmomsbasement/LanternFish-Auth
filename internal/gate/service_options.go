package gate

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// ServicePermission grants specific HTTP methods to an exact API path or a
// segment-delimited prefix. A present, empty permissions list denies all.
type ServicePermission struct {
	Methods    []string `json:"methods"`
	Path       string   `json:"path,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
}

// LoadServiceClients reads a bounded strict JSON client policy file. It holds
// identities and policy, not private keys or Jellyfin credentials.
func LoadServiceClients(file string) ([]ServiceClient, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return nil, fmt.Errorf("service client policy must be a regular file of at most 128 KiB")
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return nil, fmt.Errorf("invalid service client policy file")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 128<<10))
	decoder.DisallowUnknownFields()
	var clients []ServiceClient
	if err := decoder.Decode(&clients); err != nil {
		return nil, fmt.Errorf("invalid service client policy file: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("service client policy file must contain one JSON array")
	}
	return clients, nil
}

func serviceAuthMode(cfg Config) string {
	if cfg.ServiceAuth == "" {
		return "ip"
	}
	return cfg.ServiceAuth
}
func serviceCertificateURI(client ServiceClient) string {
	if client.CertificateURI != "" {
		return client.CertificateURI
	}
	return "spiffe://lanternfish/service/" + client.Name
}

func validateServiceOptions(cfg Config) error {
	mode := serviceAuthMode(cfg)
	if mode != "ip" && mode != "mtls" {
		return fmt.Errorf("service authentication must be ip or mtls")
	}
	tlsSet := cfg.ServiceTLSCertFile != "" || cfg.ServiceTLSKeyFile != "" || cfg.ServiceClientCAFile != ""
	if mode == "mtls" {
		if cfg.ServiceListen == "" || cfg.ServiceTLSCertFile == "" || cfg.ServiceTLSKeyFile == "" || cfg.ServiceClientCAFile == "" {
			return fmt.Errorf("mTLS service authentication requires a listener, server certificate/key and client CA")
		}
	} else if tlsSet {
		return fmt.Errorf("service TLS files require service authentication mtls")
	}
	if cfg.ServiceTimeout < 0 || (cfg.ServiceTimeout > 0 && (cfg.ServiceTimeout < time.Second || cfg.ServiceTimeout > 10*time.Minute)) {
		return fmt.Errorf("service timeout must be 1s-10m, or 0 for the default")
	}
	if cfg.ServiceMaxConcurrent < 0 || cfg.ServiceMaxConcurrent > 1024 || cfg.ServiceRequestsPerMinute < 0 || cfg.ServiceRequestsPerMinute > 100000 || cfg.ServiceMaxBodyBytes < 0 || cfg.ServiceMaxBodyBytes > 1<<30 {
		return fmt.Errorf("invalid service resource limits")
	}
	if cfg.ServiceAlertFailures < 0 || cfg.ServiceAlertFailures > 100000 || cfg.ServiceAlertWindow < 0 || (cfg.ServiceAlertWindow > 0 && cfg.ServiceAlertWindow < time.Second) || cfg.ServiceAlertWindow > 24*time.Hour || cfg.ServiceCertWarnBefore < 0 || cfg.ServiceCertWarnBefore > 365*24*time.Hour {
		return fmt.Errorf("invalid service alert parameters")
	}
	uris := map[string]bool{}
	for _, client := range cfg.ServiceClients {
		if client.MaxConcurrent < 0 || client.MaxConcurrent > 1024 || client.RequestsPerMinute < 0 || client.RequestsPerMinute > 100000 || client.MaxBodyBytes < 0 || client.MaxBodyBytes > 1<<30 {
			return fmt.Errorf("invalid resource limits for service %q", client.Name)
		}
		if mode == "mtls" {
			uri := serviceCertificateURI(client)
			parsed, err := url.Parse(uri)
			if err != nil || parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(uri) > 256 || !safeServicePath(parsed.Path) || strings.Contains(uri, "%") || uris[uri] {
				return fmt.Errorf("service certificate URIs must be unique SPIFFE URIs without query or fragment")
			}
			uris[uri] = true
		} else if client.CertificateURI != "" || len(client.RevokedSerials) > 0 {
			return fmt.Errorf("certificate identity/revocation for %q requires mTLS", client.Name)
		}
		if len(client.RevokedSerials) > 128 {
			return fmt.Errorf("at most 128 revoked serials per service")
		}
		for _, serial := range client.RevokedSerials {
			if len(serial) == 0 || len(serial) > 128 || strings.Trim(serial, "0123456789abcdefABCDEF") != "" {
				return fmt.Errorf("revoked certificate serials must be hexadecimal")
			}
		}
		if client.Permissions != nil {
			if len(*client.Permissions) > 64 {
				return fmt.Errorf("at most 64 permission rules per service")
			}
			for _, rule := range *client.Permissions {
				p := rule.Path
				if p == "" {
					p = rule.PathPrefix
				}
				if (rule.Path == "") == (rule.PathPrefix == "") || !safeServicePath(p) || strings.Contains(p, "%") || strings.HasPrefix(strings.ToLower(p), "/_lanternfish") {
					return fmt.Errorf("service permissions need one canonical exact path or path prefix")
				}
				if len(rule.Methods) == 0 || len(rule.Methods) > 7 {
					return fmt.Errorf("service permissions need explicit HTTP methods")
				}
				for _, method := range rule.Methods {
					switch method {
					case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
					default:
						return fmt.Errorf("unsupported service permission method %q", method)
					}
				}
			}
		}
	}
	if cfg.ServiceCertWarnBefore > 0 && mode != "mtls" {
		return fmt.Errorf("service certificate expiry alerts require mTLS")
	}
	if (cfg.ServiceAlertFailures > 0 || cfg.ServiceCertWarnBefore > 0 || cfg.ServiceAlertConfigDrift) && cfg.AlertWebhook == "" {
		return fmt.Errorf("service alerts require an alert webhook")
	}
	return nil
}

func safeServicePath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\;\x00\r\n?#") || strings.Contains(value, "//") {
		return false
	}
	return strings.TrimSuffix(value, "/") == strings.TrimSuffix(path.Clean(value), "/")
}

func servicePermitted(client ServiceClient, r *http.Request) bool {
	if client.Permissions == nil {
		return true
	}
	escaped := strings.ToLower(r.URL.EscapedPath())
	if !safeServicePath(r.URL.Path) || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") || strings.Contains(escaped, "%25") {
		return false
	}
	for _, rule := range *client.Permissions {
		methodOK := false
		for _, method := range rule.Methods {
			if method == r.Method {
				methodOK = true
				break
			}
		}
		if !methodOK {
			continue
		}
		if rule.Path != "" && r.URL.Path == rule.Path {
			return true
		}
		if rule.PathPrefix != "" {
			prefix := strings.TrimSuffix(rule.PathPrefix, "/")
			if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// ServiceTLSConfig loads client trust and hot-reloads the server certificate.
// Client certificate renewal is handled by the deployment's private CA; the
// stable URI binds each renewed certificate to its named service identity.
func (g *Gate) ServiceTLSConfig() (*tls.Config, error) {
	if serviceAuthMode(g.cfg) != "mtls" {
		return nil, nil
	}
	caPEM, err := os.ReadFile(g.cfg.ServiceClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("load service client CA: %w", err)
	}
	pool := x509.NewCertPool()
	count := 0
	for len(strings.TrimSpace(string(caPEM))) > 0 {
		block, rest := pem.Decode(caPEM)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("service client CA must contain only PEM CA certificates")
		}
		caPEM = rest
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("service client trust file contains an invalid CA certificate")
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("service client CA contains no certificates")
	}
	certs, err := NewCertReloader(g.cfg.ServiceTLSCertFile, g.cfg.ServiceTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load service TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, GetCertificate: certs.GetCertificate, SessionTicketsDisabled: true, Time: g.cfg.Now}, nil
}

func serviceCertificateAllowed(client ServiceClient, r *http.Request, now time.Time) bool {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return false
	}
	leaf := r.TLS.PeerCertificates[0]
	if leaf.SerialNumber == nil || len(leaf.URIs) != 1 {
		return false
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	for _, serial := range client.RevokedSerials {
		if strings.EqualFold(strings.TrimLeft(serial, "0"), strings.TrimLeft(leaf.SerialNumber.Text(16), "0")) {
			return false
		}
	}
	expected := serviceCertificateURI(client)
	for _, uri := range leaf.URIs {
		if uri.String() == expected {
			return true
		}
	}
	return false
}

type serviceState struct {
	client       ServiceClient
	slots        chan struct{}
	mu           sync.Mutex
	rateStart    time.Time
	requests     int
	failureStart time.Time
	failures     int
	alerted      bool
	expiryAlert  time.Time
}

func newServiceState(client ServiceClient, cfg Config) *serviceState {
	if client.MaxConcurrent == 0 {
		client.MaxConcurrent = cfg.ServiceMaxConcurrent
	}
	if client.RequestsPerMinute == 0 {
		client.RequestsPerMinute = cfg.ServiceRequestsPerMinute
	}
	if client.MaxBodyBytes == 0 {
		client.MaxBodyBytes = cfg.ServiceMaxBodyBytes
	}
	state := &serviceState{client: client}
	if client.MaxConcurrent > 0 {
		state.slots = make(chan struct{}, client.MaxConcurrent)
	}
	return state
}
func (s *serviceState) enter(now time.Time) (func(), bool) {
	s.mu.Lock()
	if s.rateStart.IsZero() || !now.Before(s.rateStart.Add(time.Minute)) {
		s.rateStart = now
		s.requests = 0
	}
	if s.client.RequestsPerMinute > 0 && s.requests >= s.client.RequestsPerMinute {
		s.mu.Unlock()
		return nil, false
	}
	s.requests++
	s.mu.Unlock()
	if s.slots == nil {
		return func() {}, true
	}
	select {
	case s.slots <- struct{}{}:
		return func() { <-s.slots }, true
	default:
		return nil, false
	}
}
func (g *Gate) serviceAlerts(s *serviceState, r *http.Request, status int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	window := g.cfg.ServiceAlertWindow
	if window == 0 {
		window = 5 * time.Minute
	}
	if g.cfg.ServiceAlertFailures > 0 && status >= 400 {
		if s.failureStart.IsZero() || !now.Before(s.failureStart.Add(window)) {
			s.failureStart = now
			s.failures = 0
			s.alerted = false
		}
		s.failures++
		if s.failures >= g.cfg.ServiceAlertFailures && !s.alerted {
			s.alerted = true
			g.alerts.send(fmt.Sprintf("Lanternfish service %s: repeated failures (%d in %s)", s.client.Name, s.failures, window))
		}
	}
	if g.cfg.ServiceCertWarnBefore > 0 && status < 400 && s.client.Name != "unknown" && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		expiry := r.TLS.PeerCertificates[0].NotAfter
		if expiry.After(now) && expiry.Sub(now) <= g.cfg.ServiceCertWarnBefore && (s.expiryAlert.IsZero() || !now.Before(s.expiryAlert.Add(24*time.Hour))) {
			s.expiryAlert = now
			g.alerts.send(fmt.Sprintf("Lanternfish service %s certificate expires %s", s.client.Name, expiry.UTC().Format(time.RFC3339)))
		}
	}
}

// Drift alerts compare the saved plan with Gate configuration; they cannot
// inspect the live hypervisor firewall. Suppress repeated dashboard refreshes.
func (g *Gate) alertServiceConfigDrift(warnings []string) {
	if !g.cfg.ServiceAlertConfigDrift || len(warnings) == 0 {
		return
	}
	now := g.cfg.Now()
	g.serviceAlertMu.Lock()
	if !g.serviceDriftLast.IsZero() && now.Before(g.serviceDriftLast.Add(time.Hour)) {
		g.serviceAlertMu.Unlock()
		return
	}
	g.serviceDriftLast = now
	g.serviceAlertMu.Unlock()
	g.alerts.send(fmt.Sprintf("Lanternfish firewall plan/configuration drift: %d warning(s); review the Firewall tab", len(warnings)))
}

func serviceHostMatches(cfg Config, host string) bool {
	expected, err := netip.ParseAddrPort(cfg.ServiceListen)
	if err != nil {
		return false
	}
	actual, err := netip.ParseAddrPort(host)
	if err == nil {
		return actual.Addr().Unmap() == expected.Addr().Unmap() && actual.Port() == expected.Port()
	}
	// HTTP clients omit the standard port even when the URL explicitly names
	// it. Accept only the same literal address at that mode's standard port.
	defaultPort := uint16(80)
	if serviceAuthMode(cfg) == "mtls" {
		defaultPort = 443
	}
	ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return err == nil && ip.Zone() == "" && ip.Unmap() == expected.Addr().Unmap() && expected.Port() == defaultPort
}
