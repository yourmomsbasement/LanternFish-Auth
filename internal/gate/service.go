package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ServiceClient is a backend allowed to reach Jellyfin through the separate
// internal listener. IP is one private address, never a forwarded header or
// network. The surrounding network MUST enforce source-address anti-spoofing.
// This is a trusted service identity, not an enrolled person or device.
type ServiceClient struct {
	Name              string               `json:"name"`
	IP                string               `json:"ip"`
	Disabled          bool                 `json:"disabled,omitempty"`
	CertificateURI    string               `json:"certificate_uri,omitempty"`
	RevokedSerials    []string             `json:"revoked_serials,omitempty"`
	Permissions       *[]ServicePermission `json:"permissions,omitempty"`
	MaxConcurrent     int                  `json:"max_concurrent,omitempty"`
	RequestsPerMinute int                  `json:"requests_per_minute,omitempty"`
	MaxBodyBytes      int64                `json:"max_body_bytes,omitempty"`
}

var serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)

// ParseServiceClients parses comma-separated name=IP entries from gate.env.
func ParseServiceClients(value string) ([]ServiceClient, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	var clients []ServiceClient
	for _, entry := range strings.Split(value, ",") {
		name, ip, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok {
			return nil, fmt.Errorf("service clients must be comma-separated name=IP entries")
		}
		clients = append(clients, ServiceClient{Name: strings.TrimSpace(name), IP: strings.TrimSpace(ip)})
	}
	return clients, nil
}

func validateServiceConfig(cfg Config) error {
	if err := validateServiceOptions(cfg); err != nil {
		return err
	}
	network, networkErr := netip.ParsePrefix(cfg.ServiceNetwork)
	if cfg.ServiceListen == "" {
		if len(cfg.ServiceClients) != 0 || cfg.ServiceNetwork != "" {
			return fmt.Errorf("service clients require an internal service listener")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(cfg.ServiceListen)
	addr, ipErr := netip.ParseAddr(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || addr.Zone() != "" || !addr.Unmap().IsPrivate() ||
		portErr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("service listener must be a literal private IP and port (e.g. 10.20.0.2:8096), never a wildcard or public address")
	}
	if networkErr != nil || network.Addr().Zone() != "" || network != network.Masked() || !privateServiceNetwork(network) || !network.Contains(addr.Unmap()) {
		return fmt.Errorf("service network must be an explicit canonical private subnet containing the listener")
	}
	if len(cfg.ServiceClients) == 0 || len(cfg.ServiceClients) > 32 {
		return fmt.Errorf("service listener needs 1-32 named clients")
	}
	names, ips := map[string]bool{}, map[netip.Addr]bool{}
	for _, client := range cfg.ServiceClients {
		ip, err := netip.ParseAddr(client.IP)
		if !serviceNameRE.MatchString(client.Name) || names[client.Name] {
			return fmt.Errorf("service client names must be unique lowercase names of up to 40 characters")
		}
		if err != nil || ip.Zone() != "" || !ip.Unmap().IsPrivate() || !network.Contains(ip.Unmap()) || ip.Unmap() == addr.Unmap() || ips[ip.Unmap()] {
			return fmt.Errorf("service client %q needs a unique IP on the service subnet different from the listener", client.Name)
		}
		names[client.Name], ips[ip.Unmap()] = true, true
	}
	return nil
}

func privateServiceNetwork(network netip.Prefix) bool {
	for _, value := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		private := netip.MustParsePrefix(value)
		if network.Bits() >= private.Bits() && private.Contains(network.Addr()) {
			return true
		}
	}
	return false
}

func stripGateHeaders(header http.Header) {
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "x-lanternfish-") {
			header.Del(name)
		}
	}
}

// ServiceHandler is ONLY for the separately bound internal HTTP server. It
// never dispatches to Handler or any Gate endpoint. Disabled configuration
// always refuses access. Jellyfin still checks its own users and API keys.
func (g *Gate) ServiceHandler() http.Handler {
	clients := map[netip.Addr]*serviceState{}
	unknown := newServiceState(ServiceClient{Name: "unknown"}, g.cfg)
	for _, c := range g.cfg.ServiceClients {
		ip, _ := netip.ParseAddr(c.IP)
		if !c.Disabled {
			clients[ip.Unmap()] = newServiceState(c, g.cfg)
		}
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			name, _ := pr.In.Context().Value(serviceClientKey{}).(string)
			pr.SetURL(g.routing.Load().jellyfin)
			// Remove all caller-provided Gate identity, including future headers,
			// after hop-by-hop removal, then attach a fresh signed service identity.
			stripGateHeaders(pr.Out.Header)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Real-IP")
			pr.SetXForwarded()
			pr.Out.Header.Set(deviceHeader, "service:"+name)
			pr.Out.Header.Set(authKindHeader, "service")
			g.signUpstream(pr.Out)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeError(w, http.StatusBadGateway, "upstream unavailable")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := netip.ParseAddrPort(r.RemoteAddr)
		state := clients[peer.Addr().Unmap()]
		name := ""
		if state != nil {
			name = state.client.Name
		} else {
			state = unknown
		}
		status := http.StatusForbidden
		// Do not log paths, queries, bodies or credentials: Jellyfin URLs can
		// carry authentication tokens. Record the service and result instead.
		defer func() {
			g.audit.write(g.cfg.Now(), "service_request", map[string]any{"service": name, "ip": peer.Addr().String(), "status": status})
			g.serviceAlerts(state, r, status, g.cfg.Now())
		}()
		if g.cfg.ServiceListen == "" || err != nil || name == "" {
			writeError(w, status, "service access denied")
			return
		}
		if !serviceHostMatches(g.cfg, r.Host) || r.URL.IsAbs() || r.Method == http.MethodConnect || r.Method == http.MethodTrace ||
			r.Header.Get("Upgrade") != "" || strings.HasPrefix(strings.ToLower(r.URL.Path), "/_lanternfish") {
			status = http.StatusBadRequest
			writeError(w, status, "invalid service request")
			return
		}
		if serviceAuthMode(g.cfg) == "mtls" && !serviceCertificateAllowed(state.client, r, g.cfg.Now()) {
			writeError(w, status, "service access denied")
			return
		}
		if !servicePermitted(state.client, r) {
			writeError(w, status, "service permission denied")
			return
		}
		leave, allowed := state.enter(g.cfg.Now())
		if !allowed {
			status = http.StatusTooManyRequests
			w.Header().Set("Retry-After", "60")
			writeError(w, status, "service resource limit reached")
			return
		}
		defer leave()
		timeout := g.cfg.ServiceTimeout
		if timeout == 0 {
			timeout = 2 * time.Minute
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		if timeout < 30*time.Second {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(timeout))
		}
		if state.client.MaxBodyBytes > 0 {
			if r.ContentLength > state.client.MaxBodyBytes {
				status = http.StatusRequestEntityTooLarge
				writeError(w, status, "service request too large")
				return
			}
			if r.Body != nil {
				data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, state.client.MaxBodyBytes))
				r.Body.Close()
				if err != nil {
					var limit *http.MaxBytesError
					status = http.StatusBadRequest
					if errors.As(err, &limit) {
						status = http.StatusRequestEntityTooLarge
					}
					writeError(w, status, "invalid or oversized service body")
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(data))
				r.ContentLength = int64(len(data))
			}
		}
		// Gate session credentials are never forwarded. Jellyfin Authorization,
		// X-Emby-Token and ordinary application cookies remain intact.
		r = r.Clone(r.Context())
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != sessionCookie {
				r.AddCookie(c)
			}
		}
		ctx = context.WithValue(ctx, serviceClientKey{}, name)
		recorder := &serviceResponse{ResponseWriter: w}
		proxy.ServeHTTP(recorder, r.WithContext(ctx))
		status = recorder.status
		if status == 0 {
			status = http.StatusOK
		}
	})
}

type serviceClientKey struct{}
type serviceResponse struct {
	http.ResponseWriter
	status int
}

func (w *serviceResponse) WriteHeader(status int) {
	if w.status == 0 && status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *serviceResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *serviceResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
