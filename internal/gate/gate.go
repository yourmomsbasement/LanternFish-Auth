// Package gate implements Lanternfish Gate, an authenticating reverse proxy
// for Jellyfin. See docs/PROTOCOL.md.
package gate

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

// Config configures a Gate. Zero durations and limits take the defaults.
type Config struct {
	Upstream     *url.URL
	DataPath     string
	AuditPath    string
	MasterKey    []byte
	AlertWebhook string

	SessionTTL    time.Duration // default 15m
	ChallengeTTL  time.Duration // default 60s
	TicketTTL     time.Duration // default 6h
	MaxTicketTTL  time.Duration // default 24h
	FailureLimit  int           // default 10
	FailureWindow time.Duration // default 10m

	// Now overrides the clock in tests.
	Now func() time.Time
}

func (c *Config) setDefaults() {
	if c.SessionTTL == 0 {
		c.SessionTTL = 15 * time.Minute
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = 60 * time.Second
	}
	if c.TicketTTL == 0 {
		c.TicketTTL = 6 * time.Hour
	}
	if c.MaxTicketTTL == 0 {
		c.MaxTicketTTL = 24 * time.Hour
	}
	if c.FailureLimit == 0 {
		c.FailureLimit = 10
	}
	if c.FailureWindow == 0 {
		c.FailureWindow = 10 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Platforms the Builder can create tickets for, and the credential each uses.
var platformKinds = map[string]string{
	"android": KindECDSA,
	"firetv":  KindECDSA,
	"webos":   KindECDSA,
	"tizen":   KindECDSA,
	"web":     KindECDSA,
	"roku":    KindHMAC,
}

const (
	pathPrefix    = "/_lanternfish/"
	sessionCookie = "lf_session"
	sessionHeader = "X-Lanternfish-Session"
	deviceHeader  = "X-Lanternfish-Device"
	hstsValue     = "max-age=31536000"
)

type Gate struct {
	cfg        Config
	store      *Store
	sealer     *Sealer
	ca         *deviceCA
	audit      *auditLog
	alerts     *alerter
	limiter    *failureLimiter
	sessions   *sessionTable
	challenges *challengeTable
	proxy      *httputil.ReverseProxy
	handler    http.Handler
}

func New(cfg Config) (*Gate, error) {
	cfg.setDefaults()
	if cfg.Upstream == nil {
		return nil, errors.New("upstream URL is required")
	}
	sealer, err := NewSealer(cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg.DataPath, sealer, cfg.Now())
	if err != nil {
		return nil, err
	}
	var ca *deviceCA
	var caErr error
	store.View(func(d *storeData) {
		keyDER, err := sealer.Open(caKeyPurpose, d.CAKeySealed)
		if err != nil {
			caErr = fmt.Errorf("unseal device CA key: %w", err)
			return
		}
		ca, caErr = loadDeviceCA([]byte(d.CACertPEM), keyDER)
	})
	if caErr != nil {
		return nil, caErr
	}
	audit, err := openAuditLog(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	g := &Gate{
		cfg:        cfg,
		store:      store,
		sealer:     sealer,
		ca:         ca,
		audit:      audit,
		alerts:     &alerter{url: cfg.AlertWebhook, client: &http.Client{Timeout: 10 * time.Second}},
		limiter:    newFailureLimiter(cfg.FailureLimit, cfg.FailureWindow),
		sessions:   newSessionTable(),
		challenges: newChallengeTable(10000),
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			pr.SetXForwarded()
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("Strict-Transport-Security", hstsValue)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy: %s %s: %v", r.Method, r.URL.Path, err)
			writeError(w, http.StatusBadGateway, "upstream unavailable")
		},
	}
	g.handler = g.routes()
	return g, nil
}

func (g *Gate) Close() error { return g.audit.Close() }

func (g *Gate) Handler() http.Handler { return g.handler }

// TLSConfig returns a TLS 1.3 config that asks for (but does not require)
// client certificates from the device CA. getCert supplies the server cert.
func (g *Gate) TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      g.ca.pool(),
		GetCertificate: getCert,
	}
}

// DeviceCACertPEM is the CA that issues device client certificates.
func (g *Gate) DeviceCACertPEM() []byte { return g.ca.certPEM }

func (g *Gate) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /_lanternfish/v1/enroll", g.handleEnroll)
	mux.HandleFunc("POST /_lanternfish/v1/challenge", g.handleChallenge)
	mux.HandleFunc("POST /_lanternfish/v1/session", g.handleSession)
	mux.HandleFunc("POST /_lanternfish/v1/logout", g.handleLogout)

	mux.HandleFunc("POST /_lanternfish/admin/v1/tickets", g.admin(g.handleCreateTicket))
	mux.HandleFunc("GET /_lanternfish/admin/v1/tickets", g.admin(g.handleListTickets))
	mux.HandleFunc("DELETE /_lanternfish/admin/v1/tickets/{id}", g.admin(g.handleDeleteTicket))
	mux.HandleFunc("GET /_lanternfish/admin/v1/devices", g.admin(g.handleListDevices))
	mux.HandleFunc("POST /_lanternfish/admin/v1/devices/{id}/revoke", g.admin(g.handleRevokeDevice))

	mux.HandleFunc("GET /_lanternfish/{$}", g.serveStatic("index.html"))
	mux.HandleFunc("GET /_lanternfish/gate-client.js", g.serveStatic("gate-client.js"))
	mux.HandleFunc("GET /_lanternfish/login.js", g.serveStatic("login.js"))
	mux.HandleFunc("GET /_lanternfish/style.css", g.serveStatic("style.css"))

	// Anything else under the prefix is ours, never Jellyfin's.
	mux.HandleFunc(pathPrefix, func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	mux.HandleFunc("/", g.serveProxy)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		mux.ServeHTTP(w, r)
	})
}

// authenticate returns the active device behind a request, if any.
func (g *Gate) authenticate(r *http.Request) (*Device, string) {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
		leaf := r.TLS.VerifiedChains[0][0]
		if dev := g.activeDevice(leaf.Subject.CommonName); dev != nil && dev.Kind == KindECDSA &&
			string(dev.PublicKey) == string(leaf.RawSubjectPublicKeyInfo) {
			return dev, "certificate"
		}
	}
	token := r.Header.Get(sessionHeader)
	if token == "" {
		if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
	}
	if deviceID, ok := g.sessions.lookup(token, g.cfg.Now()); ok {
		if dev := g.activeDevice(deviceID); dev != nil {
			return dev, "session"
		}
	}
	return nil, ""
}

// activeDevice returns a copy of an active device, or nil.
func (g *Gate) activeDevice(id string) *Device {
	var out *Device
	g.store.View(func(d *storeData) {
		if dev, ok := d.Devices[id]; ok && dev.Active() {
			c := *dev
			out = &c
		}
	})
	return out
}

func (g *Gate) serveProxy(w http.ResponseWriter, r *http.Request) {
	dev, _ := g.authenticate(r)
	if dev == nil {
		if r.Method == http.MethodGet && acceptsHTML(r) {
			http.Redirect(w, r, pathPrefix+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		writeError(w, http.StatusUnauthorized, "lanternfish_auth_required")
		return
	}

	// Gate credentials stay at the Gate; Jellyfin only learns who it is.
	r.Header.Del(sessionHeader)
	r.Header.Del(deviceHeader)
	if cookies := r.Cookies(); len(cookies) > 0 {
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != sessionCookie {
				r.AddCookie(c)
			}
		}
	}
	r.Header.Set(deviceHeader, dev.ID)
	g.proxy.ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomToken() string { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func newID(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(randomBytes(12))
}

// WarnIfExposed logs a warning when the upstream does not look private,
// because a Gate that can be routed around protects nothing.
func WarnIfExposed(upstream *url.URL) {
	host := upstream.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return
	}
	for _, ip := range ips {
		if !(ip.IsLoopback() || ip.IsPrivate()) {
			fmt.Fprintf(os.Stderr, "WARNING: upstream %s resolves to %s, which is not loopback or private. "+
				"Make sure Jellyfin cannot be reached except through the Gate.\n", host, ip)
			return
		}
	}
}
