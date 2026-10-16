// Package gate implements Lanternfish Gate, an authenticating reverse proxy
// for Jellyfin. See docs/PROTOCOL.md.
package gate

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
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

	// BodyReadTimeout bounds how long reading a JSON request body to the
	// Gate's own endpoints may take. Default 10s.
	BodyReadTimeout time.Duration

	// AdminAllow lists the networks the admin API answers from; elsewhere it
	// does not exist (404). Default: DefaultAdminAllow.
	AdminAllow []netip.Prefix

	// DisableRenewalInjection stops the Gate adding the session-renewal
	// script to Jellyfin's web client (see renewal.go).
	DisableRenewalInjection bool

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
	if c.BodyReadTimeout == 0 {
		c.BodyReadTimeout = 10 * time.Second
	}
	if c.AdminAllow == nil {
		c.AdminAllow = DefaultAdminAllow
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
	cfg           Config
	store         *Store
	sealer        *Sealer
	ca            *deviceCA
	upstream      *ecdsa.PrivateKey
	audit         *auditLog
	alerts        *alerter
	limiter       *failureLimiter
	sessions      *sessionTable
	challenges    *challengeTable
	streams       *streamTable
	grants        *grantTable
	adminSessions *adminSessionTable
	policies      atomic.Pointer[policySet]
	policyMu      sync.Mutex // serialises policy publishes with their reload
	proxy         *httputil.ReverseProxy

	// lastAuth holds each device's latest sign-in time; it is saved to the
	// data file only now and then (see noteAuth).
	lastAuth sync.Map // device ID -> time.Time
	// unsavedRevocations holds devices revoked in memory whose revocation
	// could not be saved yet. They are treated as revoked.
	unsavedRevocations sync.Map // device ID -> struct{}

	handler http.Handler
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
	upstreamKey, err := loadUpstreamKey(store, sealer)
	if err != nil {
		return nil, err
	}
	audit, err := openAuditLog(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	g := &Gate{
		cfg:           cfg,
		store:         store,
		sealer:        sealer,
		ca:            ca,
		upstream:      upstreamKey,
		audit:         audit,
		alerts:        &alerter{url: cfg.AlertWebhook, client: &http.Client{Timeout: 10 * time.Second}},
		limiter:       newFailureLimiter(cfg.FailureLimit, cfg.FailureWindow, 10000),
		sessions:      newSessionTable(maxSessionsPerDevice),
		challenges:    newChallengeTable(10000, 32),
		streams:       newStreamTable(),
		grants:        newGrantTable(),
		adminSessions: newAdminSessionTable(),
	}
	if err := store.Migrate(cfg.Now(), cfg.SessionTTL); err != nil {
		return nil, fmt.Errorf("upgrade data file: %w", err)
	}
	if err := g.reloadPolicies(); err != nil {
		return nil, err
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			pr.SetXForwarded()
			// SECURITY: set the identity headers on the outbound request here,
			// after ReverseProxy has removed hop-by-hop headers. Set on the
			// inbound request, a client could have them stripped by naming them
			// in its own Connection header.
			a, _ := pr.In.Context().Value(proxyAuthKey{}).(proxyAuth)
			pr.Out.Header.Set(deviceHeader, a.deviceID)
			pr.Out.Header.Set(authKindHeader, a.how)
			g.prepareRenewal(pr.Out)
			g.signUpstream(pr.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			// The Gate sets HSTS on every response itself; drop Jellyfin's
			// copy so the header isn't sent twice.
			resp.Header.Del("Strict-Transport-Security")
			return g.injectRenewal(resp)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				return // the client hung up, e.g. navigated away; nothing to report
			}
			// %q: the path is client-controlled and may hold newlines.
			log.Printf("proxy: %s %q: %v", r.Method, r.URL.Path, err)
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
	g.adminV2Routes(mux)
	g.adminUIRoutes(mux)

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

// How a request authenticated, as told to Jellyfin in X-Lanternfish-Auth.
const (
	authCertificate = "certificate"
	authCookie      = "cookie" // a browser holding a WebCrypto key
	authHeader      = "header" // an app sending X-Lanternfish-Session
)

// activeDevice returns a copy of an active device, or nil.
func (g *Gate) activeDevice(id string) *Device {
	if _, revoked := g.unsavedRevocations.Load(id); revoked {
		return nil
	}
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
	auth := g.authorizeRequest(w, r)
	if auth == nil {
		return
	}
	dev, how := auth.dev, auth.how

	// Gate credentials stay at the Gate; Jellyfin only learns who it is.
	r.Header.Del(sessionHeader)
	r.Header.Del(deviceHeader)
	r.Header.Del(authKindHeader)
	if cookies := r.Cookies(); len(cookies) > 0 {
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != sessionCookie {
				r.AddCookie(c)
			}
		}
	}
	// SECURITY: authorization is checked once per request, so a WebSocket or
	// a long stream would outlive a revocation or a policy change. Tie the
	// request to the device (and its network and deadline) so those close it.
	ctx, done := g.streams.track(r.Context(), dev.ID, clientIP(r), auth.network, auth.streamDeadline(), g.cfg.Now())
	defer done()
	if g.activeDevice(dev.ID) == nil { // revoked between authorizing and tracking
		writeError(w, http.StatusUnauthorized, "lanternfish_auth_required")
		return
	}
	ctx = context.WithValue(ctx, proxyAuthKey{}, proxyAuth{deviceID: dev.ID, how: how})
	g.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// proxyAuth carries who a request authenticated as from serveProxy to Rewrite.
type proxyAuth struct{ deviceID, how string }

type proxyAuthKey struct{}

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

// lastAuthSaveInterval is how stale a device's saved last sign-in time may
// get before a sign-in writes it to the data file.
const lastAuthSaveInterval = 15 * time.Minute

// noteAuth records a successful sign-in.
//
// SECURITY/PERFORMANCE: every save rewrites and syncs the whole data file, so
// saving on every 15-minute session renewal let renewals queue up behind
// disk I/O. The exact time is kept in memory for the admin API and saved
// only when the stored one is more than lastAuthSaveInterval old.
func (g *Gate) noteAuth(dev *Device, now time.Time) {
	g.lastAuth.Store(dev.ID, now)
	if dev.LastAuthAt != nil && now.Sub(*dev.LastAuthAt) < lastAuthSaveInterval {
		return
	}
	err := g.store.Update(func(d *storeData) error {
		if stored, ok := d.Devices[dev.ID]; ok {
			stored.LastAuthAt = &now
		}
		d.pruneTickets(now)
		return nil
	})
	if err != nil {
		log.Printf("save last sign-in of %s: %v", dev.ID, err)
	}
}
