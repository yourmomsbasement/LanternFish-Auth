// Command lanternfish-gate runs Lanternfish Gate, the authenticating proxy in
// front of Jellyfin, and manages its admin keys offline.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	// The release image has no zoneinfo; schedules need IANA time zones.
	_ "time/tzdata"

	"github.com/yourmomsbasement/lanternfish-auth/internal/gate"
)

// version is set at release build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Usage:
  lanternfish-gate serve                     Run the Gate
  lanternfish-gate gen-master-key [flags]    Print a new master key
      -dpapi FILE   (Windows) write it DPAPI-protected to FILE instead
      -machine      with -dpapi, protect for this machine rather than this user
  lanternfish-gate admin-key create -name NAME
  lanternfish-gate admin-key list
  lanternfish-gate admin-key revoke ID
  lanternfish-gate admin-key link ID SUBJECT  Link a key to an admin owner (dashboard re-verification)
  lanternfish-gate factor list               Owners and their factors
  lanternfish-gate factor reset SUBJECT      Break-glass: remove an owner's authenticator app,
                                             passkeys and recovery codes (then send a setup link)
  lanternfish-gate device-ca                 Print the device CA certificate
  lanternfish-gate upstream-key              Print the key for Jellyfin's Lanternfish plugin
  lanternfish-gate version                   Print the version

Updates (signed releases only; see docs/RELEASES.md):
  lanternfish-gate release-verify MANIFEST SIGNATURE   Check a release signature by hand
  lanternfish-gate update check              Show the newest verified release
  lanternfish-gate update apply [-version X] Install it (root; normally done by the updater service)

admin-key, factor, device-ca and upstream-key read the data file directly; stop the Gate first.

Environment:
  LANTERNFISH_LISTEN             listen address (default :8443)
  LANTERNFISH_UPSTREAM           Jellyfin URL (default http://127.0.0.1:8096)
  LANTERNFISH_TLS_CERT           server certificate (PEM, full chain)
  LANTERNFISH_TLS_KEY            server private key (PEM)
  LANTERNFISH_DATA               data file (default ./data/gate.json)
  LANTERNFISH_AUDIT_LOG          audit log (default ./data/audit.log)
  LANTERNFISH_MASTER_KEY_FILE    file holding the base64 master key (Docker secret)
  LANTERNFISH_MASTER_KEY_DPAPI_FILE  DPAPI-protected master key (Windows)
  LANTERNFISH_MASTER_KEY         base64 master key
  LANTERNFISH_ALERT_WEBHOOK      webhook for enrollment/revocation alerts (Discord-compatible)
  LANTERNFISH_SESSION_TTL        session lifetime for the initial policy (default 15m)
  LANTERNFISH_INJECT_RENEWAL     set to false to stop adding the session-renewal script to
                                 Jellyfin's web client when the Jellyfin plugin hasn't (default true)
  LANTERNFISH_ADMIN_ALLOW        networks the admin API answers from, comma-separated CIDRs
                                 (default: loopback and private ranges; add 100.64.0.0/10 for Tailscale)
  LANTERNFISH_WEBAUTHN_RP_ID     passkey relying party ID, e.g. flix.example.com (enables WebAuthn)
  LANTERNFISH_WEBAUTHN_ORIGINS   exact https origins passkeys may be used from, comma-separated
  LANTERNFISH_WEBAUTHN_RP_NAME   name shown by authenticators (default Lanternfish)
  LANTERNFISH_WEBAUTHN_MDS       cache file for FIDO metadata; enables attestation "require_trusted"
  LANTERNFISH_GEOIP_DB           local country database (GeoLite2-Country.mmdb); enables geo rules
  LANTERNFISH_GEOIP_MAX_AGE      when the database counts as stale (default 1080h, 45 days)
  LANTERNFISH_AUDIT_MAX_MB       rotate the audit log at this size, keeping 3 old files (default 20)
  LANTERNFISH_RELEASE_KEYS       trusted release signing keys (default /etc/lanternfish/release-keys)
  LANTERNFISH_AUTO_UPDATE        off (default), patch, minor or all: what the daily updater installs by itself
  LANTERNFISH_UPDATE_PRERELEASE  true to offer pre-releases
  LANTERNFISH_UPDATE_REPO        GitHub repository releases come from (default yourmomsbasement/LanternFish-Auth)
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("lanternfish-gate: ")
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"serve"}
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve()
	case "gen-master-key":
		err = genMasterKey(args[1:])
	case "admin-key":
		err = adminKey(args[1:])
	case "factor":
		err = factorCmd(args[1:])
	case "device-ca":
		err = deviceCA()
	case "upstream-key":
		err = upstreamKey()
	case "release-verify":
		err = releaseVerify(args[1:])
	case "update":
		err = updateCmd(args[1:])
	case "version", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loadConfig() (gate.Config, error) {
	var cfg gate.Config
	up, err := url.Parse(env("LANTERNFISH_UPSTREAM", "http://127.0.0.1:8096"))
	if err != nil || up.Scheme == "" || up.Host == "" {
		return cfg, fmt.Errorf("LANTERNFISH_UPSTREAM must be an absolute URL")
	}
	key, err := gate.LoadMasterKey(
		os.Getenv("LANTERNFISH_MASTER_KEY_DPAPI_FILE"),
		os.Getenv("LANTERNFISH_MASTER_KEY_FILE"),
		os.Getenv("LANTERNFISH_MASTER_KEY"))
	if err != nil {
		return cfg, err
	}
	cfg = gate.Config{
		Upstream:     up,
		DataPath:     env("LANTERNFISH_DATA", "data/gate.json"),
		AuditPath:    env("LANTERNFISH_AUDIT_LOG", "data/audit.log"),
		MasterKey:    key,
		AlertWebhook: os.Getenv("LANTERNFISH_ALERT_WEBHOOK"),
	}
	if v := os.Getenv("LANTERNFISH_ADMIN_ALLOW"); v != "" {
		nets, err := gate.ParseAdminAllow(v)
		if err != nil {
			return cfg, fmt.Errorf("LANTERNFISH_ADMIN_ALLOW: %w", err)
		}
		cfg.AdminAllow = nets
	}
	if v := os.Getenv("LANTERNFISH_INJECT_RENEWAL"); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return cfg, fmt.Errorf("LANTERNFISH_INJECT_RENEWAL must be true or false")
		}
		cfg.DisableRenewalInjection = !on
	}
	cfg.WebAuthnRPID = os.Getenv("LANTERNFISH_WEBAUTHN_RP_ID")
	cfg.WebAuthnRPName = os.Getenv("LANTERNFISH_WEBAUTHN_RP_NAME")
	cfg.WebAuthnMDSPath = os.Getenv("LANTERNFISH_WEBAUTHN_MDS")
	if v := os.Getenv("LANTERNFISH_WEBAUTHN_ORIGINS"); v != "" {
		for _, o := range strings.Split(v, ",") {
			cfg.WebAuthnOrigins = append(cfg.WebAuthnOrigins, strings.TrimSpace(o))
		}
	}
	cfg.GeoIPPath = os.Getenv("LANTERNFISH_GEOIP_DB")
	if v := os.Getenv("LANTERNFISH_GEOIP_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 24*time.Hour {
			return cfg, fmt.Errorf("LANTERNFISH_GEOIP_MAX_AGE must be a duration of at least 24h, e.g. 1080h")
		}
		cfg.GeoIPMaxAge = d
	}
	if v := os.Getenv("LANTERNFISH_AUDIT_MAX_MB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10000 {
			return cfg, fmt.Errorf("LANTERNFISH_AUDIT_MAX_MB must be a number of megabytes")
		}
		cfg.AuditMaxBytes = int64(n) << 20
	}
	if v := os.Getenv("LANTERNFISH_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return cfg, fmt.Errorf("LANTERNFISH_SESSION_TTL must be a duration between 1m and 24h")
		}
		cfg.SessionTTL = d
	}
	return cfg, nil
}

func serve() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	certFile, keyFile := os.Getenv("LANTERNFISH_TLS_CERT"), os.Getenv("LANTERNFISH_TLS_KEY")
	if certFile == "" || keyFile == "" {
		return errors.New("LANTERNFISH_TLS_CERT and LANTERNFISH_TLS_KEY are required: the Gate terminates TLS itself so it can verify client certificates")
	}
	certs, err := gate.NewCertReloader(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	unlock, err := gate.LockFile(cfg.DataPath)
	if err != nil {
		return err
	}
	defer unlock()

	cfg.Version = version
	cfg.Updates = gateUpdates()
	if p := cfg.Updates; p != nil {
		switch p.AutoPolicy {
		case "off", "patch", "minor", "all":
		default:
			return fmt.Errorf("LANTERNFISH_AUTO_UPDATE must be off, patch, minor or all")
		}
	}
	g, err := gate.New(cfg)
	if err != nil {
		return err
	}
	defer g.Close()
	gate.WarnIfExposed(cfg.Upstream)

	srv := &http.Server{
		Addr:              env("LANTERNFISH_LISTEN", ":8443"),
		Handler:           g.Handler(),
		TLSConfig:         g.TLSConfig(certs.GetCertificate),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No write timeout: video streams run for hours.
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Printf("lanternfish-gate %s listening on %s, proxying to %s", version, srv.Addr, cfg.Upstream)
	log.Printf("requests to Jellyfin are signed; Lanternfish plugin key: %s", g.UpstreamPublicKey())
	adminNets := cfg.AdminAllow
	if adminNets == nil {
		adminNets = gate.DefaultAdminAllow
	}
	log.Printf("admin API answers only from %v", adminNets)
	if err := srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func genMasterKey(args []string) error {
	fs := flag.NewFlagSet("gen-master-key", flag.ExitOnError)
	dpapiOut := fs.String("dpapi", "", "write a DPAPI-protected key to this file (Windows)")
	machine := fs.Bool("machine", false, "protect for the machine instead of the current user")
	fs.Parse(args)
	key := gate.GenerateMasterKey()
	if *dpapiOut == "" {
		fmt.Println(key)
		return nil
	}
	if !gate.DPAPIAvailable {
		return errors.New("-dpapi is only available on Windows")
	}
	raw, _ := gate.DecodeMasterKey(key)
	blob, err := gate.DPAPIProtect(raw, *machine)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*dpapiOut, blob, 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote DPAPI-protected master key to %s.\nSet LANTERNFISH_MASTER_KEY_DPAPI_FILE=%s\n", *dpapiOut, *dpapiOut)
	return nil
}

// openOffline opens the data file for CLI commands, refusing if the Gate is running.
func openOffline() (*gate.Admin, func(), error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	unlock, err := gate.LockFile(cfg.DataPath)
	if err != nil {
		return nil, nil, err
	}
	a, err := gate.OpenAdmin(cfg)
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return a, unlock, nil
}

func factorCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: factor list | factor reset SUBJECT_ID")
	}
	a, unlock, err := openOffline()
	if err != nil {
		return err
	}
	defer unlock()
	switch args[0] {
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tROLE\tSTATUS\tAUTHENTICATOR\tPASSKEYS\tRECOVERY CODES LEFT")
		for _, s := range a.Subjects() {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%d\t%d\n", s.ID, s.Name, s.Role, s.Status, s.TOTP, s.Passkeys, s.Recovery)
		}
		tw.Flush()
	case "reset":
		if len(args) != 2 {
			return errors.New("usage: factor reset SUBJECT_ID")
		}
		if err := a.ResetFactors(args[1]); err != nil {
			return err
		}
		fmt.Printf("Removed every factor of %s. Start the Gate and send them a new setup link from the dashboard.\n", args[1])
	default:
		return fmt.Errorf("unknown factor command %q", args[0])
	}
	return nil
}

func adminKey(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: admin-key create -name NAME | list | revoke ID")
	}
	a, unlock, err := openOffline()
	if err != nil {
		return err
	}
	defer unlock()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("admin-key create", flag.ExitOnError)
		name := fs.String("name", "", "who will use this key, e.g. builder")
		scopes := fs.String("scopes", "", "comma-separated scopes (default: all): "+strings.Join(gate.AllScopes(), ","))
		fs.Parse(args[1:])
		if *name == "" {
			return errors.New("-name is required")
		}
		var list []string
		if *scopes != "" {
			for _, s := range strings.Split(*scopes, ",") {
				list = append(list, strings.TrimSpace(s))
			}
		}
		id, key, err := a.CreateAdminKey(*name, list...)
		if err != nil {
			return err
		}
		fmt.Printf("Created admin key %s (%s). It is shown only once:\n\n%s\n", id, *name, key)
	case "list":
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tCREATED\tREVOKED")
		for _, k := range a.AdminKeys() {
			revoked := "-"
			if k.RevokedAt != nil {
				revoked = k.RevokedAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.ID, k.Name, k.CreatedAt.Format(time.RFC3339), revoked)
		}
		tw.Flush()
	case "link":
		if len(args) != 3 {
			return errors.New("usage: admin-key link ID SUBJECT_ID   (\"\" to unlink)")
		}
		if err := a.LinkAdminKey(args[1], args[2]); err != nil {
			return err
		}
		fmt.Printf("Linked %s to %q\n", args[1], args[2])
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: admin-key revoke ID")
		}
		if err := a.RevokeAdminKey(args[1]); err != nil {
			return err
		}
		fmt.Printf("Revoked %s\n", args[1])
	default:
		return fmt.Errorf("unknown admin-key command %q", args[0])
	}
	return nil
}

func deviceCA() error {
	a, unlock, err := openOffline()
	if err != nil {
		return err
	}
	defer unlock()
	os.Stdout.Write(a.DeviceCACertPEM())
	return nil
}

func upstreamKey() error {
	a, unlock, err := openOffline()
	if err != nil {
		return err
	}
	defer unlock()
	key, err := a.UpstreamPublicKey()
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}
