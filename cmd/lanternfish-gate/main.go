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
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/yourmomsbasement/lanternfish-auth/internal/gate"
)

const usage = `Usage:
  lanternfish-gate serve                     Run the Gate
  lanternfish-gate gen-master-key [flags]    Print a new master key
      -dpapi FILE   (Windows) write it DPAPI-protected to FILE instead
      -machine      with -dpapi, protect for this machine rather than this user
  lanternfish-gate admin-key create -name NAME
  lanternfish-gate admin-key list
  lanternfish-gate admin-key revoke ID
  lanternfish-gate device-ca                 Print the device CA certificate

admin-key and device-ca edit the data file directly; stop the Gate first.

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
  LANTERNFISH_SESSION_TTL        session lifetime (default 15m)
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
	case "device-ca":
		err = deviceCA()
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
	unlock, err := gate.LockFile(cfg.DataPath, true)
	if err != nil {
		return err
	}
	defer unlock()

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
	log.Printf("listening on %s, proxying to %s", srv.Addr, cfg.Upstream)
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
	unlock, err := gate.LockFile(cfg.DataPath, false)
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
		fs.Parse(args[1:])
		if *name == "" {
			return errors.New("-name is required")
		}
		id, key, err := a.CreateAdminKey(*name)
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
