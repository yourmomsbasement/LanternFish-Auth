package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/yourmomsbasement/lanternfish-auth/internal/gate"
	"github.com/yourmomsbasement/lanternfish-auth/internal/update"
)

const (
	defaultUpdateRepo = "yourmomsbasement/LanternFish-Auth"
	defaultKeysPath   = "/etc/lanternfish/release-keys"
	defaultStatusPath = "/var/lib/lanternfish-update/status.json"
	updaterUnit       = "/etc/systemd/system/lanternfish-gate-update.path"
)

func updateSource() (*update.Source, string) {
	src := &update.Source{Repo: env("LANTERNFISH_UPDATE_REPO", defaultUpdateRepo), API: os.Getenv("LANTERNFISH_UPDATE_API")}
	path := env("LANTERNFISH_RELEASE_KEYS", defaultKeysPath)
	keys, err := update.LoadPublicKeys(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return src, "no trusted release keys yet: put your public key in " + path
		}
		return src, err.Error()
	}
	src.Keys = keys
	return src, ""
}

func requestPath() string {
	return env("LANTERNFISH_UPDATE_REQUEST",
		filepath.Join(filepath.Dir(env("LANTERNFISH_DATA", "data/gate.json")), "update-request.json"))
}

// gateUpdates configures the dashboard's update page.
func gateUpdates() *gate.Updates {
	if runtime.GOOS != "linux" {
		return nil
	}
	src, keysErr := updateSource()
	pre, _ := strconv.ParseBool(os.Getenv("LANTERNFISH_UPDATE_PRERELEASE"))
	return &gate.Updates{Source: src, KeysError: keysErr, KeysPath: env("LANTERNFISH_RELEASE_KEYS", defaultKeysPath),
		RequestPath: requestPath(), StatusPath: env("LANTERNFISH_UPDATE_STATUS", defaultStatusPath),
		UnitPath: updaterUnit, AutoPolicy: env("LANTERNFISH_AUTO_UPDATE", "off"), Prerelease: pre}
}

func releaseVerify(args []string) error {
	fs := flag.NewFlagSet("release-verify", flag.ExitOnError)
	keys := fs.String("keys", env("LANTERNFISH_RELEASE_KEYS", defaultKeysPath), "trusted release keys")
	fs.Parse(args)
	if fs.NArg() != 2 {
		return errors.New("usage: lanternfish-gate release-verify [-keys FILE] MANIFEST SIGNATURE")
	}
	k, err := update.LoadPublicKeys(*keys)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return err
	}
	m, signer, err := update.Verify(manifest, sig, k)
	if err != nil {
		return err
	}
	fmt.Printf("Good signature: %s %s, signed by %q\n", m.Product, m.Version, signer)
	return nil
}

// updateCmd: check, apply, run-request (path unit) and auto (timer).
func updateCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: lanternfish-gate update check | apply [-version X] [-prerelease] [-allow-downgrade] | run-request | auto")
	}
	src, keysErr := updateSource()
	if keysErr != "" {
		return errors.New(keysErr)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pre, _ := strconv.ParseBool(os.Getenv("LANTERNFISH_UPDATE_PRERELEASE"))

	switch args[0] {
	case "check":
		fs := flag.NewFlagSet("update check", flag.ExitOnError)
		withPre := fs.Bool("prerelease", pre, "include pre-releases")
		fs.Parse(args[1:])
		rel, seen, err := src.Find(ctx, *withPre)
		if err != nil {
			return err
		}
		fmt.Printf("running %s\n", version)
		for _, c := range seen {
			state := "verified, signed by " + c.SignedBy
			if !c.Verified {
				state = "NOT usable: " + c.Problem
			}
			fmt.Printf("  %-14s %s\n", c.Tag, state)
		}
		if rel == nil {
			fmt.Println("no verified release found")
		} else if cur, err := update.ParseVersion(version); err != nil || rel.Version.Compare(cur) > 0 {
			fmt.Printf("update available: %s (lanternfish-gate update apply)\n", rel.Version)
		} else {
			fmt.Println("up to date")
		}
		return nil
	case "apply", "run-request", "auto":
	default:
		return fmt.Errorf("unknown update command %q", args[0])
	}

	if runtime.GOOS != "linux" {
		return errors.New("installing updates is supported on Linux with systemd; on Windows, replace the binary by hand")
	}
	if os.Geteuid() != 0 {
		return errors.New("installing updates needs root (it is normally run by lanternfish-gate-update.service)")
	}
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	in := &update.Installer{Source: src, Current: version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Prerelease: pre,
		BinPath: bin, PrevPath: "/usr/local/lib/lanternfish/lanternfish-gate.prev",
		DataPath: env("LANTERNFISH_DATA", "data/gate.json"), BackupDir: "/var/lib/lanternfish-update/backups",
		StatusPath: env("LANTERNFISH_UPDATE_STATUS", defaultStatusPath), RequestPath: requestPath(),
		Stop:    func() error { return update.Systemctl("stop", "lanternfish-gate") },
		Start:   func() error { return update.Systemctl("start", "lanternfish-gate") },
		Healthy: update.HealthCheck("lanternfish-gate", env("LANTERNFISH_LISTEN", ":8443")),
		Alert:   update.Webhook(os.Getenv("LANTERNFISH_ALERT_WEBHOOK")),
	}
	switch args[0] {
	case "run-request":
		return in.RunRequest(ctx)
	case "auto":
		return in.Auto(ctx, env("LANTERNFISH_AUTO_UPDATE", "off"))
	}
	fs := flag.NewFlagSet("update apply", flag.ExitOnError)
	want := fs.String("version", "", "version to install (default: the newest verified release)")
	withPre := fs.Bool("prerelease", pre, "allow pre-releases")
	downgrade := fs.Bool("allow-downgrade", false, "allow installing an older version (data written by the newer one may be lost)")
	fs.Parse(args[1:])
	if *want == "" {
		rel, _, err := src.Find(ctx, *withPre)
		if err != nil {
			return err
		}
		if rel == nil {
			return errors.New("no verified release found")
		}
		*want = rel.Version.String()
	}
	return in.Apply(ctx, *want, "cli", update.ApplyOptions{AllowPrerelease: *withPre, AllowDowngrade: *downgrade})
}
