package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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

// readPassphrase reads the release key passphrase from
// LANTERNFISH_RELEASE_PASSPHRASE or the terminal, without echo.
func readPassphrase(prompt string) (string, error) {
	if p := os.Getenv("LANTERNFISH_RELEASE_PASSPHRASE"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, prompt)
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		stty := func(arg string) error {
			c := exec.Command("stty", arg)
			c.Stdin = os.Stdin
			return c.Run()
		}
		if stty("-echo") == nil {
			defer func() { stty("echo"); fmt.Fprintln(os.Stderr) }()
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func releaseKey(args []string) error {
	if len(args) == 0 || args[0] != "generate" {
		return errors.New("usage: lanternfish-gate release-key generate -out FILE [-comment TEXT]")
	}
	fs := flag.NewFlagSet("release-key generate", flag.ExitOnError)
	out := fs.String("out", "", "where to write the encrypted private key")
	comment := fs.String("comment", "", "label for the public key, e.g. your name and the date")
	fs.Parse(args[1:])
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a key", *out)
	}
	pass, err := readPassphrase("Passphrase for the new release key (12+ characters): ")
	if err != nil {
		return err
	}
	again, err := readPassphrase("Repeat it: ")
	if err != nil {
		return err
	}
	if pass != again {
		return errors.New("the passphrases differ")
	}
	file, pub, err := update.GenerateKey(pass)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, file, 0o600); err != nil {
		return err
	}
	c := *comment
	if c == "" {
		c = "release key " + time.Now().Format("2006-01-02")
	}
	fmt.Fprintf(os.Stderr, "Wrote the encrypted private key to %s (key ID %s). Back it up offline; never upload it.\n", *out, update.KeyID(pub))
	fmt.Fprintln(os.Stderr, "Public key (put this line in /etc/lanternfish/release-keys on the Gate):")
	fmt.Println(update.FormatPublicKey(pub, c))
	return nil
}

// releaseManifest is run by CI to list the release's files.
func releaseManifest(args []string) error {
	fs := flag.NewFlagSet("release-manifest", flag.ExitOnError)
	ver := fs.String("version", "", "release version, e.g. v0.3.0")
	dir := fs.String("dir", ".", "directory holding the files")
	fs.Parse(args)
	names := fs.Args()
	if *ver == "" || len(names) == 0 {
		return errors.New("usage: lanternfish-gate release-manifest -version vX.Y.Z -dir DIR FILE...")
	}
	m, err := update.BuildManifest(*dir, *ver, names, time.Now())
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(m)
	return err
}

// releaseSign signs a release's manifest after checking the files it lists:
// downloaded from GitHub with -tag, or in a local -dir.
func releaseSign(args []string) error {
	fs := flag.NewFlagSet("release-sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "encrypted release key")
	tag := fs.String("tag", "", "download the release with this tag from GitHub and check its files")
	dir := fs.String("dir", "", "check the files in this directory instead")
	out := fs.String("out", update.SignatureName, "where to write the signature")
	fs.Parse(args)
	if *keyPath == "" || (*tag == "") == (*dir == "") {
		return errors.New("usage: lanternfish-gate release-sign -key FILE (-tag vX.Y.Z | -dir DIR)")
	}
	keyFile, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	var manifest []byte
	var files func(name string) ([]byte, error)
	if *tag != "" {
		src := &update.Source{Repo: env("LANTERNFISH_UPDATE_REPO", defaultUpdateRepo), API: os.Getenv("LANTERNFISH_UPDATE_API")}
		ctx := context.Background()
		manifest, files, err = src.Unverified(ctx, *tag)
		if err != nil {
			return err
		}
	} else {
		if manifest, err = os.ReadFile(filepath.Join(*dir, update.ManifestName)); err != nil {
			return err
		}
		files = func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(*dir, name)) }
	}
	m, err := update.ParseManifest(manifest)
	if err != nil {
		return err
	}
	if *tag != "" {
		if v, _ := update.ParseVersion(*tag); v.String() != m.Version {
			return fmt.Errorf("the manifest is for %s, not %s", m.Version, *tag)
		}
	}
	// Sign only what we have checked: every listed file must match.
	for _, f := range m.Files {
		data, err := files(f.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if err := f.Check(data); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "ok  %s  %s\n", f.SHA256[:16], f.Name)
	}
	pass, err := readPassphrase("Release key passphrase: ")
	if err != nil {
		return err
	}
	priv, err := update.OpenKey(keyFile, pass)
	if err != nil {
		return err
	}
	sig, err := update.Sign(priv, manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, sig, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed %s %s. Attach %s to the GitHub release.\n", update.Product, m.Version, *out)
	return nil
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
