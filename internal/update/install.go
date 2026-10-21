package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Installer applies verified releases to a systemd installation. It runs as
// root (lanternfish-gate-update.service), never inside the Gate: the Gate
// can only ask for an update by writing a request naming a version, and the
// installer verifies everything again itself.
type Installer struct {
	Source  *Source
	Current string // running version ("dev" for an unreleased build)
	GOOS    string
	GOARCH  string

	// Prerelease lets requests from the dashboard install pre-releases
	// (LANTERNFISH_UPDATE_PRERELEASE); the command line can always.
	Prerelease bool

	BinPath     string // /usr/local/bin/lanternfish-gate
	PrevPath    string // previous binary, for rollback
	DataPath    string // the Gate's data file, backed up before each update
	BackupDir   string
	StatusPath  string
	RequestPath string

	// LockPath is held for a whole installation, so the dashboard's
	// updater, the automatic one and the command line never overlap. It
	// must be in a directory only root can write.
	LockPath string
	// ProbationPath marks a new version as being on probation: while it
	// exists, the Gate refuses changes to its data, so a rollback (which
	// restores the data file) can't undo a revocation or revive a used
	// ticket. Readable by the Gate, writable only by root.
	ProbationPath string
	// StopWait is how long to wait for a stopped Gate to release its data
	// file lock. Default 30s.
	StopWait time.Duration

	Stop    func() error
	Start   func() error
	Healthy func(ctx context.Context) error
	Alert   func(msg string)
	Now     func() time.Time
}

// Request is what the Gate writes to ask for an update.
type Request struct {
	Version     string    `json:"version"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
}

// Status is the installer's last result, shown in the dashboard.
type Status struct {
	State       string    `json:"state"` // installing, succeeded, failed, rolled_back
	Version     string    `json:"version"`
	From        string    `json:"from"`
	Message     string    `json:"message"`
	RequestedBy string    `json:"requested_by,omitempty"`
	At          time.Time `json:"at"`
}

func (in *Installer) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

func (in *Installer) alert(msg string) {
	if in.Alert != nil {
		in.Alert(msg)
	}
}

func (in *Installer) status(s Status) {
	s.At = in.now().UTC()
	if s.From == "" {
		s.From = in.Current
	}
	if in.StatusPath != "" {
		data, _ := json.MarshalIndent(s, "", "  ")
		if err := writeFileAtomic(in.StatusPath, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write status: %v\n", err)
		}
	}
	fmt.Printf("%s %s: %s\n", s.State, s.Version, s.Message)
}

// RunRequest applies the update the Gate asked for, if any.
func (in *Installer) RunRequest(ctx context.Context) error {
	req, err := ReadRequest(in.RequestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// Consume it first, whatever happens, so a bad request can't loop.
	os.Remove(in.RequestPath)
	if err != nil {
		in.status(Status{State: "failed", Message: "unreadable update request: " + err.Error()})
		return err
	}
	return in.Apply(ctx, req.Version, req.RequestedBy, ApplyOptions{AllowPrerelease: in.Prerelease})
}

// Auto applies the newest verified release if policy allows it.
func (in *Installer) Auto(ctx context.Context, policy string) error {
	if policy == "" || policy == "off" {
		return nil
	}
	cur, err := ParseVersion(in.Current)
	if err != nil {
		return fmt.Errorf("automatic updates need a released build (running %q)", in.Current)
	}
	rel, _, err := in.Source.Find(ctx, false)
	if err != nil || rel == nil {
		return err
	}
	if !AutoAllowed(policy, cur, rel.Version) {
		return nil
	}
	return in.Apply(ctx, rel.Version.String(), "automatic ("+policy+")", ApplyOptions{})
}

type ApplyOptions struct {
	AllowDowngrade  bool // install a version not newer than the running one
	AllowPrerelease bool
}

// Apply installs version.
//
// SECURITY: the whole installation runs under LockPath, and the downgrade
// check compares with the version actually installed, read from the binary
// under that lock. Comparing with this process's own version let two
// overlapping updates (say the timer and the dashboard) install an older
// release over a newer one.
func (in *Installer) Apply(ctx context.Context, version, by string, opt ApplyOptions) (err error) {
	st := Status{State: "installing", Version: strings.TrimPrefix(version, "v"), RequestedBy: by}
	fail := func(e error) error {
		st.State, st.Message = "failed", e.Error()
		in.status(st)
		in.alert(fmt.Sprintf("⚠️ Lanternfish Gate update to %s failed: %v", st.Version, e))
		return e
	}
	want, err := ParseVersion(version)
	if err != nil {
		return fail(err)
	}
	if in.LockPath != "" {
		unlock, err := lockExclusive(ctx, in.LockPath)
		if err != nil {
			return fail(fmt.Errorf("wait for other updates: %w", err))
		}
		defer unlock()
	}
	installed := in.installedVersion(ctx)
	st.From = installed
	st.Message = "verifying the release"
	in.status(st)

	if cur, err := ParseVersion(installed); err == nil && want.Compare(cur) <= 0 && !opt.AllowDowngrade {
		return fail(fmt.Errorf("%s is not newer than the installed %s", want, cur))
	}
	if want.Pre != "" && !opt.AllowPrerelease {
		return fail(errors.New("pre-releases are only installed on purpose (LANTERNFISH_UPDATE_PRERELEASE, or -prerelease on the command line)"))
	}
	rel, err := in.Source.Get(ctx, want.String())
	if err != nil {
		return fail(err)
	}
	archive := ArchiveName(rel.Version.String(), in.GOOS, in.GOARCH)
	data, err := in.Source.Download(ctx, rel, archive)
	if err != nil {
		return fail(err)
	}
	bin, err := extractBinary(data)
	if err != nil {
		return fail(err)
	}

	// Stage next to the target so the final rename is atomic, and check the
	// new binary runs and is the version it claims before stopping anything.
	staged, err := stageFile(in.BinPath, bin)
	if err != nil {
		return fail(err)
	}
	defer os.Remove(staged)
	if out, err := exec.CommandContext(ctx, staged, "version").Output(); err != nil || strings.TrimSpace(string(out)) != rel.Version.String() {
		return fail(fmt.Errorf("the new binary did not report version %s (%q, %v)", rel.Version, strings.TrimSpace(string(out)), err))
	}

	st.Message = "installing"
	in.status(st)
	// restartAndFail restarts the Gate after an early failure; a failed restart
	// is part of the failure, not hidden.
	restartAndFail := func(e error) error {
		if serr := in.Start(); serr != nil {
			e = fmt.Errorf("%w; restarting the Gate also failed: %v", e, serr)
		}
		return fail(e)
	}
	stopped, err := in.stopAndConfirm()
	if err != nil {
		if stopped {
			return restartAndFail(fmt.Errorf("stop the Gate: %w", err))
		}
		return fail(fmt.Errorf("stop the Gate: %w", err))
	}
	backup, err := in.backupData()
	if err != nil {
		return restartAndFail(fmt.Errorf("back up the data file: %w", err))
	}
	if err := copyFile(in.BinPath, in.PrevPath, 0o755); err != nil {
		return restartAndFail(fmt.Errorf("keep the previous binary: %w", err))
	}
	if in.ProbationPath != "" {
		if err := writeFileAtomic(in.ProbationPath, []byte(rel.Version.String()+"\n"), 0o644); err != nil {
			return restartAndFail(fmt.Errorf("mark the new version as on probation: %w", err))
		}
		defer os.Remove(in.ProbationPath)
	}
	if err := os.Rename(staged, in.BinPath); err != nil {
		return restartAndFail(err)
	}
	startErr := in.Start()
	hctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	healthErr := startErr
	if healthErr == nil {
		healthErr = in.Healthy(hctx)
	}
	cancel()
	if healthErr == nil {
		st.State, st.Message = "succeeded", "installed and healthy"
		in.status(st)
		in.alert(fmt.Sprintf("⬆️ Lanternfish Gate updated %s → %s (%s)", installed, rel.Version, by))
		return nil
	}

	// Roll back: previous binary and the data file as it was before. Its
	// changes while on probation were refused, so restoring the data file
	// only undoes the new version's own migration.
	//
	// SECURITY: only once the new Gate has certainly stopped. Overwriting
	// the data file under a running Gate would leave the two disagreeing,
	// and its next save would undo the restore.
	st.Message = fmt.Sprintf("%s was unhealthy (%v)", rel.Version, healthErr)
	if _, err := in.stopAndConfirm(); err != nil {
		st.State = "needs_manual_recovery"
		st.Message += fmt.Sprintf("; could not confirm it stopped (%v), so nothing was rolled back: "+
			"stop lanternfish-gate, then restore %s and %s by hand", err, in.PrevPath, backup)
		in.status(st)
		in.alert("🚨 Lanternfish Gate update: " + st.Message)
		return errors.New(st.Message)
	}
	rbErr := errors.Join(copyFile(in.PrevPath, in.BinPath, 0o755), restoreFile(backup, in.DataPath))
	if rbErr == nil {
		rbErr = in.Start()
	}
	if rbErr == nil {
		// Report a rollback only when the old version is back and healthy.
		if v := in.installedVersion(ctx); v != installed {
			rbErr = fmt.Errorf("restored binary reports %q, not %s", v, installed)
		} else {
			hctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			rbErr = in.Healthy(hctx)
			cancel()
		}
	}
	st.State = "rolled_back"
	st.Message += "; restored " + installed
	if rbErr != nil {
		st.State = "needs_manual_recovery"
		st.Message += "; ROLLBACK PROBLEM: " + rbErr.Error()
	}
	in.status(st)
	in.alert("⚠️ Lanternfish Gate update: " + st.Message)
	return errors.New(st.Message)
}

// installedVersion asks the installed binary its version, falling back to
// this process's own if it can't be run.
func (in *Installer) installedVersion(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, in.BinPath, "version").Output()
	if v := strings.TrimSpace(string(out)); err == nil && v != "" {
		return v
	}
	return in.Current
}

// stopAndConfirm stops the Gate and confirms it is gone by taking its data
// file lock, which a running Gate holds. stopped reports whether the stop
// command itself succeeded (so a restart makes sense after a failure).
func (in *Installer) stopAndConfirm() (stopped bool, err error) {
	if err := in.Stop(); err != nil {
		return false, err
	}
	if in.DataPath == "" {
		return true, nil
	}
	wait := in.StopWait
	if wait == 0 {
		wait = 30 * time.Second
	}
	release, err := lockDataFile(in.DataPath+".lock", in.DataPath, wait)
	if err != nil {
		return true, fmt.Errorf("the Gate still holds its data file after stopping: %w", err)
	}
	release()
	return true, nil
}

// stageFile writes data next to target under a name of its own, so
// overlapping attempts can't overwrite each other's staged binary.
func stageFile(target string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".new*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Chmod(0o755), f.Sync(), f.Close()); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// ProbationActive reports whether a new version is on probation (the
// marker exists and is recent). A marker left by an updater that died is
// ignored after ten minutes, so the Gate can't stay read-only forever.
func ProbationActive(p string, now time.Time) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && now.Sub(st.ModTime()) < 10*time.Minute
}

// extractBinary returns lanternfish-gate from a release tar.gz.
func extractBinary(archive []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, errors.New("the archive holds no lanternfish-gate binary")
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.Trim(path.Clean(h.Name), "/"), "/")
		if h.Typeflag == tar.TypeReg && len(parts) == 2 && parts[1] == "lanternfish-gate" {
			if h.Size <= 0 || h.Size > maxArchive {
				return nil, errors.New("binary has an unreasonable size")
			}
			return io.ReadAll(io.LimitReader(tr, h.Size))
		}
	}
}

// maxBackupSize bounds the data file the updater backs up (it is read
// whole, as root, from a directory the Gate's user can write).
var maxBackupSize int64 = 256 << 20

func (in *Installer) backupData() (string, error) {
	if in.DataPath == "" {
		return "", nil
	}
	if err := os.MkdirAll(in.BackupDir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(in.BackupDir, fmt.Sprintf("gate.json.%s.%s", strings.ReplaceAll(in.Current, "/", "_"),
		in.now().UTC().Format("20060102T150405Z")))
	f, err := openNoFollow(in.DataPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("the data file is not a regular file; refusing an unsafe backup")
	}
	// SECURITY: read one byte past the limit, so a larger file fails the
	// update instead of leaving a truncated backup that looks complete.
	data, err := io.ReadAll(io.LimitReader(f, maxBackupSize+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBackupSize {
		return "", fmt.Errorf("the data file is over %d MiB; not updating without a complete backup", maxBackupSize>>20)
	}
	if err := writeFileAtomic(dst, data, 0o600); err != nil {
		return "", err
	}
	// Keep the last five.
	old, _ := filepath.Glob(filepath.Join(in.BackupDir, "gate.json.*"))
	sort.Slice(old, func(i, j int) bool {
		a, _ := os.Stat(old[i])
		b, _ := os.Stat(old[j])
		return a != nil && b != nil && a.ModTime().Before(b.ModTime())
	})
	for len(old) > 5 {
		os.Remove(old[0])
		old = old[1:]
	}
	return dst, nil
}

func restoreFile(backup, dst string) error {
	if backup == "" {
		return nil
	}
	return copyFile(backup, dst, 0o600)
}

// copyFile copies src over dst atomically.
func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, data, mode)
}

// writeFileAtomic replaces dst with data, keeping the owner of a regular
// file it replaces.
//
// SECURITY: this runs as root in directories the Gate's user can write.
// Ownership is set on the open file (never by path, which could be swapped
// for a symlink), and an existing symlink at dst is replaced, not followed.
func writeFileAtomic(dst string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if prev, err := os.Lstat(dst); err == nil && prev.Mode().IsRegular() {
		if err := chownLike(tmp, prev); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// ReadRequest reads the Gate's update request.
//
// SECURITY: the request lives in the Gate's own directory and is read by
// root, so it must be a small regular file and is never followed through a
// symlink.
func ReadRequest(p string) (*Request, error) {
	f, err := openNoFollow(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 4096 {
		return nil, errors.New("not a small regular file")
	}
	var r Request
	dec := json.NewDecoder(io.LimitReader(f, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, errors.New("malformed request")
	}
	if _, err := ParseVersion(r.Version); err != nil {
		return nil, err
	}
	r.RequestedBy = cleanText(r.RequestedBy)
	return &r, nil
}

// WriteRequest is used by the Gate to ask for an update.
func WriteRequest(p string, r Request) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(p, data, 0o644)
}

// ReadStatus returns the installer's last status, if any.
func ReadStatus(p string) (*Status, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func cleanText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// ---- systemd ----

// Systemctl runs systemctl for unit.
func Systemctl(action, unit string) error {
	out, err := exec.Command("systemctl", action, unit).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s %s: %v: %s", action, unit, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// HealthCheck waits for unit to be active and the Gate to complete TLS
// handshakes on listen, then checks that it stays up for a while.
func HealthCheck(unit, listen string) func(ctx context.Context) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "", "8443"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	probe := func() error {
		if exec.Command("systemctl", "is-active", "--quiet", unit).Run() != nil {
			return errors.New(unit + " is not running")
		}
		d := &net.Dialer{Timeout: 3 * time.Second}
		// Liveness only, on this machine: the certificate isn't the question.
		c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err != nil {
			return fmt.Errorf("no TLS on %s: %v", addr, err)
		}
		return c.Close()
	}
	return func(ctx context.Context) error {
		var last error
		for {
			if last = probe(); last == nil {
				break
			}
			select {
			case <-ctx.Done():
				return last
			case <-time.After(time.Second):
			}
		}
		// Still up after 15 seconds (catches a crash after start-up).
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
		}
		return probe()
	}
}

// Webhook posts Discord-compatible alerts.
func Webhook(url string) func(string) {
	if url == "" {
		return nil
	}
	return func(msg string) {
		// SECURITY (L6): release notes and error text end up in msg; no
		// @everyone or role pings from them, as the Gate's alerts.
		body, _ := json.Marshal(map[string]any{"content": msg, "allowed_mentions": map[string]any{"parse": []string{}}})
		c := &http.Client{Timeout: 10 * time.Second}
		if resp, err := c.Post(url, "application/json", bytes.NewReader(body)); err == nil {
			resp.Body.Close()
		}
	}
}
