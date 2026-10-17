//go:build unix

package update

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Regression tests for the updater findings (U1–U3) of the v0.2.2 review.
// Each started as the reviewer's reproduction, with its assertion reversed.

type pauseTransport func(*http.Request) (*http.Response, error)

func (f pauseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// sharedInstallers returns two installers for the same installation, both
// built by a process running current, sharing the install lock.
func sharedInstallers(t *testing.T, src *Source, current string, svc *fakeService) (*Installer, *Installer) {
	t.Helper()
	a := newInstaller(t, src, current, svc)
	a.LockPath = filepath.Join(filepath.Dir(a.StatusPath), "install.lock")
	b := *a
	return a, &b
}

// U1: an update started by an older updater can't install over a newer
// release installed meanwhile.
func TestOverlappingUpdatesCannotDowngrade(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true), signedRelease(t, priv, "v0.4.0", "0.4.0", true))
	svc := &fakeService{running: true}
	a, b := sharedInstallers(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)

	// b (say the dashboard) installs 0.4.0; a (say the timer, started from
	// the same 0.2.2 binary) then asks for 0.3.0.
	if err := b.Apply(context.Background(), "0.4.0", "dashboard", ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(context.Background(), "0.3.0", "automatic", ApplyOptions{}); err == nil {
		t.Fatal("installed 0.3.0 over 0.4.0 without AllowDowngrade")
	}
	if !strings.Contains(read(t, a.BinPath), "echo 0.4.0") {
		t.Fatalf("installed binary: %q", read(t, a.BinPath))
	}
}

// U1: updates run one at a time; a second waits for the first to finish,
// then judges against what that installed.
func TestUpdatesAreSerialized(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true), signedRelease(t, priv, "v0.4.0", "0.4.0", true))
	blocked, resume := make(chan struct{}), make(chan struct{})
	slow := &Source{Repo: "o/r", API: srv.URL, Keys: keys, Client: &http.Client{Transport: pauseTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/dl/v0.4.0/") && strings.HasSuffix(r.URL.Path, ".tar.gz") {
			close(blocked)
			<-resume
		}
		return http.DefaultTransport.RoundTrip(r)
	})}}
	svc := &fakeService{running: true}
	a, b := sharedInstallers(t, slow, "0.2.2", svc)
	b.Source = &Source{Repo: "o/r", API: srv.URL, Keys: keys}

	doneA := make(chan error, 1)
	go func() { doneA <- a.Apply(context.Background(), "0.4.0", "dashboard", ApplyOptions{}) }()
	<-blocked
	doneB := make(chan error, 1)
	go func() { doneB <- b.Apply(context.Background(), "0.3.0", "automatic", ApplyOptions{}) }()
	select {
	case err := <-doneB:
		t.Fatalf("second update ran while the first was downloading: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	close(resume)
	if err := <-doneA; err != nil {
		t.Fatal(err)
	}
	if err := <-doneB; err == nil {
		t.Fatal("the waiting update installed an older version")
	}
	if !strings.Contains(read(t, a.BinPath), "echo 0.4.0") {
		t.Fatalf("installed binary: %q", read(t, a.BinPath))
	}
}

// U2: while the new version is on probation the marker exists (so the Gate
// refuses changes), and it is gone afterwards, whether the update was kept
// or rolled back.
func TestProbationMarksTheHealthCheck(t *testing.T) {
	for _, healthy := range []bool{true, false} {
		priv, keys := testKey(t)
		srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
		svc := &fakeService{running: true}
		in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)
		in.ProbationPath = filepath.Join(filepath.Dir(in.StatusPath), "probation")
		marked := false
		svc.healthy = func() error {
			marked = ProbationActive(in.ProbationPath, time.Now())
			svc.healthy = nil // the restored version is healthy
			if healthy {
				return nil
			}
			return errors.New("crashed")
		}
		err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{})
		if (err == nil) != healthy {
			t.Fatalf("healthy=%v: %v", healthy, err)
		}
		if !marked {
			t.Errorf("healthy=%v: no probation marker during the health check", healthy)
		}
		if _, err := os.Stat(in.ProbationPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("healthy=%v: probation marker left behind", healthy)
		}
	}
	// A marker left by an updater that died stops counting.
	p := filepath.Join(t.TempDir(), "probation")
	os.WriteFile(p, nil, 0o644)
	old := time.Now().Add(-11 * time.Minute)
	os.Chtimes(p, old, old)
	if ProbationActive(p, time.Now()) {
		t.Error("stale marker still active")
	}
}

// U3: if the new Gate can't be confirmed stopped, nothing is rolled back and
// the status says recovery is needed, rather than "rolled_back".
func TestRollbackNeedsConfirmedStop(t *testing.T) {
	cases := map[string]func(in *Installer, svc *fakeService) (cleanup func()){
		"stop fails": func(in *Installer, svc *fakeService) func() {
			stops := 0
			in.Stop = func() error {
				if stops++; stops == 2 {
					return errors.New("systemctl stop failed; new process still running")
				}
				svc.running = false
				return nil
			}
			return func() {}
		},
		"Gate still holds its data lock": func(in *Installer, svc *fakeService) func() {
			// Stand in for a Gate process that outlives "systemctl stop"
			// once the new version is running.
			var held *os.File
			in.Start = func() error {
				svc.running = true
				if held == nil {
					f, err := os.OpenFile(in.DataPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
					if err == nil && syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
						held = f
					}
				}
				return nil
			}
			in.StopWait = 300 * time.Millisecond
			return func() {
				if held != nil {
					held.Close()
				}
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			priv, keys := testKey(t)
			srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
			svc := &fakeService{running: true}
			in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)
			defer setup(in, svc)()
			svc.healthy = func() error {
				os.WriteFile(in.DataPath, []byte(`{"version":3}`), 0o600)
				return errors.New("probe unavailable")
			}
			if err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{}); err == nil {
				t.Fatal("unhealthy update reported success")
			}
			st, err := ReadStatus(in.StatusPath)
			if err != nil {
				t.Fatal(err)
			}
			if st.State != "needs_manual_recovery" {
				t.Errorf("status %q, want needs_manual_recovery (%s)", st.State, st.Message)
			}
			if read(t, in.DataPath) != `{"version":3}` || !strings.Contains(read(t, in.BinPath), "echo 0.3.0") {
				t.Error("rolled back files under a Gate that may still be running")
			}
		})
	}
}

// U3: a rollback is reported only once the old version is back and healthy.
func TestRollbackReportsAnUnhealthyRestore(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)
	svc.healthy = func() error { return errors.New("down") } // neither version comes up
	if err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{}); err == nil {
		t.Fatal("reported success")
	}
	if st, _ := ReadStatus(in.StatusPath); st.State != "needs_manual_recovery" || !strings.Contains(st.Message, "ROLLBACK PROBLEM") {
		t.Fatalf("status: %+v", st)
	}
	if !strings.Contains(read(t, in.BinPath), "echo 0.2.2") || read(t, in.DataPath) != `{"version":2}` {
		t.Error("files not restored")
	}
}

// U3: when restarting after an early failure also fails, the status says so.
func TestEarlyFailureReportsRestartFailure(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)
	in.PrevPath = filepath.Join(in.DataPath, "not-a-dir", "prev") // keeping the old binary fails
	in.Start = func() error { return errors.New("unit failed to start") }
	if err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{}); err == nil {
		t.Fatal("reported success")
	}
	if st, _ := ReadStatus(in.StatusPath); !strings.Contains(st.Message, "restarting the Gate also failed") {
		t.Fatalf("status: %+v", st)
	}
}

// N2: a data file too big to back up whole stops the update; it is never
// backed up truncated.
func TestOversizeDataFileStopsUpdate(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.2", svc)
	old := maxBackupSize
	maxBackupSize = 8
	defer func() { maxBackupSize = old }()
	os.WriteFile(in.DataPath, []byte(`{"version":2,"padding":"more than eight bytes"}`), 0o600)
	err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{})
	if err == nil || !strings.Contains(err.Error(), "complete backup") {
		t.Fatalf("update with an oversize data file: %v", err)
	}
	if !strings.Contains(read(t, in.BinPath), "echo 0.2.2") || !svc.running {
		t.Fatal("the installation was changed, or the Gate left stopped")
	}
	if backups, _ := filepath.Glob(filepath.Join(in.BackupDir, "gate.json.*")); len(backups) != 0 {
		t.Fatalf("truncated backup left: %v", backups)
	}
}

// The Gate owns the data directory. A FIFO there must not be accepted as an
// empty backup, nor may a device keep the privileged updater reading forever.
func TestBackupRejectsSpecialDataFile(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "gate.json")
	if err := syscall.Mkfifo(data, 0o600); err != nil {
		t.Fatal(err)
	}
	in := &Installer{DataPath: data, BackupDir: filepath.Join(dir, "backups"), Current: "1.0.0"}
	if _, err := in.backupData(); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("backup accepted a FIFO: %v", err)
	}
	backups, err := os.ReadDir(in.BackupDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatal("special file created a misleading backup")
	}
}
