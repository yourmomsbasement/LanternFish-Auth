package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The tests sign as scripts/sign-releases.sh does: plain Ed25519 over
// SignedMessage(manifest), wrapped in the signature file's JSON.

func testKey(t *testing.T) (ed25519.PrivateKey, []PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line := "lfrk1 " + base64.StdEncoding.EncodeToString(pub) + " test key"
	keys, err := ParsePublicKeys([]byte("# trusted\n" + line + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return priv, keys
}

func testManifest(t *testing.T, dir, version string, names ...string) []byte {
	t.Helper()
	m := Manifest{Schema: 1, Product: Product, Version: strings.TrimPrefix(version, "v"), Published: time.Now().UTC()}
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		m.Files = append(m.Files, File{Name: n, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return append(out, '\n')
}

func testSign(priv ed25519.PrivateKey, manifest []byte) []byte {
	sig, _ := json.Marshal(Signature{KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SignedMessage(manifest)))})
	return sig
}

func TestSignatures(t *testing.T) {
	priv, keys := testKey(t)
	_, otherKeys := testKey(t)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.tar.gz"), []byte("archive"), 0o644)
	manifest := testManifest(t, dir, "v1.2.3", "a.tar.gz")
	sig := testSign(priv, manifest)
	m, signer, err := Verify(manifest, sig, keys)
	if err != nil || m.Version != "1.2.3" || signer != "test key" {
		t.Fatalf("verify: %v %v %q", m, err, signer)
	}
	if f, _ := m.File("a.tar.gz"); f.Check([]byte("archive")) != nil || f.Check([]byte("archivf")) == nil {
		t.Fatal("file hash check")
	}
	if _, _, err := Verify(manifest, sig, otherKeys); err == nil {
		t.Fatal("verified with an untrusted key")
	}
	tampered := bytes.Replace(manifest, []byte("1.2.3"), []byte("1.2.4"), 1)
	if _, _, err := Verify(tampered, sig, keys); err == nil {
		t.Fatal("verified a tampered manifest")
	}
}

func TestVersions(t *testing.T) {
	order := []string{"0.9.9", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0", "1.0.1", "1.1.0", "2.0.0"}
	for i := 1; i < len(order); i++ {
		a, _ := ParseVersion(order[i-1])
		b, _ := ParseVersion(order[i])
		if a.Compare(b) != -1 || b.Compare(a) != 1 {
			t.Errorf("%s should sort before %s", a, b)
		}
	}
	for _, bad := range []string{"1.2", "1.2.3.4", "01.2.3", "1.2.x", "1.2.3-r c", "dev"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	v := func(s string) Version { x, _ := ParseVersion(s); return x }
	cases := []struct {
		policy, cur, next string
		want              bool
	}{
		{"patch", "1.2.3", "1.2.4", true},
		{"patch", "1.2.3", "1.3.0", false},
		{"minor", "1.2.3", "1.3.0", true},
		{"minor", "1.2.3", "2.0.0", false},
		{"all", "1.2.3", "2.0.0", true},
		{"all", "1.2.3", "2.0.0-rc.1", false},
		{"off", "1.2.3", "1.2.4", false},
		{"all", "1.2.3", "1.2.3", false},
	}
	for _, c := range cases {
		if got := AutoAllowed(c.policy, v(c.cur), v(c.next)); got != c.want {
			t.Errorf("%s %s→%s: %v", c.policy, c.cur, c.next, got)
		}
	}
}

// ---- A fake GitHub ----

type fakeRelease struct {
	tag        string
	prerelease bool
	files      map[string][]byte
}

func fakeGitHub(t *testing.T, rels ...fakeRelease) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/releases" {
			var out []map[string]any
			for _, rel := range rels {
				var assets []map[string]any
				for name, data := range rel.files {
					assets = append(assets, map[string]any{"name": name, "size": len(data),
						"browser_download_url": srv.URL + "/dl/" + rel.tag + "/" + name})
				}
				out = append(out, map[string]any{"tag_name": rel.tag, "prerelease": rel.prerelease,
					"published_at": time.Now().UTC(), "html_url": "https://example/" + rel.tag, "assets": assets})
			}
			json.NewEncoder(w).Encode(out)
			return
		}
		for _, rel := range rels {
			for name, data := range rel.files {
				if r.URL.Path == "/dl/"+rel.tag+"/"+name {
					w.Write(data)
					return
				}
			}
		}
		http.NotFound(w, r)
	}))
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// fakeArchive is a release archive whose "binary" is a script printing version.
func fakeArchive(t *testing.T, version string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dir := fmt.Sprintf("lanternfish-gate_%s_%s_%s/", version, runtime.GOOS, runtime.GOARCH)
	script := []byte("#!/bin/sh\necho " + version + "\n")
	tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755})
	tw.WriteHeader(&tar.Header{Name: dir + "README.md", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2})
	tw.Write([]byte("hi"))
	tw.WriteHeader(&tar.Header{Name: dir + "lanternfish-gate", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(script))})
	tw.Write(script)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// signedRelease builds a release; manifestVersion lets a test attach a
// manifest for another version.
func signedRelease(t *testing.T, priv ed25519.PrivateKey, tag, manifestVersion string, sign bool) fakeRelease {
	t.Helper()
	dir := t.TempDir()
	name := ArchiveName(manifestVersion, runtime.GOOS, runtime.GOARCH)
	archive := fakeArchive(t, manifestVersion)
	os.WriteFile(filepath.Join(dir, name), archive, 0o644)
	manifest := testManifest(t, dir, manifestVersion, name)
	files := map[string][]byte{name: archive, ManifestName: manifest}
	if sign {
		sig := testSign(priv, manifest)
		files[SignatureName] = sig
	}
	return fakeRelease{tag: tag, files: files}
}

func TestFindNewestSignedRelease(t *testing.T) {
	priv, keys := testKey(t)
	pre := signedRelease(t, priv, "v0.5.0-rc.1", "0.5.0-rc.1", true)
	pre.prerelease = true
	srv := fakeGitHub(t,
		signedRelease(t, priv, "v0.3.0", "0.3.0", true),
		signedRelease(t, priv, "v0.4.0", "0.4.0", false), // not signed yet
		signedRelease(t, priv, "v0.4.1", "0.3.0", true),  // replays 0.3.0's signed manifest
		pre)
	src := &Source{Repo: "o/r", API: srv.URL, Keys: keys}
	rel, seen, err := src.Find(context.Background(), false)
	if err != nil || rel == nil || rel.Version.String() != "0.3.0" {
		t.Fatalf("find: %v %v", rel, err)
	}
	if len(seen) != 3 || !strings.Contains(seen[0].Problem, "is for 0.3.0") || !strings.Contains(seen[1].Problem, "not signed") {
		t.Fatalf("candidates: %+v", seen)
	}
	if rel, _, _ := src.Find(context.Background(), true); rel == nil || rel.Version.String() != "0.5.0-rc.1" {
		t.Fatalf("with pre-releases: %v", rel)
	}
}

type fakeService struct {
	running bool
	starts  int
	healthy func() error
}

func newInstaller(t *testing.T, src *Source, current string, svc *fakeService) *Installer {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the installer targets systemd")
	}
	dir := t.TempDir()
	in := &Installer{Source: src, Current: current, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		BinPath: filepath.Join(dir, "bin", "lanternfish-gate"), PrevPath: filepath.Join(dir, "lib", "lanternfish-gate.prev"),
		DataPath: filepath.Join(dir, "state", "gate.json"), BackupDir: filepath.Join(dir, "backups"),
		StatusPath: filepath.Join(dir, "status.json"), RequestPath: filepath.Join(dir, "state", "update-request.json"),
		Stop:  func() error { svc.running = false; return nil },
		Start: func() error { svc.running = true; svc.starts++; return nil },
		Healthy: func(context.Context) error {
			if svc.healthy != nil {
				return svc.healthy()
			}
			return nil
		}}
	os.MkdirAll(filepath.Dir(in.BinPath), 0o755)
	os.MkdirAll(filepath.Dir(in.DataPath), 0o755)
	os.WriteFile(in.BinPath, []byte("#!/bin/sh\necho "+current+"\n"), 0o755)
	os.WriteFile(in.DataPath, []byte(`{"version":2}`), 0o600)
	return in
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyInstallsAndKeepsRollbackCopies(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.0", svc)

	if err := WriteRequest(in.RequestPath, Request{Version: "0.3.0", RequestedBy: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	if err := in.RunRequest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, in.BinPath), "echo 0.3.0") || !strings.Contains(read(t, in.PrevPath), "echo 0.2.0") {
		t.Fatal("binary not swapped, or previous one not kept")
	}
	if _, err := os.Stat(in.RequestPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("request not consumed")
	}
	backups, _ := filepath.Glob(filepath.Join(in.BackupDir, "gate.json.0.2.0.*"))
	if len(backups) != 1 || read(t, backups[0]) != `{"version":2}` {
		t.Fatalf("data backup: %v", backups)
	}
	st, _ := ReadStatus(in.StatusPath)
	if st.State != "succeeded" || st.Version != "0.3.0" || st.From != "0.2.0" || st.RequestedBy != "dashboard" || !svc.running {
		t.Fatalf("status: %+v running=%v", st, svc.running)
	}
}

func TestApplyRollsBackAnUnhealthyRelease(t *testing.T) {
	priv, keys := testKey(t)
	srv := fakeGitHub(t, signedRelease(t, priv, "v0.3.0", "0.3.0", true))
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.2.0", svc)
	svc.healthy = func() error {
		// The new version "migrates" the data file, then fails.
		os.WriteFile(in.DataPath, []byte(`{"version":3}`), 0o600)
		svc.healthy = nil
		return errors.New("crashed")
	}
	if err := in.Apply(context.Background(), "0.3.0", "test", ApplyOptions{}); err == nil {
		t.Fatal("unhealthy update reported success")
	}
	if !strings.Contains(read(t, in.BinPath), "echo 0.2.0") || read(t, in.DataPath) != `{"version":2}` || !svc.running {
		t.Fatal("not rolled back")
	}
	if st, _ := ReadStatus(in.StatusPath); st.State != "rolled_back" {
		t.Fatalf("status: %+v", st)
	}
}

func TestApplyRefuses(t *testing.T) {
	priv, keys := testKey(t)
	_, otherKeys := testKey(t)
	good := signedRelease(t, priv, "v0.3.0", "0.3.0", true)
	bad := signedRelease(t, priv, "v0.4.0", "0.4.0", true)
	name := ArchiveName("0.4.0", runtime.GOOS, runtime.GOARCH)
	bad.files[name] = fakeArchive(t, "0.4.1") // not what was signed
	pre := signedRelease(t, priv, "v0.5.0-rc.1", "0.5.0-rc.1", true)
	srv := fakeGitHub(t, good, bad, pre)

	cases := []struct {
		name, current, version string
		keys                   []PublicKey
		opt                    ApplyOptions
	}{
		{"older", "0.3.0", "0.3.0", keys, ApplyOptions{}},
		{"untrusted key", "0.2.0", "0.3.0", otherKeys, ApplyOptions{}},
		{"tampered archive", "0.2.0", "0.4.0", keys, ApplyOptions{}},
		{"pre-release not asked for", "0.2.0", "0.5.0-rc.1", keys, ApplyOptions{}},
		{"missing", "0.2.0", "0.9.0", keys, ApplyOptions{}},
	}
	for _, c := range cases {
		svc := &fakeService{running: true}
		in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: c.keys}, c.current, svc)
		if err := in.Apply(context.Background(), c.version, "test", c.opt); err == nil {
			t.Errorf("%s: installed", c.name)
		}
		if !strings.Contains(read(t, in.BinPath), "echo "+c.current) || svc.starts != 0 {
			t.Errorf("%s: touched the installation", c.name)
		}
	}
	// A pre-release asked for on purpose installs.
	svc := &fakeService{running: true}
	in := newInstaller(t, &Source{Repo: "o/r", API: srv.URL, Keys: keys}, "0.3.0", svc)
	if err := in.Apply(context.Background(), "0.5.0-rc.1", "cli", ApplyOptions{AllowPrerelease: true}); err != nil {
		t.Fatalf("pre-release on purpose: %v", err)
	}
}

func TestRequestMustBeARegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	os.WriteFile(target, []byte(`{"version":"1.0.0"}`), 0o600)
	link := filepath.Join(dir, "update-request.json")
	os.Symlink(target, link)
	if _, err := ReadRequest(link); err == nil {
		t.Fatal("followed a symlinked request")
	}
	os.Remove(link)
	os.WriteFile(link, []byte(`{"version":"1.0.0","extra":1}`), 0o644)
	if _, err := ReadRequest(link); err == nil {
		t.Fatal("accepted unknown fields")
	}
}

func TestTrustedKeys(t *testing.T) {
	// The committed key file must always parse: a bad line would turn off
	// updates for everyone.
	builtIn, err := BuiltInKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, extra := testKey(t)
	dir := t.TempDir()
	local := filepath.Join(dir, "release-keys")
	os.WriteFile(local, []byte("# local\nlfrk1 "+base64.StdEncoding.EncodeToString(extra[0].Key)+" spare key\n"), 0o644)
	keys, err := TrustedKeys(local)
	if err != nil || len(keys) != len(builtIn)+1 || keys[len(keys)-1].Comment != "spare key" {
		t.Fatalf("built-in plus local: %v %v", keys, err)
	}
	os.WriteFile(local, []byte("not a key\n"), 0o644)
	if _, err := TrustedKeys(local); err == nil {
		t.Fatal("accepted a malformed local key file")
	}
	if len(builtIn) == 0 {
		if _, err := TrustedKeys(filepath.Join(dir, "missing")); err == nil {
			t.Fatal("no keys at all should be an error")
		}
	}
}
