package update

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestSignReleasesScript runs scripts/sign-releases.sh and
// scripts/release-manifest.sh against a fake GitHub, and checks that what
// they produce is exactly what Gates verify.
func TestSignReleasesScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the signing script runs on Linux or macOS")
	}
	for _, tool := range []string{"bash", "openssl", "jq", "curl", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	root, _ := filepath.Abs("../..")
	script := filepath.Join(root, "scripts", "sign-releases.sh")
	home := t.TempDir()
	token := "test-token"
	os.WriteFile(filepath.Join(home, "token"), []byte(token+"\n"), 0o600)

	// Two releases: v0.3.0 is good; v0.4.0's archive was altered after the
	// manifest was made.
	type asset struct {
		name string
		data []byte
	}
	var mu sync.Mutex
	releases := map[string][]asset{}
	for _, v := range []string{"0.3.0", "0.4.0"} {
		dist := t.TempDir()
		os.WriteFile(filepath.Join(dist, ArchiveName(v, "linux", "amd64")), []byte("archive "+v), 0o644)
		os.WriteFile(filepath.Join(dist, "SHA256SUMS"), []byte("sums "+v), 0o644)
		out, err := exec.Command("bash", filepath.Join(root, "scripts", "release-manifest.sh"), "v"+v, dist).Output()
		if err != nil {
			t.Fatalf("release-manifest.sh: %v", err)
		}
		m, err := ParseManifest(out)
		if err != nil || m.Version != v || len(m.Files) != 2 {
			t.Fatalf("manifest from the script doesn't parse: %v\n%s", err, out)
		}
		releases["v"+v] = []asset{{ManifestName, out}, {ArchiveName(v, "linux", "amd64"), []byte("archive " + v)}, {"SHA256SUMS", []byte("sums " + v)}}
	}
	releases["v0.4.0"][1].data = []byte("archive 0.4.0 (altered)")

	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		authed := r.Header.Get("Authorization") == "Bearer "+token
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/o/r/releases":
			var out []map[string]any
			for _, tag := range []string{"v0.4.0", "v0.3.0"} { // newest first, like GitHub
				var as []map[string]any
				for _, a := range releases[tag] {
					as = append(as, map[string]any{"name": a.name, "url": srv.URL + "/assets/" + tag + "/" + a.name,
						"browser_download_url": srv.URL + "/dl/" + tag + "/" + a.name})
				}
				out = append(out, map[string]any{"tag_name": tag, "draft": false, "prerelease": false,
					"upload_url": srv.URL + "/uploads/" + tag + "/assets{?name,label}", "assets": as})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/dl/"):
			// Public download links, as for published releases.
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/dl/"), "/")
			for _, a := range releases[parts[0]] {
				if a.name == parts[1] {
					w.Write(a.data)
					return
				}
			}
			http.NotFound(w, r)
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/assets/"):
			if !authed || r.Header.Get("Accept") != "application/octet-stream" {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/assets/"), "/")
			for _, a := range releases[parts[0]] {
				if a.name == parts[1] {
					w.Write(a.data)
					return
				}
			}
			http.NotFound(w, r)
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/uploads/"):
			if !authed || r.Header.Get("Content-Type") != "application/octet-stream" || r.URL.Query().Get("name") != SignatureName {
				http.Error(w, "bad upload", http.StatusForbidden)
				return
			}
			tag := strings.Split(strings.TrimPrefix(r.URL.Path, "/uploads/"), "/")[0]
			for _, a := range releases[tag] {
				if a.name == SignatureName {
					http.Error(w, `{"message":"already_exists"}`, http.StatusUnprocessableEntity)
					return
				}
			}
			body, _ := io.ReadAll(r.Body)
			releases[tag] = append(releases[tag], asset{SignatureName, body})
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Start()
	defer srv.Close()

	run := func(args ...string) (string, int) {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "config"),
			"LANTERNFISH_SIGNING_KEY="+filepath.Join(home, "release-key.pem"),
			"LANTERNFISH_SIGNING_PASSPHRASE=a long test passphrase", "LANTERNFISH_KEY_COMMENT=maintainer",
			"LANTERNFISH_REPO=o/r", "LANTERNFISH_UPDATE_API="+srv.URL, "GITHUB_TOKEN_FILE="+filepath.Join(home, "token"))
		out, err := cmd.CombinedOutput()
		code := 0
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}

	out, code := run("keygen")
	if code != 0 {
		t.Fatalf("keygen: %d %s", code, out)
	}
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "lfrk1 ") {
			line = l
		}
	}
	keys, err := ParsePublicKeys([]byte(line))
	if err != nil || len(keys) != 1 || keys[0].Comment != "maintainer" {
		t.Fatalf("public key line %q: %v", line, err)
	}
	if pem, _ := os.ReadFile(filepath.Join(home, "release-key.pem")); !strings.Contains(string(pem), "ENCRYPTED PRIVATE KEY") {
		t.Fatal("the key file isn't encrypted")
	}

	if out, code := run("pending"); code != 3 || !strings.Contains(out, "v0.3.0") || !strings.Contains(out, "v0.4.0") {
		t.Fatalf("pending: %d %s", code, out)
	}

	// The altered release stops the whole run before anything is signed.
	if out, code := run("sign"); code == 0 || !strings.Contains(out, "does not match") {
		t.Fatalf("sign with an altered file: %d %s", code, out)
	}
	mu.Lock()
	for _, a := range releases["v0.3.0"] {
		if a.name == SignatureName {
			t.Fatal("signed something although a release failed its check")
		}
	}
	mu.Unlock()

	if out, code := run("sign", "v0.3.0"); code != 0 {
		t.Fatalf("sign v0.3.0: %d %s", code, out)
	}
	var manifest, sig []byte
	mu.Lock()
	for _, a := range releases["v0.3.0"] {
		switch a.name {
		case ManifestName:
			manifest = a.data
		case SignatureName:
			sig = a.data
		}
	}
	mu.Unlock()
	m, signer, err := Verify(manifest, sig, keys)
	if err != nil || m.Version != "0.3.0" || signer != "maintainer" {
		t.Fatalf("the script's signature doesn't verify in the Gate: %v", err)
	}
	if out, code := run("pending"); code != 3 || strings.Contains(out, "v0.3.0") {
		t.Fatalf("pending after signing: %d %s", code, out)
	}
	if out, code := run("sign", "v0.3.0"); code == 0 || !strings.Contains(out, "already signed") {
		t.Fatalf("signed twice: %s", out)
	}
	if out, code := run("pubkey"); code != 0 || !strings.Contains(out, strings.Fields(line)[1]) {
		t.Fatalf("pubkey: %d %s", code, out)
	}
}
