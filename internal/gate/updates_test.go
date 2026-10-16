package gate

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yourmomsbasement/lanternfish-auth/internal/update"
)

// fakeReleases serves a GitHub releases API with one signed release.
func fakeReleases(t *testing.T, version string) ([]update.PublicKey, *httptest.Server) {
	t.Helper()
	file, pub, err := update.GenerateKey("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := update.OpenKey(file, "correct horse battery")
	keys, _ := update.ParsePublicKeys([]byte(update.FormatPublicKey(pub, "maintainer")))
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.tar.gz"), []byte("archive"), 0o644)
	manifest, _ := update.BuildManifest(dir, version, []string{"a.tar.gz"}, time.Now())
	sig, _ := update.Sign(priv, manifest)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases":
			json.NewEncoder(w).Encode([]map[string]any{{"tag_name": "v" + version, "html_url": "https://example/v" + version,
				"published_at": time.Now().UTC(), "assets": []map[string]any{
					{"name": update.ManifestName, "browser_download_url": srv.URL + "/m"},
					{"name": update.SignatureName, "browser_download_url": srv.URL + "/s"}}}})
		case "/m":
			w.Write(manifest)
		case "/s":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return keys, srv
}

func TestUpdatePage(t *testing.T) {
	h := newHarness(t)
	keys, srv := fakeReleases(t, "0.3.0")
	dir := t.TempDir()
	h.g.cfg.Version = "0.2.0"
	h.g.cfg.Updates = &Updates{Source: &update.Source{Repo: "o/r", API: srv.URL, Keys: keys},
		RequestPath: filepath.Join(dir, "update-request.json"), StatusPath: filepath.Join(dir, "status.json"), AutoPolicy: "off"}

	rec := h.admin2("GET", "update", nil)
	var page struct {
		Current         string `json:"current"`
		Supported       bool   `json:"supported"`
		UpdateAvailable bool   `json:"update_available"`
		Latest          struct {
			Version  string `json:"version"`
			SignedBy string `json:"signed_by"`
		} `json:"latest"`
	}
	json.Unmarshal(rec.Body.Bytes(), &page)
	if rec.Code != http.StatusOK || !page.Supported || !page.UpdateAvailable || page.Latest.Version != "0.3.0" || page.Latest.SignedBy != "maintainer" {
		t.Fatalf("update page: %d %s", rec.Code, rec.Body)
	}

	// Only the offered release, only once at a time.
	if rec := h.admin2("POST", "update", map[string]string{"version": "0.2.9"}); rec.Code != http.StatusConflict {
		t.Fatalf("unoffered version: %d", rec.Code)
	}
	if rec := h.admin2("POST", "update", map[string]string{"version": "0.3.0"}); rec.Code != http.StatusAccepted {
		t.Fatalf("request: %d %s", rec.Code, rec.Body)
	}
	req, err := update.ReadRequest(h.g.cfg.Updates.RequestPath)
	if err != nil || req.Version != "0.3.0" || req.RequestedBy != "builder" {
		t.Fatalf("request file: %+v %v", req, err)
	}
	if rec := h.admin2("POST", "update", map[string]string{"version": "0.3.0"}); rec.Code != http.StatusConflict {
		t.Fatalf("second request while pending: %d", rec.Code)
	}

	// Already on it: nothing to install.
	os.Remove(h.g.cfg.Updates.RequestPath)
	h.g.cfg.Version = "0.3.0"
	if rec := h.admin2("POST", "update", map[string]string{"version": "0.3.0"}); rec.Code != http.StatusConflict {
		t.Fatalf("same version: %d", rec.Code)
	}
}

func TestUpdatesNeedTrustedKeys(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.Updates = &Updates{Source: &update.Source{Repo: "o/r"}, KeysError: "no trusted release keys yet",
		RequestPath: filepath.Join(t.TempDir(), "r.json")}
	rec := h.admin2("GET", "update", nil)
	if rec.Code != http.StatusOK || decode[map[string]any](t, rec)["supported"] != false {
		t.Fatalf("without keys: %s", rec.Body)
	}
	if rec := h.admin2("POST", "update", map[string]string{"version": "9.9.9"}); rec.Code != http.StatusConflict {
		t.Fatalf("request without keys: %d", rec.Code)
	}
	// Outside the admin networks, the update API doesn't exist either.
	if rec := h.doFrom("203.0.113.9:1", "GET", "/_lanternfish/admin/v2/update", nil,
		map[string]string{"Authorization": "Bearer " + h.adminKey}); rec.Code != http.StatusNotFound {
		t.Fatalf("from the internet: %d", rec.Code)
	}
}
