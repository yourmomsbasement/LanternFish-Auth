package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Source finds releases on GitHub.
//
// SECURITY: nothing from GitHub is trusted until the manifest's signature
// verifies against a local key; GitHub only tells us where to look.
type Source struct {
	Repo   string // owner/name
	API    string // default https://api.github.com
	Client *http.Client
	Keys   []PublicKey
}

const (
	maxManifest = 256 << 10
	maxArchive  = 200 << 20
)

type ghRelease struct {
	Tag        string    `json:"tag_name"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Published  time.Time `json:"published_at"`
	HTMLURL    string    `json:"html_url"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Release is a release whose manifest verified.
type Release struct {
	Version   Version
	Tag       string
	Published time.Time
	URL       string // release page
	SignedBy  string // the key's comment
	Manifest  *Manifest
	assets    map[string]string
}

// Candidate describes a release found on GitHub, verified or not.
type Candidate struct {
	Tag        string    `json:"tag"`
	Version    string    `json:"version"`
	Prerelease bool      `json:"prerelease"`
	Published  time.Time `json:"published_at"`
	URL        string    `json:"url"`
	Verified   bool      `json:"verified"`
	SignedBy   string    `json:"signed_by,omitempty"`
	Problem    string    `json:"problem,omitempty"`
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (s *Source) api() string {
	if s.API != "" {
		return strings.TrimRight(s.API, "/")
	}
	return "https://api.github.com"
}

func (s *Source) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lanternfish-gate-updater")
	if strings.HasPrefix(url, s.api()) {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: response too large", url)
	}
	return data, nil
}

func (s *Source) releases(ctx context.Context) ([]ghRelease, error) {
	if !validRepo(s.Repo) {
		return nil, fmt.Errorf("update repository %q is not owner/name", s.Repo)
	}
	data, err := s.get(ctx, s.api()+"/repos/"+s.Repo+"/releases?per_page=20", 4<<20)
	if err != nil {
		return nil, err
	}
	var rs []ghRelease
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("GitHub releases: %w", err)
	}
	return rs, nil
}

func validRepo(r string) bool {
	owner, name, ok := strings.Cut(r, "/")
	valid := func(s string) bool {
		if s == "" || len(s) > 100 {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
		return true
	}
	return ok && valid(owner) && valid(name)
}

// verify fetches and checks one release's manifest.
func (s *Source) verify(ctx context.Context, r ghRelease) (*Release, error) {
	v, err := ParseVersion(r.Tag)
	if err != nil {
		return nil, err
	}
	assets := map[string]string{}
	for _, a := range r.Assets {
		assets[a.Name] = a.URL
	}
	if assets[ManifestName] == "" {
		return nil, errors.New("no " + ManifestName + " attached")
	}
	if assets[SignatureName] == "" {
		return nil, errors.New("not signed yet (no " + SignatureName + " attached)")
	}
	manifest, err := s.get(ctx, assets[ManifestName], maxManifest)
	if err != nil {
		return nil, err
	}
	sig, err := s.get(ctx, assets[SignatureName], maxManifest)
	if err != nil {
		return nil, err
	}
	m, signer, err := Verify(manifest, sig, s.Keys)
	if err != nil {
		return nil, err
	}
	// SECURITY: the signed manifest must be for this release, so a genuine
	// older manifest can't be attached to a newer tag.
	mv, _ := ParseVersion(m.Version)
	if mv.Compare(v) != 0 {
		return nil, fmt.Errorf("signed manifest is for %s, not %s", m.Version, r.Tag)
	}
	return &Release{Version: v, Tag: r.Tag, Published: r.Published, URL: r.HTMLURL, SignedBy: signer,
		Manifest: m, assets: assets}, nil
}

// Find returns the newest verified release (pre-releases only if
// prerelease), plus what was found on the way, newest first.
func (s *Source) Find(ctx context.Context, prerelease bool) (*Release, []Candidate, error) {
	rs, err := s.releases(ctx)
	if err != nil {
		return nil, nil, err
	}
	type cand struct {
		r ghRelease
		v Version
	}
	var cs []cand
	for _, r := range rs {
		if r.Draft || (r.Prerelease && !prerelease) {
			continue
		}
		if v, err := ParseVersion(r.Tag); err == nil {
			cs = append(cs, cand{r, v})
		}
	}
	// Newest first.
	for i := 1; i < len(cs); i++ {
		for j := i; j > 0 && cs[j].v.Compare(cs[j-1].v) > 0; j-- {
			cs[j], cs[j-1] = cs[j-1], cs[j]
		}
	}
	var seen []Candidate
	for i, c := range cs {
		if i >= 5 {
			break
		}
		cand := Candidate{Tag: c.r.Tag, Version: c.v.String(), Prerelease: c.r.Prerelease, Published: c.r.Published, URL: c.r.HTMLURL}
		rel, err := s.verify(ctx, c.r)
		if err != nil {
			cand.Problem = err.Error()
			seen = append(seen, cand)
			continue
		}
		cand.Verified, cand.SignedBy = true, rel.SignedBy
		seen = append(seen, cand)
		return rel, seen, nil
	}
	return nil, seen, nil
}

// Get returns a specific verified release.
func (s *Source) Get(ctx context.Context, version string) (*Release, error) {
	want, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	rs, err := s.releases(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range rs {
		if v, err := ParseVersion(r.Tag); err == nil && v.Compare(want) == 0 && !r.Draft {
			return s.verify(ctx, r)
		}
	}
	return nil, fmt.Errorf("release %s not found", want)
}

// Download fetches a file of the release and checks it against the manifest.
func (s *Source) Download(ctx context.Context, rel *Release, name string) ([]byte, error) {
	f, ok := rel.Manifest.File(name)
	if !ok {
		return nil, fmt.Errorf("%s is not in the signed manifest", name)
	}
	url := rel.assets[name]
	if url == "" {
		return nil, fmt.Errorf("%s is not attached to the release", name)
	}
	if f.Size > maxArchive {
		return nil, fmt.Errorf("%s is too large", name)
	}
	data, err := s.get(ctx, url, f.Size)
	if err != nil {
		return nil, err
	}
	return data, f.Check(data)
}
