package gate

import (
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Country lookups from a local MaxMind-format database (GeoLite2-Country or
// GeoIP2-Country), never an online service: no lookup leaves this machine,
// and nothing is looked up per video segment (results are cached).
//
// Location is a policy signal, not an authentication factor: VPNs and mobile
// networks routinely show misleading countries. Unknown, private and stale
// results are "unknown", never an assumed home country.

type geoResult struct {
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2; "" when unknown
	Status  string `json:"status"`            // "ok", "unknown", "private", "stale" or "unavailable"
}

func (r geoResult) known() bool { return r.Status == "ok" && r.Country != "" }

// geoResolver reads the database, reloading it when the file changes.
type geoResolver struct {
	path   string
	maxAge time.Duration // a database older than this is stale

	mu       sync.Mutex
	db       *maxminddb.Reader
	modTime  time.Time
	built    time.Time
	checked  time.Time
	loadErr  string
	cache    map[netip.Addr]geoCached
	lookupFn func(netip.Addr) (string, bool) // tests replace the database
}

type geoCached struct {
	res     geoResult
	expires time.Time
}

const (
	geoCacheTTL = 10 * time.Minute
	geoCacheMax = 20000
)

func newGeoResolver(path string, maxAge time.Duration) *geoResolver {
	if maxAge == 0 {
		maxAge = 45 * 24 * time.Hour
	}
	return &geoResolver{path: path, maxAge: maxAge, cache: map[netip.Addr]geoCached{}}
}

// configured reports whether a database (or test lookup) is set up.
func (g *geoResolver) configured() bool { return g != nil && (g.path != "" || g.lookupFn != nil) }

// reload opens the database if it changed. Caller holds g.mu.
func (g *geoResolver) reload(now time.Time) {
	if g.lookupFn != nil || g.path == "" || now.Sub(g.checked) < time.Minute && g.db != nil {
		return
	}
	g.checked = now
	st, err := os.Stat(g.path)
	if err != nil {
		g.loadErr = err.Error()
		return
	}
	if g.db != nil && st.ModTime().Equal(g.modTime) {
		return
	}
	db, err := maxminddb.Open(g.path)
	if err != nil {
		g.loadErr = err.Error()
		return
	}
	if g.db != nil {
		g.db.Close()
	}
	g.db, g.modTime, g.loadErr = db, st.ModTime(), ""
	g.built = time.Unix(int64(db.Metadata.BuildEpoch), 0)
	g.cache = map[netip.Addr]geoCached{}
}

func (g *geoResolver) lookup(ip string, now time.Time) geoResult {
	if !g.configured() {
		return geoResult{Status: "unavailable"}
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return geoResult{Status: "unknown"}
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || !a.IsGlobalUnicast() {
		return geoResult{Status: "private"}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(now)
	if c, ok := g.cache[a]; ok && now.Before(c.expires) {
		return c.res
	}
	res := g.resolve(a, now)
	if len(g.cache) >= geoCacheMax {
		g.cache = map[netip.Addr]geoCached{} // simple bound; refills from hot addresses
	}
	g.cache[a] = geoCached{res, now.Add(geoCacheTTL)}
	return res
}

// resolve looks up a. Caller holds g.mu.
func (g *geoResolver) resolve(a netip.Addr, now time.Time) geoResult {
	if g.lookupFn != nil {
		if c, ok := g.lookupFn(a); ok {
			return geoResult{Country: c, Status: "ok"}
		}
		return geoResult{Status: "unknown"}
	}
	if g.db == nil {
		return geoResult{Status: "unavailable"}
	}
	if now.Sub(g.built) > g.maxAge {
		return geoResult{Status: "stale"}
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		Registered struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}
	r := g.db.Lookup(a)
	if !r.Found() || r.Decode(&rec) != nil {
		return geoResult{Status: "unknown"}
	}
	c := rec.Country.ISOCode
	if c == "" {
		c = rec.Registered.ISOCode
	}
	if len(c) != 2 {
		return geoResult{Status: "unknown"}
	}
	return geoResult{Country: c, Status: "ok"}
}

// health describes the database for the dashboard.
func (g *geoResolver) health(now time.Time) map[string]any {
	if !g.configured() {
		return map[string]any{"configured": false}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reload(now)
	out := map[string]any{"configured": true, "path": g.path}
	if g.loadErr != "" {
		out["error"] = g.loadErr
	}
	if !g.built.IsZero() {
		out["built"] = g.built.UTC()
		out["age_days"] = int(now.Sub(g.built).Hours() / 24)
		out["stale"] = now.Sub(g.built) > g.maxAge
	}
	return out
}
