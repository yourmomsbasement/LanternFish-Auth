package gate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachedCountryExpiresWhenDatabaseBecomesStale(t *testing.T) {
	built := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, testMMDB(t, map[string]string{"203.0.113.0/24": "DE"}, built), 0o600); err != nil {
		t.Fatal(err)
	}
	g := newGeoResolver(path, 24*time.Hour)
	defer func() {
		if g.db != nil {
			g.db.Close()
		}
	}()
	// Prime the ten-minute country cache just before the database expires.
	now := built.Add(24*time.Hour - time.Second)
	if r := g.lookup("203.0.113.9", now); r.Country != "DE" || !r.known() {
		t.Fatalf("fresh database: %+v", r)
	}
	if r := g.lookup("203.0.113.9", now.Add(2*time.Second)); r.Status != "stale" || r.known() {
		t.Fatalf("cached country outlived database freshness: %+v", r)
	}
}
