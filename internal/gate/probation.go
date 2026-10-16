package gate

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yourmomsbasement/lanternfish-auth/internal/update"
)

// Probation: right after an update the updater watches the new version for a
// while and rolls back, data file included, if it turns out unhealthy.
//
// SECURITY: anything saved during that time would be undone by the rollback:
// a revoked device would come back, a used enrollment ticket would work
// again, a policy restriction would vanish. So while the updater's probation
// marker exists the Gate refuses every change to its data (enrollment, admin
// changes, approving a new network) with 503 update_in_progress, and the
// store refuses writes as a backstop. Signing in and proxying keep working:
// sessions live in memory, and a device's last sign-in time is simply not
// saved. The marker goes away when the update is confirmed or rolled back.

// startProbation enters probation if the marker is there, and leaves it once
// the marker is gone.
func (g *Gate) startProbation() {
	path := g.cfg.ProbationPath
	if !update.ProbationActive(path, time.Now()) {
		return
	}
	g.store.readOnly.Store(true)
	log.Printf("on probation after an update: changes to the data file are refused until the update is confirmed")
	go func() {
		for update.ProbationActive(path, time.Now()) {
			time.Sleep(time.Second)
		}
		g.store.readOnly.Store(false)
		log.Printf("update confirmed: changes are allowed again")
	}()
}

// changesState reports whether r could change the Gate's data. Signing in,
// out and challenges only touch memory (or fail safely), so devices and the
// dashboard keep working during probation.
func changesState(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || !strings.HasPrefix(r.URL.Path, pathPrefix) {
		return false
	}
	switch r.URL.Path {
	case pathPrefix + "v1/challenge", pathPrefix + "v1/session", pathPrefix + "v1/logout",
		adminPath + "/session", adminPath + "/logout":
		return false
	}
	return true
}
