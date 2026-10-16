package gate

import (
	"errors"
	"log"
)

// repairStoredState fixes security state saved by earlier versions under
// rules that turned out too lax. It runs once at startup, before the Gate
// serves anything (and before probation, which would refuse the write).
func (g *Gate) repairStoredState() {
	var owners []string
	err := g.store.Update(func(d *storeData) error {
		owners = repairPasskeyTrust(d)
		if len(owners) == 0 {
			return errNothingToRepair
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNothingToRepair) {
		log.Printf("repair stored state: %v", err)
		return
	}
	if len(owners) > 0 {
		g.audit.write(g.cfg.Now(), "passkey_trust_repaired", map[string]any{"subjects": owners,
			"detail": "passkeys without certificate-chain attestation are no longer marked verified; approvals they granted were withdrawn"})
		log.Printf("%d owner(s) had passkeys wrongly marked as trusted; reclassified, and the approvals they granted withdrawn", len(owners))
	}
}

var errNothingToRepair = errors.New("nothing to repair")
