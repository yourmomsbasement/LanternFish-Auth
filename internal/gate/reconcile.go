package gate

import (
	"errors"
	"log"
	"sort"
)

// reconcileLimits applies per-device limits from the current policies to
// what already exists. It runs whenever policies change.
//
// SECURITY: tightening a policy has to take effect on existing state, not
// only on what is created afterwards. A shorter approval lifetime shortens
// existing network approvals, fewer remembered networks drops the oldest
// approvals (and the sessions and certificate grants on those networks), and
// a lower session cap ends a device's oldest sessions. Open streams are then
// re-judged against the result (recheckStreams).
func (g *Gate) reconcileLimits() {
	now := g.cfg.Now()
	caps := map[string]int{}              // device ID -> session cap
	keeps := map[string]map[string]bool{} // device ID -> networks still approved, where some were dropped
	err := g.store.Update(func(d *storeData) error {
		changed := false
		for id, dev := range d.Devices {
			pol := g.policyFor(dev)
			caps[id] = pol.Policy.Session.MaxPerDevice
			ttl := pol.approvalTTL()
			nets := make([]NetworkApproval, 0, len(dev.Networks))
			for _, a := range dev.Networks {
				if ttl > 0 && a.ExpiresAt.After(a.ApprovedAt.Add(ttl)) {
					a.ExpiresAt = a.ApprovedAt.Add(ttl)
				}
				if now.Before(a.ExpiresAt) {
					nets = append(nets, a)
				}
			}
			sort.SliceStable(nets, func(i, j int) bool { return nets[i].ApprovedAt.Before(nets[j].ApprovedAt) })
			if limit := pol.Policy.IP.RememberedNetworks; limit > 0 && len(nets) > limit {
				nets = nets[len(nets)-limit:]
			}
			if !sameApprovals(dev.Networks, nets) {
				changed = true
				keep := map[string]bool{}
				for _, a := range nets {
					keep[a.Network] = true
				}
				keeps[id] = keep
				dev.Networks = nets
			}
		}
		if !changed {
			return errNothingToRepair
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNothingToRepair) {
		log.Printf("apply policy limits to existing approvals: %v", err)
		g.audit.write(now, "policy_limits_not_applied", map[string]any{"error": err.Error()})
	}
	for id, keep := range keeps {
		g.sessions.removeDeviceNetworksExcept(id, keep)
		g.grants.removeDeviceNetworksExcept(id, keep)
	}
	for id, max := range caps {
		g.sessions.trimDevice(id, max)
	}
	if len(keeps) > 0 {
		g.audit.write(now, "policy_limits_applied", map[string]any{"devices": len(keeps)})
	}
}

func sameApprovals(a, b []NetworkApproval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
