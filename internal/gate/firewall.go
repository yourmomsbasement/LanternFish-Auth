package gate

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Firewall plan: the dashboard collects what the Proxmox host needs to know
// (container IDs, addresses, ports, who talks to whom) and the Gate turns it
// into a shell script that writes the guests' Proxmox firewall files.
//
// SECURITY: the script runs as root on the hypervisor, so every value in it
// is validated here against a strict pattern (IDs are numbers, addresses are
// parsed, names are a short safe alphabet) and file contents are written
// through quoted here-documents, so nothing is expanded by the shell. The
// script never turns firewalls on at the datacenter or NIC level, which could
// lock the administrator out; it checks them and says what to do.

type FirewallPlan struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`

	Gate FirewallGate `json:"gate"`
	// InternalNet is the backends' network (vmbr1 in the guide).
	InternalNet string          `json:"internal_net"`
	Guests      []FirewallGuest `json:"guests"`
}

// FirewallGate is the Gate's own container.
type FirewallGate struct {
	ID         int    `json:"id"`
	LANNIC     string `json:"lan_nic"`     // e.g. net0: where HTTPS comes in
	InternalIP string `json:"internal_ip"` // the Gate's address on InternalNet
	PublicPort int    `json:"public_port"` // HTTPS, usually 443
	// SSHFrom are the addresses or networks allowed to SSH to the Gate.
	SSHFrom   []string `json:"ssh_from"`
	AllowPing bool     `json:"allow_ping"`
}

// FirewallGuest is a container or VM behind the Gate.
type FirewallGuest struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"` // "ct" or "vm"
	ID    int    `json:"id"`
	IP    string `json:"ip"`
	Ports []int  `json:"ports"`
	// FromGate: the Gate reaches it on Ports (Jellyfin and applications).
	FromGate bool `json:"from_gate"`
	// TalksTo names other guests this one connects to (Sonarr to
	// qBittorrent): their Ports are opened for it, both ways.
	TalksTo []string `json:"talks_to"`
	// Sources are other addresses or networks allowed to its Ports.
	Sources []string `json:"sources"`
	// BlockPrivate stops it reaching private networks (your LAN) except
	// what TalksTo allows; the internet stays reachable.
	BlockPrivate bool   `json:"block_private"`
	NIC          string `json:"nic"` // the guest's NIC on InternalNet, for its address filter (default net0)
	AppID        string `json:"app_id,omitempty"`
}

const (
	maxFirewallGuests = 64
	maxGuestPorts     = 16
)

var (
	fwNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$`)
	fwNICRE  = regexp.MustCompile(`^net[0-9]{1,2}$`)
)

func validGuestID(id int) bool { return id >= 100 && id <= 999999999 }

// fwSource parses an address or network for a firewall rule.
func fwSource(s string) (string, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap().String(), nil
	}
	return "", fmt.Errorf("%q is not an IP address or network", s)
}

// validate checks a plan and normalizes it in place.
func (p *FirewallPlan) validate() []string {
	var probs []string
	bad := func(f string, a ...any) { probs = append(probs, fmt.Sprintf(f, a...)) }
	g := &p.Gate
	if !validGuestID(g.ID) {
		bad("the Gate's container ID must be a Proxmox ID (100 or more)")
	}
	if g.LANNIC == "" {
		g.LANNIC = "net0"
	}
	if !fwNICRE.MatchString(g.LANNIC) {
		bad("the Gate's LAN interface must be like net0")
	}
	if a, err := netip.ParseAddr(g.InternalIP); err != nil || a.Zone() != "" {
		bad("the Gate's internal address %q isn't an IP address", g.InternalIP)
	} else {
		g.InternalIP = a.Unmap().String()
	}
	if g.PublicPort == 0 {
		g.PublicPort = 443
	}
	if g.PublicPort < 1 || g.PublicPort > 65535 {
		bad("the public port must be 1-65535")
	}
	for i, s := range g.SSHFrom {
		if v, err := fwSource(s); err != nil {
			bad("SSH: %v", err)
		} else {
			g.SSHFrom[i] = v
		}
	}
	var internal netip.Prefix
	if p.InternalNet != "" {
		pr, err := netip.ParsePrefix(p.InternalNet)
		if err != nil {
			bad("the internal network %q isn't a network like 10.20.0.0/24", p.InternalNet)
		} else {
			internal = pr.Masked()
			p.InternalNet = internal.String()
		}
	}
	if len(p.Guests) > maxFirewallGuests {
		bad("at most %d guests", maxFirewallGuests)
	}
	names, ids := map[string]bool{}, map[int]bool{g.ID: true}
	for i := range p.Guests {
		x := &p.Guests[i]
		x.Name = strings.TrimSpace(x.Name)
		label := fmt.Sprintf("guest %d", i+1)
		if !fwNameRE.MatchString(x.Name) {
			bad("%s needs a name of up to 40 letters, digits, spaces or ._()-", label)
		} else {
			label = fmt.Sprintf("%q", x.Name)
			if names[strings.ToLower(x.Name)] {
				bad("%s: two guests have that name", label)
			}
			names[strings.ToLower(x.Name)] = true
		}
		if x.Kind != "ct" && x.Kind != "vm" {
			bad("%s: type must be ct or vm", label)
		}
		if !validGuestID(x.ID) {
			bad("%s: the ID must be a Proxmox ID (100 or more)", label)
		} else if ids[x.ID] {
			bad("%s: ID %d is used twice (or is the Gate's)", label, x.ID)
		}
		ids[x.ID] = true
		if a, err := netip.ParseAddr(x.IP); err != nil || a.Zone() != "" {
			bad("%s: %q isn't an IP address", label, x.IP)
		} else {
			x.IP = a.Unmap().String()
		}
		if len(x.Ports) == 0 || len(x.Ports) > maxGuestPorts {
			bad("%s needs 1 to %d ports", label, maxGuestPorts)
		}
		for _, port := range x.Ports {
			if port < 1 || port > 65535 {
				bad("%s: port %d isn't 1-65535", label, port)
			}
		}
		sort.Ints(x.Ports)
		for j, s := range x.Sources {
			if v, err := fwSource(s); err != nil {
				bad("%s: %v", label, err)
			} else {
				x.Sources[j] = v
			}
		}
		if x.NIC == "" {
			x.NIC = "net0"
		}
		if !fwNICRE.MatchString(x.NIC) {
			bad("%s: the interface must be like net0", label)
		}
	}
	for _, x := range p.Guests {
		for _, t := range x.TalksTo {
			if !names[strings.ToLower(t)] || strings.EqualFold(t, x.Name) {
				bad("%q talks to %q, which isn't another guest in the plan", x.Name, t)
			}
		}
	}
	return probs
}

// warnings are things the plan allows but that are probably mistakes.
func (p *FirewallPlan) warnings(rt *routing) []string {
	var out []string
	internal, _ := netip.ParsePrefix(p.InternalNet)
	gateIP, _ := netip.ParseAddr(p.Gate.InternalIP)
	if internal.IsValid() && gateIP.IsValid() && !internal.Contains(gateIP) {
		out = append(out, fmt.Sprintf("the Gate's internal address %s isn't in %s", gateIP, internal))
	}
	byIP := map[string]FirewallGuest{}
	for _, x := range p.Guests {
		byIP[x.IP] = x
		if a, err := netip.ParseAddr(x.IP); err == nil && internal.IsValid() && !internal.Contains(a) {
			out = append(out, fmt.Sprintf("%q (%s) isn't on the internal network %s: anything on that network can still reach it unless its own firewall stops it", x.Name, x.IP, internal))
		}
		for _, t := range x.TalksTo {
			for _, y := range p.Guests {
				if strings.EqualFold(y.Name, t) && y.AppID == "jellyfin" {
					out = append(out, fmt.Sprintf("%q talks to Jellyfin: the Lanternfish plugin refuses requests the Gate didn't sign, so it will get 403", x.Name))
				}
			}
		}
	}
	// Every upstream the Gate uses should be reachable under the plan.
	if rt != nil {
		check := func(name string, u *url.URL) {
			if u == nil {
				return
			}
			host, port := u.Hostname(), u.Port()
			if port == "" {
				port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
			}
			x, ok := byIP[host]
			if !ok {
				if a, err := netip.ParseAddr(host); err == nil && !a.IsLoopback() {
					out = append(out, fmt.Sprintf("%s is at %s, which no guest in the plan has", name, host))
				}
				return
			}
			n, _ := strconv.Atoi(port)
			found := false
			for _, p := range x.Ports {
				found = found || p == n
			}
			if !x.FromGate || !found {
				out = append(out, fmt.Sprintf("the Gate reaches %s at %s:%s, but the plan doesn't let it (%q)", name, host, port, x.Name))
			}
		}
		check("Jellyfin", rt.jellyfin)
		for _, a := range rt.byID {
			if a.Enabled {
				check(a.Name, a.target)
			}
		}
	}
	sort.Strings(out)
	return out
}

// suggestFirewall drafts a plan from the network settings: one guest for
// Jellyfin and each application whose address is an IP.
func suggestFirewall(rt *routing) FirewallPlan {
	p := FirewallPlan{InternalNet: "10.20.0.0/24", Gate: FirewallGate{LANNIC: "net0", InternalIP: "10.20.0.2", PublicPort: 443,
		AllowPing: true, SSHFrom: []string{}}, Guests: []FirewallGuest{}}
	add := func(name, appID string, u *url.URL) {
		if u == nil {
			return
		}
		a, err := netip.ParseAddr(u.Hostname())
		if err != nil || a.IsLoopback() {
			return
		}
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = map[string]int{"http": 80, "https": 443}[u.Scheme]
		}
		clean := strings.Map(func(r rune) rune {
			if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._()-", r) {
				return r
			}
			return -1
		}, name)
		if len(clean) > 40 {
			clean = clean[:40]
		}
		p.Guests = append(p.Guests, FirewallGuest{Name: clean, Kind: "ct", IP: a.String(), Ports: []int{port}, FromGate: true,
			TalksTo: []string{}, Sources: []string{}, BlockPrivate: true, NIC: "net0", AppID: appID})
	}
	add("Jellyfin", "jellyfin", rt.jellyfin)
	ids := make([]string, 0, len(rt.byID))
	for id := range rt.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		add(rt.byID[id].Name, id, rt.byID[id].target)
	}
	return p
}

// ---- the script ----

func (p *FirewallPlan) guestFile(x FirewallGuest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Lanternfish firewall for %s %d (%s)\n", strings.ToUpper(x.Kind), x.ID, x.Name)
	b.WriteString("[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: ACCEPT\n")
	// SECURITY: ipfilter makes the guest send only from its own address, so
	// a compromised guest can't pose as the Gate to reach the others. The
	// address is listed explicitly: VMs have none in their config, and a CT
	// on DHCP would otherwise be left with none.
	b.WriteString("ipfilter: 1\n")
	fmt.Fprintf(&b, "\n[IPSET ipfilter-%s]\n%s\n", x.NIC, x.IP)
	b.WriteString("\n[RULES]\n")
	for _, port := range x.Ports {
		if x.FromGate {
			fmt.Fprintf(&b, "IN ACCEPT -source %s -p tcp -dport %d -log nolog # from the Gate\n", p.Gate.InternalIP, port)
		}
		for _, y := range p.Guests {
			for _, t := range y.TalksTo {
				if strings.EqualFold(t, x.Name) {
					fmt.Fprintf(&b, "IN ACCEPT -source %s -p tcp -dport %d -log nolog # from %s\n", y.IP, port, y.Name)
				}
			}
		}
		for _, s := range x.Sources {
			fmt.Fprintf(&b, "IN ACCEPT -source %s -p tcp -dport %d -log nolog # extra source\n", s, port)
		}
	}
	for _, t := range x.TalksTo {
		for _, y := range p.Guests {
			if strings.EqualFold(t, y.Name) {
				for _, port := range y.Ports {
					fmt.Fprintf(&b, "OUT ACCEPT -dest %s -p tcp -dport %d -log nolog # to %s\n", y.IP, port, y.Name)
				}
			}
		}
	}
	if x.BlockPrivate {
		b.WriteString("# The internet stays reachable (metadata, updates); private networks don't.\n")
		for _, n := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"} {
			fmt.Fprintf(&b, "OUT DROP -dest %s -log nolog\n", n)
		}
	}
	return b.String()
}

func (p *FirewallPlan) gateFile() string {
	g := p.Gate
	var b strings.Builder
	fmt.Fprintf(&b, "# Lanternfish firewall for CT %d (the Gate)\n", g.ID)
	b.WriteString("[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: ACCEPT\n\n[RULES]\n")
	fmt.Fprintf(&b, "IN ACCEPT -i %s -p tcp -dport %d -log nolog # HTTPS: the only public entry point\n", g.LANNIC, g.PublicPort)
	for _, s := range g.SSHFrom {
		fmt.Fprintf(&b, "IN ACCEPT -i %s -source %s -p tcp -dport 22 -log nolog # SSH\n", g.LANNIC, s)
	}
	if g.AllowPing {
		fmt.Fprintf(&b, "IN ACCEPT -i %s -p icmp -log nolog # ping\n", g.LANNIC)
	}
	return b.String()
}

// script renders the plan as a bash script for the Proxmox host.
func (p *FirewallPlan) script(version string, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/bash
# Proxmox firewall rules for Lanternfish, generated by Lanternfish Gate %s
# on %s.
#
# Review it, then run it on the Proxmox host as root:
#   DRY_RUN=1 bash lanternfish-firewall.sh   # show the files, change nothing
#   bash lanternfish-firewall.sh             # write them
#
# It writes /etc/pve/firewall/<ID>.fw for the Gate and each guest below,
# keeping any existing file as <ID>.fw.bak-<time>. Proxmox applies them within
# seconds. It doesn't turn the firewall on for the datacenter or for NICs (that
# could lock you out); it checks them and tells you what to do.
set -euo pipefail

DRY_RUN=${DRY_RUN:-0}
FW_DIR=${FW_DIR:-/etc/pve/firewall}
stamp=$(date +%%Y%%m%%d-%%H%%M%%S)
problems=0

if [ "$(id -u)" != 0 ] || ! command -v pve-firewall >/dev/null 2>&1; then
  echo "Run this as root on the Proxmox host." >&2
  exit 1
fi

# guest_config KIND ID: the guest's configuration, or nothing if it doesn't exist.
guest_config() {
  if [ "$1" = ct ]; then pct config "$2" 2>/dev/null || true; else qm config "$2" 2>/dev/null || true; fi
}

# write_fw KIND ID NAME, with the file on standard input.
write_fw() {
  local kind=$1 id=$2 name=$3 file=$FW_DIR/$2.fw content cfg
  content=$(cat)
  cfg=$(guest_config "$kind" "$id")
  if [ -z "$cfg" ]; then
    echo "!! $name: there is no $kind $id on this host; skipped" >&2
    problems=$((problems + 1))
    return
  fi
  # Every NIC needs firewall=1, or its rules don't apply.
  while IFS= read -r nic; do
    case "$nic" in
      *firewall=1*) ;;
      *) echo "!! $name ($kind $id): ${nic%%%%:*} has no firewall=1: set it under $id > Network > ${nic%%%%:*} > Firewall" >&2
         problems=$((problems + 1)) ;;
    esac
  done < <(printf '%%s\n' "$cfg" | grep -E '^net[0-9]+:' || true)
  if [ "$DRY_RUN" = 1 ]; then
    printf '\n----- %%s (%%s)\n%%s\n' "$file" "$name" "$content"
    return
  fi
  if [ -f "$file" ]; then
    cp -p "$file" "$file.bak-$stamp"
    echo "   kept the old $file as $file.bak-$stamp"
  fi
  printf '%%s\n' "$content" > "$file"
  echo "ok $name: wrote $file"
}

`, version, now.UTC().Format("2006-01-02 15:04 MST"))

	fmt.Fprintf(&b, "write_fw ct %d 'the Gate' <<'LANTERNFISH_FW'\n%sLANTERNFISH_FW\n\n", p.Gate.ID, p.gateFile())
	for _, x := range p.Guests {
		fmt.Fprintf(&b, "write_fw %s %d '%s' <<'LANTERNFISH_FW'\n%sLANTERNFISH_FW\n\n", x.Kind, x.ID, x.Name, p.guestFile(x))
	}
	b.WriteString(`if ! grep -qs '^enable: 1' "$FW_DIR/cluster.fw"; then
  echo "!! The datacenter firewall is off, so none of these rules apply yet. First make sure" >&2
  echo "   Datacenter > Firewall still lets you reach the web UI (8006) and SSH from your LAN," >&2
  echo "   then turn it on under Datacenter > Firewall > Options > Firewall." >&2
  problems=$((problems + 1))
fi

if [ "$DRY_RUN" = 1 ]; then
  echo
  echo "Dry run: nothing was changed."
elif [ "$problems" = 0 ]; then
  echo "Done. pve-firewall status:"
  pve-firewall status || true
fi
if [ "$problems" != 0 ]; then
  echo "$problems thing(s) need your attention (marked !! above)." >&2
  exit 2
fi
`)
	return b.String()
}

// ---- admin API ----

func (g *Gate) handleGetFirewall(w http.ResponseWriter, r *http.Request, _ *AdminKey) {
	var plan *FirewallPlan
	g.store.View(func(d *storeData) {
		if d.Firewall != nil {
			c := *d.Firewall
			plan = &c
		}
	})
	rt := g.routing.Load()
	suggested := suggestFirewall(rt)
	out := map[string]any{"suggested": suggested}
	if plan != nil {
		out["plan"] = plan
		out["warnings"] = nonNil(plan.warnings(rt))
	}
	writeJSON(w, http.StatusOK, out)
}

func (g *Gate) handlePutFirewall(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var p FirewallPlan
	if err := g.readJSON(w, r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if probs := p.validate(); len(probs) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_plan", "problems": probs})
		return
	}
	now := g.cfg.Now()
	errStale := errors.New("stale")
	err := g.store.Update(func(d *storeData) error {
		cur := 0
		if d.Firewall != nil {
			cur = d.Firewall.Version
		}
		if p.Version != cur {
			return errStale
		}
		p.Version, p.UpdatedAt, p.UpdatedBy = cur+1, now, key.Name
		c := p
		d.Firewall = &c
		return nil
	})
	switch {
	case errors.Is(err, errStale):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "version_conflict", "detail": "the plan was changed meanwhile; reload it"})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "could not save")
		return
	}
	g.audit.write(now, "firewall_plan_saved", map[string]any{"version": p.Version, "guests": len(p.Guests), "admin_key": key.Name})
	writeJSON(w, http.StatusOK, map[string]any{"version": p.Version, "warnings": nonNil(p.warnings(g.routing.Load()))})
}

// handleFirewallScript renders a plan (as sent, saved or not) as a script.
func (g *Gate) handleFirewallScript(w http.ResponseWriter, r *http.Request, key *AdminKey) {
	var p FirewallPlan
	if err := g.readJSON(w, r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if probs := p.validate(); len(probs) > 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "invalid_plan", "problems": probs})
		return
	}
	now := g.cfg.Now()
	version := g.cfg.Version
	if version == "" {
		version = "dev"
	}
	g.audit.write(now, "firewall_script_generated", map[string]any{"guests": len(p.Guests), "admin_key": key.Name})
	writeJSON(w, http.StatusOK, map[string]any{"script": p.script(version, now), "filename": "lanternfish-firewall.sh",
		"warnings": nonNil(p.warnings(g.routing.Load()))})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
