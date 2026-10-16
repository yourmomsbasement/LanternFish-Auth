package gate

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testPlan() FirewallPlan {
	return FirewallPlan{InternalNet: "10.20.0.0/24",
		Gate: FirewallGate{ID: 200, LANNIC: "net0", InternalIP: "10.20.0.2", PublicPort: 443, SSHFrom: []string{"192.168.1.10"}, AllowPing: true},
		Guests: []FirewallGuest{
			{Name: "Jellyfin", Kind: "ct", ID: 201, IP: "10.20.0.3", Ports: []int{8096}, FromGate: true, BlockPrivate: true, AppID: "jellyfin"},
			{Name: "Sonarr", Kind: "ct", ID: 203, IP: "10.20.0.5", Ports: []int{8989}, FromGate: true, TalksTo: []string{"qBittorrent"},
				Egress: []EgressTarget{{IP: "192.168.1.50", Protocol: "tcp", Ports: []int{445}}}, BlockPrivate: true},
			{Name: "qBittorrent", Kind: "vm", ID: 204, IP: "10.20.0.6", Ports: []int{8080}, BlockPrivate: true},
		}}
}

func TestFirewallRules(t *testing.T) {
	p := testPlan()
	if probs := p.validate(); len(probs) > 0 {
		t.Fatal(probs)
	}
	s := p.script("1.2.3", time.Now())
	for _, want := range []string{
		"IN ACCEPT -i net0 -p tcp -dport 443 -log nolog",
		"IN ACCEPT -i net0 -source 192.168.1.10 -p tcp -dport 22",
		"IN ACCEPT -source 10.20.0.2 -p tcp -dport 8096 -log nolog # from the Gate",
		"IN ACCEPT -source 10.20.0.2 -p tcp -dport 8989",
		"OUT ACCEPT -dest 10.20.0.6 -p tcp -dport 8080 -log nolog # to qBittorrent",
		"IN ACCEPT -source 10.20.0.5 -p tcp -dport 8080 -log nolog # from Sonarr",
		"OUT ACCEPT -dest 192.168.1.50 -p tcp -dport 445 -log nolog # external target",
		"[IPSET ipfilter-net0]\n10.20.0.6",
		"OUT DROP -dest 192.168.0.0/16",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// qBittorrent isn't reached by the Gate.
	if strings.Contains(s, "-source 10.20.0.2 -p tcp -dport 8080") {
		t.Error("the Gate was let into a guest it doesn't use")
	}
	// The allow rule comes before the private-network drops in Sonarr's file.
	sonarr := p.guestFile(p.Guests[1])
	if strings.Index(sonarr, "OUT ACCEPT -dest 10.20.0.6") > strings.Index(sonarr, "OUT DROP") {
		t.Error("an OUT DROP comes before Sonarr's allowance")
	}
	// The external-target allowance also comes before the drops, and opens
	// nothing inbound.
	if strings.Index(sonarr, "OUT ACCEPT -dest 192.168.1.50") > strings.Index(sonarr, "OUT DROP") {
		t.Error("an OUT DROP comes before Sonarr's external-target allowance")
	}
	if strings.Contains(sonarr, "IN ACCEPT -source 192.168.1.50") {
		t.Error("an external target must not get an inbound rule")
	}
	// Talks-to stays directed: qBittorrent gets nothing toward Sonarr, and an
	// external target belongs to the guest that lists it.
	qbit := p.guestFile(p.Guests[2])
	if strings.Contains(qbit, "OUT ACCEPT -dest 10.20.0.5") {
		t.Error("talks-to is directed: qBittorrent gets no outbound rule to Sonarr")
	}
	if strings.Contains(qbit, "192.168.1.50") {
		t.Error("an external target belongs to one guest only")
	}
	if strings.Contains(p.guestFile(p.Guests[0]), "192.168.1.50") {
		t.Error("Jellyfin isn't the guest with that external target")
	}
}

func TestFirewallEgressValidation(t *testing.T) {
	for name, target := range map[string]EgressTarget{
		"network":     {IP: "10.0.0.0/8", Protocol: "tcp", Ports: []int{445}},
		"wildcard":    {IP: "0.0.0.0", Protocol: "tcp", Ports: []int{445}},
		"unspecified": {IP: "::", Protocol: "tcp", Ports: []int{445}},
		"multicast":   {IP: "224.0.0.1", Protocol: "tcp", Ports: []int{445}},
		"broadcast":   {IP: "255.255.255.255", Protocol: "tcp", Ports: []int{445}},
		"hostname":    {IP: "nas.example", Protocol: "tcp", Ports: []int{445}},
		"metachars":   {IP: "192.168.1.50; rm -rf /", Protocol: "tcp", Ports: []int{445}},
		"zone":        {IP: "fe80::1%eth0", Protocol: "tcp", Ports: []int{445}},
		"empty ip":    {IP: "", Protocol: "tcp", Ports: []int{445}},
		"protocol":    {IP: "192.168.1.50", Protocol: "sctp", Ports: []int{445}},
		"no protocol": {IP: "192.168.1.50", Protocol: "", Ports: []int{445}},
		"no ports":    {IP: "192.168.1.50", Protocol: "tcp", Ports: []int{}},
		"port 0":      {IP: "192.168.1.50", Protocol: "tcp", Ports: []int{0}},
		"port big":    {IP: "192.168.1.50", Protocol: "tcp", Ports: []int{70000}},
	} {
		p := testPlan()
		p.Guests[0].Egress = []EgressTarget{target}
		if probs := p.validate(); len(probs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}

	// Bounded: too many targets, and too many ports in one target.
	p := testPlan()
	for i := 0; i <= maxEgressTargets; i++ {
		p.Guests[0].Egress = append(p.Guests[0].Egress, EgressTarget{IP: "192.168.1.50", Protocol: "tcp", Ports: []int{445}})
	}
	if probs := p.validate(); len(probs) == 0 {
		t.Error("too many external targets: accepted")
	}
	p = testPlan()
	ports := make([]int, maxGuestPorts+1)
	for i := range ports {
		ports[i] = 1000 + i
	}
	p.Guests[0].Egress = []EgressTarget{{IP: "192.168.1.50", Protocol: "tcp", Ports: ports}}
	if probs := p.validate(); len(probs) == 0 {
		t.Error("too many ports in one target: accepted")
	}
}

func TestFirewallEgressNormalization(t *testing.T) {
	p := testPlan()
	p.Guests[0].Egress = []EgressTarget{
		{IP: " 2001:0DB8::1 ", Protocol: " TCP ", Ports: []int{445, 139, 445, 2049}},
		{IP: "::ffff:192.168.1.50", Protocol: "udp", Ports: []int{123}},
	}
	if probs := p.validate(); len(probs) > 0 {
		t.Fatal(probs)
	}
	e := p.Guests[0].Egress[0]
	if e.IP != "2001:db8::1" || e.Protocol != "tcp" {
		t.Errorf("not normalized: %+v", e)
	}
	if len(e.Ports) != 3 || e.Ports[0] != 139 || e.Ports[1] != 445 || e.Ports[2] != 2049 {
		t.Errorf("ports not sorted and deduped: %v", e.Ports)
	}
	if got := p.Guests[0].Egress[1].IP; got != "192.168.1.50" {
		t.Errorf("mapped IPv4 not unmapped: %q", got)
	}
}

func TestFirewallDuplicateAddresses(t *testing.T) {
	// Source authorization trusts the address, so two guests must not share one.
	p := testPlan()
	p.Guests[1].IP = p.Guests[0].IP
	if probs := p.validate(); len(probs) == 0 {
		t.Error("two guests on the same address: accepted")
	}
	// Nor may a guest sit on the Gate's own address.
	p = testPlan()
	p.Guests[0].IP = p.Gate.InternalIP
	if probs := p.validate(); len(probs) == 0 {
		t.Error("a guest on the Gate's address: accepted")
	}
}

func TestFirewallRejectsShellInjection(t *testing.T) {
	for name, mutate := range map[string]func(*FirewallPlan){
		"name":    func(p *FirewallPlan) { p.Guests[0].Name = "x'; rm -rf / #" },
		"ip":      func(p *FirewallPlan) { p.Guests[0].IP = "10.20.0.3; reboot" },
		"source":  func(p *FirewallPlan) { p.Guests[0].Sources = []string{"$(id)"} },
		"ssh":     func(p *FirewallPlan) { p.Gate.SSHFrom = []string{"`id`"} },
		"nic":     func(p *FirewallPlan) { p.Gate.LANNIC = "net0 -p tcp" },
		"heredoc": func(p *FirewallPlan) { p.Guests[0].Name = "a\nLANTERNFISH_FW\nreboot" },
		"id":      func(p *FirewallPlan) { p.Guests[0].ID = 5 },
		"port":    func(p *FirewallPlan) { p.Guests[0].Ports = []int{70000} },
		"kind":    func(p *FirewallPlan) { p.Guests[0].Kind = "ct; reboot" },
		"dup id":  func(p *FirewallPlan) { p.Guests[1].ID = 201 },
		"dup ip":  func(p *FirewallPlan) { p.Guests[1].IP = p.Guests[0].IP },
		"talks":   func(p *FirewallPlan) { p.Guests[1].TalksTo = []string{"Nobody"} },
		"egress": func(p *FirewallPlan) {
			p.Guests[0].Egress = []EgressTarget{{IP: "$(id)", Protocol: "tcp", Ports: []int{445}}}
		},
		"proto": func(p *FirewallPlan) {
			p.Guests[0].Egress = []EgressTarget{{IP: "192.168.1.50", Protocol: "tcp; reboot", Ports: []int{445}}}
		},
	} {
		p := testPlan()
		mutate(&p)
		if probs := p.validate(); len(probs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The script runs: against stand-ins for pct, qm and pve-firewall.
func TestFirewallScriptRuns(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	p := testPlan()
	p.validate()
	dir := t.TempDir()
	bin, fw := filepath.Join(dir, "bin"), filepath.Join(dir, "fw")
	os.MkdirAll(bin, 0o755)
	os.MkdirAll(fw, 0o755)
	stub := func(name, body string) {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/bash\n"+body+"\n"), 0o755)
	}
	stub("id", "echo 0")
	stub("pve-firewall", "echo running")
	// CT 201's NIC lacks firewall=1; CT 205 doesn't exist (not in plan).
	stub("pct", `case "$2" in
  200) printf 'net0: name=eth0,bridge=vmbr0,firewall=1\nnet1: name=eth1,bridge=vmbr1,firewall=1\n' ;;
  201) printf 'net0: name=eth0,bridge=vmbr1,ip=10.20.0.3/24\n' ;;
  203) printf 'net0: name=eth0,bridge=vmbr1,firewall=1\n' ;;
  *) exit 2 ;;
esac`)
	stub("qm", `[ "$2" = 204 ] && printf 'net0: virtio=AA:BB,bridge=vmbr1,firewall=1\n' || exit 2`)
	script := filepath.Join(dir, "fw.sh")
	os.WriteFile(script, []byte(p.script("test", time.Now())), 0o755)
	os.WriteFile(filepath.Join(fw, "201.fw"), []byte("old\n"), 0o644)
	os.WriteFile(filepath.Join(fw, "cluster.fw"), []byte("[OPTIONS]\nenable: 1\n"), 0o644)

	run := func(env ...string) (string, int) {
		cmd := exec.Command("bash", script)
		cmd.Env = append([]string{"PATH=" + bin + ":/usr/bin:/bin", "FW_DIR=" + fw}, env...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return string(out), code
	}
	out, code := run("DRY_RUN=1")
	if _, err := os.Stat(filepath.Join(fw, "203.fw")); err == nil {
		t.Fatal("dry run wrote a file")
	}
	if !strings.Contains(out, "Dry run") || !strings.Contains(out, "OUT ACCEPT -dest 10.20.0.6") {
		t.Fatalf("dry run output: %s", out)
	}
	out, code = run()
	if code != 2 || !strings.Contains(out, "net0 has no firewall=1") {
		t.Fatalf("missing firewall=1 not reported (%d): %s", code, out)
	}
	for _, id := range []string{"200", "201", "203", "204"} {
		b, err := os.ReadFile(filepath.Join(fw, id+".fw"))
		if err != nil || !strings.Contains(string(b), "[RULES]") {
			t.Fatalf("%s.fw: %v %q", id, err, b)
		}
	}
	backups, _ := filepath.Glob(filepath.Join(fw, "201.fw.bak-*"))
	if len(backups) != 1 {
		t.Fatalf("no backup of the old file: %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != "old\n" {
		t.Fatalf("backup: %q", b)
	}
	// With the datacenter firewall off, it says so.
	os.WriteFile(filepath.Join(fw, "cluster.fw"), []byte("[OPTIONS]\nenable: 0\n"), 0o644)
	if out, _ := run(); !strings.Contains(out, "datacenter firewall is off") {
		t.Fatalf("datacenter check: %s", out)
	}
	if sc, err := exec.LookPath("shellcheck"); err == nil {
		if out, err := exec.Command(sc, "-s", "bash", script).CombinedOutput(); err != nil {
			t.Fatalf("shellcheck: %s", out)
		}
	}
}

func TestFirewallAPI(t *testing.T) {
	h := newHarness(t)
	s := h.settings()
	s.Upstream = "http://10.20.0.3:8096"
	s.Apps = []App{{Name: "Sonarr", Enabled: true, Hosts: []string{appHost}, Upstream: "http://10.20.0.5:8989"}}
	if rec := h.saveSettings(s); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	got := decode[struct {
		Suggested FirewallPlan `json:"suggested"`
		Warnings  []string     `json:"warnings"`
	}](t, h.admin2("GET", "firewall", nil))
	sug := got.Suggested
	if len(sug.Guests) != 2 || sug.Guests[0].IP != "10.20.0.3" || sug.Guests[1].Ports[0] != 8989 || !sug.Guests[1].FromGate {
		t.Fatalf("suggested: %+v", sug.Guests)
	}
	plan := testPlan()
	plan.Guests = plan.Guests[:1] // Sonarr left out
	rec := h.admin2("PUT", "firewall", plan)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if w := decode[map[string]any](t, rec)["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "Sonarr is at 10.20.0.5") {
		t.Fatalf("warnings: %v", w)
	}
	if rec := h.admin2("PUT", "firewall", plan); rec.Code != http.StatusConflict {
		t.Fatalf("stale save: %d", rec.Code)
	}
	rec = h.admin2("POST", "firewall/script", plan)
	if rec.Code != http.StatusOK || !strings.HasPrefix(decode[map[string]any](t, rec)["script"].(string), "#!/bin/bash") {
		t.Fatalf("script: %d %s", rec.Code, rec.Body)
	}
	bad := testPlan()
	bad.Guests[0].IP = "nope"
	if rec := h.admin2("POST", "firewall/script", bad); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid plan: %d", rec.Code)
	}
	badEgress := testPlan()
	badEgress.Guests[0].Egress = []EgressTarget{{IP: "10.0.0.0/8", Protocol: "tcp", Ports: []int{445}}}
	if rec := h.admin2("POST", "firewall/script", badEgress); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid egress: %d %s", rec.Code, rec.Body)
	}
	// A valid external target reaches the generated script unchanged.
	withEgress := testPlan()
	rec = h.admin2("POST", "firewall/script", withEgress)
	if rec.Code != http.StatusOK || !strings.Contains(decode[map[string]any](t, rec)["script"].(string),
		"OUT ACCEPT -dest 192.168.1.50 -p tcp -dport 445 -log nolog") {
		t.Fatalf("egress script: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallInternalServiceRules(t *testing.T) {
	p := testPlan()
	p.Gate.ServicePort = 8096
	p.Gate.InternalNIC = "net1"
	p.Guests[1].ToService = true
	if problems := p.validate(); len(problems) > 0 {
		t.Fatal(problems)
	}
	gate := p.gateFile()
	want := "IN ACCEPT -i net1 -source 10.20.0.5 -dest 10.20.0.2 -p tcp -dport 8096"
	if !strings.Contains(gate, want) {
		t.Fatalf("service rule missing: %s", gate)
	}
	if strings.Contains(gate, "-source 10.20.0.6") || strings.Contains(gate, "IN ACCEPT -i net0 -source 10.20.0.5") {
		t.Fatal("service access opened to an unselected guest or LAN interface")
	}
	guest := p.guestFile(p.Guests[1])
	allow := strings.Index(guest, "OUT ACCEPT -dest 10.20.0.2 -p tcp -dport 8096")
	if allow < 0 || allow > strings.Index(guest, "OUT DROP") {
		t.Fatalf("service allowance missing or follows drop: %s", guest)
	}
	if strings.Contains(p.guestFile(p.Guests[2]), "OUT ACCEPT -dest 10.20.0.2") {
		t.Fatal("unselected guest allowed service egress")
	}
	p.Gate.ServicePort = 0
	if len(p.validate()) == 0 {
		t.Fatal("service access accepted without a service port")
	}
	p.Gate.ServicePort = 8096
	p.Gate.InternalNIC = "net0"
	if len(p.validate()) == 0 {
		t.Fatal("service access accepted on LAN interface")
	}
	p.Gate.InternalNIC = "net1"
	p.Gate.InternalIP = "invalid"
	if len(p.validate()) == 0 {
		t.Fatal("invalid service address accepted")
	}
}

func TestFirewallServiceConfigurationDrift(t *testing.T) {
	h := newHarness(t)
	h.g.cfg.ServiceListen = "10.20.0.2:8096"
	h.g.cfg.ServiceNetwork = "10.20.0.0/24"
	h.g.cfg.ServiceClients = []ServiceClient{{Name: "sonarr", IP: "10.20.0.5"}}
	p := testPlan()
	p.Gate.ServicePort = 8096
	p.Gate.InternalNIC = "net1"
	p.Guests[1].ToService = true
	if problems := p.validate(); len(problems) > 0 {
		t.Fatal(problems)
	}
	if warnings := h.g.firewallWarnings(&p); len(warnings) != 0 {
		t.Fatal(warnings)
	}
	p.Guests[1].ToService = false
	if warnings := h.g.firewallWarnings(&p); !strings.Contains(strings.Join(warnings, " "), "needs a guest") {
		t.Fatal("missing service allowance not reported")
	}
	p.Guests[1].ToService = true
	p.Gate.ServicePort = 8097
	if warnings := h.g.firewallWarnings(&p); !strings.Contains(strings.Join(warnings, " "), "does not match gate.env") {
		t.Fatal("wrong port not reported")
	}
	p.Gate.ServicePort = 8096
	p.Guests[2].ToService = true
	if warnings := h.g.firewallWarnings(&p); !strings.Contains(strings.Join(warnings, " "), "not an authorized service client") {
		t.Fatal("untrusted extra client not reported")
	}
}

func TestFirewallServiceDisabledAndDefaultInterface(t *testing.T) {
	p := testPlan()
	if strings.Contains(p.gateFile(), "# service client") || strings.Contains(p.guestFile(p.Guests[1]), "# internal Jellyfin service route") {
		t.Fatal("disabled service opened rules")
	}
	p.Gate.ServicePort = 8096
	p.Guests[1].ToService = true
	if problems := p.validate(); len(problems) > 0 {
		t.Fatal(problems)
	}
	if p.Gate.InternalNIC != "net1" || !strings.Contains(p.gateFile(), "IN ACCEPT -i net1 -source 10.20.0.5 -dest 10.20.0.2") {
		t.Fatal("service did not default to the internal interface")
	}
	h := newHarness(t)
	p.Gate.InternalNIC = p.Gate.LANNIC
	if rec := h.admin2("POST", "firewall/script", p); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("service on LAN NIC accepted: %d %s", rec.Code, rec.Body)
	}
	p.Gate.ServicePort = 0
	if rec := h.admin2("POST", "firewall/script", p); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("client without service port accepted: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallBlockedNetworksNormalized(t *testing.T) {
	p := testPlan()
	p.BlockedNetworks = []string{
		"192.168.50.5/24",     // host bits set: becomes 192.168.50.0/24
		"192.168.50.0/24",     // the same network, spelled canonically
		"2001:db8:1234::1/48", // a public IPv6 LAN
		"::ffff:10.0.0.0/104", // IPv4-mapped IPv6: becomes 10.0.0.0/8
		" 169.254.0.0/16 ",    // trimmed
	}
	if probs := p.validate(); len(probs) > 0 {
		t.Fatalf("validate: %v", probs)
	}
	want := []string{"10.0.0.0/8", "169.254.0.0/16", "192.168.50.0/24", "2001:db8:1234::/48"}
	if strings.Join(p.BlockedNetworks, " ") != strings.Join(want, " ") {
		t.Fatalf("canonical networks: %v, want %v", p.BlockedNetworks, want)
	}
	p.Guests[2].BlockPrivate = false
	for i, x := range p.Guests {
		file := p.guestFile(x)
		if i == 2 {
			if strings.Contains(file, "OUT DROP") {
				t.Errorf("guest %q doesn't block private networks but got OUT DROP rules", x.Name)
			}
			continue
		}
		for _, n := range want {
			if !strings.Contains(file, "OUT DROP -dest "+n+" -log nolog") {
				t.Errorf("guest %q lacks a drop for %s", x.Name, n)
			}
		}
	}
	sonarr := p.guestFile(p.Guests[1])
	if strings.Index(sonarr, "OUT ACCEPT -dest 10.20.0.6") > strings.Index(sonarr, "OUT DROP -dest 192.168.50.0/24") {
		t.Error("an OUT DROP comes before Sonarr's allowance")
	}
	// The built-in ranges come first, then the plan's extras, then the end.
	extra := strings.Index(sonarr, "# Extra networks this plan blocks.")
	if extra == -1 || extra < strings.Index(sonarr, "OUT DROP -dest 192.168.0.0/16") || extra < strings.Index(sonarr, "OUT ACCEPT -dest 10.20.0.6") {
		t.Error("the extra drops aren't after the built-in drops and the allowances")
	}
}

func TestFirewallBlockedNetworksRejected(t *testing.T) {
	for name, nets := range map[string][]string{
		"shell":     {"$(id)"},
		"interface": {"eth0"},
		"zone":      {"fe80::%eth0/10"},
		"bits":      {"10.0.0.0/33"},
		"words":     {"not a network"},
		"address":   {"10.0.0.5"}, // a prefix is required, not a bare address
		"empty":     {"   "},
		"too many":  make([]string, maxBlockedNetworks+1),
	} {
		p := testPlan()
		p.BlockedNetworks = nets
		if probs := p.validate(); len(probs) == 0 {
			t.Errorf("%s: accepted %q", name, nets)
		}
	}
	// Duplicates that only show up after canonicalizing still count once, so
	// twice the cap of spellings collapses to exactly the cap.
	many := make([]string, 0, maxBlockedNetworks*2)
	for i := 0; i < maxBlockedNetworks*2; i++ {
		many = append(many, fmt.Sprintf("10.%d.0.0/16", i/2))
	}
	p := testPlan()
	p.BlockedNetworks = many
	if probs := p.validate(); len(probs) > 0 {
		t.Fatalf("deduplicated to the cap: %v", probs)
	}
	if len(p.BlockedNetworks) != maxBlockedNetworks {
		t.Fatalf("kept %d networks", len(p.BlockedNetworks))
	}
}

func TestFirewallBlockLinkLocal(t *testing.T) {
	p := testPlan()
	p.BlockLinkLocal = true
	if probs := p.validate(); len(probs) > 0 {
		t.Fatalf("validate: %v", probs)
	}
	file := p.guestFile(p.Guests[0])
	for _, n := range fwLinkLocal {
		if !strings.Contains(file, "OUT DROP -dest "+n+" -log nolog") {
			t.Errorf("block_link_local lacks a drop for %s", n)
		}
	}
	p.BlockLinkLocal = false
	if off := p.guestFile(p.Guests[0]); strings.Contains(off, "OUT DROP -dest 169.254.0.0/16") {
		t.Error("link-local was dropped with the option off")
	}
}

// A plan without the new options renders exactly what it always did.
func TestFirewallDefaultsUnchanged(t *testing.T) {
	p := testPlan()
	if probs := p.validate(); len(probs) > 0 {
		t.Fatal(probs)
	}
	if len(p.BlockedNetworks) != 0 || p.BlockLinkLocal {
		t.Fatalf("new options defaulted to %v / %v", p.BlockedNetworks, p.BlockLinkLocal)
	}
	for _, x := range p.Guests {
		file := p.guestFile(x)
		var drops []string
		for _, line := range strings.Split(file, "\n") {
			if strings.HasPrefix(line, "OUT DROP -dest ") {
				drops = append(drops, strings.Fields(line)[3])
			}
		}
		if !x.BlockPrivate {
			if len(drops) != 0 {
				t.Errorf("guest %q: %v", x.Name, drops)
			}
			continue
		}
		want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}
		if strings.Join(drops, " ") != strings.Join(want, " ") {
			t.Errorf("guest %q drops: %v, want %v", x.Name, drops, want)
		}
	}
}

// The extra options do nothing while no guest blocks private networks: the
// plan still validates, the files are unchanged and it says so.
func TestFirewallBlockedNetworksWithoutBlockPrivate(t *testing.T) {
	p := testPlan()
	p.BlockedNetworks = []string{"2001:db8::/32"}
	p.BlockLinkLocal = true
	for i := range p.Guests {
		p.Guests[i].BlockPrivate = false
	}
	if probs := p.validate(); len(probs) > 0 {
		t.Fatalf("validate: %v", probs)
	}
	if file := p.guestFile(p.Guests[0]); strings.Contains(file, "OUT DROP") {
		t.Error("extra options were applied to a guest that doesn't block private networks")
	}
	if w := p.warnings(nil); len(w) != 1 || !strings.Contains(w[0], "do nothing") {
		t.Errorf("warnings: %v", w)
	}
}

// deploy/proxmox/guarded-firewall.sh backs up and restores the <ID>.fw files
// a rendered script writes by reading its write_fw lines. Keep that shape,
// and the wrapper's pattern for it, in step.
func TestFirewallScriptWrapperTargets(t *testing.T) {
	p := testPlan()
	if probs := p.validate(); len(probs) > 0 {
		t.Fatal(probs)
	}
	s := p.script("1.2.3", time.Now())
	re := regexp.MustCompile(`(?m)^write_fw[ \t]+(ct|vm)[ \t]+([0-9]+)[ \t]`)
	got := map[int]string{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		id, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		got[id] = m[1]
	}
	want := map[int]string{200: "ct", 201: "ct", 203: "ct", 204: "vm"}
	if len(got) != len(want) {
		t.Fatalf("the wrapper would capture %v, want %v", got, want)
	}
	for id, kind := range want {
		if got[id] != kind {
			t.Errorf("guest %d: %q, want %q", id, got[id], kind)
		}
	}
}

// The script runs: against stand-ins for pct, qm and pve-firewall.
