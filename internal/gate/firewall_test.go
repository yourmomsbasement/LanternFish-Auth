package gate

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPlan() FirewallPlan {
	return FirewallPlan{InternalNet: "10.20.0.0/24",
		Gate: FirewallGate{ID: 200, LANNIC: "net0", InternalIP: "10.20.0.2", PublicPort: 443, SSHFrom: []string{"192.168.1.10"}, AllowPing: true},
		Guests: []FirewallGuest{
			{Name: "Jellyfin", Kind: "ct", ID: 201, IP: "10.20.0.3", Ports: []int{8096}, FromGate: true, BlockPrivate: true, AppID: "jellyfin"},
			{Name: "Sonarr", Kind: "ct", ID: 203, IP: "10.20.0.5", Ports: []int{8989}, FromGate: true, TalksTo: []string{"qBittorrent"}, BlockPrivate: true},
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
		"talks":   func(p *FirewallPlan) { p.Guests[1].TalksTo = []string{"Nobody"} },
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
	got := decode[map[string]FirewallPlan](t, h.admin2("GET", "firewall", nil))
	sug := got["suggested"]
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
}
