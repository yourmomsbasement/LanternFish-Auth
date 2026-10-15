package gate

import (
	"fmt"
	"net/netip"
	"strings"
)

// DefaultAdminAllow is where the admin API answers from unless configured:
// loopback and private networks, never the internet.
var DefaultAdminAllow = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// ParseAdminAllow parses a comma-separated list of CIDRs or single addresses,
// as given in LANTERNFISH_ADMIN_ALLOW.
func ParseAdminAllow(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", part)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no networks given")
	}
	return out, nil
}

func (g *Gate) adminAllowed(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range g.cfg.AdminAllow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
