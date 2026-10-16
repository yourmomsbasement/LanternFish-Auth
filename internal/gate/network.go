package gate

import "net/netip"

// networkKey is what a session or network approval is bound to: the client
// address itself ("exact"), or the network around it ("prefix"). It returns
// "" when IP binding is off or the address can't be parsed (which then
// matches nothing that was bound).
//
// SECURITY: the address is the TCP peer the Gate sees. Forwarded-for headers
// are never consulted: anyone could send them. Behind a TCP passthrough proxy
// every client shares the proxy's address; see docs/PROTOCOL.md.
// unknownLocationSource is what an approval for an unknown location (an
// address GeoIP can't place) is bound to: the network key when IP binding is
// on, else the client address itself.
//
// SECURITY: with IP binding off, networkKey is "" for every address, so an
// approval bound to it would hold for every unknown address at once:
// verifying from one address nobody can place would approve all of them.
func unknownLocationSource(ip string, p IPPolicy) string {
	if p.Enabled {
		return networkKey(ip, p)
	}
	exact := p
	exact.Enabled, exact.Match = true, "exact"
	return networkKey(ip, exact)
}

func networkKey(ip string, p IPPolicy) string {
	if !p.Enabled {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "invalid:" + ip
	}
	a = a.Unmap().WithZone("")
	bits := a.BitLen()
	if p.Match == "prefix" {
		if a.Is4() {
			bits = p.IPv4PrefixLen
		} else {
			bits = p.IPv6PrefixLen
		}
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}
