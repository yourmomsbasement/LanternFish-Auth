package gate

import (
	"bytes"
	"net/netip"
	"sort"
	"testing"
	"time"
)

// testMMDB builds a tiny IPv4 MaxMind-format database (record size 24) that
// maps each prefix to {"country": {"iso_code": ...}}, so geo.go is tested
// against the real reader without shipping a GeoLite file.
func testMMDB(t *testing.T, prefixes map[string]string, built time.Time) []byte {
	t.Helper()
	// Data section: one record per distinct country.
	var data bytes.Buffer
	offsets := map[string]int{}
	countries := make([]string, 0, len(prefixes))
	for _, c := range prefixes {
		if _, ok := offsets[c]; !ok {
			offsets[c] = -1
			countries = append(countries, c)
		}
	}
	sort.Strings(countries)
	for _, c := range countries {
		offsets[c] = data.Len()
		mmdbMap(&data, 1)
		mmdbString(&data, "country")
		mmdbMap(&data, 1)
		mmdbString(&data, "iso_code")
		mmdbString(&data, c)
	}

	// Search tree: nodes[i] = [left, right]; -1 = empty, -2-x = data offset x.
	nodes := [][2]int{{-1, -1}}
	for p, c := range prefixes {
		pfx := netip.MustParsePrefix(p)
		ip := pfx.Addr().As4()
		n := 0
		for bit := 0; bit < pfx.Bits(); bit++ {
			b := int(ip[bit/8]>>(7-bit%8)) & 1
			if bit == pfx.Bits()-1 {
				nodes[n][b] = -2 - offsets[c]
				break
			}
			if nodes[n][b] < 0 {
				nodes = append(nodes, [2]int{-1, -1})
				nodes[n][b] = len(nodes) - 1
			}
			n = nodes[n][b]
		}
	}
	count := len(nodes)
	var out bytes.Buffer
	for _, nd := range nodes {
		for _, r := range nd {
			v := r
			switch {
			case r == -1:
				v = count
			case r < -1:
				v = count + 16 + (-2 - r)
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.WriteString("\xab\xcd\xefMaxMind.com")
	mmdbMap(&out, 9)
	mmdbString(&out, "node_count")
	mmdbUint(&out, 6, uint64(count))
	mmdbString(&out, "record_size")
	mmdbUint(&out, 5, 24)
	mmdbString(&out, "ip_version")
	mmdbUint(&out, 5, 4)
	mmdbString(&out, "database_type")
	mmdbString(&out, "LanternFish-Test-Country")
	mmdbString(&out, "languages")
	out.Write([]byte{0x00, 11 - 7}) // empty array (extended type 11)
	mmdbString(&out, "description")
	mmdbMap(&out, 0)
	mmdbString(&out, "binary_format_major_version")
	mmdbUint(&out, 5, 2)
	mmdbString(&out, "binary_format_minor_version")
	mmdbUint(&out, 5, 0)
	mmdbString(&out, "build_epoch")
	mmdbUint(&out, 9, uint64(built.Unix()))
	return out.Bytes()
}

func mmdbMap(b *bytes.Buffer, n int)       { b.WriteByte(7<<5 | byte(n)) }
func mmdbString(b *bytes.Buffer, s string) { b.WriteByte(2<<5 | byte(len(s))); b.WriteString(s) }

// mmdbUint writes an unsigned integer of the given type (5 uint16, 6 uint32,
// 9 uint64) in its minimal big-endian length.
func mmdbUint(b *bytes.Buffer, typ byte, v uint64) {
	var raw []byte
	for x := v; x > 0; x >>= 8 {
		raw = append([]byte{byte(x)}, raw...)
	}
	if typ <= 7 {
		b.WriteByte(typ<<5 | byte(len(raw)))
	} else {
		b.WriteByte(byte(len(raw)))
		b.WriteByte(typ - 7)
	}
	b.Write(raw)
}
