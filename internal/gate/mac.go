package gate

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// MAC observations from native clients.
//
// What this is and isn't: a browser cannot report a MAC address, and a
// server can't see one across routed networks, so browser sessions record
// "unavailable". A native client can report the address of its active
// interface, signed with its device key over a fresh challenge. The signature
// shows which enrolled client made the report; it does not show the report is
// true, nor that the address is fixed (phones randomise them). It is an
// administrative signal, never proof of a physical device.

// MACObservation is one reported interface address, kept as a keyed tag
// (HMAC-SHA256 under a key derived from the master key) rather than the
// address, so the data file doesn't list hardware addresses.
type MACObservation struct {
	ID            string    `json:"id"`
	Tag           string    `json:"tag"`
	TagKeyVersion int       `json:"tag_key_version"`
	InterfaceKind string    `json:"interface_kind"`
	Randomized    string    `json:"randomized"` // "yes", "no" or "unknown"
	Source        string    `json:"source"`     // "native_report" or "admin"
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// MACReport is what a native client sends with a session request.
type MACReport struct {
	InterfaceKind string `json:"interface_kind"` // "wifi", "ethernet", ...
	MAC           string `json:"mac"`            // aa:bb:cc:dd:ee:ff
	Randomized    *bool  `json:"randomized"`     // omit when unknown
	CollectedAt   int64  `json:"collected_at"`   // unix seconds, client clock (advisory)
	Signature     string `json:"signature"`      // over macMessage
}

const macTagKeyVersion = 1

// macMessage is what the device key signs: the session challenge and a
// canonical digest of the report.
func macMessage(deviceID, challenge string, r *MACReport, mac net.HardwareAddr) []byte {
	return []byte("lanternfish-gate/v2/mac\n" + deviceID + "\n" + challenge + "\n" + macReportDigest(r, mac))
}

func macReportDigest(r *MACReport, mac net.HardwareAddr) string {
	rnd := "unknown"
	if r.Randomized != nil {
		rnd = map[bool]string{true: "yes", false: "no"}[*r.Randomized]
	}
	h := sha256.New()
	for _, part := range []string{r.InterfaceKind, mac.String(), rnd, fmt.Sprint(r.CollectedAt)} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		h.Write(n[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// parseMAC accepts a 48-bit unicast/multicast address and refuses
// placeholders that identify nothing.
func parseMAC(s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(mac) != 6 {
		return nil, errors.New("mac must be a 48-bit address like aa:bb:cc:dd:ee:ff")
	}
	zero, ones := true, true
	for _, b := range mac {
		zero = zero && b == 0
		ones = ones && b == 0xff
	}
	if zero || ones || mac.String() == "02:00:00:00:00:00" { // Android's "not available" value
		return nil, errors.New("mac is a placeholder, not an address")
	}
	return mac, nil
}

func validInterfaceKind(k string) bool {
	switch k {
	case "wifi", "ethernet", "cellular", "other":
		return true
	}
	return false
}

// macTagKey derives the tag key from the master key (HKDF-SHA256, its own
// purpose), so it's stable across restarts and useless without the master key.
func macTagKey(master []byte) []byte {
	k, err := hkdf.Key(sha256.New, master, nil, "lanternfish mac-tag v1", 32)
	if err != nil {
		panic(err)
	}
	return k
}

func macTag(key []byte, subjectID, deviceID, kind string, mac net.HardwareAddr) string {
	m := hmac.New(sha256.New, key)
	for _, part := range [][]byte{[]byte(subjectID), []byte(deviceID), []byte(kind), mac} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		m.Write(n[:])
		m.Write(part)
	}
	return hex.EncodeToString(m.Sum(nil))
}
