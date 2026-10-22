package gate

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
)

// Regression test for L1 of the 2026-10-17 review: a signed sign-in can't
// be replayed from another address, nor turned from a browser sign-in into
// a native client's bearer token.
func TestChallengeBoundToSourceAndClient(t *testing.T) {
	h := newHarness(t)
	key, er := h.enrollECDSA("web")
	sign := func(msg []byte) string {
		d := sha256.Sum256(msg)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
		return base64.StdEncoding.EncodeToString(sig)
	}
	challenge := func(from string, hdr map[string]string) string {
		rec := h.doFrom(from, "POST", "/_lanternfish/v2/challenge", map[string]string{"device_id": er.DeviceID}, hdr)
		if rec.Code != http.StatusOK {
			t.Fatalf("challenge: %d", rec.Code)
		}
		return decode[map[string]any](t, rec)["challenge"].(string)
	}
	session := func(from, ch, client string) int {
		return h.doFrom(from, "POST", "/_lanternfish/v2/session", map[string]any{
			"device_id": er.DeviceID, "challenge": ch, "signature": sign(sessionMessage(er.DeviceID, ch)), "client": client,
		}, nil).Code
	}
	page := map[string]string{"Sec-Fetch-Site": "same-origin"}

	// The review's replay: issued to one address, answered from another.
	if c := session("203.0.113.99:5555", challenge("198.51.100.7:1234", page), "native"); c != http.StatusUnauthorized {
		t.Fatalf("replayed from another address: %d", c)
	}
	if c := session("203.0.113.99:5555", challenge("198.51.100.7:1234", nil), "native"); c != http.StatusUnauthorized {
		t.Fatalf("native challenge answered from another address: %d", c)
	}
	// Same address, but a browser's challenge exchanged for a bearer token.
	if c := session("198.51.100.7:1234", challenge("198.51.100.7:1234", page), "native"); c != http.StatusUnauthorized {
		t.Fatalf("browser challenge exchanged for a native token: %d", c)
	}
	// What clients really do still works.
	if c := session("198.51.100.7:1234", challenge("198.51.100.7:1234", page), "browser"); c != http.StatusOK {
		t.Fatalf("browser sign-in: %d", c)
	}
	if c := session("198.51.100.7:1234", challenge("198.51.100.7:1234", nil), "native"); c != http.StatusOK {
		t.Fatalf("native sign-in: %d", c)
	}
	// An IPv6 client moving within its /64 is the same source.
	if c := session("[2001:db8::2]:1", challenge("[2001:db8::1]:1", nil), "native"); c != http.StatusOK {
		t.Fatalf("IPv6 sign-in within a /64: %d", c)
	}
}
