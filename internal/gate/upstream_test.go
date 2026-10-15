package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"testing"
)

const vectorPath = "../../testdata/upstream-vector.json"

type upstreamVector struct {
	PublicKey string `json:"public_key"`
	Method    string `json:"method"`
	Target    string `json:"target"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"`
}

func verifyUpstream(t *testing.T, pubSPKI []byte, r *http.Request) bool {
	t.Helper()
	pub, err := parseP256PublicKey(pubSPKI)
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := strconv.ParseInt(r.Header.Get(gateTimestampHeader), 10, 64)
	sig, _ := decodeB64(r.Header.Get(gateSignatureHeader))
	msg := upstreamMessage(r.Method, r.RequestURI, ts, r.Header.Get(gateNonceHeader), r.Header.Get(deviceHeader))
	return len(sig) == 64 && verifyP256(pub, msg, sig)
}

func TestUpstreamRequestsAreSigned(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	var pub []byte
	h.g.store.View(func(d *storeData) { pub = d.UpstreamPublicKey })
	if h.g.UpstreamPublicKey() != encodeB64(pub) {
		t.Fatal("stored and live upstream keys differ")
	}

	rec := h.do("GET", "/Items/abc%2Fdef?SortBy=Name&x=%C3%A9", nil, map[string]string{
		sessionHeader:       token,
		gateSignatureHeader: "forged",
		gateNonceHeader:     "forged",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("proxied: %d", rec.Code)
	}
	up := h.lastUpstream()
	if up.RequestURI != "/Items/abc%2Fdef?SortBy=Name&x=%C3%A9" {
		t.Fatalf("upstream target %q", up.RequestURI)
	}
	if !verifyUpstream(t, pub, up) {
		t.Fatal("upstream signature does not verify")
	}

	// Tampering with any signed part breaks it.
	tampered := up.Clone(up.Context())
	tampered.RequestURI = "/Users"
	if verifyUpstream(t, pub, tampered) {
		t.Fatal("signature verified for a different target")
	}
	tampered = up.Clone(up.Context())
	tampered.Header.Set(deviceHeader, "dev_other")
	if verifyUpstream(t, pub, tampered) {
		t.Fatal("signature verified for a different device")
	}

	// The key survives a restart.
	g2, err := New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer g2.Close()
	if g2.UpstreamPublicKey() != h.g.UpstreamPublicKey() {
		t.Fatal("upstream key changed across restart")
	}
}

// TestUpstreamVector checks the shared test vector that the Jellyfin plugin's
// tests also verify, so the Go and .NET sides can't drift apart.
// Regenerate with LANTERNFISH_WRITE_VECTOR=1 go test -run TestUpstreamVector.
func TestUpstreamVector(t *testing.T) {
	if os.Getenv("LANTERNFISH_WRITE_VECTOR") == "1" {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
		v := upstreamVector{
			PublicKey: encodeB64(spki), Method: "GET",
			Target:    "/Videos/1a2b/stream.mp4?Static=true&api_key=x%2By",
			Timestamp: 1760000000, Nonce: "bm9uY2UtdmFsdWUtMTIzNA", DeviceID: "dev_ExampleDevice01",
		}
		d := sha256.Sum256(upstreamMessage(v.Method, v.Target, v.Timestamp, v.Nonce, v.DeviceID))
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		v.Signature = encodeB64(sig)
		raw, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorPath, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v upstreamVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	spki, _ := decodeB64(v.PublicKey)
	pub, err := parseP256PublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := decodeB64(v.Signature)
	if !verifyP256(pub, upstreamMessage(v.Method, v.Target, v.Timestamp, v.Nonce, v.DeviceID), sig) {
		t.Fatal("vector does not verify")
	}
	sig[10] ^= 1
	if verifyP256(pub, upstreamMessage(v.Method, v.Target, v.Timestamp, v.Nonce, v.DeviceID), sig) {
		t.Fatal("corrupted vector verified")
	}
}
