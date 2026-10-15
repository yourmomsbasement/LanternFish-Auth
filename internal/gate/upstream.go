package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
)

// Every request the Gate forwards to Jellyfin is signed, so Jellyfin's
// Lanternfish plugin can refuse anything that did not come through the Gate.
const (
	upstreamContext     = "lanternfish-gate/v1/upstream\n"
	upstreamKeyPurpose  = "upstream-signing-key"
	gateTimestampHeader = "X-Lanternfish-Gate-Timestamp"
	gateNonceHeader     = "X-Lanternfish-Gate-Nonce"
	gateSignatureHeader = "X-Lanternfish-Gate-Signature"
)

// upstreamMessage is what the Gate signs. target is the request target exactly
// as sent on the wire (escaped path plus query).
func upstreamMessage(method, target string, timestamp int64, nonce, deviceID string) []byte {
	return []byte(upstreamContext + method + "\n" + target + "\n" +
		strconv.FormatInt(timestamp, 10) + "\n" + nonce + "\n" + deviceID)
}

// loadUpstreamKey unseals the upstream signing key, creating it on first use
// (including for data files made before request signing existed).
func loadUpstreamKey(store *Store, sealer *Sealer) (*ecdsa.PrivateKey, error) {
	var key *ecdsa.PrivateKey
	err := store.Update(func(d *storeData) error {
		if d.UpstreamKeySealed == "" {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return err
			}
			pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				return err
			}
			d.UpstreamKeySealed = sealer.Seal(upstreamKeyPurpose, der)
			d.UpstreamPublicKey = pub
		}
		der, err := sealer.Open(upstreamKeyPurpose, d.UpstreamKeySealed)
		if err != nil {
			return errors.New("unseal upstream signing key: " + err.Error())
		}
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return err
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("upstream signing key is not ECDSA")
		}
		key = ec
		return nil
	})
	return key, err
}

// UpstreamPublicKey is the base64 SubjectPublicKeyInfo to paste into the
// Jellyfin plugin's settings.
func (g *Gate) UpstreamPublicKey() string {
	pub, _ := x509.MarshalPKIXPublicKey(&g.upstream.PublicKey)
	return encodeB64(pub)
}

func (g *Gate) signUpstream(out *http.Request) {
	ts := g.cfg.Now().Unix()
	nonce := randomToken()
	msg := upstreamMessage(out.Method, out.URL.RequestURI(), ts, nonce, out.Header.Get(deviceHeader))
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, g.upstream, digest[:])
	if err != nil {
		panic("ecdsa sign: " + err.Error())
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	out.Header.Set(gateTimestampHeader, strconv.FormatInt(ts, 10))
	out.Header.Set(gateNonceHeader, nonce)
	out.Header.Set(gateSignatureHeader, encodeB64(sig))
}
