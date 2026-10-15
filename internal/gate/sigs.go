package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
)

// Credential kinds.
const (
	KindECDSA = "ecdsa-p256"
	KindHMAC  = "hmac-sha256"
)

// Context strings keep a signature made for one purpose from being accepted
// for another.
const (
	enrollContext  = "lanternfish-gate/v1/enroll\n"
	sessionContext = "lanternfish-gate/v1/session\n"
)

func enrollMessage(ticket string) []byte {
	return []byte(enrollContext + ticket)
}

func sessionMessage(deviceID, challenge string) []byte {
	return []byte(sessionContext + deviceID + "\n" + challenge)
}

func parseP256PublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("public key must be ECDSA P-256")
	}
	return ec, nil
}

// verifyP256 accepts both raw r||s signatures (WebCrypto) and ASN.1 DER
// signatures (Android, Java).
func verifyP256(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	digest := sha256.Sum256(msg)
	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if ecdsa.Verify(pub, digest[:], r, s) {
			return true
		}
	}
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func signHMAC(secret, msg []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return m.Sum(nil)
}

func verifyHMAC(secret, msg, sig []byte) bool {
	return hmac.Equal(signHMAC(secret, msg), sig)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
