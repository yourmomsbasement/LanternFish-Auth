package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuthenticator is a software passkey ("none" attestation, ES256), enough
// to drive registration and assertions through the real library checks.
type softAuthenticator struct {
	key     *ecdsa.PrivateKey
	id      []byte
	rpID    string
	origin  string
	counter uint32
	flags   byte // added to UP|UV, e.g. 0x08 backup eligible

	aaguid []byte // 16 bytes; nil: all zero
	// attest makes the attestation statement for create; nil: "none".
	attest func(authData, clientDataHash []byte) (format string, stmt map[string]any)
}

const (
	testRPID   = "flix.example.com"
	testOrigin = "https://flix.example.com"
)

func newSoftAuthenticator() *softAuthenticator {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &softAuthenticator{key: key, id: randomBytes(16), rpID: testRPID, origin: testOrigin}
}

var b64u = base64.RawURLEncoding

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return cd
}

func (a *softAuthenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rp[:]...)
	flags := byte(0x01|0x04) | a.flags
	if attested {
		flags |= 0x40
	}
	a.counter++
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	if attested {
		if a.aaguid != nil {
			out = append(out, a.aaguid...)
		} else {
			out = append(out, make([]byte, 16)...) // AAGUID
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
		out = append(out, a.id...)
		x, y := make([]byte, 32), make([]byte, 32)
		a.key.PublicKey.X.FillBytes(x)
		a.key.PublicKey.Y.FillBytes(y)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
	}
	return out
}

// challengeOf pulls publicKey.challenge out of an options response.
func challengeOf(t *testing.T, body []byte) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(body, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("options: %s", body)
	}
	return o.PublicKey.Challenge
}

func (a *softAuthenticator) create(challenge string) map[string]any {
	ad := a.authData(true)
	cd := a.clientData("webauthn.create", challenge)
	format, stmt := "none", map[string]any{}
	if a.attest != nil {
		h := sha256.Sum256(cd)
		format, stmt = a.attest(ad, h[:])
	}
	att, _ := cbor.Marshal(map[string]any{"fmt": format, "attStmt": stmt, "authData": ad})
	return map[string]any{"id": b64u.EncodeToString(a.id), "rawId": b64u.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd),
			"attestationObject": b64u.EncodeToString(att)}}
}

func (a *softAuthenticator) get(challenge, userHandle string) map[string]any {
	ad := a.authData(false)
	cd := a.clientData("webauthn.get", challenge)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	return map[string]any{"id": b64u.EncodeToString(a.id), "rawId": b64u.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig), "userHandle": b64u.EncodeToString([]byte(userHandle))}}
}

func (h *harness) enablePasskeys() {
	h.t.Helper()
	rp, err := newPasskeyRP(Config{WebAuthnRPID: testRPID, WebAuthnOrigins: []string{testOrigin}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.g.passkeys = rp
}

func (h *harness) registerPasskey(subjectID string, a *softAuthenticator) *http.Response {
	h.t.Helper()
	rec := h.admin2("POST", "subjects/"+subjectID+"/setup-link", nil)
	path := decode[map[string]any](h.t, rec)["path"].(string)
	grant := path[strings.Index(path, "grant=")+len("grant="):]
	rec = h.do("POST", "/_lanternfish/v2/factors/passkey/options", map[string]string{"grant": grant, "name": "Test key"}, nil)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("passkey options: %d %s", rec.Code, rec.Body)
	}
	c := challengeOf(h.t, rec.Body.Bytes())
	rec = h.do("POST", "/_lanternfish/v2/factors/passkey/finish", a.create(c), map[string]string{"X-Lanternfish-Grant": grant})
	return rec.Result()
}

func passkeyPolicy() Policy {
	p := RecommendedPolicy()
	p.IP.OnChange = onChangeVerify
	p.WebAuthn = WebAuthnPolicy{Enabled: true, Attestation: attCollect, UserVerification: "required"}
	p.Verification.NewNetworkRequiredAll = []string{factorWebAuthn}
	p.normalize()
	return p
}

func TestPasskeyStepUp(t *testing.T) {
	h := newHarness(t)
	h.enablePasskeys()
	h.publish(scopeGlobal, passkeyPolicy())
	key, enr := h.enrollECDSA("web")

	auth := newSoftAuthenticator()
	if res := h.registerPasskey(defaultSubjectID, auth); res.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d", res.StatusCode)
	}
	h.g.store.View(func(d *storeData) {
		pk := d.Subjects[defaultSubjectID].Passkeys
		if len(pk) != 1 || pk[0].AttestationResult != "not_provided" {
			t.Fatalf("stored passkey: %+v", pk)
		}
	})

	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	// Finishing without options (no challenge issued) is refused.
	if rec := h.step(otherAddr, id, "/webauthn/finish", auth.get("AAAA", defaultSubjectID)); rec.Code != http.StatusConflict {
		t.Fatalf("finish without options: %d", rec.Code)
	}
	rec := h.step(otherAddr, id, "/webauthn/options", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("options: %d %s", rec.Code, rec.Body)
	}
	c := challengeOf(t, rec.Body.Bytes())
	// Another authenticator's assertion fails and uses up the challenge.
	if rec := h.step(otherAddr, id, "/webauthn/finish", newSoftAuthenticator().get(c, defaultSubjectID)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown authenticator: %d %s", rec.Code, rec.Body)
	}
	if rec := h.step(otherAddr, id, "/webauthn/finish", auth.get(c, defaultSubjectID)); rec.Code != http.StatusConflict {
		t.Fatalf("reused challenge: %d", rec.Code)
	}
	rec = h.step(otherAddr, id, "/webauthn/options", map[string]any{})
	c = challengeOf(t, rec.Body.Bytes())
	if rec := h.step(otherAddr, id, "/webauthn/finish", auth.get(c, defaultSubjectID)); rec.Code != http.StatusOK {
		t.Fatalf("assertion: %d %s", rec.Code, rec.Body)
	}
	rec = h.complete(otherAddr, id, enr.DeviceID, key)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}
	if rec := h.get(otherAddr, tokenOf(t, rec)); rec.Code != http.StatusOK {
		t.Fatalf("session after passkey: %d", rec.Code)
	}
}

func TestPasskeyPolicyRules(t *testing.T) {
	h := newHarness(t)
	h.enablePasskeys()
	p := passkeyPolicy()
	p.WebAuthn.AllowBackupEligible = false
	h.publish(scopeGlobal, p)
	synced := newSoftAuthenticator()
	synced.flags = 0x08 | 0x10 // backup eligible, backed up
	if res := h.registerPasskey(defaultSubjectID, synced); res.StatusCode != http.StatusForbidden {
		t.Fatalf("synced passkey under a device-bound policy: %d", res.StatusCode)
	}
	// require_trusted needs FIDO metadata; without it the policy can't publish.
	p.WebAuthn.Attestation = attRequired
	rec := h.admin2("PUT", "policy", map[string]any{"expected_version": h.globalVersion(), "policy": p})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("require_trusted without metadata: %d %s", rec.Code, rec.Body)
	}
	// Wrong origin is rejected by the library.
	p.WebAuthn.Attestation = attCollect
	other := newSoftAuthenticator()
	other.origin = "https://evil.example.net"
	if res := h.registerPasskey(defaultSubjectID, other); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong origin: %d", res.StatusCode)
	}
}
