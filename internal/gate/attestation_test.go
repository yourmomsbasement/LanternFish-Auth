package gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// A1: only a certificate-chain attestation for an authenticator the FIDO
// metadata lists makes a passkey "verified".

// attestationVendor is a fake authenticator vendor: a root CA, an attestation
// certificate for one model, and the metadata entry that vouches for it.
type attestationVendor struct {
	aaguid  uuid.UUID
	rootDER []byte
	root    *x509.Certificate
	leafKey *ecdsa.PrivateKey
	leafDER []byte
}

func newAttestationVendor(t *testing.T) *attestationVendor {
	t.Helper()
	v := &attestationVendor{aaguid: uuid.New()}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Vendor Root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	var err error
	if v.rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey); err != nil {
		t.Fatal(err)
	}
	v.root, _ = x509.ParseCertificate(v.rootDER)
	v.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ext, _ := asn1.Marshal(v.aaguid[:])
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"Test Vendor"},
			OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Test Key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: ext}}}
	if v.leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, v.root, &v.leafKey.PublicKey, rootKey); err != nil {
		t.Fatal(err)
	}
	return v
}

// provider is FIDO metadata listing the vendor's model (or nothing), with
// the validation production uses.
func (v *attestationVendor) provider(t *testing.T, listed bool) metadata.Provider {
	t.Helper()
	entries := map[uuid.UUID]*metadata.Entry{}
	if listed {
		entries[v.aaguid] = &metadata.Entry{AaGUID: v.aaguid,
			MetadataStatement: metadata.Statement{AaGUID: v.aaguid, Description: "Test Key",
				AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
				AttestationRootCertificates: []*x509.Certificate{v.root}},
			StatusReports: []metadata.StatusReport{{Status: metadata.FidoCertified}}}
	}
	mds, err := memory.New(memory.WithMetadata(entries), memory.WithValidateEntry(true),
		memory.WithValidateTrustAnchor(true), memory.WithValidateStatus(true))
	if err != nil {
		t.Fatal(err)
	}
	return mds
}

// authenticator is a passkey of the vendor's model; packed attestation with
// the vendor's certificate chain.
func (v *attestationVendor) authenticator() *softAuthenticator {
	a := newSoftAuthenticator()
	a.aaguid = v.aaguid[:]
	a.attest = func(authData, clientDataHash []byte) (string, map[string]any) {
		d := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
		sig, _ := ecdsa.SignASN1(rand.Reader, v.leafKey, d[:])
		return "packed", map[string]any{"alg": -7, "sig": sig, "x5c": []any{v.leafDER}}
	}
	return a
}

// selfAttesting is a packed self attestation (signed with the credential's
// own key, no certificate chain) claiming the vendor's AAGUID.
func selfAttesting(aaguid uuid.UUID) *softAuthenticator {
	a := newSoftAuthenticator()
	a.aaguid = aaguid[:]
	a.attest = func(authData, clientDataHash []byte) (string, map[string]any) {
		d := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))
		sig, _ := ecdsa.SignASN1(rand.Reader, a.key, d[:])
		return "packed", map[string]any{"alg": -7, "sig": sig}
	}
	return a
}

func (h *harness) strictPasskeys(mds metadata.Provider) {
	h.t.Helper()
	h.enablePasskeys()
	strict, err := webauthn.New(&webauthn.Config{RPID: testRPID, RPDisplayName: "Test", RPOrigins: []string{testOrigin}, MDS: mds})
	if err != nil {
		h.t.Fatal(err)
	}
	h.g.passkeys.strict, h.g.passkeys.mds = strict, mds
}

func (h *harness) passkeyResults(subjectID string) []string {
	var out []string
	h.g.store.View(func(d *storeData) {
		for _, p := range d.Subjects[subjectID].Passkeys {
			out = append(out, p.AttestationResult)
		}
	})
	return out
}

func TestRequireTrustedAcceptsOnlyVerifiedAttestation(t *testing.T) {
	vendor := newAttestationVendor(t)
	cases := []struct {
		name   string
		listed bool // the model is in the metadata
		auth   func() *softAuthenticator
		want   int
	}{
		{"listed model with its certificate chain", true, vendor.authenticator, http.StatusCreated},
		{"no attestation", true, newSoftAuthenticator, http.StatusForbidden},
		{"self attestation claiming a listed model", true, func() *softAuthenticator { return selfAttesting(vendor.aaguid) }, http.StatusForbidden},
		{"chain for a model the metadata doesn't list", false, vendor.authenticator, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.strictPasskeys(vendor.provider(t, c.listed))
			p := passkeyPolicy()
			p.WebAuthn.Attestation = attRequired
			h.publish(scopeGlobal, p)
			res := h.registerPasskey(defaultSubjectID, c.auth())
			if res.StatusCode != c.want {
				t.Fatalf("registration: %d, want %d", res.StatusCode, c.want)
			}
			if c.want == http.StatusCreated {
				if r := h.passkeyResults(defaultSubjectID); len(r) != 1 || r[0] != "verified" {
					t.Fatalf("stored as %v", r)
				}
			} else if len(h.passkeyResults(defaultSubjectID)) != 0 {
				t.Fatal("a rejected passkey was stored")
			}
		})
	}
}

// The trusted passkey from the fixture really works for a require_trusted
// step-up, end to end.
func TestTrustedPasskeyCompletesStepUp(t *testing.T) {
	vendor := newAttestationVendor(t)
	h := newHarness(t)
	h.strictPasskeys(vendor.provider(t, true))
	p := passkeyPolicy()
	p.WebAuthn.Attestation = attRequired
	h.publish(scopeGlobal, p)
	a := vendor.authenticator()
	if res := h.registerPasskey(defaultSubjectID, a); res.StatusCode != http.StatusCreated {
		t.Fatalf("registration: %d", res.StatusCode)
	}
	key, enr := h.enrollECDSA("web")
	id := h.startStepUp(otherAddr, enr.DeviceID, key)
	opts := h.step(otherAddr, id, "/webauthn/options", map[string]any{})
	if rec := h.step(otherAddr, id, "/webauthn/finish", a.get(challengeOf(t, opts.Body.Bytes()), defaultSubjectID)); rec.Code != http.StatusOK {
		t.Fatalf("assertion: %d %s", rec.Code, rec.Body)
	}
	if rec := h.get(otherAddr, tokenOf(t, h.complete(otherAddr, id, enr.DeviceID, key))); rec.Code != http.StatusOK {
		t.Fatalf("proxy: %d", rec.Code)
	}
}

// In collection mode nothing is refused, but only verified evidence is
// labelled verified.
func TestCollectModeLabelsHonestly(t *testing.T) {
	vendor := newAttestationVendor(t)
	cases := map[string]struct {
		auth func() *softAuthenticator
		want string
	}{
		"listed model":     {vendor.authenticator, "verified"},
		"no attestation":   {newSoftAuthenticator, "not_provided"},
		"self attestation": {func() *softAuthenticator { return selfAttesting(vendor.aaguid) }, "unverified"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.strictPasskeys(vendor.provider(t, true))
			h.publish(scopeGlobal, passkeyPolicy()) // collect_if_available
			if res := h.registerPasskey(defaultSubjectID, c.auth()); res.StatusCode != http.StatusCreated {
				t.Fatalf("registration: %d", res.StatusCode)
			}
			if r := h.passkeyResults(defaultSubjectID); len(r) != 1 || r[0] != c.want {
				t.Fatalf("stored as %v, want %s", r, c.want)
			}
		})
	}
}

// Credentials stored as "verified" by an earlier version without
// certificate-chain attestation are reclassified at startup, and the
// approvals a passkey granted for that owner's devices are withdrawn.
func TestWronglyTrustedPasskeysAreRepaired(t *testing.T) {
	h := newHarness(t)
	_, enr := h.enrollECDSA("web")
	err := h.g.store.Update(func(d *storeData) error {
		s := d.Subjects[defaultSubjectID]
		s.Passkeys = append(s.Passkeys, WebAuthnCredential{Name: "old", AttestationResult: "verified",
			Credential: webauthn.Credential{ID: []byte("x"), AttestationFormat: "none", AttestationType: "none"}})
		dev := d.Devices[enr.DeviceID]
		dev.Networks = append(dev.Networks,
			NetworkApproval{ID: "net_pk", Network: "203.0.113.0/24", Method: "webauthn", Verified: true, ExpiresAt: h.now.Add(time.Hour)},
			NetworkApproval{ID: "net_totp", Network: "198.51.100.0/24", Method: "totp", Verified: true, ExpiresAt: h.now.Add(time.Hour)})
		dev.Countries = append(dev.Countries, CountryApproval{Country: "NL", Method: "totp+webauthn", ExpiresAt: h.now.Add(time.Hour)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(h.g.cfg) // restart on the new version
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.store.View(func(d *storeData) {
		if r := d.Subjects[defaultSubjectID].Passkeys[0].AttestationResult; r != "not_provided" {
			t.Errorf("reclassified as %q", r)
		}
		dev := d.Devices[enr.DeviceID]
		for _, a := range dev.Networks {
			if a.ID == "net_pk" {
				t.Error("approval granted by the passkey kept")
			}
		}
		kept := false
		for _, a := range dev.Networks {
			kept = kept || a.ID == "net_totp"
		}
		if !kept {
			t.Error("approval granted by TOTP alone withdrawn")
		}
		if len(dev.Countries) != 0 {
			t.Error("country approval granted with the passkey kept")
		}
	})
}
