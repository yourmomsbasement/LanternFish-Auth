package gate

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Owner factors: authenticator-app codes (TOTP), passkeys/security keys
// (WebAuthn, webauthn.go) and one-time recovery codes. They belong to a
// subject, never to a device: approving a laptop on a network never approves
// another device there.
//
// SECURITY: factors are only ever set up through a setup grant an
// administrator issued (or a recovery code redeemed during verification).
// Failing verification never lets a client enroll a new factor.

// TOTPFactor is an owner's authenticator app. The secret is sealed under the
// master key, bound to the subject and factor ID.
type TOTPFactor struct {
	ID           string    `json:"id"`
	SealedSecret string    `json:"sealed_secret"`
	Digits       int       `json:"digits"`
	Period       int       `json:"period"`
	ActivatedAt  time.Time `json:"activated_at"`
	// LastStep is the last time step a code was accepted for; codes for it
	// or earlier steps are refused (no replay).
	LastStep int64 `json:"last_step"`
}

// RecoveryCode is a one-time code for replacing a lost authenticator. Only
// its hash is stored.
type RecoveryCode struct {
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// WebAuthnCredential is an owner's passkey or security key.
type WebAuthnCredential struct {
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	// AttestationResult is what registration established about the
	// authenticator: "verified" (checked against FIDO metadata),
	// "unverified" (evidence offered but not checked against a trust root),
	// or "not_provided". It says nothing about the computer it was used on.
	AttestationResult string              `json:"attestation_result"`
	Credential        webauthn.Credential `json:"credential"`
}

func totpPurpose(subjectID, factorID string) string {
	return "totp-secret:" + subjectID + ":" + factorID
}

// totpCode computes an RFC 6238 code (HMAC-SHA-1) for a time step.
func totpCode(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// totpMatch returns the time step code is valid for, within drift steps of
// now and after lastStep.
func totpMatch(secret []byte, code string, now time.Time, period, digits, drift int, lastStep int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != digits {
		return 0, false
	}
	cur := now.Unix() / int64(period)
	matched := int64(-1)
	// Compare against every candidate so timing doesn't reveal which matched.
	for d := -drift; d <= drift; d++ {
		step := cur + int64(d)
		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step, digits)), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	return matched, matched >= 0
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// totpURI is the otpauth:// link authenticator apps import (also as a QR code).
func totpURI(secret []byte, account string) string {
	label := url.PathEscape("Lanternfish:" + account)
	q := url.Values{"secret": {b32.EncodeToString(secret)}, "issuer": {"Lanternfish"},
		"algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// newRecoveryCodes returns n codes like "k7qd-4mzp-x2ha" and their records.
func newRecoveryCodes(n int, now time.Time) ([]string, []RecoveryCode) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	codes := make([]string, n)
	recs := make([]RecoveryCode, n)
	for i := range codes {
		raw := randomBytes(12)
		var b strings.Builder
		for j, c := range raw {
			if j > 0 && j%4 == 0 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(c)%len(alphabet)])
		}
		codes[i] = b.String()
		recs[i] = RecoveryCode{Hash: hashToken(normalizeRecovery(codes[i])), CreatedAt: now}
	}
	return codes, recs
}

func normalizeRecovery(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

// ---- Setup grants ----

// A setupGrant lets whoever holds it set up factors for one owner, for a
// short time. An administrator issues it (as a link) or an owner gets one by
// redeeming a recovery code. It lives in memory: a restart cancels it.
type setupGrant struct {
	subjectID string
	issuedBy  string // admin key name, or "recovery code"
	expires   time.Time
	recovery  bool // replaces the existing authenticator app

	// Ceremony state.
	totpSecret    []byte // proposed, not yet confirmed
	waSession     *webauthn.SessionData
	passkeyName   string
	passkeys      int  // registered with this grant
	replaceTOTP   bool // the admin chose to replace an existing authenticator
	recoveryCodes []string
}

const (
	setupGrantTTL   = 30 * time.Minute
	maxSetupGrants  = 256
	maxPasskeysEach = 10
)

type setupGrantTable struct {
	mu     sync.Mutex
	byHash map[string]*setupGrant
}

func newSetupGrantTable() *setupGrantTable {
	return &setupGrantTable{byHash: map[string]*setupGrant{}}
}

// issue returns a new grant's handle.
func (t *setupGrantTable) issue(subjectID, by string, recovery bool, now time.Time) (string, time.Time) {
	handle := "lfg_" + randomToken()
	g := &setupGrant{subjectID: subjectID, issuedBy: by, expires: now.Add(setupGrantTTL), recovery: recovery}
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, x := range t.byHash {
		if !now.Before(x.expires) {
			delete(t.byHash, h)
		}
	}
	if len(t.byHash) >= maxSetupGrants { // drop the one closest to expiring
		var oldest string
		for h, x := range t.byHash {
			if oldest == "" || x.expires.Before(t.byHash[oldest].expires) {
				oldest = h
			}
		}
		delete(t.byHash, oldest)
	}
	t.byHash[hashToken(handle)] = g
	return handle, g.expires
}

// with runs fn on a live grant under the table lock.
func (t *setupGrantTable) with(handle string, now time.Time, fn func(g *setupGrant) error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	g, ok := t.byHash[hashToken(handle)]
	if !ok || !now.Before(g.expires) {
		return errGrantInvalid
	}
	return fn(g)
}

func (t *setupGrantTable) revoke(handle string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byHash, hashToken(handle))
}

// revokeSubject cancels every grant for an owner (factor reset, disable).
func (t *setupGrantTable) revokeSubject(subjectID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, g := range t.byHash {
		if g.subjectID == subjectID {
			delete(t.byHash, h)
		}
	}
}

var errGrantInvalid = fmt.Errorf("setup link invalid or expired")
