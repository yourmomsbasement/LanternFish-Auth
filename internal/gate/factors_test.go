package gate

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 (secret "12345678901234567890", 8 digits).
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "94287082", 1111111109: "07081804", 1111111111: "14050471",
		1234567890: "89005924", 2000000000: "69279037", 20000000000: "65353130",
	} {
		if got := totpCode(secret, unix/30, 8); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestTOTPMatchDriftAndReplay(t *testing.T) {
	secret := randomBytes(20)
	now := time.Unix(1_800_000_000, 0)
	step := now.Unix() / 30
	code := totpCode(secret, step, 6)
	if s, ok := totpMatch(secret, code, now, 30, 6, 1, 0); !ok || s != step {
		t.Fatal("current code refused")
	}
	if _, ok := totpMatch(secret, code, now, 30, 6, 1, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := totpMatch(secret, totpCode(secret, step-1, 6), now, 30, 6, 1, 0); !ok {
		t.Fatal("previous step refused with drift 1")
	}
	if _, ok := totpMatch(secret, totpCode(secret, step-1, 6), now, 30, 6, 0, 0); ok {
		t.Fatal("previous step accepted with drift 0")
	}
	if _, ok := totpMatch(secret, totpCode(secret, step+2, 6), now, 30, 6, 1, 0); ok {
		t.Fatal("code two steps ahead accepted")
	}
	if _, ok := totpMatch(secret, "12345", now, 30, 6, 1, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, recs := newRecoveryCodes(10, time.Now())
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 14 || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if recs[i].Hash != hashToken(normalizeRecovery(" "+strings.ToUpper(c)+" ")) {
			t.Fatal("recovery code normalisation")
		}
	}
}
