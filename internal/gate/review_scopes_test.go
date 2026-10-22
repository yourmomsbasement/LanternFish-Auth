package gate

import (
	"net/http"
	"strings"
	"testing"

	mailer "github.com/yourmomsbasement/lanternfish-auth/internal/mail"
)

// Regression tests for M2, L2 and L3 of the 2026-10-17 review.

func (h *harness) scopedKey(id string, scopes ...string) map[string]string {
	h.t.Helper()
	raw := "lfa_" + randomToken()
	h.g.store.Update(func(d *storeData) error {
		d.AdminKeys[id] = &AdminKey{ID: id, Name: id, Hash: hashToken(raw), CreatedAt: h.now, Scopes: scopes}
		return nil
	})
	return map[string]string{"Authorization": "Bearer " + raw}
}

// M2: a tickets-only key enrolls devices for ordinary owners in their
// default profile, and nothing more.
func TestTicketsScopeLimitsOwnerAndProfile(t *testing.T) {
	h := newHarness(t)
	h.g.store.Update(func(d *storeData) error {
		d.Subjects["sub_admin"] = &Subject{ID: "sub_admin", Name: "admin", Role: "admin", Status: "active", CreatedAt: h.now}
		d.Profiles["prf_open"] = &Profile{ID: "prf_open", Name: "open", CreatedAt: h.now}
		// Port 1: nothing is delivered.
		d.EmailSettings = &emailSettings{Settings: mailer.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, FromEmail: "sender@example.com"}, PublicOrigin: "https://gate.example"}
		return nil
	})
	low := h.scopedKey("adm_low", scopeTickets)
	ticket := func(hdr map[string]string, subject, profile string) int {
		return h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "android", "subject_id": subject, "profile_id": profile}, hdr).Code
	}
	invite := func(hdr map[string]string, subject, profile string) int {
		return h.do("POST", "/_lanternfish/admin/v2/email/invitations", map[string]any{"platform": "android", "recipient": "a@example.com", "subject_id": subject, "profile_id": profile}, hdr).Code
	}
	if c := ticket(low, "sub_default", ""); c != http.StatusCreated {
		t.Fatalf("ordinary ticket: %d", c)
	}
	if c := invite(low, "sub_default", ""); c != http.StatusAccepted {
		t.Fatalf("ordinary invitation: %d", c)
	}
	if c := ticket(low, "sub_admin", ""); c != http.StatusForbidden {
		t.Fatalf("tickets-only key minted a ticket for an admin owner: %d", c)
	}
	if c := ticket(low, "sub_default", "prf_open"); c != http.StatusForbidden {
		t.Fatalf("tickets-only key chose a profile: %d", c)
	}
	if c := invite(low, "sub_admin", ""); c != http.StatusForbidden {
		t.Fatalf("tickets-only key invited for an admin owner: %d", c)
	}
	if c := invite(low, "sub_default", "prf_open"); c != http.StatusForbidden {
		t.Fatalf("tickets-only key invited into a profile: %d", c)
	}
	wide := h.scopedKey("adm_wide", scopeTickets, scopeOwners, scopePolicyWrite)
	if c := ticket(wide, "sub_admin", "prf_open"); c != http.StatusCreated {
		t.Fatalf("key with owners and policy-write: %d", c)
	}
	var n int
	h.g.store.View(func(d *storeData) {
		for _, tk := range d.Tickets {
			if tk.SubjectID == "sub_admin" || tk.ProfileID != "" {
				n++
			}
		}
	})
	if n != 1 {
		t.Fatalf("%d tickets for the admin owner or a profile, want 1", n)
	}
}

// L2: listing admin keys needs the owners scope.
func TestAdminKeyListNeedsOwnersScope(t *testing.T) {
	h := newHarness(t)
	if rec := h.do("GET", "/_lanternfish/admin/v2/admin-keys", nil, h.scopedKey("adm_low", scopeTickets)); rec.Code != http.StatusForbidden {
		t.Fatalf("tickets-only key listed admin keys: %d", rec.Code)
	}
	if rec := h.do("GET", "/_lanternfish/admin/v2/admin-keys", nil, h.scopedKey("adm_own", scopeOwners)); rec.Code != http.StatusOK {
		t.Fatalf("owners key: %d", rec.Code)
	}
}

// L3: the subjects list carries no factor material.
func TestSubjectListHidesFactors(t *testing.T) {
	h := newHarness(t)
	h.g.store.Update(func(d *storeData) error {
		s := d.Subjects[defaultSubjectID]
		s.TOTP = &TOTPFactor{SealedSecret: "SEALED-SECRET"}
		s.Passkeys = []WebAuthnCredential{{Name: "key"}}
		s.RecoveryCodes = []RecoveryCode{{Hash: "RECOVERY-HASH"}}
		return nil
	})
	rec := h.do("GET", "/_lanternfish/admin/v2/subjects", nil, h.scopedKey("adm_mon", scopeDevices))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	body := rec.Body.String()
	for _, leak := range []string{"SEALED-SECRET", "RECOVERY-HASH", "sealed", "recovery_codes", "credential"} {
		if strings.Contains(body, leak) {
			t.Errorf("subjects list contains %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, `"has_totp":true`) || !strings.Contains(body, `"passkey_count":1`) {
		t.Errorf("factor status missing: %s", body)
	}
}
