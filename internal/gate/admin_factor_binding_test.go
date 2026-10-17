package gate

import (
	"net/http"
	"strings"
	"testing"
)

// Possession of another admin key must not satisfy a dashboard session's
// second factor, or borrow a session's verification to change that key's link.
func TestAdminFactorVerificationBoundToAuthenticatedKey(t *testing.T) {
	h := newHarness(t)
	h.setUpTOTP(defaultSubjectID)
	h.g.store.Update(func(d *storeData) error {
		d.AdminKeys["adm_test"].SubjectID = defaultSubjectID
		return nil
	})
	h.g.store.Update(func(d *storeData) error {
		d.Subjects["sub_other"] = &Subject{ID: "sub_other", Name: "Other admin", Role: "admin", Status: "active"}
		return nil
	})
	secret, _ := h.setUpTOTP("sub_other")
	otherToken := "lfa_" + randomToken()
	h.g.store.Update(func(d *storeData) error {
		d.AdminKeys["adm_other"] = &AdminKey{ID: "adm_other", Name: "Other", Hash: hashToken(otherToken), SubjectID: "sub_other"}
		return nil
	})
	cookie, _ := h.dashboardSignIn() // adm_test's session, not adm_other's
	hdr := map[string]string{"Cookie": cookie, "Authorization": "Bearer " + otherToken}
	rec := h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/verify", map[string]string{"code": h.code(secret)}, hdr)
	if rec.Code != http.StatusConflict {
		t.Fatalf("another key verified this session: %d %s", rec.Code, rec.Body)
	}
	token := strings.TrimPrefix(cookie, adminCookie+"=")
	sess, ok := h.g.adminSessions.use(token, strings.Split(testClientAddr, ":")[0], h.now)
	if !ok || !sess.verifiedAt.IsZero() {
		t.Fatal("foreign-key verification changed the session")
	}
	// A separately verified session for adm_test cannot unlink adm_other,
	// even when the caller supplies adm_other's legitimate bearer credential.
	h.g.adminSessions.markVerified(token, h.now)
	rec = h.dashboard(testClientAddr, "POST", "/_lanternfish/admin/link", map[string]string{"subject_id": ""}, hdr)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("another key borrowed session verification: %d %s", rec.Code, rec.Body)
	}
	h.g.store.View(func(d *storeData) {
		if d.AdminKeys["adm_other"].SubjectID != "sub_other" {
			t.Error("foreign verified session unlinked the owner")
		}
	})
}
