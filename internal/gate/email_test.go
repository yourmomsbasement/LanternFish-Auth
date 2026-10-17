package gate

import (
	"context"
	"crypto/x509"
	"encoding/json"
	mailer "github.com/yourmomsbasement/lanternfish-auth/internal/mail"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func seedClaim(t *testing.T, h *harness, expiry time.Time) *EnrollmentClaim {
	t.Helper()
	raw := "lfc_" + randomToken()
	c := &EnrollmentClaim{ID: newID("clm_"), Hash: hashToken(raw), Platform: "web", SubjectID: defaultSubjectID, ExpiresAt: expiry}
	if e := h.g.store.Update(func(d *storeData) error {
		if d.Claims == nil {
			d.Claims = map[string]*EnrollmentClaim{}
		}
		d.Claims[c.ID] = c
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	seededTokens.Store(c.ID, raw)
	return c
}

var seededTokens sync.Map

func TestEmailClaimConcurrentSingleUse(t *testing.T) {
	h := newHarness(t)
	c := seedClaim(t, h, h.now.Add(15*time.Minute))
	raw, _ := seededTokens.Load(c.ID)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, e := h.g.consumeEmailClaim(raw.(string))
			if e == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successes=%d", successes.Load())
	}
	b, _ := os.ReadFile(h.cfg.DataPath)
	if strings.Contains(string(b), raw.(string)) {
		t.Fatal("raw token persisted")
	}
}
func TestEmailClaimRejectedStates(t *testing.T) {
	for _, state := range []string{"expired", "revoked", "used"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			c := seedClaim(t, h, h.now.Add(time.Minute))
			raw, _ := seededTokens.Load(c.ID)
			h.g.store.Update(func(d *storeData) error {
				x := d.Claims[c.ID]
				switch state {
				case "expired":
					x.ExpiresAt = h.now
				case "revoked":
					x.Revoked = true
				case "used":
					x.Used = true
				}
				return nil
			})
			if _, _, e := h.g.consumeEmailClaim(raw.(string)); e == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
}
func TestEmailClaimRandomAndAudit(t *testing.T) {
	h := newHarness(t)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		c := seedClaim(t, h, h.now.Add(time.Minute))
		raw, _ := seededTokens.Load(c.ID)
		token := raw.(string)
		if len(token) != 47 || seen[token] {
			t.Fatal("invalid random token")
		}
		seen[token] = true
	}
	c := seedClaim(t, h, h.now.Add(time.Minute))
	raw, _ := seededTokens.Load(c.ID)
	res := h.do("POST", "/_lanternfish/v2/claim", map[string]any{"token": raw}, nil)
	if res.Code != 200 {
		t.Fatal(res.Code, res.Body.String())
	}
	b, _ := os.ReadFile(h.cfg.AuditPath)
	if strings.Contains(string(b), raw.(string)) {
		t.Fatal("token in audit")
	}
	if _, _, e := h.g.consumeEmailClaim("lfc_invalid"); e == nil {
		t.Fatal("accepted malformed claim")
	}
}
func TestEmailRateLimits(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		if !h.g.reserveMail(map[string]int{"recipient": 3}) {
			t.Fatal("premature limit")
		}
		h.g.releaseMail()
	}
	if h.g.reserveMail(map[string]int{"recipient": 3}) {
		t.Fatal("limit bypassed")
	}
}
func TestEmailAdminAuthorization(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"email/test", "email/invitations"} {
		r := h.do("POST", "/_lanternfish/admin/v2/"+p, map[string]any{"recipient": "user@example.com"}, nil)
		if r.Code != 401 {
			t.Fatalf("%s: %d", p, r.Code)
		}
	}
}
func TestJellyfinPolicyRestrictions(t *testing.T) {
	p := &JellyfinEnrollment{Libraries: []string{strings.Repeat("a", 32)}, Playback: true}
	if validateJellyfinEnrollment(p) != nil {
		t.Fatal("valid policy rejected")
	}
	m := p.policy(false)
	for _, key := range []string{"IsAdministrator", "EnableAllFolders", "EnableContentDeletion", "EnableLiveTvAccess"} {
		if m[key] != false {
			t.Fatalf("%s enabled", key)
		}
	}
	if validateJellyfinEnrollment(&JellyfinEnrollment{}) == nil {
		t.Fatal("empty libraries accepted")
	}
}
func TestTicketBindsJellyfinPolicy(t *testing.T) {
	h := newHarness(t)
	p := &JellyfinEnrollment{Libraries: []string{strings.Repeat("a", 32)}, Playback: true}
	r := h.do("POST", "/_lanternfish/admin/v1/tickets", map[string]any{"platform": "web", "jellyfin_enrollment": p}, map[string]string{"Authorization": "Bearer " + h.adminKey})
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	var out struct {
		Ticket string `json:"ticket"`
	}
	json.Unmarshal(r.Body.Bytes(), &out)
	ticket, ok := h.g.lookupTicket(out.Ticket, h.now)
	if !ok || ticket.JellyfinEnrollment == nil || ticket.JellyfinEnrollment.Libraries[0] != p.Libraries[0] {
		t.Fatal("policy not bound")
	}
}

func TestEmailAdminCSRF(t *testing.T) {
	h := newHarness(t)
	cookie, csrf := h.dashboardSignIn()
	for _, path := range []string{"email/test", "email/invitations"} {
		endpoint := "/_lanternfish/admin/v2/" + path
		r := h.dashboard(testClientAddr, "POST", endpoint, map[string]string{"recipient": "a@example.com"}, map[string]string{"Cookie": cookie})
		if r.Code != 401 {
			t.Fatalf("missing CSRF accepted: %d", r.Code)
		}
		r = h.dashboard(testClientAddr, "POST", endpoint, map[string]string{"recipient": "a@example.com"}, map[string]string{"Cookie": cookie, csrfHeader: csrf})
		if r.Code == 401 || r.Code == 403 {
			t.Fatalf("valid CSRF denied: %d", r.Code)
		}
	}
}
func TestSMTPFailureLeavesClaimUsable(t *testing.T) {
	h := newHarness(t)
	c := seedClaim(t, h, h.now.Add(time.Minute))
	raw, _ := seededTokens.Load(c.ID)
	s := emailSettings{Settings: mailer.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, FromEmail: "sender@example.com"}}
	if !h.g.reserveMail(map[string]int{"test": 5}) {
		t.Fatal("queue unavailable")
	}
	h.g.submitEmail(s, mailer.Message{To: "user@example.com", Subject: "Invitation", TextBody: raw.(string)}, c.ID, "test")
	h.g.store.View(func(d *storeData) {
		if d.Claims[c.ID].Status != "email_failed" || d.Claims[c.ID].Used {
			t.Error("claim changed by mail failure")
		}
	})
	if _, _, e := h.g.consumeEmailClaim(raw.(string)); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(h.cfg.AuditPath)
	if strings.Contains(string(b), raw.(string)) {
		t.Fatal("SMTP failure logged token")
	}
}
func TestJellyfinAccountProvisioning(t *testing.T) {
	for _, failPolicy := range []bool{false, true} {
		t.Run(map[bool]string{true: "rollback", false: "success"}[failPolicy], func(t *testing.T) {
			h := newHarness(t)
			key, enr := h.enrollECDSA("web")
			token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
			id := strings.Repeat("a", 32)
			var mu sync.Mutex
			calls := []string{}
			var policies []map[string]any
			var createPassword string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				pub, _ := x509.MarshalPKIXPublicKey(&h.g.upstream.PublicKey)
				if !verifyUpstream(t, pub, r) || r.Header.Get(deviceHeader) != "gate-service" {
					t.Error("unsigned Jellyfin administration request")
					w.WriteHeader(403)
					return
				}
				if r.Header.Get("Authorization") != `MediaBrowser Token="secret-api-key"` || r.Header.Get("X-Emby-Token") != "" {
					t.Error("API authentication missing")
				}
				switch {
				case r.URL.Path == "/Users/New":
					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					createPassword = body["Password"]
					io.WriteString(w, `{"Id":"`+id+`"}`)
				case strings.HasSuffix(r.URL.Path, "/Policy"):
					var body map[string]any
					json.NewDecoder(r.Body).Decode(&body)
					policies = append(policies, body)
					if failPolicy {
						w.WriteHeader(500)
					} else {
						w.WriteHeader(204)
					}
				default:
					w.WriteHeader(204)
				}
			}))
			defer server.Close()
			h.g.store.Update(func(d *storeData) error {
				d.JellyfinAdmin = &JellyfinAdminSettings{URL: server.URL, SealedKey: h.g.sealer.Seal("jellyfin-admin-key", []byte("secret-api-key"))}
				d.Devices[enr.DeviceID].JellyfinEnrollment = &JellyfinEnrollment{Libraries: []string{id}, Playback: true}
				return nil
			})
			headers := map[string]string{sessionHeader: token, "Origin": "https://gate.example", "X-Lanternfish-Account": "create"}
			body := map[string]string{"username": "alice", "password": "a-long-private-password"}
			r := h.do("POST", "/_lanternfish/v2/jellyfin/account", body, headers)
			mu.Lock()
			defer mu.Unlock()
			if failPolicy {
				if r.Code != 502 || calls[len(calls)-1] != "DELETE /Users/"+id {
					t.Fatalf("rollback failed: %d %v", r.Code, calls)
				}
			} else {
				if r.Code != 201 {
					t.Fatal(r.Code, r.Body.String())
				}
				if len(policies) != 2 || policies[0]["IsDisabled"] != true || policies[1]["IsDisabled"] != false || policies[1]["EnableAllFolders"] != false || policies[1]["IsAdministrator"] != false {
					t.Fatalf("unsafe policies: %v", policies)
				}
				if r = h.do("POST", "/_lanternfish/v2/jellyfin/account", body, headers); r.Code != 409 {
					t.Fatal("duplicate account allowed", r.Code)
				}
			}
			if createPassword == body["password"] || createPassword == "" {
				t.Fatal("chosen password exposed before policy applied")
			}
			for _, path := range []string{h.cfg.DataPath, h.cfg.AuditPath} {
				b, _ := os.ReadFile(path)
				if strings.Contains(string(b), body["password"]) || strings.Contains(string(b), "secret-api-key") {
					t.Fatal("plaintext secret persisted")
				}
			}
		})
	}
}
func TestJellyfinAccountRequiresAuthorizationAndCSRF(t *testing.T) {
	h := newHarness(t)
	body := map[string]string{"username": "alice", "password": "a-long-private-password"}
	if r := h.do("POST", "/_lanternfish/v2/jellyfin/account", body, nil); r.Code != 403 {
		t.Fatal(r.Code)
	}
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })
	if r := h.do("POST", "/_lanternfish/v2/jellyfin/account", body, map[string]string{sessionHeader: token, "Origin": "https://evil.example", "X-Lanternfish-Account": "create"}); r.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	if r := h.do("POST", "/_lanternfish/v2/jellyfin/account", body, map[string]string{sessionHeader: token, "Origin": "https://gate.example", "X-Lanternfish-Account": "create"}); r.Code != 409 {
		t.Fatal("account creation without invitation policy", r.Code)
	}
}
func TestJellyfinClientRefusesRedirects(t *testing.T) {
	h := newHarness(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("API key followed redirect") }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	s := JellyfinAdminSettings{URL: server.URL, SealedKey: h.g.sealer.Seal("jellyfin-admin-key", []byte("secret"))}
	if h.g.jellyfinCall(context.Background(), s, "GET", "/", nil, nil) == nil {
		t.Fatal("redirect accepted")
	}
}

func TestEmailRetryRotatesClaimAndPreservesPolicy(t *testing.T) {
	h := newHarness(t)
	c := seedClaim(t, h, h.now.Add(15*time.Minute))
	oldRaw, _ := seededTokens.Load(c.ID)
	policy := &JellyfinEnrollment{Libraries: []string{strings.Repeat("a", 32)}, Playback: true}
	h.g.store.Update(func(d *storeData) error {
		d.Claims[c.ID].JellyfinEnrollment = policy
		d.EmailSettings = &emailSettings{Settings: mailer.Settings{Enabled: true, Host: "127.0.0.1", Port: 1, FromEmail: "sender@example.com"}, PublicOrigin: "https://gate.example"}
		return nil
	})
	r := h.do("POST", "/_lanternfish/admin/v2/email/invitations/"+c.ID+"/retry", map[string]any{"recipient": "a@example.com"}, map[string]string{"Authorization": "Bearer " + h.adminKey})
	if r.Code != 202 {
		t.Fatal(r.Code, r.Body.String())
	}
	out := decode[map[string]any](t, r)
	link := out["link"].(string)
	raw := strings.Split(link, "#token=")[1]
	if _, _, e := h.g.consumeEmailClaim(oldRaw.(string)); e == nil {
		t.Fatal("old link remains usable")
	}
	ticket, _, e := h.g.consumeEmailClaim(raw)
	if e != nil {
		t.Fatal(e)
	}
	stored, ok := h.g.lookupTicket(ticket, h.now)
	if !ok || stored.JellyfinEnrollment == nil || !stored.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatal("retry changed policy or expiry")
	}
	b, _ := os.ReadFile(h.cfg.DataPath)
	if strings.Contains(string(b), raw) {
		t.Fatal("retry token persisted")
	}
}

func TestJellyfinLibrariesRequireGateSignatureAndAPIKey(t *testing.T) {
	h := newHarness(t)
	pub, _ := x509.MarshalPKIXPublicKey(&h.g.upstream.PublicKey)
	nonces := map[string]bool{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		nonce := r.Header.Get(gateNonceHeader)
		if !verifyUpstream(t, pub, r) || nonce == "" || nonces[nonce] || r.Header.Get(deviceHeader) != "gate-service" || r.Header.Get("Authorization") != `MediaBrowser Token="admin-key"` || r.Header.Get("X-Emby-Token") != "" {
			w.WriteHeader(403)
			return
		}
		nonces[nonce] = true
		if r.RequestURI != "/jellyfin/Library/VirtualFolders" {
			t.Error("base path not preserved", r.RequestURI)
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `[{"Name":"Movies","ItemId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]`)
	}))
	defer server.Close()
	h.g.store.Update(func(d *storeData) error {
		d.JellyfinAdmin = &JellyfinAdminSettings{URL: server.URL + "/jellyfin", SealedKey: h.g.sealer.Seal("jellyfin-admin-key", []byte("admin-key"))}
		return nil
	})
	for i := 0; i < 2; i++ {
		r := h.admin2("GET", "jellyfin/libraries", nil)
		if r.Code != 200 || !strings.Contains(r.Body.String(), "Movies") {
			t.Fatal(r.Code, r.Body.String())
		}
	}
}

func TestJellyfinSettingsValidateBeforeSave(t *testing.T) {
	h := newHarness(t)
	pub, _ := x509.MarshalPKIXPublicKey(&h.g.upstream.PublicKey)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !verifyUpstream(t, pub, r) {
			t.Error("validation request unsigned")
			w.WriteHeader(403)
			return
		}
		switch r.Header.Get("Authorization") {
		case `MediaBrowser Token="good-key"`:
			io.WriteString(w, `[]`)
		case `MediaBrowser Token="wrong-response"`:
			io.WriteString(w, `<html>login</html>`)
		case `MediaBrowser Token="redirect"`:
			http.Redirect(w, r, "/login", 302)
		default:
			w.WriteHeader(401)
			io.WriteString(w, "private diagnostics must not reach browser")
		}
	}))
	defer server.Close()
	r := h.admin2("PUT", "jellyfin", map[string]any{"url": server.URL, "api_key": "bad-key"})
	if r.Code != 400 || h.g.jellyfinConfig().SealedKey != "" {
		t.Fatal("invalid initial connection saved", r.Code)
	}
	r = h.admin2("PUT", "jellyfin", map[string]any{"url": server.URL, "api_key": "good-key"})
	if r.Code != 200 || !strings.Contains(r.Body.String(), `"validated":true`) {
		t.Fatal("missing confirmation", r.Code, r.Body.String())
	}
	saved := h.g.jellyfinConfig()
	for _, key := range []string{"bad-key", "wrong-response", "redirect"} {
		r = h.admin2("PUT", "jellyfin", map[string]any{"url": server.URL, "api_key": key})
		if r.Code != 400 || h.g.jellyfinConfig() != saved {
			t.Fatal("failed validation overwrote saved settings", key, r.Code)
		}
		if strings.Contains(r.Body.String(), "private diagnostics") {
			t.Fatal("upstream response leaked")
		}
	}
	r = h.admin2("PUT", "jellyfin", map[string]any{"url": server.URL, "api_key": ""})
	if r.Code != 200 || h.g.jellyfinConfig() != saved {
		t.Fatal("keeping saved key failed", r.Code)
	}
	failed := httptest.NewServer(http.NotFoundHandler())
	failedURL := failed.URL
	failed.Close()
	r = h.admin2("PUT", "jellyfin", map[string]any{"url": failedURL, "api_key": "good-key"})
	if r.Code != 400 || h.g.jellyfinConfig() != saved {
		t.Fatal("unreachable connection saved", r.Code)
	}
	b, _ := os.ReadFile(h.cfg.DataPath)
	if strings.Contains(string(b), "good-key") {
		t.Fatal("API key persisted as plaintext")
	}
}

func TestJellyfinAuthorizationNormalizesSavedToken(t *testing.T) {
	h := newHarness(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != `MediaBrowser Token="test-key"` || r.Header.Get("X-Emby-Token") != "" {
			t.Error("incorrect Jellyfin authorization header")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	for _, token := range []string{"test-key", "  test-key \n"} {
		s := JellyfinAdminSettings{URL: server.URL, SealedKey: h.g.sealer.Seal("jellyfin-admin-key", []byte(token))}
		if e := h.g.jellyfinCall(context.Background(), s, "GET", "/Library/VirtualFolders", nil, nil); e != nil {
			t.Fatal(e)
		}
	}
	for _, token := range []string{"   ", `key"quoted`, "key\r\nInjected: value", `key\escaped`} {
		s := JellyfinAdminSettings{URL: server.URL, SealedKey: h.g.sealer.Seal("jellyfin-admin-key", []byte(token))}
		if e := h.g.jellyfinCall(context.Background(), s, "GET", "/Library/VirtualFolders", nil, nil); e == nil {
			t.Fatal("invalid token accepted")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("invalid token sent to server")
	}
}
