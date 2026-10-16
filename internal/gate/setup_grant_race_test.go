package gate

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// A2: a setup grant revoked while a passkey registration is in flight can't
// still register the passkey.

// beforeRead runs before at the first read of the body: the request has
// been accepted and is waiting for the client.
type beforeRead struct {
	io.Reader
	once   sync.Once
	before func()
}

func (r *beforeRead) Read(p []byte) (int, error) { r.once.Do(r.before); return r.Reader.Read(p) }

func TestRevokedSetupGrantCannotFinishRegistration(t *testing.T) {
	revocations := map[string]func(h *harness){
		"new setup link": func(h *harness) {
			if rec := h.admin2("POST", "subjects/"+defaultSubjectID+"/setup-link", nil); rec.Code != http.StatusCreated {
				h.t.Fatalf("reissue: %d", rec.Code)
			}
		},
		"owner disabled": func(h *harness) {
			if rec := h.admin2("POST", "subjects/"+defaultSubjectID+"/disable", nil); rec.Code != http.StatusNoContent {
				h.t.Fatalf("disable: %d", rec.Code)
			}
		},
	}
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.enablePasskeys()
			rec := h.admin2("POST", "subjects/"+defaultSubjectID+"/setup-link", nil)
			path := decode[map[string]any](t, rec)["path"].(string)
			grant := strings.Split(path, "grant=")[1]
			opts := h.do("POST", "/_lanternfish/v2/factors/passkey/options", map[string]string{"grant": grant}, nil)
			body, _ := json.Marshal(newSoftAuthenticator().create(challengeOf(t, opts.Body.Bytes())))

			req := httptest.NewRequest("POST", "https://gate.example/_lanternfish/v2/factors/passkey/finish",
				&beforeRead{Reader: bytes.NewReader(body), before: func() { revoke(h) }})
			req.RemoteAddr = testClientAddr
			req.Header.Set("X-Lanternfish-Grant", grant)
			out := httptest.NewRecorder()
			h.g.Handler().ServeHTTP(out, req)
			if out.Code == http.StatusCreated {
				t.Fatalf("registration finished with a revoked grant")
			}
			if n := len(h.passkeyResults(defaultSubjectID)); n != 0 {
				t.Fatalf("%d passkey(s) stored", n)
			}
		})
	}
}
