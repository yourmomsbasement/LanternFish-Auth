package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A client must not be able to drop the identity headers the Gate adds by
// listing them as hop-by-hop in its Connection header.
func TestConnectionHeaderCannotStripIdentity(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	rec := h.do("GET", "/Items", nil, map[string]string{
		sessionHeader: token,
		"Connection":  "X-Lanternfish-Device, X-Lanternfish-Auth",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("proxied request: %d %s", rec.Code, rec.Body)
	}
	up := h.lastUpstream()
	if got := up.Header.Get(deviceHeader); got != enr.DeviceID {
		t.Errorf("upstream device header = %q, want %q", got, enr.DeviceID)
	}
	if got := up.Header.Get(authKindHeader); got != authHeader {
		t.Errorf("upstream auth header = %q, want %q", got, authHeader)
	}
}

// One source must not be able to take every challenge slot.
func TestChallengesAreLimitedPerSource(t *testing.T) {
	h := newHarness(t)
	ask := func(remote string) int {
		return h.doFrom(remote, "POST", "/_lanternfish/v1/challenge", map[string]string{"device_id": "dev_x"}, nil).Code
	}
	for i := 0; i < 32; i++ {
		if code := ask("203.0.113.7:1000"); code != http.StatusOK {
			t.Fatalf("challenge %d: %d", i, code)
		}
	}
	if code := ask("203.0.113.7:1001"); code != http.StatusTooManyRequests {
		t.Fatalf("challenge over the per-source limit: %d", code)
	}
	// Other IPv6 addresses in the same /64 count as the same source.
	for i := 0; i < 32; i++ {
		ask("[2001:db8:1:2::1]:1000")
	}
	if code := ask("[2001:db8:1:2::ffff]:1000"); code != http.StatusTooManyRequests {
		t.Fatalf("same /64 over the limit: %d", code)
	}
	if code := ask("198.51.100.9:1000"); code != http.StatusOK {
		t.Fatalf("other source: %d", code)
	}
	h.now = h.now.Add(h.g.cfg.ChallengeTTL + time.Second)
	if code := ask("203.0.113.7:1002"); code != http.StatusOK {
		t.Fatalf("after expiry: %d", code)
	}
}

// Revoking a device must also end requests it already has open, such as a
// WebSocket or a media stream, not only future ones.
func TestRevocationEndsOpenStreams(t *testing.T) {
	h := newHarness(t)
	key, enr := h.enrollECDSA("web")
	token := h.signIn(enr.DeviceID, func(m []byte) []byte { return rawSign(key, m) })

	started := make(chan struct{})
	h.mu.Lock()
	h.respond = func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "chunk")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}
	h.mu.Unlock()

	finished := make(chan int)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "https://gate.example/Videos/1/stream", nil)
		req.RemoteAddr = testClientAddr
		req.Header.Set(sessionHeader, token)
		h.g.Handler().ServeHTTP(rec, req)
		finished <- rec.Code
	}()
	<-started

	rec := h.do("POST", "/_lanternfish/admin/v1/devices/"+enr.DeviceID+"/revoke", nil,
		map[string]string{"Authorization": "Bearer " + h.adminKey})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("open stream survived revocation")
	}
	h.g.streams.mu.Lock()
	n := len(h.g.streams.byDevice)
	h.g.streams.mu.Unlock()
	if n != 0 {
		t.Errorf("%d devices still tracked after their requests ended", n)
	}
}

// Device names are chosen by whoever enrolls, so alerts must not ping anyone.
func TestAlertsAllowNoMentions(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		got <- body
	}))
	defer srv.Close()
	(&alerter{url: srv.URL, client: srv.Client()}).send(`"@everyone" enrolled`)
	select {
	case body := <-got:
		am, _ := body["allowed_mentions"].(map[string]any)
		if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 {
			t.Fatalf("allowed_mentions = %v", body["allowed_mentions"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert sent")
	}
}
