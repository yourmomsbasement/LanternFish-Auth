package update

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// L6: updater alerts can't ping anyone.
func TestWebhookSuppressesMentions(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		got <- body
	}))
	defer srv.Close()
	Webhook(srv.URL)("update failed: @everyone")
	body := <-got
	am, _ := body["allowed_mentions"].(map[string]any)
	if parse, ok := am["parse"].([]any); !ok || len(parse) != 0 || body["content"] != "update failed: @everyone" {
		t.Fatalf("webhook body: %v", body)
	}
}
