package api

import (
	"encoding/json"
	"github.com/unrandoms/callback-ledger/internal/store"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementRequiresAuthentication(t *testing.T) {
	mux, s := newTestRouter()
	tok := s.GenerateToken()
	for _, path := range []string{"/token", "/check/" + tok, "/list", "/clear", "/export/" + tok, "/ws"} {
		for _, auth := range []string{"", "Bearer wrong"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Authorization", auth)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("%s: %d", path, w.Code)
			}
		}
	}
	if !s.Exists(tok) {
		t.Fatal("unauthorized clear")
	}
}
func TestExportFormats(t *testing.T) {
	mux, s := newTestRouter()
	tok, _ := s.CreateToken("release-test")
	s.RecordCallback(tok, store.CallbackRequest{Protocol: "http", BodyTruncated: true})
	for _, format := range []string{"json", "ndjson"} {
		r := httptest.NewRequest("GET", "/export/"+tok+"?format="+format, nil)
		r.Header.Set("Authorization", "Bearer test-admin")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		raw := w.Body.String()
		var doc map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		if doc["schema_version"] != float64(1) {
			t.Fatal(doc)
		}
		session := doc["session"].(map[string]interface{})
		if session["label"] != "release-test" || session["max_events"] != float64(64) {
			t.Fatal(session)
		}
		if format == "ndjson" {
			if !strings.Contains(raw, "callback") {
				t.Fatal("missing event")
			}
		}
	}
}
