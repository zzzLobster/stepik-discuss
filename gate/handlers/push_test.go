package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func authedReq(t *testing.T, s *Server, store *sessions.Store, method, path, sid string, body any, origin string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.RemoteAddr = "127.0.0.1:1"
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: sid})
	rec, _ := store.GetSession(sid)
	if rec != nil {
		r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: rec.CSRFToken})
		r.Header.Set("X-CSRF-Token", rec.CSRFToken)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

func TestUnsubscribe_ownership(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-a", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{100}})
	putSess(t, store, "sid-teacher", &sessions.SessionRecord{StepikUserID: 1182644732, IsTeacher: true, AllowedClassIDs: []int64{100}})
	_ = store.PutPushSub(&sessions.PushSub{UID: 1, SID: "sid-a", Endpoint: "https://fcm.googleapis.com/a", CreatedAt: time.Now()})
	_ = store.PutPushSub(&sessions.PushSub{UID: 1182644732, SID: "sid-teacher", Endpoint: "https://fcm.googleapis.com/t", CreatedAt: time.Now()})
	w := authedReq(t, s, store, "POST", "/push/unsubscribe", "sid-a", map[string]string{"endpoint": "https://fcm.googleapis.com/a"}, "https://stepik.study67.fyi")
	if w.Code != 200 {
		t.Fatalf("own delete = %d", w.Code)
	}
	w = authedReq(t, s, store, "POST", "/push/unsubscribe", "sid-a", map[string]string{"endpoint": "https://fcm.googleapis.com/t"}, "https://stepik.study67.fyi")
	if w.Code != 403 {
		t.Fatalf("foreign live = %d, want 403", w.Code)
	}
	if got, _ := store.GetPushSub("https://fcm.googleapis.com/t"); got == nil {
		t.Error("foreign live row deleted")
	}
	_ = store.DeleteSession("sid-teacher")
	w = authedReq(t, s, store, "POST", "/push/unsubscribe", "sid-a", map[string]string{"endpoint": "https://fcm.googleapis.com/t"}, "https://stepik.study67.fyi")
	if w.Code != 200 {
		t.Fatalf("orphan delete = %d, want 200", w.Code)
	}
}

func TestResubscribe_matrix(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-a", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{100}})
	_ = store.PutPushSub(&sessions.PushSub{UID: 1, SID: "sid-a", Endpoint: "https://fcm.googleapis.com/old", Cids: []int64{100}, CreatedAt: time.Now()})
	validKeys := map[string]string{"p256dh": "B" + strings.Repeat("A", 86), "auth": strings.Repeat("A", 22)}
	w := authedReq(t, s, store, "POST", "/push/resubscribe", "sid-a", map[string]any{"old_endpoint": "", "endpoint": "https://fcm.googleapis.com/new", "keys": validKeys, "device": map[string]string{"ua": "t"}}, "https://stepik.study67.fyi")
	if w.Code != 400 {
		t.Errorf("empty old = %d, want 400", w.Code)
	}
	w = authedReq(t, s, store, "POST", "/push/resubscribe", "sid-a", map[string]any{"old_endpoint": "https://fcm.googleapis.com/old", "endpoint": "https://evil.example/x", "keys": validKeys, "device": map[string]string{"ua": "t"}}, "https://stepik.study67.fyi")
	if w.Code != 400 {
		t.Errorf("attacker endpoint = %d, want 400", w.Code)
	}
	putSess(t, store, "sid-b", &sessions.SessionRecord{StepikUserID: 2, AllowedClassIDs: []int64{100}})
	w = authedReq(t, s, store, "POST", "/push/resubscribe", "sid-b", map[string]any{"old_endpoint": "https://fcm.googleapis.com/old", "endpoint": "https://fcm.googleapis.com/new2", "keys": validKeys, "device": map[string]string{"ua": "t"}}, "https://stepik.study67.fyi")
	if w.Code != 403 {
		t.Errorf("mismatch = %d, want 403", w.Code)
	}
	for _, tc := range []struct {
		name   string
		origin string
	}{
		{"missing", ""}, {"null", "null"}, {"mismatch", "https://evil.example"},
	} {
		r := httptest.NewRequest("POST", "/push/resubscribe", strings.NewReader(`{"old_endpoint":"x","endpoint":"https://fcm.googleapis.com/n","keys":{"p256dh":"x","auth":"y"},"device":{"ua":"t"}}`))
		r.RemoteAddr = "127.0.0.1:1"
		r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-a"})
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Errorf("origin %s = %d, want 403", tc.name, w.Code)
		}
	}
}

func TestSubscribe_validation(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-a", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{100}})
	validKeys := map[string]string{"p256dh": "B" + strings.Repeat("A", 86), "auth": strings.Repeat("A", 22)}
	badEp := map[string]any{"endpoint": "https://evil.example/x", "keys": validKeys, "device": map[string]string{"ua": "t"}, "cids": []int64{100}}
	if w := authedReq(t, s, store, "POST", "/push/subscribe", "sid-a", badEp, "https://stepik.study67.fyi"); w.Code != 400 {
		t.Errorf("bad endpoint = %d, want 400", w.Code)
	}
	badKeys := map[string]any{"endpoint": "https://fcm.googleapis.com/x", "keys": map[string]string{"p256dh": "x", "auth": "y"}, "device": map[string]string{"ua": "t"}, "cids": []int64{100}}
	if w := authedReq(t, s, store, "POST", "/push/subscribe", "sid-a", badKeys, "https://stepik.study67.fyi"); w.Code != 400 {
		t.Errorf("bad keys = %d, want 400", w.Code)
	}
	missingCids := map[string]any{"endpoint": "https://fcm.googleapis.com/x", "keys": validKeys, "device": map[string]string{"ua": "t"}}
	if w := authedReq(t, s, store, "POST", "/push/subscribe", "sid-a", missingCids, "https://stepik.study67.fyi"); w.Code != 400 {
		t.Errorf("missing cids = %d, want 400", w.Code)
	}
	forbiddenCids := map[string]any{"endpoint": "https://fcm.googleapis.com/x", "keys": validKeys, "device": map[string]string{"ua": "t"}, "cids": []int64{999}}
	if w := authedReq(t, s, store, "POST", "/push/subscribe", "sid-a", forbiddenCids, "https://stepik.study67.fyi"); w.Code != 403 {
		t.Errorf("forbidden cids = %d, want 403", w.Code)
	}
}

func TestWebhook_handler(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/push/webhook", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("GET webhook = %d, want 404", w.Code)
	}
}

func TestPushHealth_deep(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/push/health?deep=1", nil)
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("deep without token = %d, want 404", w.Code)
	}
}

func TestLogout_prunesPush(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-lo", &sessions.SessionRecord{StepikUserID: 3})
	_ = store.PutPushSub(&sessions.PushSub{UID: 3, SID: "sid-lo", Endpoint: "https://fcm.googleapis.com/lo", CreatedAt: time.Now()})
	rec, _ := store.GetSession("sid-lo")
	form := "csrf_token=" + rec.CSRFToken
	r := httptest.NewRequest("POST", "/auth/logout", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-lo"})
	r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: rec.CSRFToken})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("logout = %d", w.Code)
	}
	if got, _ := store.GetPushSub("https://fcm.googleapis.com/lo"); got != nil {
		t.Error("push survived logout")
	}
}
