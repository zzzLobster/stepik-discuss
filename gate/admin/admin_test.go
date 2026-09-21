package admin

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func testStore(t *testing.T) *sessions.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Open(filepath.Join(t.TempDir(), "a.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testAdmin(store *sessions.Store) *Admin {
	return &Admin{Store: store, Origin: "https://stepik.study67.fyi", Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func putSess(t *testing.T, store *sessions.Store, sid string, uid int64, teacher bool) {
	t.Helper()
	now := time.Now()
	csrf, err := sessions.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	rec := &sessions.SessionRecord{
		StepikUserID: uid, IsTeacher: teacher,
		AllowedClassIDs: []int64{82866},
		CreatedAt:       now, LastVerifiedAt: now,
		ExpiresAt: now.Add(30 * 24 * time.Hour), LastSeenAt: now,
		CSRFToken: csrf,
	}
	if err := store.PutSession(sid, rec); err != nil {
		t.Fatal(err)
	}
}

func postAs(t *testing.T, a *Admin, path, sid, origin string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest("POST", path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: sid})
		if sess, err := a.Store.GetSession(sid); err == nil && sess != nil && sess.CSRFToken != "" {
			r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: sess.CSRFToken})
			r.Header.Set("X-CSRF-Token", sess.CSRFToken)
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestAdmin_methodNotAllowed(t *testing.T) {
	a := testAdmin(testStore(t))
	r := httptest.NewRequest("GET", "/auth/admin/logout-all", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAdmin_originChecked(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	a := testAdmin(store)
	w := postAs(t, a, "/auth/admin/logout-all", "t1", "https://evil.example", nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on Origin mismatch", w.Code)
	}
}

func TestAdmin_unauthorizedNoSession(t *testing.T) {
	a := testAdmin(testStore(t))
	w := postAs(t, a, "/auth/admin/logout-all", "", "https://stepik.study67.fyi", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdmin_nonTeacherForbidden(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "s1", 42, false)
	a := testAdmin(store)
	for _, p := range []string{"/auth/admin/logout-all", "/auth/admin/revoke-user", "/auth/admin/revoke-class"} {
		w := postAs(t, a, p, "s1", "https://stepik.study67.fyi", nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", p, w.Code)
		}
	}
}

func TestAdmin_logoutAll_bumpsEpoch(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	putSess(t, store, "s1", 42, false)
	a := testAdmin(store)
	w := postAs(t, a, "/auth/admin/logout-all", "t1", "https://stepik.study67.fyi", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["ok"] != true || v["global_epoch"] != float64(1) {
		t.Errorf("body = %v", v)
	}
	if _, _, err := auth.LoadSession(store, sidReq("s1")); err == nil {
		t.Error("student session survived logout-all")
	}
	if _, _, err := auth.LoadSession(store, sidReq("t1")); err == nil {
		t.Error("teacher session survived logout-all")
	}
}

func sidReq(sid string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: sid})
	return r
}

func TestAdmin_revokeUser(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	putSess(t, store, "s1", 42, false)
	a := testAdmin(store)
	w := postAs(t, a, "/auth/admin/revoke-user", "t1", "https://stepik.study67.fyi", url.Values{"uid": {"42"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if _, _, err := auth.LoadSession(store, sidReq("s1")); err == nil {
		t.Error("revoked user session still loads")
	}
	bad := postAs(t, a, "/auth/admin/revoke-user", "t1", "https://stepik.study67.fyi", url.Values{"uid": {"abc"}})
	if bad.Code != http.StatusBadRequest {
		t.Errorf("bad uid status = %d, want 400", bad.Code)
	}
	zero := postAs(t, a, "/auth/admin/revoke-user", "t1", "https://stepik.study67.fyi", url.Values{"uid": {"0"}})
	if zero.Code != http.StatusBadRequest {
		t.Errorf("uid=0 status = %d, want 400", zero.Code)
	}
}

func TestAdmin_revokeClass(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	putSess(t, store, "s1", 42, false)
	a := testAdmin(store)
	w := postAs(t, a, "/auth/admin/revoke-class", "t1", "https://stepik.study67.fyi", url.Values{"uid": {"42"}, "cid": {"82866"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["stripped"] != float64(1) {
		t.Errorf("stripped = %v, want 1", v["stripped"])
	}
	sess, _, err := auth.LoadSession(store, sidReq("s1"))
	if err != nil {
		t.Fatalf("session should still load (only class stripped): %v", err)
	}
	if auth.Allowed(sess, 82866) {
		t.Error("cid 82866 still allowed after revoke-class")
	}
	bad := postAs(t, a, "/auth/admin/revoke-class", "t1", "https://stepik.study67.fyi", url.Values{"uid": {"42"}})
	if bad.Code != http.StatusBadRequest {
		t.Errorf("missing cid status = %d, want 400", bad.Code)
	}
}

func TestAdmin_unknown404(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	a := testAdmin(store)
	w := postAs(t, a, "/auth/admin/nope", "t1", "https://stepik.study67.fyi", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAdmin_csrfMissing(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	a := testAdmin(store)
	r := httptest.NewRequest("POST", "/auth/admin/logout-all", nil)
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "t1"})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on missing CSRF header", w.Code)
	}
}

func TestAdmin_csrfMismatch(t *testing.T) {
	store := testStore(t)
	putSess(t, store, "t1", 1182644732, true)
	a := testAdmin(store)
	sess, _ := store.GetSession("t1")
	r := httptest.NewRequest("POST", "/auth/admin/logout-all", nil)
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.Header.Set("X-CSRF-Token", "wrong")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "t1"})
	r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: sess.CSRFToken})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on CSRF mismatch", w.Code)
	}
}
