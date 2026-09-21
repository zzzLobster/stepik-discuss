package auth

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/config"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func testStore(t *testing.T) *sessions.Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := sessions.Open(filepath.Join(t.TempDir(), "gate.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testChecker(store *sessions.Store) *Checker {
	return &Checker{
		Cfg: config.Config{
			Origin:          config.DefaultOrigin,
			GateToken:       "gate-token",
			RemarkJWTSecret: "remark-secret",
			Site:            "stepik-discuss",
			TeacherID:       1182644732,
			VerifyTTL:       6 * time.Hour,
			RetryAfter:      15 * time.Minute,
			MaxStale:        48 * time.Hour,
		},
		Store:  store,
		Stepik: stepik.New(1182644732, slog.New(slog.NewTextHandler(io.Discard, nil))),
		Limits: ratelimit.NewStore(),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func putSession(t *testing.T, store *sessions.Store, sid string, rec *sessions.SessionRecord) {
	t.Helper()
	now := time.Now()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	if rec.LastVerifiedAt.IsZero() {
		rec.LastVerifiedAt = now
	}
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = now.Add(30 * 24 * time.Hour)
	}
	if rec.LastSeenAt.IsZero() {
		rec.LastSeenAt = now
	}
	if err := store.PutSession(sid, rec); err != nil {
		t.Fatal(err)
	}
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func checkReq(remoteAddr, fwdURI, sid string) *http.Request {
	r := httptest.NewRequest("GET", "/auth/check", nil)
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-Gate-Auth", "gate-token")
	if fwdURI != "" {
		r.Header.Set("X-Forwarded-Uri", fwdURI)
	}
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: sid})
	}
	return r
}

func TestAllowed(t *testing.T) {
	teacher := &sessions.SessionRecord{IsTeacher: true}
	if !Allowed(teacher, 999) {
		t.Error("teacher must be allowed any cid")
	}
	student := &sessions.SessionRecord{AllowedClassIDs: []int64{82866, 87566}}
	for _, tc := range []struct {
		cid  int64
		want bool
	}{
		{82866, true}, {87566, true}, {82491, false}, {0, false},
	} {
		if got := Allowed(student, tc.cid); got != tc.want {
			t.Errorf("Allowed(cid=%d) = %v, want %v", tc.cid, got, tc.want)
		}
	}
}

func TestExtractCID_matrix(t *testing.T) {
	cases := []struct {
		name    string
		fwdURI  string
		referer string
		want    int64
		wantErr bool
	}{
		{"fwd_url_param", "/discuss/api/v1/comments?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82866"), "", 82866, false},
		{"fwd_trailing_slash", "/discuss/api/v1/comments?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82866/"), "", 82866, false},
		{"referer_fallback", "", "https://stepik.study67.fyi/class/87566", 87566, false},
		{"fwd_wins_over_referer", "/discuss/api/v1/comments?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82866"), "https://stepik.study67.fyi/class/87566", 82866, false},
		{"iframe_referer_plain", "/discuss/api/v1/config?site=stepik-discuss", "https://stepik.study67.fyi/discuss/web/iframe.html?url=https://stepik.study67.fyi/class/87566&site=stepik-discuss", 87566, false},
		{"iframe_referer_encoded", "/discuss/api/v1/config?site=stepik-discuss", "https://stepik.study67.fyi/discuss/web/iframe.html?url=" + urlQueryEscape("https://stepik.study67.fyi/class/87566") + "&site=stepik-discuss", 87566, false},
		{"iframe_referer_trailing_slash", "", "https://stepik.study67.fyi/discuss/web/iframe.html?url=" + urlQueryEscape("https://stepik.study67.fyi/class/87566/"), 87566, false},
		{"iframe_referer_double_encode_rejected", "", "https://stepik.study67.fyi/discuss/web/iframe.html?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82%2566"), 0, true},
		{"iframe_referer_no_nested_url", "/discuss/api/v1/config?site=stepik-discuss", "https://stepik.study67.fyi/discuss/web/iframe.html?site=stepik-discuss", 0, true},
		{"double_encode_rejected", "/discuss/api/v1/comments?url=" + "https%3A%2F%2Fstepik.study67.fyi%2Fclass%2F82866%252F..", "", 0, true},
		{"pct25_lower_rejected", "/x?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82%2566"), "", 0, true},
		{"pct25_upper_rejected", "/x?url=https://stepik.study67.fyi/class/82%2566", "", 0, true},
		{"wrong_host", "/x?url=" + urlQueryEscape("https://evil.example/class/82866"), "", 0, true},
		{"non_numeric", "/x?url=" + urlQueryEscape("https://stepik.study67.fyi/class/abc"), "", 0, true},
		{"too_long", "/x?url=" + urlQueryEscape("https://stepik.study67.fyi/class/12345678901234567890"), "", 0, true},
		{"empty", "", "", 0, true},
		{"path_traversal", "/x?url=" + urlQueryEscape("https://stepik.study67.fyi/class/82866/../87566"), "", 0, true},
		{"http_scheme", "/x?url=" + urlQueryEscape("http://stepik.study67.fyi/class/82866"), "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractCID(tc.fwdURI, tc.referer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ExtractCID = %d, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractCID error: %v", err)
			}
			if got != tc.want {
				t.Errorf("ExtractCID = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestExtractCIDWithBase_customOrigin(t *testing.T) {
	cfg := config.Config{Origin: "https://custom.example"}
	base := cfg.ClassBase()
	if base != "https://custom.example/class/" {
		t.Fatalf("ClassBase = %q, want custom base", base)
	}
	pageURL := base + "82866"
	fwd := "/discuss/api/v1/comments?url=" + urlQueryEscape(pageURL)
	got, err := ExtractCIDWithBase(fwd, "", base)
	if err != nil {
		t.Fatalf("ExtractCIDWithBase error: %v", err)
	}
	if got != 82866 {
		t.Fatalf("ExtractCIDWithBase = %d, want 82866", got)
	}
	if _, err := ExtractCIDWithBase(fwd, "", config.ClassBaseURL); err == nil {
		t.Fatal("default base must reject custom-origin pageURL")
	}
}

func TestCheck_customOriginAcceptsOwnBase(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-custom", &sessions.SessionRecord{
		StepikUserID: 1190530325, AllowedClassIDs: []int64{82866},
	})
	c := testChecker(store)
	c.Cfg.Origin = "https://custom.example"
	pageURL := c.Cfg.ClassBase() + "82866"
	fwd := "/discuss/api/v1/comments?url=" + urlQueryEscape(pageURL)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", fwd, "sid-custom"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for custom-origin pageURL: %s", w.Code, w.Body.String())
	}
}

func TestGuard_matrix(t *testing.T) {
	cases := []struct {
		name   string
		token  string
		remote string
		want   bool
	}{
		{"loopback_ok", "gate-token", "127.0.0.1:4000", true},
		{"loopback_bare", "gate-token", "127.0.0.1", true},
		{"docker_private_ok", "gate-token", "172.18.0.3:8081", true},
		{"rfc1918_ok", "gate-token", "10.0.0.2:1", true},
		{"public_denied", "gate-token", "8.8.8.8:443", false},
		{"bad_token", "wrong", "127.0.0.1:1", false},
		{"empty_token", "", "127.0.0.1:1", false},
		{"garbage_remote", "gate-token", "not-an-ip", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/auth/check", nil)
			r.RemoteAddr = tc.remote
			if tc.token != "" {
				r.Header.Set("X-Gate-Auth", tc.token)
			}
			if got := Guard(r, "gate-token"); got != tc.want {
				t.Errorf("Guard = %v, want %v", got, tc.want)
			}
		})
	}
	if r := httptest.NewRequest("GET", "/", nil); Guard(r, "") {
		t.Error("empty expected token must deny")
	}
}

func TestSlidingNeeded(t *testing.T) {
	now := time.Now()
	if SlidingNeeded(&sessions.SessionRecord{ExpiresAt: now.Add(30 * 24 * time.Hour)}, now) {
		t.Error("fresh 30d session must not need sliding")
	}
	if !SlidingNeeded(&sessions.SessionRecord{ExpiresAt: now.Add(28 * 24 * time.Hour)}, now) {
		t.Error("session expiring in 28d must need sliding (29d window)")
	}
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("body %q is not JSON: %v", w.Body.String(), err)
	}
	return v
}

func TestCheck_badGateAuth404(t *testing.T) {
	c := testChecker(testStore(t))
	r := checkReq("127.0.0.1:1", "", "")
	r.Header.Set("X-Gate-Auth", "wrong")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestCheck_noSession401(t *testing.T) {
	c := testChecker(testStore(t))
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "", ""))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if decodeBody(t, w)["error"] != "auth_required" {
		t.Errorf("error = %v, want auth_required", decodeBody(t, w)["error"])
	}
}

func TestCheck_expiredSession401(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "oldsid", &sessions.SessionRecord{StepikUserID: 1, ExpiresAt: time.Now().Add(-time.Hour)})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "", "oldsid"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestCheck_revokedUser401(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-rev", &sessions.SessionRecord{StepikUserID: 5, UserVersion: 0})
	if _, err := store.BumpUserVersion(5); err != nil {
		t.Fatal(err)
	}
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "", "sid-rev"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 after revoke-user", w.Code)
	}
}

func TestCheck_logoutAll401(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-all", &sessions.SessionRecord{StepikUserID: 5, GlobalEpoch: 0})
	if _, err := store.BumpGlobalEpoch(); err != nil {
		t.Fatal(err)
	}
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "", "sid-all"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 after logout-all", w.Code)
	}
}

func TestCheck_unknownThread403(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-u", &sessions.SessionRecord{StepikUserID: 1})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "/discuss/api/v1/comments?site=stepik-discuss", "sid-u"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if decodeBody(t, w)["error"] != "forbidden" {
		t.Errorf("error = %v, want forbidden", decodeBody(t, w)["error"])
	}
}

func fwdFor(cid string) string {
	return "/discuss/api/v1/comments?url=" + urlQueryEscape("https://stepik.study67.fyi/class/"+cid)
}

func TestCheck_forbidden403_leftClass(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-f", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{82866}})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", fwdFor("87566"), "sid-f"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if decodeBody(t, w)["error"] != "forbidden" {
		t.Errorf("error = %v, want forbidden", decodeBody(t, w)["error"])
	}
}

func TestCheck_allow200_student(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-ok", &sessions.SessionRecord{
		StepikUserID: 1190530325, FIO: "Student", AllowedClassIDs: []int64{82866},
	})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", fwdFor("82866"), "sid-ok"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-JWT") == "" || w.Header().Get("X-XSRF-TOKEN") == "" {
		t.Error("missing X-JWT / X-XSRF-TOKEN on 200")
	}
	if w.Header().Get("Cache-Control") != "private,no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
}

func TestCheck_adminTeacherOnly403(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-st", &sessions.SessionRecord{StepikUserID: 2, AllowedClassIDs: []int64{82866}})
	c := testChecker(store)
	r := checkReq("127.0.0.1:1", "/discuss/admin/api/v1/comments", "sid-st")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 teacher_only", w.Code)
	}
	if decodeBody(t, w)["error"] != "teacher_only" {
		t.Errorf("error = %v, want teacher_only", decodeBody(t, w)["error"])
	}
}

func TestCheck_adminTeacher200(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-t", &sessions.SessionRecord{StepikUserID: 1182644732, IsTeacher: true})
	c := testChecker(store)
	r := checkReq("127.0.0.1:1", "/discuss/admin/api/v1/comments", "sid-t")
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for teacher admin: %s", w.Code, w.Body.String())
	}
}

func TestCheck_rateLimited429(t *testing.T) {
	store := testStore(t)
	putSession(t, store, "sid-rl", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{82866}})
	c := testChecker(store)
	var last *httptest.ResponseRecorder
	for range 25 {
		last = httptest.NewRecorder()
		c.ServeHTTP(last, checkReq("127.0.0.1:1", fwdFor("82866"), "sid-rl"))
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("25th status = %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After on 429")
	}
	if decodeBody(t, last)["error"] != "rate_limited" {
		t.Errorf("error = %v, want rate_limited", decodeBody(t, last)["error"])
	}
}

func TestCheck_stale200_withHeader(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	putSession(t, store, "sid-stale", &sessions.SessionRecord{
		StepikUserID:    1,
		AllowedClassIDs: []int64{82866},
		LastVerifiedAt:  now.Add(-7 * time.Hour),
		NextRetryAt:     now.Add(5 * time.Minute),
	})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", fwdFor("82866"), "sid-stale"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 stale: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Gate-Stale") != "1" {
		t.Error("missing X-Gate-Stale: 1 on stale 200 (edge must strip it)")
	}
}

func TestCheck_transient503_noNetwork(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	putSession(t, store, "sid-tr", &sessions.SessionRecord{
		StepikUserID:    1,
		AllowedClassIDs: []int64{82866},
		LastVerifiedAt:  now.Add(-49 * time.Hour),
		NextRetryAt:     now.Add(5 * time.Minute),
	})
	c := testChecker(store)
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", fwdFor("82866"), "sid-tr"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", w.Code, w.Body.String())
	}
	if decodeBody(t, w)["error"] != "transient" {
		t.Errorf("error = %v, want transient", decodeBody(t, w)["error"])
	}
}
