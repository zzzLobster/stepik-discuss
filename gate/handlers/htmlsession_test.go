package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func doHTML(t *testing.T, s *Server, method, target string, sid string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: sid})
	}
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	return w
}

func nextOf(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad Location %q: %v", loc, err)
	}
	next, err := url.QueryUnescape(u.Query().Get("next"))
	if err != nil {
		t.Fatalf("bad next in %q: %v", loc, err)
	}
	return next
}

func TestExpiryUX_classFlows(t *testing.T) {
	s, store := testServer(t, baseCfg())
	now := time.Now()
	putSess(t, store, "ux-exp1", &sessions.SessionRecord{StepikUserID: 1, ExpiresAt: now.Add(-time.Hour)})
	putSess(t, store, "ux-trans", &sessions.SessionRecord{
		StepikUserID: 2, AllowedClassIDs: []int64{82866},
		ClassTitles:       map[string]string{"82866": "2025-26"},
		LastVerifiedAt:    now.Add(-49 * time.Hour),
		NextRetryAt:       now.Add(5 * time.Minute),
	})
	putSess(t, store, "ux-stale", &sessions.SessionRecord{
		StepikUserID: 3, AllowedClassIDs: []int64{82866},
		ClassTitles:       map[string]string{"82866": "2025-26"},
		LastVerifiedAt:    now.Add(-7 * time.Hour),
		NextRetryAt:       now.Add(5 * time.Minute),
	})
	putSess(t, store, "ux-out", &sessions.SessionRecord{StepikUserID: 4, AllowedClassIDs: []int64{}})
	putSess(t, store, "ux-fresh", &sessions.SessionRecord{
		StepikUserID: 5, AllowedClassIDs: []int64{82866},
		ClassTitles: map[string]string{"82866": "2025-26"},
	})

	t.Run("expired-first 302+flag", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866", "ux-exp1")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		if got := nextOf(t, w.Header().Get("Location")); got != "/class/82866?relogin=1" {
			t.Errorf("next = %q, want /class/82866?relogin=1", got)
		}
	})

	t.Run("expired-second 401+link", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866?relogin=1", "ux-exp1")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, RUExpired) {
			t.Errorf("body missing RUExpired")
		}
		if !strings.Contains(body, RULoginButton) {
			t.Errorf("body missing login button")
		}
		if !strings.Contains(body, "/auth/login?next=") {
			t.Errorf("body missing clean login link")
		}
		if strings.Contains(body, "relogin") {
			t.Errorf("final login link must use clean next, got relogin in body")
		}
	})

	t.Run("no-session 302 clean", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866", "")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		if got := nextOf(t, w.Header().Get("Location")); got != "/class/82866" {
			t.Errorf("next = %q, want clean /class/82866", got)
		}
	})

	t.Run("no-session with flag still 302 clean", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866?relogin=1", "")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		if got := nextOf(t, w.Header().Get("Location")); got != "/class/82866" {
			t.Errorf("next = %q, want clean /class/82866", got)
		}
	})

	t.Run("transient 503", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866", "ux-trans")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		if !strings.Contains(w.Body.String(), RUTransient) {
			t.Errorf("body missing RUTransient")
		}
	})

	t.Run("transient with flag 503 never 302", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866?relogin=1", "ux-trans")
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 even with flag", w.Code)
		}
	})

	t.Run("stale class 200", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866", "ux-stale")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (stale proceeds)", w.Code)
		}
	})

	t.Run("stale index 200+banner", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "ux-stale")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), RUTransient) {
			t.Errorf("index missing stale banner RUTransient")
		}
	})

	t.Run("outsider 403 never 302", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866", "ux-out")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if !strings.Contains(w.Body.String(), RUOutsider) {
			t.Errorf("body missing RUOutsider")
		}
	})

	t.Run("outsider with flag 403 never 302", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866?relogin=1", "ux-out")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 even with flag", w.Code)
		}
	})

	t.Run("callback termination: flagged next renders 200 with flag inert", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/class/82866?relogin=1", "ux-fresh")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (fresh session, flag inert)", w.Code)
		}
	})
}

func TestExpiryUX_indexFlows(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "ux-idx-exp", &sessions.SessionRecord{StepikUserID: 1, ExpiresAt: time.Now().Add(-time.Hour)})

	t.Run("index anon 200 consent unchanged", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if !strings.Contains(w.Body.String(), RUConsent) {
			t.Errorf("anon index missing consent")
		}
	})

	t.Run("index expired-first 302+flag", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "ux-idx-exp")
		if w.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", w.Code)
		}
		if got := nextOf(t, w.Header().Get("Location")); got != "/?relogin=1" {
			t.Errorf("next = %q, want /?relogin=1", got)
		}
	})

	t.Run("index expired-second 401+link", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/?relogin=1", "ux-idx-exp")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if !strings.Contains(w.Body.String(), RUExpired) {
			t.Errorf("body missing RUExpired")
		}
	})

	t.Run("index teacher banner has relogin link", func(t *testing.T) {
		cfg := baseCfg()
		s2, store2 := testServer(t, cfg)
		putSess(t, store2, "ux-teacher", &sessions.SessionRecord{
			StepikUserID: cfg.TeacherID, IsTeacher: true,
			AllowedClassIDs: []int64{82866},
			ClassTitles:     map[string]string{"82866": "2025-26"},
		})
		w := doHTML(t, s2, "GET", "/", "ux-teacher")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, RUTeacherBanner) {
			t.Fatalf("missing teacher banner")
		}
		if !strings.Contains(body, RULoginButton) {
			t.Errorf("teacher banner missing relogin button")
		}
		if !strings.Contains(body, "/auth/login?next=") {
			t.Errorf("teacher banner missing login link")
		}
	})
}

func TestValidNext_reloginSuffix(t *testing.T) {
	cases := []struct {
		raw    string
		want   string
		wantOK bool
	}{
		{"/class/82866?relogin=1", "/class/82866?relogin=1", true},
		{"/?relogin=1", "/?relogin=1", true},
		{"/class/82866/?relogin=1", "/class/82866/?relogin=1", true},
		{"%2Fclass%2F82866%3Frelogin%3D1", "/class/82866?relogin=1", true},
		{"/class/82866?relogin=0", "", false},
		{"/class/82866?relogin=1&x=1", "", false},
		{"/class/82866?x=1", "", false},
		{"/class/82866?relogin=1 ", "", false},
		{"/evil?relogin=1", "", false},
		{"/class/82866#relogin=1", "", false},
		{"/?relogin=1&x=1", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := validNext(tc.raw)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("validNext(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestCurrentNext_neverEchoesInput(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	_ = s
	for _, tc := range []struct{ path, want string }{
		{"/", "/"},
		{"/class/82866", "/class/82866"},
		{"/class/82866/", "/class/82866"},
		{"/evil", "/"},
		{"/class/abc", "/"},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if got := currentNext(r); got != tc.want {
			t.Errorf("currentNext(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
	r := httptest.NewRequest("GET", "/class/82866?next=/evil", nil)
	if got := currentNext(r); got != "/class/82866" {
		t.Errorf("currentNext with query = %q, want /class/82866 (query never echoed)", got)
	}
}
