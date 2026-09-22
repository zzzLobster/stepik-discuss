package handlers

import (
	"crypto/rand"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/admin"
	"github.com/zzzLobster/stepik-discuss/gate/auth"
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
	s, err := sessions.Open(filepath.Join(t.TempDir(), "h.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testTemplates(t *testing.T) *template.Template {
	t.Helper()
	tpl, err := template.ParseGlob("../templates/*.html")
	if err != nil {
		t.Fatalf("real templates must parse: %v", err)
	}
	return tpl
}

func testServer(t *testing.T, cfg config.Config) (*Server, *sessions.Store) {
	t.Helper()
	store := testStore(t)
	log := testLogger()
	step := stepik.New(cfg.TeacherID, log)
	limits := ratelimit.NewStore()
	checker := &auth.Checker{Cfg: cfg, Store: store, Stepik: step, Limits: limits, Log: log}
	adm := &admin.Admin{Store: store, Origin: cfg.Origin, Log: log}
	s := New(cfg, store, step, limits, checker, adm, log, testTemplates(t), os.DirFS("../static"), "test-rev")
	if s.states == nil {
		t.Fatal("states map nil")
	}
	return s, store
}

func baseCfg() config.Config {
	return config.Config{
		StepikClientID: "test-client", StepikClientSecret: "s",
		StepikRedirectURL: "https://stepik.study67.fyi/auth/callback",
		TeacherID:         1182644732,
		RemarkJWTSecret:   "remark-secret", GateToken: "gate-token",
		VerifyTTL: 6 * time.Hour, RetryAfter: 15 * time.Minute, MaxStale: 48 * time.Hour,
		Site: "stepik-discuss", RemarkURL: "https://stepik.study67.fyi/discuss",
		Origin: "https://stepik.study67.fyi",
		VapidPublicKey: "B" + strings.Repeat("A", 86),
		VapidPrivateKey: strings.Repeat("A", 43),
		VapidSubject: "mjgavrilov@gmail.com",
		PushWebhookSecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func putSess(t *testing.T, store *sessions.Store, sid string, rec *sessions.SessionRecord) {
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
	if rec.CSRFToken == "" {
		tok, err := sessions.NewCSRFToken()
		if err != nil {
			t.Fatal(err)
		}
		rec.CSRFToken = tok
	}
	if err := store.PutSession(sid, rec); err != nil {
		t.Fatal(err)
	}
}

func TestRender_templateErrorReturns500(t *testing.T) {
	tpl := template.Must(template.New("error.html").Funcs(template.FuncMap{
		"fail": func() (string, error) { return "", errors.New("forced template error") },
	}).Parse(`{{ fail }}`))
	s := &Server{tpl: tpl, log: testLogger()}
	w := httptest.NewRecorder()
	s.render(w, http.StatusBadRequest, "error.html", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on template error", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	if !strings.Contains(w.Body.String(), "Internal Server Error") {
		t.Errorf("body missing error text: %s", w.Body.String())
	}
}

func TestRUStrings_frozen(t *testing.T) {
	frozen := map[string]string{
		"RUOutsider":         "Доступ запрещён. Этот сайт только для учеников моих классов на Stepik. Если вы мой ученик — напишите мне, проверим состав класса.",
		"RUTransient":        "Не удалось проверить состав класса. Попробуйте позже.",
		"RULeft":             "Нет доступа. Вы больше не состоите в классе.",
		"RUExpired":          "Сессия истекла. Войдите через Stepik снова.",
		"RURateLimited":      "Слишком много запросов. Подождите минуту и попробуйте снова.",
		"RUNextInvalid":      "Некорректная ссылка для возврата.",
		"RUOAuthDeny":        "Вход через Stepik отменён или не удался. Попробуйте ещё раз.",
		"RULoginUnavailable": "Вход временно недоступен. Попробуйте позже.",
		"RULoginButton":      "Войти через Stepik",
		"RUConsent":          "Входя через Stepik, вы соглашаетесь, что ваше имя и аватар Stepik будут видны участникам вашего класса. Обсуждения закрыты, не индексируются и доступны только вашему классу и преподавателю. Если включите уведомления, браузер получит технический ключ для доставки оповещений о новых комментариях в ваших классах. Уведомления доставляются через сервис push вашего браузера (Google/Apple/Mozilla) — текст уведомления будет передан ему для показа. Отключить можно в любой момент на странице класса или на главной, а также выходом из аккаунта на этом устройстве.",
		"RUTeacherBanner":    "Проверка студентов приостановлена: токен преподавателя истёк. Войдите через Stepik ещё раз, чтобы возобновить её.",
	}
	got := map[string]string{
		"RUOutsider": RUOutsider, "RUTransient": RUTransient, "RULeft": RULeft,
		"RUExpired": RUExpired, "RURateLimited": RURateLimited, "RUNextInvalid": RUNextInvalid,
		"RUOAuthDeny": RUOAuthDeny, "RULoginUnavailable": RULoginUnavailable,
		"RULoginButton": RULoginButton, "RUConsent": RUConsent, "RUTeacherBanner": RUTeacherBanner,
	}
	for k, want := range frozen {
		if got[k] != want {
			t.Errorf("%s changed:\n got: %q\nwant: %q", k, got[k], want)
		}
	}
}

func TestValidNext_matrix(t *testing.T) {
	cases := []struct {
		raw    string
		want   string
		wantOK bool
	}{
		{"", "/", true},
		{"/", "/", true},
		{"/class/82866", "/class/82866", true},
		{"/class/82866/", "/class/82866/", true},
		{"/class/1", "/class/1", true},
		{"/class/1234567890", "/class/1234567890", true},
		{"/class/12345678901234567890", "", false},
		{"/class/abc", "", false},
		{"/class/", "", false},
		{"/evil", "", false},
		{"https://evil.example/", "", false},
		{"//evil.example/class/1", "", false},
		{"/class/82866?x=1", "", false},
		{"%2Fclass%2F82866", "/class/82866", true},
		{"%252Fclass%252F82866", "", false},
		{"%zz", "", false},
		{"/discuss/admin/", "", false},
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

func TestState_replaySingleUse(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	state, err := s.newState("/class/82866", "binder1", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	next, ok := s.takeState(state, "binder1", "1.2.3.4")
	if !ok || next != "/class/82866" {
		t.Fatalf("first take = (%q,%v), want (/class/82866,true)", next, ok)
	}
	if _, ok := s.takeState(state, "binder1", "1.2.3.4"); ok {
		t.Fatal("state replay accepted, want single-use")
	}
}

func TestState_binderMismatch(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	state, _ := s.newState("/", "binder-A", "1.2.3.4")
	if _, ok := s.takeState(state, "binder-B", "1.2.3.4"); ok {
		t.Fatal("wrong binder accepted")
	}
}

func TestState_unknownRejected(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	if _, ok := s.takeState("no-such-state", "b", "1.2.3.4"); ok {
		t.Fatal("unknown state accepted")
	}
}

func TestState_expired(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	state, _ := s.newState("/", "binder1", "1.2.3.4")
	s.mu.Lock()
	for k, v := range s.states {
		v.created = time.Now().Add(-11 * time.Minute)
		s.states[k] = v
	}
	s.mu.Unlock()
	if _, ok := s.takeState(state, "binder1", "1.2.3.4"); ok {
		t.Fatal("expired state accepted (TTL 10m)")
	}
}

func TestState_ipBinding_enforced(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	state, _ := s.newState("/", "binder1", "1.2.3.4")
	if _, ok := s.takeState(state, "binder1", "9.9.9.9"); ok {
		t.Fatal("takeState accepted different IP, want ip_hash binding")
	}
	state2, _ := s.newState("/", "binder1", "1.2.3.4")
	if _, ok := s.takeState(state2, "binder1", "1.2.3.4"); !ok {
		t.Fatal("takeState rejected same IP, want accept")
	}
}

func TestLogin_placeholder503(t *testing.T) {
	cfg := baseCfg()
	cfg.Placeholder = true
	s, _ := testServer(t, cfg)
	r := httptest.NewRequest("GET", "/auth/login?next=/class/82866", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 placeholder", w.Code)
	}
	if !strings.Contains(w.Body.String(), RULoginUnavailable) {
		t.Errorf("body missing placeholder RU string: %s", w.Body.String())
	}
}

func TestLogin_nextInvalid400(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/auth/login?next=https://evil.example/", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), RUNextInvalid) {
		t.Errorf("body missing next-invalid RU string")
	}
}

func TestLogin_redirectBindsBinder(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/auth/login?next=/class/82866", nil)
	r.RemoteAddr = "1.2.3.4:1"
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 to Stepik", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://stepik.org/oauth2/authorize/") {
		t.Errorf("Location = %q, want Stepik authorize", loc)
	}
	var binder *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessions.CookieBinder {
			binder = c
		}
	}
	if binder == nil {
		t.Fatal("no __Host-oa binder cookie set")
	}
	if binder.Path != "/" {
		t.Errorf("binder Path = %q, want /", binder.Path)
	}
}

func TestLogin_rateLimited429(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	var last *httptest.ResponseRecorder
	for range 8 {
		r := httptest.NewRequest("GET", "/auth/login", nil)
		r.RemoteAddr = "9.9.9.9:1"
		last = httptest.NewRecorder()
		s.Routes().ServeHTTP(last, r)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after burst", last.Code)
	}
}

func TestHealthz_shallow(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("body = %s", w.Body.String())
	}
}

func TestManifest_sw_robots(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	type want struct{ ct, body string }
	cases := map[string]want{
		"/manifest.json": {"application/manifest+json", `"start_url"`},
		"/sw.js":         {"application/javascript", "addEventListener"},
		"/robots.txt":    {"text/plain; charset=utf-8", "Disallow: /"},
	}
	for path, wc := range cases {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d", path, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); ct != wc.ct {
			t.Errorf("%s Content-Type = %q, want %q", path, ct, wc.ct)
		}
		if !strings.Contains(w.Body.String(), wc.body) {
			t.Errorf("%s body missing %q: %s", path, wc.body, w.Body.String())
		}
	}
}

func TestFavicon(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	serve := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	w := serve(http.MethodGet, "/favicon.ico")
	if w.Code != http.StatusOK {
		t.Fatalf("/favicon.ico status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("/favicon.ico Content-Type = %q, want image/x-icon", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public,max-age=3600" {
		t.Errorf("/favicon.ico Cache-Control = %q, want public,max-age=3600", cc)
	}
	raw := w.Body.Bytes()
	if len(raw) == 0 {
		t.Fatal("/favicon.ico empty body, want non-empty")
	}
	if len(raw) < 4 || raw[0] != 0x00 || raw[1] != 0x00 || raw[2] != 0x01 || raw[3] != 0x00 {
		preview := raw
		if len(preview) > 16 {
			preview = preview[:16]
		}
		t.Errorf("/favicon.ico missing ICO magic 00 00 01 00, got % x", preview)
	}

	if w = serve(http.MethodPost, "/favicon.ico"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /favicon.ico = %d, want 405", w.Code)
	}
	if allow := serve(http.MethodPost, "/favicon.ico").Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("POST /favicon.ico Allow = %q, want GET, HEAD", allow)
	}

	w = serve(http.MethodHead, "/favicon.ico")
	if w.Code != http.StatusOK {
		t.Errorf("HEAD /favicon.ico = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("HEAD /favicon.ico Content-Type = %q, want image/x-icon", ct)
	}
}

func TestStaticImages(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	serve := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	const expectedTheme = "#3776AB"

	w := serve(http.MethodGet, "/static/favicon.svg")
	if w.Code != http.StatusOK {
		t.Fatalf("/static/favicon.svg status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("/static/favicon.svg Content-Type = %q, want image/svg+xml", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public,max-age=3600" {
		t.Errorf("/static/favicon.svg Cache-Control = %q, want public,max-age=3600", cc)
	}
	svg := w.Body.String()
	for _, want := range []string{expectedTheme, "#FFD43B"} {
		if !strings.Contains(svg, want) {
			t.Errorf("/static/favicon.svg missing %q", want)
		}
	}
	if strings.Contains(strings.ToLower(svg), "1a73e8") {
		t.Error("/static/favicon.svg contains stale #1a73e8")
	}

	for _, p := range []string{"/static/icon-192.png", "/static/icon-512.png", "/static/apple-touch-icon.png"} {
		w = serve(http.MethodGet, p)
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", p, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); ct != "image/png" {
			t.Errorf("%s Content-Type = %q, want image/png", p, ct)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "public,max-age=3600" {
			t.Errorf("%s Cache-Control = %q, want public,max-age=3600", p, cc)
		}
		if w.Body.Len() == 0 {
			t.Errorf("%s empty body, want non-empty", p)
		}
	}

	if w = serve(http.MethodGet, "/static/missing.png"); w.Code != http.StatusNotFound {
		t.Errorf("GET /static/missing.png = %d, want 404", w.Code)
	}
	if w = serve(http.MethodPost, "/static/style.css"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /static/style.css = %d, want 405", w.Code)
	}
	if allow := serve(http.MethodPost, "/static/style.css").Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("POST /static/style.css Allow = %q, want GET, HEAD", allow)
	}
}

func TestManifest(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	serve := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	const expectedTheme = "#3776AB"

	w := serve(http.MethodGet, "/manifest.json")
	if w.Code != http.StatusOK {
		t.Fatalf("/manifest.json status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/manifest+json" {
		t.Errorf("/manifest.json Content-Type = %q, want application/manifest+json", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public,max-age=3600" {
		t.Errorf("/manifest.json Cache-Control = %q, want public,max-age=3600", cc)
	}
	manifest := w.Body.String()
	for _, want := range []string{
		"theme_color", expectedTheme,
		"background_color", "#ffffff",
		"/static/icon-192.png",
		"192x192", "512x512", "purpose",
	} {
		if !strings.Contains(manifest, want) {
			t.Errorf("/manifest.json missing %q: %s", want, manifest)
		}
	}

	if w = serve(http.MethodPost, "/static/icon-192.png"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /static/icon-192.png = %d, want 405", w.Code)
	}
}

func TestIndex_anonShowsConsent(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, RUConsent) || !strings.Contains(body, RULoginButton) {
		t.Errorf("anon index missing consent/button")
	}
	if w.Header().Get("X-Robots-Tag") != "noindex" {
		t.Errorf("missing X-Robots-Tag: noindex")
	}
}

func TestIndex_loggedInListsClasses(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-idx", &sessions.SessionRecord{
		StepikUserID: 1, FIO: "Ученик", AllowedClassIDs: []int64{82866},
		ClassTitles: map[string]string{"82866": "2025-26"},
	})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-idx"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/class/82866") {
		t.Errorf("index missing class card: %s", w.Body.String())
	}
}

func TestClass_noSession302Login(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/class/82866", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 login", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "/auth/login?next=") {
		t.Errorf("Location = %q", w.Header().Get("Location"))
	}
}

func TestClass_badCID404(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/class/abc", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestClass_expired401(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-exp", &sessions.SessionRecord{StepikUserID: 1, ExpiresAt: time.Now().Add(-time.Hour)})
	r := httptest.NewRequest("GET", "/class/82866", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-exp"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 first-visit relogin redirect", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "relogin") {
		t.Errorf("Location = %q, want ?relogin=1 flag", loc)
	}
	r2 := httptest.NewRequest("GET", "/class/82866?relogin=1", nil)
	r2.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-exp"})
	w2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("second-visit status = %d, want 401", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), RUExpired) {
		t.Errorf("body missing expired RU string")
	}
}

func TestClass_outsider403(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-out", &sessions.SessionRecord{StepikUserID: 2, AllowedClassIDs: []int64{}})
	r := httptest.NewRequest("GET", "/class/82866", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-out"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), RUOutsider) {
		t.Errorf("outsider body missing outsider RU string")
	}
}

func TestClass_left403(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-left", &sessions.SessionRecord{StepikUserID: 2, AllowedClassIDs: []int64{87566}})
	r := httptest.NewRequest("GET", "/class/82866", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-left"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), RULeft) {
		t.Errorf("left-class body missing left RU string")
	}
}

func TestClass_allowed200_embed(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-cl", &sessions.SessionRecord{
		StepikUserID: 2, FIO: "Ученик", AllowedClassIDs: []int64{82866},
		ClassTitles: map[string]string{"82866": "2025-26"},
	})
	r := httptest.NewRequest("GET", "/class/82866", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-cl"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	body := strings.ReplaceAll(w.Body.String(), `\/`, `/`)
	for _, want := range []string{
		`"https://stepik.study67.fyi/class/82866"`,
		`"https://stepik.study67.fyi/discuss"`,
		`"stepik-discuss"`,
		"https://stepik.org/class/82866",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("class page missing %q", want)
		}
	}
}

func TestStatic_okAndTraversal404(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	r := httptest.NewRequest("GET", "/static/style.css", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("style.css status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("css Content-Type = %q", ct)
	}
	for _, p := range []string{"/static/", "/static/missing.css"} {
		rr := httptest.NewRequest("GET", p, nil)
		ww := httptest.NewRecorder()
		mux.ServeHTTP(ww, rr)
		if ww.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", p, ww.Code)
		}
	}
	rr := httptest.NewRequest("GET", "/static/../go.mod", nil)
	ww := httptest.NewRecorder()
	mux.ServeHTTP(ww, rr)
	if ww.Code != http.StatusMovedPermanently && ww.Code != http.StatusTemporaryRedirect {
		t.Errorf("unclean path status = %d, want mux-clean redirect (307/301), never 200", ww.Code)
	}
	direct := httptest.NewRequest("GET", "/static/x", nil)
	direct.URL.Path = "/static/../gate/Dockerfile"
	dw := httptest.NewRecorder()
	s.handleStatic(dw, direct)
	if dw.Code != http.StatusNotFound {
		t.Errorf("direct .. status = %d, want 404", dw.Code)
	}
}

func TestLogout_methodAndOrigin(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/auth/logout", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET logout = %d, want 405", w.Code)
	}
	r = httptest.NewRequest("POST", "/auth/logout", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("bad-origin logout = %d, want 403", w.Code)
	}
}

func TestLogout_clearsSession(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-lo", &sessions.SessionRecord{StepikUserID: 3})
	rec, err := store.GetSession("sid-lo")
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"csrf_token": {rec.CSRFToken}}
	r := httptest.NewRequest("POST", "/auth/logout", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-lo"})
	r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: rec.CSRFToken})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 /", w.Code)
	}
	if got, _ := store.GetSession("sid-lo"); got != nil {
		t.Error("session row survived logout")
	}
	csrfCleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessions.CookieCSRF && c.MaxAge < 0 {
			csrfCleared = true
		}
	}
	if !csrfCleared {
		t.Error("__Host-csrf cookie was not cleared on logout")
	}
}

func TestLogout_csrfMissing(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-lo-missing", &sessions.SessionRecord{StepikUserID: 3})
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-lo-missing"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on missing CSRF", w.Code)
	}
}

func TestLogout_csrfMismatch(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-lo-bad", &sessions.SessionRecord{StepikUserID: 3})
	rec, _ := store.GetSession("sid-lo-bad")
	form := url.Values{"csrf_token": {"wrong"}}
	r := httptest.NewRequest("POST", "/auth/logout", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-lo-bad"})
	r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: rec.CSRFToken})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 on CSRF mismatch", w.Code)
	}
}

func TestLogout_csrfInQueryRejected(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-lo-query", &sessions.SessionRecord{StepikUserID: 3})
	rec, _ := store.GetSession("sid-lo-query")
	r := httptest.NewRequest("POST", "/auth/logout?csrf_token="+rec.CSRFToken, nil)
	r.Header.Set("Origin", "https://stepik.study67.fyi")
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-lo-query"})
	r.AddCookie(&http.Cookie{Name: sessions.CookieCSRF, Value: rec.CSRFToken})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 when CSRF token is only in query string", w.Code)
	}
}

func TestIndex_includesCSRFInLogoutForm(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-csrf", &sessions.SessionRecord{StepikUserID: 1, AllowedClassIDs: []int64{82866}})
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-csrf"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	rec, _ := store.GetSession("sid-csrf")
	body := w.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) || !strings.Contains(body, rec.CSRFToken) {
		t.Errorf("index logout form missing CSRF hidden field: %s", body)
	}
}

func TestMe_noTokensLeaked(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "sid-me", &sessions.SessionRecord{
		StepikUserID: 7, FIO: "Имя", AvatarURL: "https://cdn/a.png",
		AllowedClassIDs: []int64{82866}, TokenCiphertext: []byte("ct"), TokenNonce: []byte("n"),
	})
	r := httptest.NewRequest("GET", "/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: sessions.CookieSID, Value: "sid-me"})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	for _, leak := range []string{"ciphertext", "ct", "nonce", "token"} {
		if strings.Contains(body, `"`+leak+`"`) {
			t.Errorf("/auth/me leaks %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "is_teacher") || !strings.Contains(body, "allowed") {
		t.Errorf("/auth/me missing fields: %s", body)
	}
	r2 := httptest.NewRequest("GET", "/auth/me", nil)
	w2 := httptest.NewRecorder()
	s.Routes().ServeHTTP(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("anon /auth/me = %d, want 401", w2.Code)
	}
}
