package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/admin"
	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/config"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

const (
	RUOutsider         = "Доступ запрещён. Этот сайт только для учеников моих классов на Stepik. Если вы мой ученик — напишите мне, проверим состав класса."
	RUTransient        = "Не удалось проверить состав класса. Попробуйте позже."
	RULeft             = "Нет доступа. Вы больше не состоите в классе."
	RUExpired          = "Сессия истекла. Войдите через Stepik снова."
	RURateLimited      = "Слишком много запросов. Подождите минуту и попробуйте снова."
	RUNextInvalid      = "Некорректная ссылка для возврата."
	RUOAuthDeny        = "Вход через Stepik отменён или не удался. Попробуйте ещё раз."
	RULoginUnavailable = "Вход временно недоступен. Попробуйте позже."
	RULoginButton      = "Войти через Stepik"
	RUConsent          = "Входя через Stepik, вы соглашаетесь, что ваше имя и аватар Stepik будут видны участникам вашего класса. Обсуждения закрыты, не индексируются и доступны только вашему классу и преподавателю."
	RUTeacherBanner    = "Проверка студентов приостановлена: токен преподавателя истёк. Войдите через Stepik ещё раз, чтобы возобновить её."
)

var nextPattern = regexp.MustCompile(`^/($|class/[0-9]{1,19}/?$)`)
var classPathPattern = regexp.MustCompile(`^/class/([0-9]{1,19})/?$`)

type oauthState struct {
	next    string
	binder  string
	ipHash  string
	created time.Time
}

type Server struct {
	cfg      config.Config
	store    *sessions.Store
	step     *stepik.Client
	limits   *ratelimit.Store
	checker  *auth.Checker
	adm      *admin.Admin
	log      *slog.Logger
	tpl      *template.Template
	staticFS fs.FS

	mu     sync.Mutex
	states map[string]oauthState
}

func New(cfg config.Config, store *sessions.Store, step *stepik.Client, limits *ratelimit.Store, checker *auth.Checker, adm *admin.Admin, log *slog.Logger, tpl *template.Template, staticFS fs.FS) *Server {
	return &Server{
		cfg: cfg, store: store, step: step, limits: limits,
		checker: checker, adm: adm, log: log, tpl: tpl, staticFS: staticFS,
		states: map[string]oauthState{},
	}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/manifest.json", s.handleManifest)
	mux.HandleFunc("/sw.js", s.handleSW)
	mux.HandleFunc("/robots.txt", s.handleRobots)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/static/", s.handleStatic)
	mux.HandleFunc("/auth/login", s.handleLogin)
	mux.HandleFunc("/auth/callback", s.handleCallback)
	mux.HandleFunc("/auth/logout", s.handleLogout)
	mux.HandleFunc("/auth/me", s.handleMe)
	mux.Handle("/auth/check", s.checker)
	mux.Handle("/auth/admin/", s.adm)
	mux.HandleFunc("/class/", s.handleClass)
	mux.HandleFunc("/", s.handleIndex)
	return mux
}

func (s *Server) privateHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private,no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("template render failed", "template", name, "status", status, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.privateHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

func (s *Server) renderError(w http.ResponseWriter, status int, message string) {
	s.render(w, status, "error.html", errorData{Message: message})
}

func validNext(raw string) (string, bool) {
	if raw == "" {
		return "/", true
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", false
	}
	base := decoded
	if strings.HasSuffix(decoded, reloginSuffix) {
		base, _ = stripReloginSuffix(decoded)
		if base == "" {
			return "", false
		}
	} else if strings.ContainsAny(decoded, "?#&") {
		return "", false
	}
	if !nextPattern.MatchString(base) {
		return "", false
	}
	return decoded, true
}

type classCard struct {
	CID   int64
	Title string
}

type indexData struct {
	LoggedIn      bool
	FIO           string
	Classes       []classCard
	IsTeacher     bool
	TeacherBanner string
	LoginNext     string
	StaleBanner   string
	Consent       string
	LoginButton   string
	CSRFToken     string
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfRay := r.Header.Get("CF-Ray")
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	var uid int64
	outcome, reason := htmlOutcomeAnon, ""
	var stale bool
	reauth := hasReloginFlag(r)
	var classCount int
	defer func() {
		s.log.Info("index", "route", "index", "path", r.URL.Path, "status", sr.status, "outcome", outcome, "reason", reason, "stale", stale, "reauth", reauth, "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay, "uid", uid, "class_count", classCount)
	}()
	w = sr
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data := indexData{Consent: RUConsent, LoginButton: RULoginButton}
	sess, _, st, out, rsn, handled := s.resolveHTMLSession(w, r, 0, false)
	outcome, reason, stale = out, rsn, st
	if sess != nil {
		classCount = len(sess.AllowedClassIDs)
	}
	if handled {
		return
	}
	if sess == nil {
		s.render(w, http.StatusOK, "index.html", data)
		return
	}
	uid = sess.StepikUserID
	data.LoggedIn = true
	data.FIO = sess.FIO
	data.IsTeacher = sess.IsTeacher
	data.CSRFToken = sess.CSRFToken
	for _, cid := range sess.AllowedClassIDs {
		title := sess.ClassTitles[strconv.FormatInt(cid, 10)]
		if title == "" {
			title = "Класс " + strconv.FormatInt(cid, 10)
		}
		data.Classes = append(data.Classes, classCard{CID: cid, Title: title})
	}
	if sess.IsTeacher && !s.teacherTokenValid() {
		data.TeacherBanner = RUTeacherBanner
		data.LoginNext = loginURL(currentNext(r))
	}
	if stale {
		data.StaleBanner = RUTransient
	}
	s.render(w, http.StatusOK, "index.html", data)
}

func (s *Server) teacherTokenValid() bool {
	_, ok := s.store.TeacherTokenPlain(s.cfg.TeacherID)
	return ok
}

type classData struct {
	CID       int64
	Title     string
	StepikURL string
	EmbedHost string
	SiteID    string
	PageURL   string
	FIO       string
}

func (s *Server) handleClass(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfRay := r.Header.Get("CF-Ray")
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	var uid, cid int64
	outcome, reason := htmlOutcomeAnon, ""
	var stale bool
	reauth := hasReloginFlag(r)
	var classCount int
	defer func() {
		s.log.Info("class", "route", "class", "path", r.URL.Path, "status", sr.status, "outcome", outcome, "reason", reason, "stale", stale, "reauth", reauth, "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay, "uid", uid, "cid", cid, "class_count", classCount)
	}()
	w = sr
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	m := classPathPattern.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	cid, _ = strconv.ParseInt(m[1], 10, 64)
	sess, _, st, out, rsn, handled := s.resolveHTMLSession(w, r, cid, true)
	outcome, reason, stale = out, rsn, st
	if sess != nil {
		classCount = len(sess.AllowedClassIDs)
	}
	if handled {
		if sess != nil {
			uid = sess.StepikUserID
		}
		return
	}
	uid = sess.StepikUserID
	title := sess.ClassTitles[strconv.FormatInt(cid, 10)]
	if title == "" {
		title = "Класс " + strconv.FormatInt(cid, 10)
	}
	pageURL := s.cfg.ClassBase() + strconv.FormatInt(cid, 10)
	s.render(w, http.StatusOK, "class.html", classData{
		CID:       cid,
		Title:     title,
		StepikURL: "https://stepik.org/class/" + strconv.FormatInt(cid, 10),
		EmbedHost: s.cfg.EmbedHost(),
		SiteID:    s.cfg.Site,
		PageURL:   pageURL,
		FIO:       sess.FIO,
	})
}

func (s *Server) newState(next, binder, ip string) (string, error) {
	raw := make([]byte, 32)
	if _, err := readRandom(raw); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(state))
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.states {
		if now.Sub(v.created) > 10*time.Minute {
			delete(s.states, k)
		}
	}
	s.states[hex.EncodeToString(sum[:])] = oauthState{
		next:    next,
		binder:  binder,
		ipHash:  ipHash(ip),
		created: now,
	}
	return state, nil
}

func (s *Server) takeState(state, binder, ip string) (string, bool) {
	sum := sha256.Sum256([]byte(state))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.states[key]
	if !ok {
		return "", false
	}
	delete(s.states, key)
	if time.Since(rec.created) > 10*time.Minute {
		return "", false
	}
	if subtleCompare(rec.binder, binder) != 1 {
		return "", false
	}
	// Strict IP bind narrows state replay; may flake on CGNAT/mobile.
	if subtleCompare(rec.ipHash, ipHash(ip)) != 1 {
		return "", false
	}
	return rec.next, true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	next, ok := validNext(r.URL.Query().Get("next"))
	if !ok {
		s.renderError(w, http.StatusBadRequest, RUNextInvalid)
		return
	}
	if s.cfg.Placeholder {
		s.renderError(w, http.StatusServiceUnavailable, RULoginUnavailable)
		return
	}
	ip := ratelimit.ClientIP(r)
	if !s.limits.AllowLogin(ip) {
		w.Header().Set("Retry-After", "60")
		s.renderError(w, http.StatusTooManyRequests, RURateLimited)
		return
	}
	binder, err := sessions.NewBinder()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	state, err := s.newState(next, binder, ip)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	sessions.SetBinder(w, binder)
	http.Redirect(w, r, stepik.AuthCodeURL(s.cfg.StepikClientID, s.cfg.StepikRedirectURL, state), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	start := time.Now()
	ip := ratelimit.ClientIP(r)
	cfRay := r.Header.Get("CF-Ray")
	if !s.limits.AllowCallback(ip) {
		w.Header().Set("Retry-After", "60")
		s.renderError(w, http.StatusTooManyRequests, RURateLimited)
		return
	}
	binderCookie, err := r.Cookie(sessions.CookieBinder)
	if err != nil {
		s.renderError(w, http.StatusForbidden, RUOAuthDeny)
		return
	}
	if r.URL.Query().Get("error") != "" {
		s.renderError(w, http.StatusForbidden, RUOAuthDeny)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		s.renderError(w, http.StatusForbidden, RUOAuthDeny)
		return
	}
	next, ok := s.takeState(state, binderCookie.Value, ip)
	if !ok {
		s.renderError(w, http.StatusForbidden, RUOAuthDeny)
		return
	}
	ctx := r.Context()
	access, refresh, tokenExpires, err := s.step.ExchangeCode(ctx, s.cfg.StepikClientID, s.cfg.StepikClientSecret, s.cfg.StepikRedirectURL, code)
	if err != nil {
		s.log.Warn("oauth exchange failed", "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
		s.renderError(w, http.StatusServiceUnavailable, RUTransient)
		return
	}
	uid, err := s.step.GetLoggedID(ctx, access)
	if err != nil {
		if stepik.IsTransient(err) {
			s.renderError(w, http.StatusServiceUnavailable, RUTransient)
			return
		}
		s.renderError(w, http.StatusForbidden, RUOAuthDeny)
		return
	}
	fio, avatar, err := s.step.GetProfile(ctx, access, uid)
	if err != nil {
		if stepik.IsTransient(err) {
			s.renderError(w, http.StatusServiceUnavailable, RUTransient)
			return
		}
		fio = "Stepik " + strconv.FormatInt(uid, 10)
	}
	now := time.Now()
	ct, nonce, err := s.store.EncryptToken(access)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	// Re-login writes access+refresh unconditionally; a concurrent renewal
	// loses via ObtainedAt fencing because this record is strictly newer.
	var refreshCT, refreshNonce []byte
	var refreshObtained time.Time
	if refresh != "" {
		refreshCT, refreshNonce, err = s.store.EncryptToken(refresh)
		if err != nil {
			s.renderError(w, http.StatusInternalServerError, RUTransient)
			return
		}
		refreshObtained = now
	}
	uv, err := s.store.GetUserVersion(uid)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	epoch, err := s.store.GetGlobalEpoch()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	csrf, err := sessions.NewCSRFToken()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	sess := &sessions.SessionRecord{
		StepikUserID:      uid,
		FIO:               fio,
		AvatarURL:         avatar,
		CreatedAt:         now,
		LastVerifiedAt:    now,
		ExpiresAt:         now.Add(30 * 24 * time.Hour),
		LastSeenAt:        now,
		UserVersion:       uv,
		GlobalEpoch:       epoch,
		CSRFToken:         csrf,
		TokenCiphertext:   ct,
		TokenNonce:        nonce,
		TokenObtainedAt:   now,
		TokenExpiresAt:    tokenExpires,
		RefreshCiphertext: refreshCT,
		RefreshNonce:      refreshNonce,
		RefreshObtainedAt: refreshObtained,
	}
	var authPath string
	if uid == s.cfg.TeacherID {
		sess.IsTeacher = true
		if err := s.checker.SeedTeacherToken(&sessions.TeacherToken{
			Ciphertext:        ct,
			Nonce:             nonce,
			ObtainedAt:        now,
			ExpiresAt:         tokenExpires,
			OwnerUID:          s.cfg.TeacherID,
			RefreshCiphertext: refreshCT,
			RefreshNonce:      refreshNonce,
			RefreshObtainedAt: refreshObtained,
		}); err != nil {
			s.renderError(w, http.StatusInternalServerError, RUTransient)
			return
		}
		classes, lerr := s.step.ListOwned(ctx, access)
		if lerr != nil {
			if stepik.IsTransient(lerr) {
				s.renderError(w, http.StatusServiceUnavailable, RUTransient)
				return
			}
			s.renderError(w, http.StatusForbidden, RUOAuthDeny)
			return
		}
		authPath = "B"
		sess.AllowedClassIDs = idsOf(classes)
		sess.ClassTitles = titlesOf(classes)
	} else {
		teacherPlain, teacherValid := s.currentTeacherToken()
		classes, path, verr := stepik.VerifyStudent(ctx, s.step, access, teacherPlain, teacherValid, uid)
		authPath = path
		if verr != nil {
			if stepik.IsTransient(verr) {
				s.renderError(w, http.StatusServiceUnavailable, RUTransient)
				return
			}
			s.renderError(w, http.StatusForbidden, RUOAuthDeny)
			return
		}
		if len(classes) == 0 {
			s.log.Info("login deny", "uid", uid, "auth_path", authPath, "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
			s.renderError(w, http.StatusForbidden, RUOutsider)
			return
		}
		sess.AllowedClassIDs = idsOf(classes)
		sess.ClassTitles = titlesOf(classes)
	}
	sid, err := sessions.NewSID()
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	if err := s.store.PutSession(sid, sess); err != nil {
		s.renderError(w, http.StatusInternalServerError, RUTransient)
		return
	}
	s.log.Info("login allow", "uid", uid, "auth_path", authPath, "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
	sessions.SetSID(w, sid)
	sessions.SetCSRF(w, csrf)
	sessions.ClearBinder(w)
	http.Redirect(w, r, next, http.StatusFound)
}

func (s *Server) currentTeacherToken() (string, bool) {
	return s.store.TeacherTokenPlain(s.cfg.TeacherID)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !validSameOrigin(r, s.cfg.Origin) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !sessions.VerifyFormCSRF(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(sessions.CookieSID); err == nil {
		_ = s.store.DeleteSession(c.Value)
	}
	sessions.ClearSID(w)
	sessions.ClearCSRF(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "auth_required"})
		return
	}
	stale, err := s.checker.EnsureFresh(r.Context(), sid, sess)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if errors.Is(err, auth.ErrExpired) {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "auth_required"})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "transient"})
		return
	}
	_ = stale
	if auth.SlideSession(s.store, sid, sess, time.Now(), s.log) {
		sessions.SetSID(w, sid)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private,no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":         sess.StepikUserID,
		"fio":        sess.FIO,
		"avatar":     sess.AvatarURL,
		"allowed":    sess.AllowedClassIDs,
		"is_teacher": sess.IsTeacher,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("deep") == "1" {
		if !auth.Guard(r, s.cfg.GateToken) {
			http.NotFound(w, r)
			return
		}
		if err := s.store.Ping(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": false})
			return
		}
		if _, err := net.ResolveIPAddr("ip", "stepik.org"); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": false})
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public,max-age=3600")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":             "Обсуждения классов Stepik",
		"short_name":       "Stepik Discuss",
		"display":          "standalone",
		"scope":            "/",
		"start_url":        "/",
		"lang":             "ru",
		"theme_color":      "#3776AB",
		"background_color": "#ffffff",
		"icons": []map[string]string{
			{"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
			{"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
		},
	})
}

func (s *Server) handleSW(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("self.addEventListener('fetch',function(e){return;});\n"))
}

func (s *Server) handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	if name == "" || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	raw, err := fs.ReadFile(s.staticFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	case strings.HasSuffix(name, ".png"):
		w.Header().Set("Content-Type", "image/png")
	}
	w.Header().Set("Cache-Control", "public,max-age=3600")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(raw)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	raw, err := fs.ReadFile(s.staticFS, "favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public,max-age=3600")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(raw)
}

func idsOf(classes []stepik.Class) []int64 {
	ids := make([]int64, 0, len(classes))
	for _, cl := range classes {
		ids = append(ids, cl.ID)
	}
	return ids
}

func titlesOf(classes []stepik.Class) map[string]string {
	m := make(map[string]string, len(classes))
	for _, cl := range classes {
		m[strconv.FormatInt(cl.ID, 10)] = cl.DisplayTitle()
	}
	return m
}

func ipHash(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:16])
}
