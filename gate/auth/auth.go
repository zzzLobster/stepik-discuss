package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/config"
	gatejwt "github.com/zzzLobster/stepik-discuss/gate/jwt"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

var (
	ErrNoSession     = errors.New("no session")
	ErrExpired       = errors.New("session expired")
	ErrUnknownThread = errors.New("unknown_thread")
)

const (
	codeAuthRequired = "auth_required"
	codeForbidden    = "forbidden"
	codeTeacherOnly  = "teacher_only"
	codeTransient    = "transient"
	codeRateLimited  = "rate_limited"
)

var cidPattern = regexp.MustCompile(`^[0-9]{1,10}$`)

func Allowed(sess *sessions.SessionRecord, cid int64) bool {
	if sess.IsTeacher {
		return true
	}
	for _, id := range sess.AllowedClassIDs {
		if id == cid {
			return true
		}
	}
	return false
}

func LoadSession(store *sessions.Store, r *http.Request) (*sessions.SessionRecord, string, error) {
	c, err := r.Cookie(sessions.CookieSID)
	if err != nil {
		return nil, "", ErrNoSession
	}
	sess, err := store.GetSession(c.Value)
	if err != nil {
		return nil, "", err
	}
	if sess == nil {
		return nil, "", ErrNoSession
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, "", ErrExpired
	}
	uv, err := store.GetUserVersion(sess.StepikUserID)
	if err != nil {
		return nil, "", err
	}
	if uv != sess.UserVersion {
		return nil, "", ErrExpired
	}
	epoch, err := store.GetGlobalEpoch()
	if err != nil {
		return nil, "", err
	}
	if epoch != sess.GlobalEpoch {
		return nil, "", ErrExpired
	}
	return sess, c.Value, nil
}

func SlidingNeeded(sess *sessions.SessionRecord, now time.Time) bool {
	return now.After(sess.ExpiresAt.Add(-29 * 24 * time.Hour))
}

func SlideSession(store *sessions.Store, sid string, sess *sessions.SessionRecord, now time.Time) bool {
	if !SlidingNeeded(sess, now) {
		return false
	}
	sess.ExpiresAt = now.Add(30 * 24 * time.Hour)
	sess.LastSeenAt = now
	_ = store.PutSession(sid, sess)
	return true
}

func ExtractCID(forwardedURI, referer string) (int64, error) {
	raw := ""
	if forwardedURI != "" {
		if u, err := url.Parse(forwardedURI); err == nil {
			raw = u.Query().Get("url")
		}
	}
	if raw == "" {
		raw = referer
	}
	if raw == "" {
		return 0, ErrUnknownThread
	}
	if strings.Contains(strings.ToLower(raw), "%25") {
		return 0, ErrUnknownThread
	}
	trimmed := strings.TrimSuffix(raw, "/")
	if !strings.HasPrefix(trimmed, config.ClassBaseURL) {
		return 0, ErrUnknownThread
	}
	rest := strings.TrimPrefix(trimmed, config.ClassBaseURL)
	if !cidPattern.MatchString(rest) {
		return 0, ErrUnknownThread
	}
	cid, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return 0, ErrUnknownThread
	}
	return cid, nil
}

func Guard(r *http.Request, expected string) bool {
	if expected == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gate-Auth")), []byte(expected)) != 1 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func verifyJitter(sid string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sid))
	span := int64(30 * time.Minute)
	return time.Duration(int64(h.Sum32())%span) - 15*time.Minute
}

func retryJitter(sid string) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte("retry" + sid))
	return time.Duration(int64(h.Sum32()) % int64(5*time.Minute))
}

type Checker struct {
	Cfg    config.Config
	Store  *sessions.Store
	Stepik *stepik.Client
	Limits *ratelimit.Store
	Log    *slog.Logger
}

func (c *Checker) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private,no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (c *Checker) teacherTokenValid() (string, bool) {
	return c.Store.TeacherTokenPlain(c.Cfg.TeacherID)
}

func (c *Checker) EnsureFresh(ctx context.Context, sid string, sess *sessions.SessionRecord) (bool, error) {
	now := time.Now()
	if now.Sub(sess.LastVerifiedAt) <= c.Cfg.VerifyTTL+verifyJitter(sid) {
		if now.Sub(sess.LastSeenAt) > 5*time.Minute {
			sess.LastSeenAt = now
			if err := c.Store.PutSession(sid, sess); err != nil {
				c.Log.Error("session save failed", "uid", sess.StepikUserID)
			}
		}
		return false, nil
	}
	if !sess.NextRetryAt.IsZero() && now.Before(sess.NextRetryAt) {
		if now.Sub(sess.LastVerifiedAt) <= c.Cfg.MaxStale {
			return true, nil
		}
		return false, &stepik.TransientError{Status: 0}
	}
	if sess.IsTeacher {
		return c.refreshTeacher(ctx, sid, sess, now)
	}
	return c.refreshStudent(ctx, sid, sess, now)
}

func (c *Checker) staleOrFresh(ctx context.Context, sid string, sess *sessions.SessionRecord, now time.Time) (bool, error) {
	_ = ctx
	if now.Sub(sess.LastVerifiedAt) <= c.Cfg.MaxStale {
		sess.NextRetryAt = now.Add(c.Cfg.RetryAfter + retryJitter(sid))
		sess.LastSeenAt = now
		if err := c.Store.PutSession(sid, sess); err != nil {
			c.Log.Error("session save failed", "uid", sess.StepikUserID)
		}
		return true, nil
	}
	return false, &stepik.TransientError{Status: 0}
}

func (c *Checker) refreshTeacher(ctx context.Context, sid string, sess *sessions.SessionRecord, now time.Time) (bool, error) {
	plain, err := c.Store.DecryptToken(sess.TokenCiphertext, sess.TokenNonce)
	if err != nil {
		return false, ErrExpired
	}
	classes, err := c.Stepik.ListOwned(ctx, plain)
	if err != nil {
		if stepik.IsUnauthorized(err) {
			return false, ErrExpired
		}
		c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
		return c.staleOrFresh(ctx, sid, sess, now)
	}
	ct, nonce, err := c.Store.EncryptToken(plain)
	if err != nil {
		return false, err
	}
	_ = c.Store.PutTeacherToken(&sessions.TeacherToken{
		Ciphertext: ct,
		Nonce:      nonce,
		ObtainedAt: now,
		ExpiresAt:  now.Add(36000*time.Second - 300*time.Second),
		ExpiresIn:  36000,
		OwnerUID:   c.Cfg.TeacherID,
	})
	sess.AllowedClassIDs = idsOf(classes)
	sess.ClassTitles = titlesOf(classes)
	sess.LastVerifiedAt = now
	sess.NextRetryAt = time.Time{}
	sess.LastSeenAt = now
	if err := c.Store.PutSession(sid, sess); err != nil {
		return false, err
	}
	return false, nil
}

func (c *Checker) refreshStudent(ctx context.Context, sid string, sess *sessions.SessionRecord, now time.Time) (bool, error) {
	plain, err := c.Store.DecryptToken(sess.TokenCiphertext, sess.TokenNonce)
	if err != nil {
		return false, ErrExpired
	}
	teacherPlain, teacherValid := c.teacherTokenValid()
	classes, path, verr := stepik.VerifyStudent(ctx, c.Stepik, plain, teacherPlain, teacherValid, sess.StepikUserID)
	if verr != nil {
		if stepik.IsUnauthorized(verr) {
			return false, ErrExpired
		}
		c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
		return c.staleOrFresh(ctx, sid, sess, now)
	}
	sess.AllowedClassIDs = idsOf(classes)
	sess.ClassTitles = titlesOf(classes)
	sess.LastVerifiedAt = now
	sess.NextRetryAt = time.Time{}
	sess.LastSeenAt = now
	if err := c.Store.PutSession(sid, sess); err != nil {
		return false, err
	}
	return false, nil
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

func forwardedPath(forwardedURI string) string {
	if forwardedURI == "" {
		return ""
	}
	if u, err := url.Parse(forwardedURI); err == nil {
		return u.Path
	}
	return ""
}

func (c *Checker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	cfRay := r.Header.Get("CF-Ray")
	if !Guard(r, c.Cfg.GateToken) {
		c.Log.Warn("check bad gate auth", "cf_ray", cfRay)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	sess, sid, err := LoadSession(c.Store, r)
	if err != nil {
		c.Log.Info("check deny", "uid", 0, "cid", 0, "owner", 0, "auth_path", "deny", "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
		c.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": codeAuthRequired})
		return
	}
	uid := sess.StepikUserID
	deny := func(status int, code string, cid int64, path string) {
		var owner int64
		if cid != 0 {
			owner = c.Cfg.TeacherID
		}
		c.Log.Info("check deny", "uid", uid, "cid", cid, "owner", owner, "auth_path", path, "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
		c.writeJSON(w, status, map[string]string{"error": code})
	}
	ok, retryAfter := c.Limits.AllowDiscuss(sid)
	if !ok {
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter/time.Second), 10))
		deny(http.StatusTooManyRequests, codeRateLimited, 0, "deny")
		return
	}
	fwdURI := r.Header.Get("X-Forwarded-Uri")
	if strings.HasPrefix(forwardedPath(fwdURI), "/discuss/admin/") {
		if !sess.IsTeacher {
			deny(http.StatusForbidden, codeTeacherOnly, 0, "deny")
			return
		}
		c.mint(w, r, sess, 0, false, start, cfRay)
		return
	}
	cid, err := ExtractCID(fwdURI, r.Header.Get("Referer"))
	if err != nil {
		c.Log.Warn("check unknown thread", "uid", uid, "cf_ray", cfRay)
		deny(http.StatusForbidden, codeForbidden, 0, "deny")
		return
	}
	stale, err := c.EnsureFresh(r.Context(), sid, sess)
	if err != nil {
		if errors.Is(err, ErrExpired) {
			deny(http.StatusUnauthorized, codeAuthRequired, cid, "deny")
			return
		}
		deny(http.StatusServiceUnavailable, codeTransient, cid, "transient")
		return
	}
	if !Allowed(sess, cid) {
		deny(http.StatusForbidden, codeForbidden, cid, "deny")
		return
	}
	SlideSession(c.Store, sid, sess, time.Now())
	c.mint(w, r, sess, cid, stale, start, cfRay)
}

func (c *Checker) mint(w http.ResponseWriter, r *http.Request, sess *sessions.SessionRecord, cid int64, stale bool, start time.Time, cfRay string) {
	_ = r
	signed, jti, err := gatejwt.Mint(c.Cfg.RemarkJWTSecret, c.Cfg.Site, sess.StepikUserID, sess.FIO, sess.AvatarURL, sess.IsTeacher)
	if err != nil {
		c.Log.Error("jwt mint failed", "uid", sess.StepikUserID)
		c.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": codeTransient})
		return
	}
	w.Header().Set("X-JWT", signed)
	w.Header().Set("X-XSRF-TOKEN", jti)
	if stale {
		w.Header().Set("X-Gate-Stale", "1")
	}
	var owner int64
	if cid != 0 {
		owner = c.Cfg.TeacherID
	}
	c.Log.Info("check allow", "uid", sess.StepikUserID, "cid", cid, "owner", owner, "auth_path", "cache", "latency_ms", time.Since(start).Milliseconds(), "cf_ray", cfRay)
	c.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
