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
	"sync"
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
	raw = unwrapIframeURL(raw)
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

func unwrapIframeURL(raw string) string {
	if raw == "" {
		return raw
	}
	isIframe := strings.HasPrefix(raw, config.DefaultRemarkURL+"/web/iframe.html")
	if !isIframe && !strings.Contains(raw, "?url=") && !strings.Contains(raw, "&url=") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	nested := u.Query().Get("url")
	if nested == "" {
		return raw
	}
	return nested
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
	// ListOwnedFn overrides Stepik.ListOwned when non-nil (tests only).
	ListOwnedFn func(ctx context.Context, token string) ([]stepik.Class, error)
	// GetLoggedIDFn overrides Stepik.GetLoggedID when non-nil (tests only).
	GetLoggedIDFn func(ctx context.Context, token string) (int64, error)
	// VerifyStudentFn overrides stepik.VerifyStudent when non-nil (tests only).
	VerifyStudentFn func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error)
	// RedeemRefreshFn overrides Stepik.RedeemRefresh when non-nil (tests only).
	RedeemRefreshFn func(ctx context.Context, refresh string) (access, refreshOut string, expires time.Time, err error)
	// PutTeacherTokenFn overrides Store.PutTeacherToken when non-nil (tests
	// only). It exercises the demand dual-write failure path; all other
	// teacher-record writes keep using the store directly.
	PutTeacherTokenFn func(*sessions.TeacherToken) error
	// renewMu coalesces concurrent renewals for the same key ("sid:<sid>" or
	// "teacher:current"). It is held across the redeem network call so a
	// second waiter reuses the winner instead of redeeming twice; Bolt
	// transactions are never held across the network. Zero value is ready.
	renewMu renewKeyMutex
	// teacherBG holds background teacher-loop state (park, probe backoff).
	// Zero value is ready; see teacher_refresh.go.
	teacherBG teacherBGState
}

// renewKeyMutex is a hand-rolled keyed mutex with refcounted entries so stale
// session keys do not leak.
type renewKeyMutex struct {
	mu sync.Mutex
	m  map[string]*renewKeyEntry
}

type renewKeyEntry struct {
	mu   sync.Mutex
	refs int
}

func (k *renewKeyMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*renewKeyEntry)
	}
	e, ok := k.m[key]
	if !ok {
		e = &renewKeyEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
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

// ForceTeacherEmptyRefresh forces one live re-verify for a fresh teacher
// session whose snapshot is empty. Bounded by NextRetryAt: at most one
// attempt per RetryAfter window. (stale=true, nil) while in backoff grace;
// (false, TransientError) beyond MaxStale; (false, ErrExpired) when refresh dead.
// Callers must treat non-ErrExpired errors as transient.
// On genuinely-empty success it arms NextRetryAt so rapid HTML hits do not
// hammer Stepik. HTML helper path only; never used by /auth/check.
func (c *Checker) ForceTeacherEmptyRefresh(ctx context.Context, sid string, sess *sessions.SessionRecord) (bool, error) {
	now := time.Now()
	if !sess.NextRetryAt.IsZero() && now.Before(sess.NextRetryAt) {
		if now.Sub(sess.LastVerifiedAt) <= c.Cfg.MaxStale {
			return true, nil
		}
		return false, &stepik.TransientError{Status: 0}
	}
	return c.refreshTeacher(ctx, sid, sess, now)
}

func (c *Checker) staleOrFresh(ctx context.Context, sid string, sess *sessions.SessionRecord, now time.Time, terr error) (bool, error) {
	_ = ctx
	if now.Sub(sess.LastVerifiedAt) <= c.Cfg.MaxStale {
		delay := c.Cfg.RetryAfter + retryJitter(sid)
		var te *stepik.TransientError
		if errors.As(terr, &te) && te.After > 0 {
			if d := te.After + retryJitter(sid); d > delay {
				delay = d
			}
		}
		sess.NextRetryAt = now.Add(delay)
		sess.LastSeenAt = now
		if err := c.Store.PutSession(sid, sess); err != nil {
			c.Log.Error("session save failed", "uid", sess.StepikUserID)
		}
		return true, nil
	}
	return false, &stepik.TransientError{Status: 0}
}

type probeOutcome int

const (
	probeAlive probeOutcome = iota
	probeExpired
	probeTransient
)

func (c *Checker) probeAlive(ctx context.Context, token string, uid int64) (probeOutcome, error) {
	getLoggedID := c.Stepik.GetLoggedID
	if c.GetLoggedIDFn != nil {
		getLoggedID = c.GetLoggedIDFn
	}
	// Stepik degrades dead bearers to anonymous with 200 everywhere (anon uid observed 1390904444);
	// equality with the session uid is the vitality signal, so any mismatch means a dead token.
	probeUID, perr := getLoggedID(ctx, token)
	if perr != nil {
		if stepik.IsUnauthorized(perr) || errors.Is(perr, stepik.ErrEmptyStepics) {
			return probeExpired, nil
		}
		return probeTransient, perr
	}
	if probeUID != uid {
		return probeExpired, nil
	}
	return probeAlive, nil
}

func probeStatus(err error) int {
	var te *stepik.TransientError
	if errors.As(err, &te) {
		return te.Status
	}
	return -1
}

type renewResult int

const (
	// renewNone means no refresh token is stored (pre-feature row) or the
	// record vanished: the caller follows the legacy path.
	renewNone renewResult = iota
	// renewOK means a fresh access token was persisted (or a concurrent
	// winner's token was reused); the returned token must be verified once.
	renewOK
	// renewExpired means the refresh token is dead (invalid_grant); the
	// stored refresh was cleared and the caller must report ErrExpired.
	renewExpired
	// renewTransient means renewal is impossible right now; the caller must
	// fall back to staleOrFresh without persisting anything.
	renewTransient
)

func (c *Checker) redeem(ctx context.Context, refresh string) (string, string, time.Time, error) {
	if c.RedeemRefreshFn != nil {
		return c.RedeemRefreshFn(ctx, refresh)
	}
	return c.Stepik.RedeemRefresh(ctx, c.Cfg.StepikClientID, c.Cfg.StepikClientSecret, refresh)
}

// reloadSessionInPlace refreshes sess from the store so a later persist does
// not overwrite tokens rotated by tryRenewSession. The pointer is preserved
// for callers holding it (ServeHTTP, HTML helpers).
func (c *Checker) reloadSessionInPlace(sid string, sess *sessions.SessionRecord) {
	if fresh, err := c.Store.GetSession(sid); err == nil && fresh != nil {
		*sess = *fresh
	}
}

// clearSessionRefresh clears the stored refresh token after invalid_grant,
// fenced so a record that advanced mid-flight keeps its refresh.
func (c *Checker) clearSessionRefresh(sid string, obtained, refreshObtained time.Time) {
	cur, err := c.Store.GetSession(sid)
	if err != nil || cur == nil {
		return
	}
	if !cur.TokenObtainedAt.Equal(obtained) || !cur.RefreshObtainedAt.Equal(refreshObtained) {
		return
	}
	cur.RefreshCiphertext = nil
	cur.RefreshNonce = nil
	cur.RefreshObtainedAt = time.Time{}
	_ = c.Store.PutSession(sid, cur)
}

// tryRenewSession redeems the session's stored refresh token and persists the
// rotated access token (plus rotation when the endpoint rotates; an empty
// refreshOut retains the previous refresh). Only the token fields and
// ObtainedAt/ExpiresAt are persisted here; the retried verify persists
// LastVerifiedAt via the existing success branches. invalid_grant clears the
// stored refresh only. The per-sid lock is held across the redeem so
// concurrent renewals coalesce: a waiter whose pre-lock snapshot advanced
// reuses the winner without redeeming. A re-login wins via ObtainedAt
// fencing: a superseded redeem result is discarded for the winner's token.
// Teacher sessions delegate to tryRenewTeacherSession so demand and
// background renewals for the teacher identity serialize on one mutex.
func (c *Checker) tryRenewSession(ctx context.Context, sid, reason string) (string, renewResult) {
	pre, _ := c.Store.GetSession(sid)
	if pre != nil && pre.IsTeacher {
		return c.tryRenewTeacherSession(ctx, sid, reason, pre)
	}
	unlock := c.renewMu.lock("sid:" + sid)
	cur, err := c.Store.GetSession(sid)
	if err != nil || cur == nil {
		unlock()
		return "", renewNone
	}
	if cur.IsTeacher {
		unlock()
		return c.tryRenewTeacherSession(ctx, sid, reason, pre)
	}
	defer unlock()
	var preObtained time.Time
	if pre != nil {
		preObtained = pre.TokenObtainedAt
	}
	uid := cur.StepikUserID
	if pre != nil && !cur.TokenObtainedAt.Equal(preObtained) {
		if winner, werr := c.Store.DecryptToken(cur.TokenCiphertext, cur.TokenNonce); werr == nil {
			c.Log.Info("session_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "session")
			return winner, renewOK
		}
		return "", renewNone
	}
	if len(cur.RefreshCiphertext) == 0 {
		return "", renewNone
	}
	obtained := cur.TokenObtainedAt
	refreshObtained := cur.RefreshObtainedAt
	refresh, err := c.Store.DecryptToken(cur.RefreshCiphertext, cur.RefreshNonce)
	if err != nil {
		return "", renewNone
	}
	c.Log.Info("session_renew_demand_start", "uid", uid, "reason", reason, "scope", "session")
	access, refreshOut, expires, rerr := c.redeem(ctx, refresh)
	if rerr != nil {
		if stepik.IsUnauthorized(rerr) {
			c.clearSessionRefresh(sid, obtained, refreshObtained)
			c.Log.Info("session_renew_demand_invalid_grant", "uid", uid, "reason", reason, "scope", "session")
			return "", renewExpired
		}
		c.Log.Warn("session_renew_demand_transient", "uid", uid, "reason", reason, "scope", "session")
		return "", renewTransient
	}
	live, gerr := c.Store.GetSession(sid)
	if gerr != nil || live == nil {
		return "", renewNone
	}
	if !live.TokenObtainedAt.Equal(obtained) {
		if winner, werr := c.Store.DecryptToken(live.TokenCiphertext, live.TokenNonce); werr == nil {
			c.Log.Info("session_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "session")
			return winner, renewOK
		}
		return "", renewNone
	}
	ct, nonce, eerr := c.Store.EncryptToken(access)
	if eerr != nil {
		c.Log.Warn("session_renew_demand_transient", "uid", uid, "reason", reason, "scope", "session")
		return "", renewTransient
	}
	live.TokenCiphertext = ct
	live.TokenNonce = nonce
	live.TokenObtainedAt = time.Now()
	live.TokenExpiresAt = expires
	rotated := false
	if refreshOut != "" {
		if rct, rnonce, rerr := c.Store.EncryptToken(refreshOut); rerr == nil {
			live.RefreshCiphertext = rct
			live.RefreshNonce = rnonce
			live.RefreshObtainedAt = live.TokenObtainedAt
			rotated = true
		}
	}
	if perr := c.Store.PutSession(sid, live); perr != nil {
		c.Log.Warn("session_renew_demand_transient", "uid", uid, "reason", reason, "scope", "session")
		return "", renewTransient
	}
	c.Log.Info("session_renew_demand_success", "uid", uid, "reason", reason, "scope", "session", "rotated", rotated)
	return access, renewOK
}

// putTeacherToken persists the shared teacher record, honouring the test-only
// PutTeacherTokenFn override when set.
func (c *Checker) putTeacherToken(tok *sessions.TeacherToken) error {
	if c.PutTeacherTokenFn != nil {
		return c.PutTeacherTokenFn(tok)
	}
	return c.Store.PutTeacherToken(tok)
}

// tryRenewTeacherSession is tryRenewSession for teacher sessions. After login
// the session and the shared teacher record hold the same refresh string, so
// redeeming under different keys ("sid:<sid>" vs "teacher:current") can redeem
// the same refresh concurrently and the rotation loser gets invalid_grant.
// Both paths route through one mutex for the teacher identity here: the
// "teacher:current" lock is acquired first, then "sid:<sid>" in fixed order
// (the background path never takes a sid lock, so no cycle). The winner's
// tokens are written to both records, and a waiter whose snapshot advanced
// reuses the winner without redeeming, so the two copies never diverge onto
// dead refresh chains. Taxonomy, logging and backoff match tryRenewSession.
func (c *Checker) tryRenewTeacherSession(ctx context.Context, sid, reason string, pre *sessions.SessionRecord) (string, renewResult) {
	var preObtained time.Time
	if pre != nil {
		preObtained = pre.TokenObtainedAt
	}
	preTeacher, _ := c.Store.GetTeacherToken()
	var preTeacherObtained time.Time
	hasPreTeacher := preTeacher != nil
	if hasPreTeacher {
		preTeacherObtained = preTeacher.ObtainedAt
	}
	tUnlock := c.renewMu.lock("teacher:current")
	sUnlock := c.renewMu.lock("sid:" + sid)
	defer func() {
		sUnlock()
		tUnlock()
	}()
	cur, err := c.Store.GetSession(sid)
	if err != nil || cur == nil {
		return "", renewNone
	}
	uid := cur.StepikUserID
	if pre != nil && !cur.TokenObtainedAt.Equal(preObtained) {
		if winner, werr := c.Store.DecryptToken(cur.TokenCiphertext, cur.TokenNonce); werr == nil {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_session")
			return winner, renewOK
		}
		return "", renewNone
	}
	teacherCur, _ := c.Store.GetTeacherToken()
	if hasPreTeacher && teacherCur != nil && !teacherCur.ObtainedAt.Equal(preTeacherObtained) {
		if winner, werr := c.Store.DecryptToken(teacherCur.Ciphertext, teacherCur.Nonce); werr == nil {
			cur.TokenCiphertext = teacherCur.Ciphertext
			cur.TokenNonce = teacherCur.Nonce
			cur.TokenObtainedAt = teacherCur.ObtainedAt
			cur.TokenExpiresAt = teacherCur.ExpiresAt
			if len(teacherCur.RefreshCiphertext) != 0 {
				cur.RefreshCiphertext = teacherCur.RefreshCiphertext
				cur.RefreshNonce = teacherCur.RefreshNonce
				cur.RefreshObtainedAt = teacherCur.RefreshObtainedAt
			}
			_ = c.Store.PutSession(sid, cur)
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_session")
			return winner, renewOK
		}
		return "", renewNone
	}
	if len(cur.RefreshCiphertext) == 0 && teacherCur != nil && len(teacherCur.RefreshCiphertext) != 0 {
		if winner, werr := c.Store.DecryptToken(teacherCur.Ciphertext, teacherCur.Nonce); werr == nil {
			cur.TokenCiphertext = teacherCur.Ciphertext
			cur.TokenNonce = teacherCur.Nonce
			cur.TokenObtainedAt = teacherCur.ObtainedAt
			cur.TokenExpiresAt = teacherCur.ExpiresAt
			cur.RefreshCiphertext = teacherCur.RefreshCiphertext
			cur.RefreshNonce = teacherCur.RefreshNonce
			cur.RefreshObtainedAt = teacherCur.RefreshObtainedAt
			_ = c.Store.PutSession(sid, cur)
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_session")
			return winner, renewOK
		}
		return "", renewNone
	}
	if len(cur.RefreshCiphertext) == 0 {
		return "", renewNone
	}
	obtained := cur.TokenObtainedAt
	refreshObtained := cur.RefreshObtainedAt
	var teacherObtained, teacherRefreshObtained time.Time
	if teacherCur != nil {
		teacherObtained = teacherCur.ObtainedAt
		teacherRefreshObtained = teacherCur.RefreshObtainedAt
	}
	refresh, err := c.Store.DecryptToken(cur.RefreshCiphertext, cur.RefreshNonce)
	if err != nil {
		return "", renewNone
	}
	c.Log.Info("teacher_renew_demand_start", "uid", uid, "reason", reason, "scope", "teacher_session")
	access, refreshOut, expires, rerr := c.redeem(ctx, refresh)
	if rerr != nil {
		if stepik.IsUnauthorized(rerr) {
			c.clearSessionRefresh(sid, obtained, refreshObtained)
			if teacherCur != nil {
				c.clearTeacherRefresh(teacherObtained, teacherRefreshObtained)
			}
			c.Log.Info("teacher_renew_demand_invalid_grant", "uid", uid, "reason", reason, "scope", "teacher_session")
			return "", renewExpired
		}
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_session")
		return "", renewTransient
	}
	live, gerr := c.Store.GetSession(sid)
	if gerr != nil || live == nil {
		return "", renewNone
	}
	liveTeacher, _ := c.Store.GetTeacherToken()
	if !live.TokenObtainedAt.Equal(obtained) {
		if winner, werr := c.Store.DecryptToken(live.TokenCiphertext, live.TokenNonce); werr == nil {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_session")
			return winner, renewOK
		}
		return "", renewNone
	}
	if liveTeacher != nil && !liveTeacher.ObtainedAt.Equal(teacherObtained) {
		if winner, werr := c.Store.DecryptToken(liveTeacher.Ciphertext, liveTeacher.Nonce); werr == nil {
			live.TokenCiphertext = liveTeacher.Ciphertext
			live.TokenNonce = liveTeacher.Nonce
			live.TokenObtainedAt = liveTeacher.ObtainedAt
			live.TokenExpiresAt = liveTeacher.ExpiresAt
			if len(liveTeacher.RefreshCiphertext) != 0 {
				live.RefreshCiphertext = liveTeacher.RefreshCiphertext
				live.RefreshNonce = liveTeacher.RefreshNonce
				live.RefreshObtainedAt = liveTeacher.RefreshObtainedAt
			}
			_ = c.Store.PutSession(sid, live)
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_session")
			return winner, renewOK
		}
		return "", renewNone
	}
	ct, nonce, eerr := c.Store.EncryptToken(access)
	if eerr != nil {
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_session")
		return "", renewTransient
	}
	now := time.Now()
	// Snapshot the pre-renew session tokens: a teacher-put failure below must
	// not leave the session fresh while the teacher record is stale, or the
	// background loop would redeem the stale refresh into a false
	// invalid_grant park.
	origTokenCt, origTokenNonce := live.TokenCiphertext, live.TokenNonce
	origObtained, origExpires := live.TokenObtainedAt, live.TokenExpiresAt
	origRefreshCt, origRefreshNonce := live.RefreshCiphertext, live.RefreshNonce
	origRefreshObtained := live.RefreshObtainedAt
	live.TokenCiphertext = ct
	live.TokenNonce = nonce
	live.TokenObtainedAt = now
	live.TokenExpiresAt = expires
	rotated := false
	if refreshOut != "" {
		rct, rnonce, rerr := c.Store.EncryptToken(refreshOut)
		if rerr == nil {
			live.RefreshCiphertext = rct
			live.RefreshNonce = rnonce
			live.RefreshObtainedAt = now
			rotated = true
		}
	}
	if perr := c.Store.PutSession(sid, live); perr != nil {
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_session")
		return "", renewTransient
	}
	owner := c.Cfg.TeacherID
	expiresIn := 36000
	if liveTeacher != nil {
		owner = liveTeacher.OwnerUID
		expiresIn = liveTeacher.ExpiresIn
	} else if teacherCur != nil {
		owner = teacherCur.OwnerUID
		expiresIn = teacherCur.ExpiresIn
	}
	next := &sessions.TeacherToken{
		Ciphertext:        ct,
		Nonce:             nonce,
		ObtainedAt:        now,
		ExpiresAt:         expires,
		ExpiresIn:         expiresIn,
		OwnerUID:          owner,
		RefreshCiphertext: live.RefreshCiphertext,
		RefreshNonce:      live.RefreshNonce,
		RefreshObtainedAt: live.RefreshObtainedAt,
	}
	if perr := c.putTeacherToken(next); perr != nil {
		if refreshOut == "" {
			// No rotation: the previous refresh is still valid at Stepik,
			// so roll the session back to it. Heal path: both records keep
			// the previous refresh and the next renewal (demand or
			// background) redeems normally.
			live.TokenCiphertext, live.TokenNonce = origTokenCt, origTokenNonce
			live.TokenObtainedAt, live.TokenExpiresAt = origObtained, origExpires
			live.RefreshCiphertext, live.RefreshNonce = origRefreshCt, origRefreshNonce
			live.RefreshObtainedAt = origRefreshObtained
			_ = c.Store.PutSession(sid, live)
		}
		// Rotated: the previous refresh is consumed server-side, so the
		// session keeps the rotated chain. Heal path: the next demand
		// renewal for this sid re-persists both records, and the background
		// loop re-checks session freshness before parking on invalid_grant
		// (see teacherBackgroundRenew) instead of parking on the stale
		// teacher refresh.
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_session")
		return "", renewTransient
	}
	c.Log.Info("teacher_renew_demand_success", "uid", uid, "reason", reason, "scope", "teacher_session", "rotated", rotated)
	return access, renewOK
}

// clearTeacherRefresh is clearSessionRefresh for the shared teacher record.
func (c *Checker) clearTeacherRefresh(obtained, refreshObtained time.Time) {
	cur, err := c.Store.GetTeacherToken()
	if err != nil || cur == nil {
		return
	}
	if !cur.ObtainedAt.Equal(obtained) || !cur.RefreshObtainedAt.Equal(refreshObtained) {
		return
	}
	cur.RefreshCiphertext = nil
	cur.RefreshNonce = nil
	cur.RefreshObtainedAt = time.Time{}
	_ = c.Store.PutTeacherToken(cur)
}

// tryRenewTeacherRecord is tryRenewSession for the shared teacher record
// (key "teacher:current"), used by the background loop. On success the fresh
// access token is returned for a liveness confirm. Teacher demand renewals
// (tryRenewTeacherSession) hold this same key in fixed order
// ("teacher:current" then "sid:<sid>"), so demand and background renewals for
// the teacher identity never redeem the same refresh concurrently.
func (c *Checker) tryRenewTeacherRecord(ctx context.Context, reason string) (string, renewResult) {
	pre, _ := c.Store.GetTeacherToken()
	var preObtained time.Time
	if pre != nil {
		preObtained = pre.ObtainedAt
	}
	unlock := c.renewMu.lock("teacher:current")
	defer unlock()
	cur, err := c.Store.GetTeacherToken()
	if err != nil || cur == nil {
		return "", renewNone
	}
	uid := cur.OwnerUID
	if pre != nil && !cur.ObtainedAt.Equal(preObtained) {
		if winner, werr := c.Store.DecryptToken(cur.Ciphertext, cur.Nonce); werr == nil {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_record")
			return winner, renewOK
		}
		return "", renewNone
	}
	if len(cur.RefreshCiphertext) == 0 {
		return "", renewNone
	}
	obtained := cur.ObtainedAt
	refreshObtained := cur.RefreshObtainedAt
	refresh, err := c.Store.DecryptToken(cur.RefreshCiphertext, cur.RefreshNonce)
	if err != nil {
		return "", renewNone
	}
	c.Log.Info("teacher_renew_demand_start", "uid", uid, "reason", reason, "scope", "teacher_record")
	access, refreshOut, expires, rerr := c.redeem(ctx, refresh)
	if rerr != nil {
		if stepik.IsUnauthorized(rerr) {
			c.clearTeacherRefresh(obtained, refreshObtained)
			c.Log.Info("teacher_renew_demand_invalid_grant", "uid", uid, "reason", reason, "scope", "teacher_record")
			return "", renewExpired
		}
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_record")
		return "", renewTransient
	}
	live, gerr := c.Store.GetTeacherToken()
	if gerr != nil || live == nil {
		return "", renewNone
	}
	if !live.ObtainedAt.Equal(obtained) {
		if winner, werr := c.Store.DecryptToken(live.Ciphertext, live.Nonce); werr == nil {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", reason, "scope", "teacher_record")
			return winner, renewOK
		}
		return "", renewNone
	}
	ct, nonce, eerr := c.Store.EncryptToken(access)
	if eerr != nil {
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_record")
		return "", renewTransient
	}
	now := time.Now()
	next := &sessions.TeacherToken{
		Ciphertext:        ct,
		Nonce:             nonce,
		ObtainedAt:        now,
		ExpiresAt:         expires,
		ExpiresIn:         live.ExpiresIn,
		OwnerUID:          live.OwnerUID,
		RefreshCiphertext: live.RefreshCiphertext,
		RefreshNonce:      live.RefreshNonce,
		RefreshObtainedAt: live.RefreshObtainedAt,
	}
	rotated := false
	if refreshOut != "" {
		if rct, rnonce, rerr := c.Store.EncryptToken(refreshOut); rerr == nil {
			next.RefreshCiphertext = rct
			next.RefreshNonce = rnonce
			next.RefreshObtainedAt = now
			rotated = true
		}
	}
	if perr := c.Store.PutTeacherToken(next); perr != nil {
		c.Log.Warn("teacher_renew_demand_transient", "uid", uid, "reason", reason, "scope", "teacher_record")
		return "", renewTransient
	}
	c.Log.Info("teacher_renew_demand_success", "uid", uid, "reason", reason, "scope", "teacher_record", "rotated", rotated)
	return access, renewOK
}

// putTeacherTokenFenced overwrites the shared teacher record unless it
// advanced since snap or the calling SID holds a stale vintage; then the
// write is discarded. sessTokenObtained/sessRefreshObtained are the calling
// SID's vintages at the success branch (reloaded winner on renew paths,
// load-time copy on first-try success).
func (c *Checker) putTeacherTokenFenced(snap *sessions.TeacherToken, sessTokenObtained, sessRefreshObtained time.Time, tok *sessions.TeacherToken, uid int64) (wrote bool) {
	unlock := c.renewMu.lock("teacher:current")
	defer unlock()
	if live, err := c.Store.GetTeacherToken(); err == nil && live != nil {
		if snap != nil && !live.ObtainedAt.Equal(snap.ObtainedAt) {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", "stale_snap", "scope", "teacher_record")
			return false
		}
		if len(live.RefreshCiphertext) != 0 && live.RefreshObtainedAt.After(sessRefreshObtained) {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", "stale_refresh", "scope", "teacher_record")
			return false
		}
		if live.ObtainedAt.After(sessTokenObtained) {
			c.Log.Info("teacher_renew_demand_superseded", "uid", uid, "reason", "stale_access", "scope", "teacher_record")
			return false
		}
	}
	_ = c.Store.PutTeacherToken(tok)
	return true
}

// SeedTeacherToken overwrites the shared teacher record unconditionally under
// the same "teacher:current" lock used by renew/clear paths. The OAuth
// callback always wins with no ObtainedAt fence, so a mid-window renewal
// result can neither overwrite nor wipe a fresh login. Session records need
// no equivalent: each login mints a fresh SID, never a shared key.
func (c *Checker) SeedTeacherToken(tok *sessions.TeacherToken) {
	unlock := c.renewMu.lock("teacher:current")
	defer unlock()
	_ = c.Store.PutTeacherToken(tok)
}

func (c *Checker) refreshTeacher(ctx context.Context, sid string, sess *sessions.SessionRecord, now time.Time) (bool, error) {
	plain, err := c.Store.DecryptToken(sess.TokenCiphertext, sess.TokenNonce)
	if err != nil {
		return false, ErrExpired
	}
	// Snapshot the teacher record so the success branch can fence its
	// overwrite against a concurrent background renewal.
	teacherSnap, _ := c.Store.GetTeacherToken()
	listOwned := c.Stepik.ListOwned
	if c.ListOwnedFn != nil {
		listOwned = c.ListOwnedFn
	}
	renewed := false
	classes, err := listOwned(ctx, plain)
	if err != nil {
		if !stepik.IsUnauthorized(err) {
			c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
			return c.staleOrFresh(ctx, sid, sess, now, err)
		}
		newPlain, res := c.tryRenewSession(ctx, sid, "teacher_401")
		switch res {
		case renewOK:
			plain = newPlain
			renewed = true
			c.reloadSessionInPlace(sid, sess)
		case renewTransient:
			c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
			return c.staleOrFresh(ctx, sid, sess, now, nil)
		default:
			return false, ErrExpired
		}
		classes, err = listOwned(ctx, plain)
		if err != nil {
			if !stepik.IsUnauthorized(err) {
				c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
				return c.staleOrFresh(ctx, sid, sess, now, err)
			}
			return false, ErrExpired
		}
	}
	if len(classes) == 0 {
		switch outcome, perr := c.probeAlive(ctx, plain, sess.StepikUserID); outcome {
		case probeExpired:
			if renewed {
				return false, ErrExpired
			}
			newPlain, res := c.tryRenewSession(ctx, sid, "teacher_probe")
			switch res {
			case renewOK:
				plain = newPlain
				c.reloadSessionInPlace(sid, sess)
				classes, err = listOwned(ctx, plain)
				if err != nil {
					if !stepik.IsUnauthorized(err) {
						c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
						return c.staleOrFresh(ctx, sid, sess, now, err)
					}
					return false, ErrExpired
				}
				if len(classes) == 0 {
					// The probe re-runs after renew+retry before genuine-empty.
					switch outcome, perr := c.probeAlive(ctx, plain, sess.StepikUserID); outcome {
					case probeExpired:
						c.Log.Info("teacher token dead on empty probe", "uid", sess.StepikUserID, "matched", false)
						return false, ErrExpired
					case probeTransient:
						c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID, "status", probeStatus(perr))
						return c.staleOrFresh(ctx, sid, sess, now, perr)
					}
				}
			case renewTransient:
				c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID)
				return c.staleOrFresh(ctx, sid, sess, now, nil)
			default:
				c.Log.Info("teacher token dead on empty probe", "uid", sess.StepikUserID, "matched", false)
				return false, ErrExpired
			}
		case probeTransient:
			c.Log.Warn("teacher recheck transient", "uid", sess.StepikUserID, "status", probeStatus(perr))
			return c.staleOrFresh(ctx, sid, sess, now, perr)
		}
	}
	ct, nonce, err := c.Store.EncryptToken(plain)
	if err != nil {
		return false, err
	}
	wrote := c.putTeacherTokenFenced(teacherSnap, sess.TokenObtainedAt, sess.RefreshObtainedAt, &sessions.TeacherToken{
		Ciphertext:        ct,
		Nonce:             nonce,
		ObtainedAt:        now,
		ExpiresAt:         now.Add(36000*time.Second - 300*time.Second),
		ExpiresIn:         36000,
		OwnerUID:          c.Cfg.TeacherID,
		RefreshCiphertext: sess.RefreshCiphertext,
		RefreshNonce:      sess.RefreshNonce,
		RefreshObtainedAt: sess.RefreshObtainedAt,
	}, sess.StepikUserID)
	if !wrote {
		if live, lerr := c.Store.GetTeacherToken(); lerr == nil && live != nil {
			sess.TokenCiphertext = live.Ciphertext
			sess.TokenNonce = live.Nonce
			sess.TokenObtainedAt = live.ObtainedAt
			sess.TokenExpiresAt = live.ExpiresAt
			if len(live.RefreshCiphertext) != 0 {
				sess.RefreshCiphertext = live.RefreshCiphertext
				sess.RefreshNonce = live.RefreshNonce
				sess.RefreshObtainedAt = live.RefreshObtainedAt
			}
		}
	}
	sess.AllowedClassIDs = idsOf(classes)
	sess.ClassTitles = titlesOf(classes)
	sess.LastVerifiedAt = now
	sess.NextRetryAt = time.Time{}
	if len(sess.AllowedClassIDs) == 0 {
		sess.NextRetryAt = now.Add(c.Cfg.RetryAfter + retryJitter(sid))
	}
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
	var classes []stepik.Class
	var path string
	var verr error
	verify := func(token string) {
		if c.VerifyStudentFn != nil {
			classes, path, verr = c.VerifyStudentFn(ctx, token, teacherPlain, teacherValid, sess.StepikUserID)
		} else {
			classes, path, verr = stepik.VerifyStudent(ctx, c.Stepik, token, teacherPlain, teacherValid, sess.StepikUserID)
		}
	}
	verify(plain)
	renewed := false
	if verr != nil {
		if !stepik.IsUnauthorized(verr) {
			c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
			return c.staleOrFresh(ctx, sid, sess, now, verr)
		}
		newPlain, res := c.tryRenewSession(ctx, sid, "student_401")
		switch res {
		case renewOK:
			plain = newPlain
			renewed = true
			c.reloadSessionInPlace(sid, sess)
		case renewTransient:
			c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
			return c.staleOrFresh(ctx, sid, sess, now, nil)
		default:
			return false, ErrExpired
		}
		verify(plain)
		if verr != nil {
			if !stepik.IsUnauthorized(verr) {
				c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
				return c.staleOrFresh(ctx, sid, sess, now, verr)
			}
			return false, ErrExpired
		}
	}
	if len(classes) == 0 {
		switch outcome, perr := c.probeAlive(ctx, plain, sess.StepikUserID); outcome {
		case probeExpired:
			if renewed {
				return false, ErrExpired
			}
			newPlain, res := c.tryRenewSession(ctx, sid, "student_probe")
			switch res {
			case renewOK:
				plain = newPlain
				c.reloadSessionInPlace(sid, sess)
				verify(plain)
				if verr != nil {
					if !stepik.IsUnauthorized(verr) {
						c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
						return c.staleOrFresh(ctx, sid, sess, now, verr)
					}
					return false, ErrExpired
				}
				if len(classes) == 0 {
					// The probe re-runs after renew+retry before genuine-empty.
					switch outcome, perr := c.probeAlive(ctx, plain, sess.StepikUserID); outcome {
					case probeExpired:
						c.Log.Info("student token dead on empty probe", "uid", sess.StepikUserID, "matched", false)
						return false, ErrExpired
					case probeTransient:
						c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path, "status", probeStatus(perr))
						return c.staleOrFresh(ctx, sid, sess, now, perr)
					}
				}
			case renewTransient:
				c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path)
				return c.staleOrFresh(ctx, sid, sess, now, nil)
			default:
				c.Log.Info("student token dead on empty probe", "uid", sess.StepikUserID, "matched", false)
				return false, ErrExpired
			}
		case probeTransient:
			c.Log.Warn("student recheck transient", "uid", sess.StepikUserID, "auth_path", path, "status", probeStatus(perr))
			return c.staleOrFresh(ctx, sid, sess, now, perr)
		}
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
	referer := r.Header.Get("Referer")
	cid, err := ExtractCID(fwdURI, referer)
	if err != nil {
		hasURL := false
		if u, perr := url.Parse(fwdURI); perr == nil {
			hasURL = u.Query().Get("url") != ""
		}
		c.Log.Warn("check unknown thread", "uid", uid, "cf_ray", cfRay, "fwd_path", forwardedPath(fwdURI), "has_url", hasURL, "has_referer", referer != "")
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
