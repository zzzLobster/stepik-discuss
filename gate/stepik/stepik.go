package stepik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

const (
	AuthorizeURL = "https://stepik.org/oauth2/authorize/"
	TokenURL     = "https://stepik.org/oauth2/token/"
	APIBase      = "https://stepik.org/api"
	// MaxClassPages caps class pagination (~200 classes at page size 20).
	MaxClassPages = 10
)

type Class struct {
	ID            int64  `json:"id"`
	Title         string `json:"title"`
	Name          string `json:"name"`
	Course        int64  `json:"course"`
	Owner         int64  `json:"owner"`
	StudentsCount int    `json:"students_count"`
}

func (c Class) DisplayTitle() string {
	if c.Title != "" {
		return c.Title
	}
	if c.Name != "" {
		return c.Name
	}
	return "Класс " + strconv.FormatInt(c.ID, 10)
}

type TransientError struct {
	Status int
	// After is the server's Retry-After ask, if present. Advisory only;
	// staleOrFresh takes max(cfg RetryAfter, After) + jitter.
	After time.Duration
}

func (e *TransientError) Error() string {
	return "stepik transient status=" + strconv.Itoa(e.Status)
}

func IsTransient(err error) bool {
	var te *TransientError
	return errors.As(err, &te)
}

type UnauthorizedError struct {
	Status int
}

func (e *UnauthorizedError) Error() string {
	return "stepik unauthorized status=" + strconv.Itoa(e.Status)
}

func IsUnauthorized(err error) bool {
	var ue *UnauthorizedError
	return errors.As(err, &ue)
}

type TeacherFallbackError struct {
	Status int
	Err    error
}

// IsTeacherFallback must be checked before IsUnauthorized; deliberately does
// not Unwrap to inner Unauthorized to avoid misclassification.
func (e *TeacherFallbackError) Error() string {
	if e == nil {
		return "stepik teacher fallback status=unknown"
	}
	if e.Err == nil {
		return "stepik teacher fallback status=" + strconv.Itoa(e.Status)
	}
	return "stepik teacher fallback status=" + strconv.Itoa(e.Status) + ": " + e.Err.Error()
}

func IsTeacherFallback(err error) bool {
	var te *TeacherFallbackError
	return errors.As(err, &te)
}

var ErrEmptyStepics = errors.New("stepics empty")

type Client struct {
	http      *http.Client
	out       *rate.Limiter
	teacherID int64
	log       *slog.Logger
	// TokenURL overrides the default token endpoint (tests only).
	TokenURL string
}

func New(teacherID int64, log *slog.Logger) *Client {
	return &Client{
		http:      &http.Client{Timeout: 15 * time.Second},
		out:       rate.NewLimiter(4, 8),
		teacherID: teacherID,
		log:       log,
	}
}

func AuthCodeURL(clientID, redirect, state string) string {
	conf := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirect,
		Scopes:      []string{"read"},
		Endpoint:    oauth2.Endpoint{AuthURL: AuthorizeURL, TokenURL: TokenURL},
	}
	return conf.AuthCodeURL(state)
}

func (c *Client) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return TokenURL
}

func (c *Client) ExchangeCode(ctx context.Context, clientID, secret, redirect, code string) (access, refresh string, expires time.Time, err error) {
	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURL:  redirect,
		Scopes:       []string{"read"},
		Endpoint:     oauth2.Endpoint{AuthURL: AuthorizeURL, TokenURL: c.tokenURL()},
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires = tok.Expiry
	if expires.IsZero() {
		expires = time.Now().Add(36000*time.Second - 300*time.Second)
	}
	refresh = tok.RefreshToken
	c.log.Info("oauth exchange ok", "has_refresh", refresh != "")
	return tok.AccessToken, refresh, expires, nil
}

// RedeemRefresh exchanges a stored refresh token for a fresh access token.
// refreshOut is empty when the endpoint omits rotation: the caller must
// retain the previous refresh token. A 400 containing invalid_grant or any 401
// means the refresh token is dead and is reported as UnauthorizedError with
// no retry; 429/5xx/transport map to TransientError with retry; other 4xx
// (including 400 without invalid_grant) yield a plain non-retryable error
// that backs off without wiping the stored refresh.
func (c *Client) RedeemRefresh(ctx context.Context, clientID, secret, refresh string) (access, refreshOut string, expires time.Time, err error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	encoded := form.Encode()
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			wait := time.Duration(500*(1<<uint(attempt-1)))*time.Millisecond + time.Duration(rand.Intn(250))*time.Millisecond
			select {
			case <-ctx.Done():
				return "", "", time.Time{}, ctx.Err()
			case <-time.After(wait):
			}
		}
		if err := c.out.Wait(ctx); err != nil {
			return "", "", time.Time{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL(), strings.NewReader(encoded))
		if err != nil {
			return "", "", time.Time{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, secret)
		start := time.Now()
		resp, err := c.http.Do(req)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			last = &TransientError{Status: 0}
			c.log.Warn("stepik refresh transport error", "latency_ms", latency)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil {
			last = &TransientError{Status: resp.StatusCode}
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			var v struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				ExpiresIn    int64  `json:"expires_in"`
			}
			if err := json.Unmarshal(body, &v); err != nil {
				return "", "", time.Time{}, err
			}
			if v.AccessToken == "" {
				return "", "", time.Time{}, fmt.Errorf("stepik refresh empty access token")
			}
			if v.ExpiresIn > 0 {
				expires = time.Now().Add(time.Duration(v.ExpiresIn) * time.Second)
			} else {
				expires = time.Now().Add(36000*time.Second - 300*time.Second)
			}
			c.log.Info("stepik refresh ok", "has_refresh", v.RefreshToken != "")
			return v.AccessToken, v.RefreshToken, expires, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			after := retryAfter(resp.Header.Get("Retry-After"))
			c.log.Warn("stepik refresh transient", "status", resp.StatusCode, "latency_ms", latency)
			last = &TransientError{Status: resp.StatusCode, After: after}
			continue
		case resp.StatusCode == http.StatusUnauthorized:
			c.log.Warn("stepik refresh unauthorized", "status", resp.StatusCode, "latency_ms", latency, "body_trunc", truncRefreshBody(body))
			return "", "", time.Time{}, &UnauthorizedError{Status: resp.StatusCode}
		case resp.StatusCode == http.StatusBadRequest:
			if isInvalidGrant(body) {
				c.log.Warn("stepik refresh invalid_grant", "status", resp.StatusCode, "latency_ms", latency, "body_trunc", truncRefreshBody(body))
				return "", "", time.Time{}, &UnauthorizedError{Status: resp.StatusCode}
			}
			c.log.Warn("stepik refresh bad request", "status", resp.StatusCode, "latency_ms", latency, "body_trunc", truncRefreshBody(body))
			return "", "", time.Time{}, fmt.Errorf("stepik refresh status=400 body=%.200s", body)
		default:
			return "", "", time.Time{}, fmt.Errorf("stepik refresh status=%d", resp.StatusCode)
		}
	}
	return "", "", time.Time{}, last
}

func (c *Client) get(ctx context.Context, token, path string, query url.Values, v any) error {
	u := APIBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			wait := time.Duration(500*(1<<uint(attempt-1)))*time.Millisecond + time.Duration(rand.Intn(250))*time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		if err := c.out.Wait(ctx); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		start := time.Now()
		resp, err := c.http.Do(req)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			last = &TransientError{Status: 0}
			c.log.Warn("stepik transport error", "latency_ms", latency)
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if rerr != nil {
			last = &TransientError{Status: resp.StatusCode}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			after := retryAfter(resp.Header.Get("Retry-After"))
			c.log.Warn("stepik transient", "status", resp.StatusCode, "latency_ms", latency)
			last = &TransientError{Status: resp.StatusCode, After: after}
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return &UnauthorizedError{Status: resp.StatusCode}
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("stepik status=%d", resp.StatusCode)
		}
		if err := json.Unmarshal(body, v); err != nil {
			return err
		}
		return nil
	}
	return last
}

func retryAfter(h string) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > 30 {
			secs = 30
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		if d > 30*time.Second {
			return 30 * time.Second
		}
		return d
	}
	return 0
}

func isInvalidGrant(body []byte) bool {
	return bytes.Contains(bytes.ToLower(body), []byte("invalid_grant"))
}

func truncRefreshBody(body []byte) string {
	if len(body) > 200 {
		body = body[:200]
	}
	return string(body)
}

func (c *Client) GetLoggedID(ctx context.Context, token string) (int64, error) {
	var v struct {
		Stepics []struct {
			User int64 `json:"user"`
		} `json:"stepics"`
	}
	if err := c.get(ctx, token, "/stepics/1", nil, &v); err != nil {
		return 0, err
	}
	if len(v.Stepics) == 0 {
		return 0, ErrEmptyStepics
	}
	return v.Stepics[0].User, nil
}

func (c *Client) GetProfile(ctx context.Context, token string, uid int64) (fio, avatar string, err error) {
	var v struct {
		Users []struct {
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Avatar    string `json:"avatar"`
		} `json:"users"`
	}
	if err := c.get(ctx, token, "/users/"+strconv.FormatInt(uid, 10), nil, &v); err != nil {
		return "", "", err
	}
	if len(v.Users) == 0 {
		return "Stepik " + strconv.FormatInt(uid, 10), "", nil
	}
	u := v.Users[0]
	fio = (u.FirstName + " " + u.LastName)
	fio = string(bytes.TrimSpace([]byte(fio)))
	if fio == "" {
		fio = "Stepik " + strconv.FormatInt(uid, 10)
	}
	return fio, u.Avatar, nil
}

type classList struct {
	Classes []Class `json:"classes"`
	Meta    struct {
		HasNext bool `json:"has_next"`
		Page    int  `json:"page"`
	} `json:"meta"`
}

func (c *Client) listPages(ctx context.Context, token string, q url.Values) ([]Class, error) {
	var all []Class
	page := 1
	for {
		if page > MaxClassPages {
			c.log.Warn("stepik classes page cap hit", "pages", MaxClassPages, "total", len(all))
			break
		}
		qq := url.Values{}
		for k, vs := range q {
			qq[k] = vs
		}
		qq.Set("page", strconv.Itoa(page))
		var v classList
		if err := c.get(ctx, token, "/classes", qq, &v); err != nil {
			return nil, err
		}
		if len(v.Classes) == 0 {
			if v.Meta.HasNext {
				c.log.Warn("stepik classes empty page with has_next", "page", page, "total", len(all))
			}
			break
		}
		all = append(all, v.Classes...)
		if !v.Meta.HasNext {
			return all, nil
		}
		page++
	}
	return all, nil
}

func (c *Client) ListByStudent(ctx context.Context, token string, studentID int64) ([]Class, error) {
	q := url.Values{}
	q.Set("student", strconv.FormatInt(studentID, 10))
	return c.listPages(ctx, token, q)
}

func (c *Client) ListOwned(ctx context.Context, token string) ([]Class, error) {
	q := url.Values{}
	q.Set("owner_or_assistant", strconv.FormatInt(c.teacherID, 10))
	return c.listPages(ctx, token, q)
}

func (c *Client) GetClass(ctx context.Context, token string, cid int64) (Class, error) {
	var v struct {
		Classes []Class `json:"classes"`
	}
	if err := c.get(ctx, token, "/classes/"+strconv.FormatInt(cid, 10), nil, &v); err != nil {
		return Class{}, err
	}
	if len(v.Classes) == 0 {
		return Class{}, fmt.Errorf("class empty")
	}
	return v.Classes[0], nil
}

func (c *Client) granted(classes []Class, uid int64, path string) []Class {
	var out []Class
	for _, cl := range classes {
		if cl.Owner == c.teacherID {
			out = append(out, cl)
			c.log.Info("class decision", "uid", uid, "cid", cl.ID, "owner", cl.Owner, "decision", "allow", "auth_path", path)
			continue
		}
		c.log.Info("class decision", "uid", uid, "cid", cl.ID, "owner", cl.Owner, "decision", "deny", "auth_path", path)
	}
	return out
}

func VerifyStudent(ctx context.Context, c *Client, userToken, teacherToken string, teacherValid bool, uid int64) ([]Class, string, error) {
	mine, err := c.ListByStudent(ctx, userToken, uid)
	if err == nil {
		needDetail := false
		for _, cl := range mine {
			if cl.Owner == 0 {
				needDetail = true
				break
			}
		}
		if !needDetail {
			return c.granted(mine, uid, "B"), "B", nil
		}
		var resolved []Class
		for _, cl := range mine {
			if cl.Owner != 0 {
				resolved = append(resolved, cl)
				continue
			}
			full, derr := c.GetClass(ctx, userToken, cl.ID)
			if derr != nil {
				if IsTransient(derr) || IsUnauthorized(derr) {
					return nil, "B+detail", derr
				}
				c.log.Info("class decision", "uid", uid, "cid", cl.ID, "owner", 0, "decision", "deny", "auth_path", "B+detail")
				continue
			}
			resolved = append(resolved, full)
		}
		return c.granted(resolved, uid, "B+detail"), "B+detail", nil
	}
	if !IsTransient(err) {
		return nil, "deny", err
	}
	if !teacherValid {
		return nil, "A-expired", err
	}
	fallback, ferr := c.ListByStudent(ctx, teacherToken, uid)
	if ferr != nil {
		if IsTransient(ferr) {
			return nil, "transient", ferr
		}
		// Direct errors.As (not IsUnauthorized helper) is for Status extraction.
		var ue *UnauthorizedError
		if errors.As(ferr, &ue) {
			c.log.Warn("stepik teacher fallback", "uid", uid, "status", ue.Status, "auth_path", "A-teacher-fallback")
			return nil, "A-teacher-fallback", &TeacherFallbackError{Status: ue.Status, Err: ferr}
		}
		return nil, "deny", ferr
	}
	return c.granted(fallback, uid, "A-fallback"), "A-fallback", nil
}
