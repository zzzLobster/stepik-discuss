package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTeacherID   int64  = 1182644732
	DefaultSite        string = "stepik-discuss"
	DefaultRemarkURL   string = "https://stepik.study67.fyi/discuss"
	DefaultRedirectURL string = "https://stepik.study67.fyi/auth/callback"
	DefaultOrigin      string = "https://stepik.study67.fyi"
	ClassBaseURL       string = "https://stepik.study67.fyi/class/"
	SiteHost           string = "stepik.study67.fyi"
)

type Config struct {
	StepikClientID     string
	StepikClientSecret string
	StepikRedirectURL  string
	Placeholder        bool
	TeacherID          int64
	TokenKey           []byte
	RemarkJWTSecret    string
	GateToken          string
	VerifyTTL          time.Duration
	RetryAfter         time.Duration
	MaxStale           time.Duration
	Site               string
	RemarkURL          string
	Origin             string
	DBPath             string
	VapidPublicKey     string
	VapidPrivateKey    string
	VapidPublicKeyOld  string
	VapidSubject       string
	PushWebhookSecret  string
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	var c Config
	c.StepikClientID = os.Getenv("STEPIK_CLIENT_ID")
	c.StepikClientSecret = os.Getenv("STEPIK_CLIENT_SECRET")
	c.StepikRedirectURL = getenv("STEPIK_REDIRECT_URL", DefaultRedirectURL)
	if c.StepikClientID == "" || c.StepikClientID == "placeholder" {
		c.Placeholder = true
	}
	teacherID := getenv("TEACHER_ID", strconv.FormatInt(DefaultTeacherID, 10))
	tid, err := strconv.ParseInt(teacherID, 10, 64)
	if err != nil {
		return Config{}, errors.New("TEACHER_ID must be an integer")
	}
	c.TeacherID = tid
	rawKey := os.Getenv("GATE_TOKEN_KEY")
	if rawKey == "" {
		return Config{}, errors.New("GATE_TOKEN_KEY is required (32 bytes hex from VPS .env)")
	}
	key, err := hex.DecodeString(rawKey)
	if err != nil {
		return Config{}, errors.New("GATE_TOKEN_KEY must be hex")
	}
	if len(key) != 32 {
		return Config{}, errors.New("GATE_TOKEN_KEY must decode to 32 bytes")
	}
	c.TokenKey = key
	c.RemarkJWTSecret = os.Getenv("REMARK_JWT_SECRET")
	if len(c.RemarkJWTSecret) < 32 {
		return Config{}, errors.New("REMARK_JWT_SECRET must be at least 32 chars")
	}
	c.GateToken = os.Getenv("CADDY_GATE_TOKEN")
	rawGate, err := hex.DecodeString(c.GateToken)
	if err != nil {
		return Config{}, errors.New("CADDY_GATE_TOKEN must be hex")
	}
	if len(rawGate) != 16 {
		return Config{}, errors.New("CADDY_GATE_TOKEN must decode to 16 bytes")
	}
	c.VerifyTTL, err = parseDuration("GATE_VERIFY_TTL", "6h")
	if err != nil {
		return Config{}, err
	}
	c.RetryAfter, err = parseDuration("GATE_RETRY_AFTER", "15m")
	if err != nil {
		return Config{}, err
	}
	c.MaxStale, err = parseDuration("GATE_MAX_STALE", "48h")
	if err != nil {
		return Config{}, err
	}
	if c.RetryAfter > c.MaxStale {
		return Config{}, errors.New("GATE_RETRY_AFTER must be <= GATE_MAX_STALE")
	}
	c.Site = getenv("SITE", DefaultSite)
	c.RemarkURL = getenv("REMARK_URL", DefaultRemarkURL)
	c.Origin = getenv("GATE_ORIGIN", DefaultOrigin)
	if strings.TrimSpace(c.Origin) == "" {
		return Config{}, errors.New("GATE_ORIGIN must be an absolute URL")
	}
	if u, err := url.Parse(c.Origin); err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, errors.New("GATE_ORIGIN must be an absolute URL")
	}
	c.Origin = strings.TrimSuffix(c.Origin, "/")
	if c.ClassBase() == "" {
		return Config{}, errors.New("GATE_ORIGIN must be an absolute URL")
	}
	c.VapidPublicKey = os.Getenv("VAPID_PUBLIC_KEY")
	c.VapidPrivateKey = os.Getenv("VAPID_PRIVATE_KEY")
	c.VapidPublicKeyOld = os.Getenv("VAPID_PUBLIC_KEY_OLD")
	c.VapidSubject = os.Getenv("VAPID_SUBJECT")
	c.PushWebhookSecret = os.Getenv("PUSH_WEBHOOK_SECRET")
	if c.VapidPublicKey == "" {
		return Config{}, errors.New("VAPID_PUBLIC_KEY is required")
	}
	if c.VapidPrivateKey == "" {
		return Config{}, errors.New("VAPID_PRIVATE_KEY is required")
	}
	if c.VapidSubject == "" {
		return Config{}, errors.New("VAPID_SUBJECT is required")
	}
	if c.PushWebhookSecret == "" {
		return Config{}, errors.New("PUSH_WEBHOOK_SECRET is required")
	}
	if err := validateVAPIDKeys(c.VapidPublicKey, c.VapidPrivateKey); err != nil {
		return Config{}, err
	}
	if c.VapidPublicKeyOld != "" {
		raw, err := base64.RawURLEncoding.DecodeString(c.VapidPublicKeyOld)
		if err != nil || len(raw) != 65 || raw[0] != 0x04 {
			return Config{}, errors.New("VAPID_PUBLIC_KEY_OLD must be base64url 65B uncompressed 0x04")
		}
	}
	// webpush-go prepends "mailto:" unless the value starts with "https:"
	// (module source: vapid.go getVAPIDAuthorizationHeader), so store bare
	// email — a stored "mailto:" prefix would double to
	// "mailto:mailto:..." in the JWT sub claim (Apple rejects with 403,
	// FCM/Mozilla are lenient). Fail fast on the prefixed form.
	switch {
	case strings.HasPrefix(c.VapidSubject, "mailto:"):
		return Config{}, errors.New("VAPID_SUBJECT must be bare email (webpush-go prepends mailto:) or https:// URL")
	case strings.HasPrefix(c.VapidSubject, "https://"):
	default:
		if !strings.Contains(c.VapidSubject, "@") || strings.Contains(c.VapidSubject, "://") || strings.ContainsAny(c.VapidSubject, " \t\r\n") {
			return Config{}, errors.New("VAPID_SUBJECT must be bare email or https:// URL")
		}
	}
	if len(c.PushWebhookSecret) != 64 {
		return Config{}, errors.New("PUSH_WEBHOOK_SECRET must be 64 hex chars")
	}
	if _, err := hex.DecodeString(c.PushWebhookSecret); err != nil {
		return Config{}, errors.New("PUSH_WEBHOOK_SECRET must be hex")
	}
	c.DBPath = getenv("GATE_DB_PATH", "/data/gate.db")
	return c, nil
}

func parseDuration(key, fallback string) (time.Duration, error) {
	d, err := time.ParseDuration(getenv(key, fallback))
	if err != nil {
		return 0, errors.New(key + " must be a Go duration")
	}
	if d <= 0 {
		return 0, errors.New(key + " must be > 0")
	}
	return d, nil
}

// ClassBase returns the canonical class page base derived from Origin.
// Single source for page URLs rendered by handlers and parsed by
// auth.ExtractCIDWithBase; the ClassBaseURL const remains the default only.
func (c Config) ClassBase() string {
	return strings.TrimSuffix(c.Origin, "/") + "/class/"
}

// CanonicalOrigin returns Origin without trailing slash for exact Origin matching.
func (c Config) CanonicalOrigin() string {
	return strings.TrimSuffix(c.Origin, "/")
}

// VapidFP8 returns fp8 hex (8 chars) = hex(sha256(public base64url string))[:8].
func VapidFP8(public string) string {
	sum := sha256.Sum256([]byte(public))
	return hex.EncodeToString(sum[:])[:8]
}

func validateVAPIDKeys(public, private string) error {
	pubRaw, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil {
		return errors.New("VAPID_PUBLIC_KEY must be base64url")
	}
	if len(pubRaw) != 65 || pubRaw[0] != 0x04 {
		return errors.New("VAPID_PUBLIC_KEY must decode to 65B uncompressed 0x04")
	}
	privRaw, err := base64.RawURLEncoding.DecodeString(private)
	if err != nil {
		return errors.New("VAPID_PRIVATE_KEY must be base64url")
	}
	if len(privRaw) != 32 {
		return errors.New("VAPID_PRIVATE_KEY must decode to 32B")
	}
	return nil
}

// EmbedHost returns the normalized RemarkURL (keeps the /discuss base path
// required by templates as {{.EmbedHost}}/web/embed.js). Falls back to
// DefaultRemarkURL when RemarkURL is unset or unparsable. Query and fragment
// are stripped; trailing slash is trimmed.
// Note: auth.ExtractCIDWithConfig matches against ClassBase() above; the
// iframe unwrap uses EmbedHost() so custom REMARK_URL values are honored.
func (c Config) EmbedHost() string {
	raw := c.RemarkURL
	if raw == "" {
		return DefaultRemarkURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return DefaultRemarkURL
	}
	return u.Scheme + "://" + u.Host + strings.TrimSuffix(u.Path, "/")
}

// AdminSharedID is the remark42 admin identifier for the teacher.
func (c Config) AdminSharedID() string {
	return "stepik_" + strconv.FormatInt(c.TeacherID, 10)
}
