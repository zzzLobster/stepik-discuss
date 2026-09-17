package config

import (
	"encoding/hex"
	"errors"
	"os"
	"strconv"
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
	c.Site = getenv("SITE", DefaultSite)
	c.RemarkURL = getenv("REMARK_URL", DefaultRemarkURL)
	c.Origin = getenv("GATE_ORIGIN", DefaultOrigin)
	c.DBPath = getenv("GATE_DB_PATH", "/data/gate.db")
	return c, nil
}

func parseDuration(key, fallback string) (time.Duration, error) {
	d, err := time.ParseDuration(getenv(key, fallback))
	if err != nil {
		return 0, errors.New(key + " must be a Go duration")
	}
	return d, nil
}
