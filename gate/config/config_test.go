package config

import (
	"os"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"STEPIK_CLIENT_ID", "STEPIK_CLIENT_SECRET", "STEPIK_REDIRECT_URL",
		"TEACHER_ID", "GATE_TOKEN_KEY", "REMARK_JWT_SECRET", "CADDY_GATE_TOKEN",
		"GATE_VERIFY_TTL", "GATE_RETRY_AFTER", "GATE_MAX_STALE",
		"SITE", "REMARK_URL", "GATE_ORIGIN", "GATE_DB_PATH",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func validEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GATE_TOKEN_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("REMARK_JWT_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("CADDY_GATE_TOKEN", "0123456789abcdef0123456789abcdef")
}

func TestLoad_defaults(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load = %v", err)
	}
	if c.TeacherID != 1182644732 {
		t.Errorf("TeacherID = %d, want 1182644732", c.TeacherID)
	}
	if c.Site != "stepik-discuss" {
		t.Errorf("Site = %q", c.Site)
	}
	if !c.Placeholder {
		t.Error("empty STEPIK_CLIENT_ID must set Placeholder=true")
	}
	if len(c.TokenKey) != 32 {
		t.Errorf("TokenKey len = %d, want 32", len(c.TokenKey))
	}
}

func TestLoad_placeholderVariants(t *testing.T) {
	for _, id := range []string{"", "placeholder"} {
		clearEnv(t)
		validEnv(t)
		if id != "" {
			t.Setenv("STEPIK_CLIENT_ID", id)
		}
		c, err := Load()
		if err != nil {
			t.Fatalf("id=%q: %v", id, err)
		}
		if !c.Placeholder {
			t.Errorf("id=%q: Placeholder=false, want true", id)
		}
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("STEPIK_CLIENT_ID", "real-id-123")
	t.Setenv("STEPIK_CLIENT_SECRET", "s")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Placeholder {
		t.Error("real client id must not be placeholder")
	}
}

func TestLoad_missingSecrets(t *testing.T) {
	clearEnv(t)
	if _, err := Load(); err == nil {
		t.Fatal("missing GATE_TOKEN_KEY accepted")
	}
	clearEnv(t)
	t.Setenv("GATE_TOKEN_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if _, err := Load(); err == nil {
		t.Fatal("missing REMARK_JWT_SECRET accepted")
	}
	clearEnv(t)
	t.Setenv("GATE_TOKEN_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("REMARK_JWT_SECRET", "x")
	if _, err := Load(); err == nil {
		t.Fatal("missing CADDY_GATE_TOKEN accepted")
	}
}

func TestLoad_badTokenKey(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	t.Setenv("GATE_TOKEN_KEY", "zzzz")
	if _, err := Load(); err == nil {
		t.Fatal("non-hex GATE_TOKEN_KEY accepted")
	}
	t.Setenv("GATE_TOKEN_KEY", "abcd")
	if _, err := Load(); err == nil {
		t.Fatal("short GATE_TOKEN_KEY accepted")
	}
}

func TestLoad_badTeacherID(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	t.Setenv("TEACHER_ID", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("non-numeric TEACHER_ID accepted")
	}
}

func TestLoad_badDuration(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	t.Setenv("GATE_VERIFY_TTL", "bogus")
	if _, err := Load(); err == nil {
		t.Fatal("bad GATE_VERIFY_TTL accepted")
	}
}

func TestLoad_weakSecrets(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	t.Setenv("REMARK_JWT_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Fatal("short REMARK_JWT_SECRET accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("CADDY_GATE_TOKEN", "not-hex!!")
	if _, err := Load(); err == nil {
		t.Fatal("non-hex CADDY_GATE_TOKEN accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("CADDY_GATE_TOKEN", "abcd")
	if _, err := Load(); err == nil {
		t.Fatal("short CADDY_GATE_TOKEN accepted")
	}
}
