package config

import (
	"strings"
	"testing"
)

func TestVapidFP8(t *testing.T) {
	pub := "B" + strings.Repeat("A", 86)
	fp := VapidFP8(pub)
	if len(fp) != 8 {
		t.Fatalf("fp len = %d", len(fp))
	}
	if fp != VapidFP8(pub) {
		t.Error("non-deterministic")
	}
}

func TestCanonicalOrigin(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	t.Setenv("GATE_ORIGIN", "https://stepik.study67.fyi/")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Origin != "https://stepik.study67.fyi" {
		t.Errorf("Origin = %q", c.Origin)
	}
	if c.CanonicalOrigin() != "https://stepik.study67.fyi" {
		t.Errorf("CanonicalOrigin = %q", c.CanonicalOrigin())
	}
	if c.ClassBase() != "https://stepik.study67.fyi/class/" {
		t.Errorf("ClassBase = %q", c.ClassBase())
	}
}

func TestLoad_vapid(t *testing.T) {
	clearEnv(t)
	validEnv(t)
	if _, err := Load(); err != nil {
		t.Fatalf("valid vapid rejected: %v", err)
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("VAPID_PUBLIC_KEY", "short")
	if _, err := Load(); err == nil {
		t.Fatal("bad public accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("VAPID_SUBJECT", "bare@example.com")
	if _, err := Load(); err == nil {
		t.Fatal("bare subject accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("PUSH_WEBHOOK_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Fatal("short webhook secret accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("PUSH_WEBHOOK_SECRET", strings.Repeat("zz", 32))
	if _, err := Load(); err == nil {
		t.Fatal("non-hex webhook secret accepted")
	}
	clearEnv(t)
	validEnv(t)
	t.Setenv("VAPID_PUBLIC_KEY_OLD", "bad")
	if _, err := Load(); err == nil {
		t.Fatal("bad OLD accepted")
	}
}
