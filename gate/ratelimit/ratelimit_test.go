package ratelimit

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestClientIP_precedence(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		remote  string
		want    string
	}{
		{"cf_trusted_peer", map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"}, "127.0.0.1:1", "1.2.3.4"},
		{"xff_ignored_trusted_peer", map[string]string{"X-Forwarded-For": "5.6.7.8, 9.9.9.9"}, "10.0.0.1:1", "10.0.0.1"},
		{"spoof_ignored_public_peer", map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"}, "9.9.9.9:1", "9.9.9.9"},
		{"remote_addr_host", map[string]string{}, "10.0.0.5:443", "10.0.0.5"},
		{"remote_addr_bare", map[string]string{}, "10.0.0.6", "10.0.0.6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			r.RemoteAddr = tc.remote
			if got := ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAllowLogin_10perMinBurst5(t *testing.T) {
	s := NewStore()
	ip := "1.2.3.4"
	allowed := 0
	for range 5 {
		if s.AllowLogin(ip) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("burst: allowed %d, want 5", allowed)
	}
	if s.AllowLogin(ip) {
		t.Fatal("6th immediate login allowed, want rate-limited (burst 5)")
	}
}

func TestAllowCallback_20perMinBurst10(t *testing.T) {
	s := NewStore()
	ip := "5.6.7.8"
	allowed := 0
	for range 10 {
		if s.AllowCallback(ip) {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("burst: allowed %d, want 10", allowed)
	}
	if s.AllowCallback(ip) {
		t.Fatal("11th immediate callback allowed, want rate-limited (burst 10)")
	}
}

func TestAllowDiscuss_100perMinBurst20(t *testing.T) {
	s := NewStore()
	sid := "sid-test-123"
	allowed := 0
	for range 20 {
		ok, _ := s.AllowDiscuss(sid)
		if ok {
			allowed++
		}
	}
	if allowed != 20 {
		t.Fatalf("burst: allowed %d, want 20", allowed)
	}
	ok, retryAfter := s.AllowDiscuss(sid)
	if ok {
		t.Fatal("21st immediate discuss allowed, want 429 (burst 20)")
	}
	if retryAfter < time.Second {
		t.Errorf("Retry-After = %v, want >= 1s", retryAfter)
	}
}

func TestAllowDiscuss_perSessionIsolation(t *testing.T) {
	s := NewStore()
	for range 20 {
		_, _ = s.AllowDiscuss("sid-a")
	}
	ok, _ := s.AllowDiscuss("sid-b")
	if !ok {
		t.Fatal("fresh sid-b denied while sid-a exhausted: buckets must be per-session")
	}
}

func TestOutbound_4perSecBurst8(t *testing.T) {
	lim := Outbound()
	if lim.Limit() != rate.Limit(4) {
		t.Errorf("outbound rate = %v, want 4/s", lim.Limit())
	}
	if lim.Burst() != 8 {
		t.Errorf("outbound burst = %d, want 8", lim.Burst())
	}
	allowed := 0
	for range 8 {
		if lim.Allow() {
			allowed++
		}
	}
	if allowed != 8 {
		t.Errorf("outbound burst allowed %d, want 8", allowed)
	}
	if lim.Allow() {
		t.Fatal("9th immediate outbound allowed, want throttled")
	}
}
