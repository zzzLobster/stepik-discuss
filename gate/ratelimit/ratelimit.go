package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type visitor struct {
	lim  *rate.Limiter
	last time.Time
}

type Store struct {
	mu       sync.Mutex
	login    map[string]*visitor
	callback map[string]*visitor
	discuss  map[string]*visitor
	check    map[string]*visitor
	push     map[string]*visitor
	pushIP   map[string]*visitor
}

func NewStore() *Store {
	return &Store{
		login:    map[string]*visitor{},
		callback: map[string]*visitor{},
		discuss:  map[string]*visitor{},
		check:    map[string]*visitor{},
		push:     map[string]*visitor{},
		pushIP:   map[string]*visitor{},
	}
}

// trustedPeer reports whether r arrived via local/docker-private proxy (Caddy).
// Gate trusts CF-Connecting-IP only from such peers (see ClientIP).
// Defence in depth: Caddy overwrites CF-Connecting-IP with the trusted
// restored client IP ({client_ip}), which comes from trusted_proxies parsing
// X-Forwarded-For for Cloudflare traffic and falls back to the direct TCP
// peer for non-trusted sources, so a direct-to-origin attacker cannot forge
// the header. Still lock the origin firewall to Cloudflare ranges
// (ufw: 22,80,443); plan §5.3 trusted_proxies = Cloudflare ranges + docker
// private_ranges.
func trustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func ClientIP(r *http.Request) string {
	if trustedPeer(r) {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			return cf
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Store) allow(m map[string]*visitor, key string, every time.Duration, burst int) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range m {
		if now.Sub(v.last) > 3*time.Minute {
			delete(m, k)
		}
	}
	v, ok := m[key]
	if !ok {
		v = &visitor{lim: rate.NewLimiter(rate.Every(every), burst)}
		m[key] = v
	}
	v.last = now
	res := v.lim.ReserveN(now, 1)
	if d := res.DelayFrom(now); d > 0 {
		res.Cancel()
		secs := d.Truncate(time.Second)
		if d > secs {
			secs += time.Second
		}
		if secs < time.Second {
			secs = time.Second
		}
		return false, secs
	}
	return true, 0
}

func (s *Store) AllowLogin(ip string) bool {
	ok, _ := s.allow(s.login, ip, 6*time.Second, 5)
	return ok
}

func (s *Store) AllowCallback(ip string) bool {
	ok, _ := s.allow(s.callback, ip, 3*time.Second, 10)
	return ok
}

func (s *Store) AllowDiscuss(sid string) (bool, time.Duration) {
	return s.allow(s.discuss, sid, 600*time.Millisecond, 20)
}

// AllowCheckByIP is the pre-auth limiter for /auth/check: per-IP gate
// before any session load, so unknown-SID floods cannot fan out to Bolt.
func (s *Store) AllowCheckByIP(ip string) (bool, time.Duration) {
	return s.allow(s.check, ip, 300*time.Millisecond, 30)
}

// AllowPush is the per-sid limiter for push routes after auth.
func (s *Store) AllowPush(sid string) (bool, time.Duration) {
	return s.allow(s.push, sid, 3*time.Second, 20)
}

// AllowPushByIP is the pre-auth per-IP limiter for all /push/* incl. shallow health.
func (s *Store) AllowPushByIP(ip string) (bool, time.Duration) {
	return s.allow(s.pushIP, ip, time.Second, 30)
}

func Outbound() *rate.Limiter {
	return rate.NewLimiter(4, 8)
}
