package stepik

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func refreshServer(t *testing.T, h http.HandlerFunc) (*Client, *int) {
	t.Helper()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := &Client{
		http:      srv.Client(),
		out:       rate.NewLimiter(1000, 1000),
		teacherID: 1182644732,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		TokenURL:  srv.URL,
	}
	return c, &hits
}

func writeTokenJSON(w http.ResponseWriter, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestExchangeCode_triple(t *testing.T) {
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q, want authorization_code", r.PostForm.Get("grant_type"))
		}
		writeTokenJSON(w, map[string]any{
			"access_token":  "a1",
			"refresh_token": "r1",
			"expires_in":    3600,
			"token_type":    "Bearer",
		})
	})
	before := time.Now()
	access, refresh, expires, err := c.ExchangeCode(context.Background(), "id", "secret", "https://x/cb", "code1")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if access != "a1" || refresh != "r1" {
		t.Errorf("access = %q, refresh = %q; want a1, r1", access, refresh)
	}
	if d := expires.Sub(before); d < 3500*time.Second || d > 3700*time.Second {
		t.Errorf("expires in %v, want ~3600s", d)
	}
}

func TestExchangeCode_omittedRefresh(t *testing.T) {
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeTokenJSON(w, map[string]any{
			"access_token": "a1",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	access, refresh, _, err := c.ExchangeCode(context.Background(), "id", "secret", "https://x/cb", "code1")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if access != "a1" {
		t.Errorf("access = %q, want a1", access)
	}
	if refresh != "" {
		t.Errorf("refresh = %q, want empty when endpoint omits it", refresh)
	}
}

func TestExchangeCode_omittedExpiryFallback(t *testing.T) {
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeTokenJSON(w, map[string]any{
			"access_token":  "a1",
			"refresh_token": "r1",
			"token_type":    "Bearer",
		})
	})
	before := time.Now()
	_, _, expires, err := c.ExchangeCode(context.Background(), "id", "secret", "https://x/cb", "code1")
	if err != nil {
		t.Fatalf("ExchangeCode = %v", err)
	}
	if d := expires.Sub(before); d < 35600*time.Second || d > 35800*time.Second {
		t.Errorf("expires in %v, want ~35700s fallback", d)
	}
}

func TestRedeem_rotation(t *testing.T) {
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("refresh_token") != "r-old" {
			t.Errorf("refresh_token = %q, want r-old", r.PostForm.Get("refresh_token"))
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "cid" || p != "csecret" {
			t.Errorf("basic auth = %q %q, want cid csecret", u, p)
		}
		writeTokenJSON(w, map[string]any{
			"access_token":  "a-new",
			"refresh_token": "r-new",
			"expires_in":    7200,
		})
	})
	before := time.Now()
	access, refreshOut, expires, err := c.RedeemRefresh(context.Background(), "cid", "csecret", "r-old")
	if err != nil {
		t.Fatalf("RedeemRefresh = %v", err)
	}
	if access != "a-new" || refreshOut != "r-new" {
		t.Errorf("access = %q, refreshOut = %q; want a-new, r-new", access, refreshOut)
	}
	if d := expires.Sub(before); d < 7100*time.Second || d > 7300*time.Second {
		t.Errorf("expires in %v, want ~7200s", d)
	}
}

func TestRedeem_noRotation(t *testing.T) {
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeTokenJSON(w, map[string]any{"access_token": "a-new", "expires_in": 3600})
	})
	access, refreshOut, _, err := c.RedeemRefresh(context.Background(), "cid", "csecret", "r-old")
	if err != nil {
		t.Fatalf("RedeemRefresh = %v", err)
	}
	if access != "a-new" {
		t.Errorf("access = %q, want a-new", access)
	}
	if refreshOut != "" {
		t.Errorf("refreshOut = %q, want empty (retain old)", refreshOut)
	}
}

func TestRedeem_invalidGrantNoRetry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   map[string]any
	}{
		{"invalid_grant", 400, map[string]any{"error": "invalid_grant"}},
		{"bare_400", 400, map[string]any{}},
		{"bare_401", 401, map[string]any{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, hits := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				writeTokenJSON(w, tc.body)
			})
			_, _, _, err := c.RedeemRefresh(context.Background(), "cid", "csecret", "r-old")
			if err == nil || !IsUnauthorized(err) {
				t.Errorf("err = %v, want UnauthorizedError", err)
			}
			if *hits != 1 {
				t.Errorf("hits = %d, want 1 (no retry on dead refresh)", *hits)
			}
		})
	}
}

func TestRedeem_transientRetry(t *testing.T) {
	var n int
	c, _ := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(500)
			writeTokenJSON(w, map[string]any{})
			return
		}
		writeTokenJSON(w, map[string]any{"access_token": "a-new", "expires_in": 3600})
	})
	access, _, _, err := c.RedeemRefresh(context.Background(), "cid", "csecret", "r-old")
	if err != nil {
		t.Fatalf("RedeemRefresh = %v", err)
	}
	if access != "a-new" {
		t.Errorf("access = %q, want a-new after retry", access)
	}
	if n != 2 {
		t.Errorf("hits = %d, want 2 (one retry on 5xx)", n)
	}
}

func TestRedeem_other4xxPlain(t *testing.T) {
	c, hits := refreshServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		writeTokenJSON(w, map[string]any{"error": "forbidden"})
	})
	_, _, _, err := c.RedeemRefresh(context.Background(), "cid", "csecret", "r-old")
	if err == nil {
		t.Fatal("want plain error on 403")
	}
	if IsUnauthorized(err) || IsTransient(err) {
		t.Errorf("err = %v, want plain non-retryable error", err)
	}
	if *hits != 1 {
		t.Errorf("hits = %d, want 1 (no retry on other 4xx)", *hits)
	}
}
