package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSW_bundle(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/sw.js", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("sw.js status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("sw.js Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("sw.js Cache-Control = %q", cc)
	}
	body := w.Body.String()
	for _, want := range []string{
		"urlBase64ToUint8Array",
		`STATIC_CACHE = "static-" + REV`,
		`caches.open(STATIC_CACHE)`,
		`startsWith("/class/")`,
		`focus()`,
		`navigate(url)`,
		`userVisibleOnly`,
		`showNotification`,
		`pushsubscriptionchange`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sw.js missing %q", want)
		}
	}
	for _, banned := range []string{
		"localStorage",
		"document.cookie",
		"caches.add('/')",
		`caches.add("/class`,
		"/auth/",
		"/discuss/",
		"/manifest.json",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("sw.js contains banned %q", banned)
		}
	}
	if !strings.Contains(body, `REV = "test-rev"`) {
		t.Errorf("sw.js REV not injected via %%q, body=%.200s", body)
	}
}

func TestSW_staticAssets200(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	mux := s.Routes()
	assets := map[string]string{
		"/static/style.css":              "text/css; charset=utf-8",
		"/static/push.js":                "application/javascript; charset=utf-8",
		"/static/icon-192.png":           "image/png",
		"/static/icon-512.png":           "image/png",
		"/static/icon-512-maskable.png":  "image/png",
		"/static/apple-touch-icon.png":   "image/png",
		"/static/favicon.svg":            "image/svg+xml",
		"/favicon.ico":                   "image/x-icon",
		"/offline.html":                  "text/html; charset=utf-8",
	}
	for path, wantCT := range assets {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200", path, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); ct != wantCT {
			t.Errorf("%s Content-Type = %q, want %q", path, ct, wantCT)
		}
		if w.Body.Len() == 0 {
			t.Errorf("%s empty body", path)
		}
	}
}

func TestManifest_full(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/manifest.json", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest status = %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		`"id":"/"`,
		`"start_url":"/?source=pwa"`,
		`"scope":"/"`,
		`"display":"standalone"`,
		`"orientation":"portrait-primary"`,
		`"lang":"ru"`,
		`"dir":"ltr"`,
		`"categories"`,
		`"education"`,
		`/static/icon-192.png`,
		`/static/icon-512.png`,
		`/static/icon-512-maskable.png`,
		`"purpose":"any"`,
		`"purpose":"maskable"`,
	} {
		compact := strings.ReplaceAll(body, " ", "")
		compact = strings.ReplaceAll(compact, "\n", "")
		if !strings.Contains(compact, strings.ReplaceAll(want, " ", "")) {
			t.Errorf("manifest missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "any maskable") {
		t.Errorf("manifest contains combined any maskable, want split")
	}
}

func TestOffline_public(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/offline.html", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("offline status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("offline Content-Type = %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public,max-age=3600" {
		t.Errorf("offline Cache-Control = %q", cc)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Нет соединения") {
		t.Errorf("offline missing RU shell")
	}
	if strings.Contains(body, "{{.FIO}}") || strings.Contains(body, "{{") {
		t.Errorf("offline contains template leak")
	}
}

func TestVapidKey_401anon(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	r := httptest.NewRequest("GET", "/push/vapid-key", nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("vapid-key anon = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "auth_required") {
		t.Errorf("vapid-key anon body missing auth_required: %s", w.Body.String())
	}
}

func TestPush_wrongMethod405(t *testing.T) {
	s, _ := testServer(t, baseCfg())
	for _, p := range []string{"/push/subscribe", "/push/unsubscribe", "/push/resubscribe", "/push/webhook"} {
		r := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		s.Routes().ServeHTTP(w, r)
		if p == "/push/webhook" {
			if w.Code != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", p, w.Code)
			}
			continue
		}
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", p, w.Code)
		}
	}
}
