package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func TestCheck_adminStale200_withHeader(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "sid-admin-stale", true, 1182644732, []int64{82866})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, &stepik.TransientError{Status: 500}
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "/discuss/admin/panel", "sid-admin-stale"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 stale admin: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Gate-Stale") != "1" {
		t.Error("missing X-Gate-Stale: 1 on stale admin 200")
	}
	if w.Header().Get("X-JWT") == "" {
		t.Error("missing X-JWT on stale admin 200")
	}
}

func TestCheck_adminExpired401(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "sid-admin-exp", true, 1182644732, []int64{82866})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, &stepik.UnauthorizedError{Status: 401}
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "/discuss/admin/panel", "sid-admin-exp"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 expired admin: %s", w.Code, w.Body.String())
	}
	if body := decodeBody(t, w); body["error"] != "auth_required" {
		t.Errorf("error = %v, want auth_required", body["error"])
	}
	if w.Header().Get("X-JWT") != "" {
		t.Error("X-JWT must be absent on 401 expired admin")
	}
}

func TestCheck_adminTransient503(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	putSession(t, store, "sid-admin-tr", &sessions.SessionRecord{
		StepikUserID:    1182644732,
		IsTeacher:       true,
		AllowedClassIDs: []int64{82866},
		LastVerifiedAt:  now.Add(-49 * time.Hour),
		NextRetryAt:     now.Add(5 * time.Minute),
	})
	c := testChecker(store)
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, &stepik.TransientError{Status: 500}
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, checkReq("127.0.0.1:1", "/discuss/admin/panel", "sid-admin-tr"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 transient admin: %s", w.Code, w.Body.String())
	}
	if decodeBody(t, w)["error"] != "transient" {
		t.Errorf("error = %v, want transient", decodeBody(t, w)["error"])
	}
}
