package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func TestTeacherEmptyProbe_deadAnonMismatch302(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-anon-empty")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	// Live evidence: dead bearer degrades to 200-anonymous (uid 1390904444), not 401.
	s.checker.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	w := doHTML(t, s, "GET", "/", "teach-anon-empty")
	if w.Code != http.StatusFound {
		t.Fatalf("anon-mismatch status = %d, want 302", w.Code)
	}
	if got := nextOf(t, w.Header().Get("Location")); got != "/?relogin=1" {
		t.Errorf("next = %q, want /?relogin=1", got)
	}
	w2 := doHTML(t, s, "GET", "/?relogin=1", "teach-anon-empty")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("second-visit status = %d, want 401", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), RUExpired) {
		t.Error("body missing RUExpired")
	}
	got, err := store.GetSession("teach-anon-empty")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on probe-detected death)", got.NextRetryAt)
	}
}

func TestTeacherEmptyProbe_stepicsEmpty302(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-stepics-empty")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	s.checker.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, stepik.ErrEmptyStepics
	}
	w := doHTML(t, s, "GET", "/", "teach-stepics-empty")
	if w.Code != http.StatusFound {
		t.Fatalf("stepics-empty status = %d, want 302", w.Code)
	}
	if got := nextOf(t, w.Header().Get("Location")); got != "/?relogin=1" {
		t.Errorf("next = %q, want /?relogin=1", got)
	}
	got, err := store.GetSession("teach-stepics-empty")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on probe-detected death)", got.NextRetryAt)
	}
}

func TestTeacherEmptyProbe_transientStale200(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-probe-transient")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	s.checker.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.TransientError{Status: 500}
	}
	w := doHTML(t, s, "GET", "/", "teach-probe-transient")
	if w.Code != http.StatusOK {
		t.Fatalf("probe-transient status = %d, want 200 stale", w.Code)
	}
	if !strings.Contains(w.Body.String(), RUTransient) {
		t.Error("stale index missing RUTransient banner")
	}
	got, err := store.GetSession("teach-probe-transient")
	if err != nil {
		t.Fatal(err)
	}
	if got.NextRetryAt.IsZero() {
		t.Error("NextRetryAt must be armed on probe-transient stale")
	}
}
func TestTeacherEmptyProbe_deadTokenEmpty302(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-dead-empty")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	s.checker.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	w := doHTML(t, s, "GET", "/", "teach-dead-empty")
	if w.Code != http.StatusFound {
		t.Fatalf("dead-token-empty status = %d, want 302", w.Code)
	}
	if got := nextOf(t, w.Header().Get("Location")); got != "/?relogin=1" {
		t.Errorf("next = %q, want /?relogin=1", got)
	}
	w2 := doHTML(t, s, "GET", "/?relogin=1", "teach-dead-empty")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("second-visit status = %d, want 401", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), RUExpired) {
		t.Error("body missing RUExpired")
	}
	got, err := store.GetSession("teach-dead-empty")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on probe-detected death)", got.NextRetryAt)
	}
}
