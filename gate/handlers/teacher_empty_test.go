package handlers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func putTeacherEmptyFresh(t *testing.T, store *sessions.Store, sid string) {
	t.Helper()
	ct, nonce, err := store.EncryptToken("teacher-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSess(t, store, sid, &sessions.SessionRecord{
		StepikUserID:    baseCfg().TeacherID,
		FIO:             "Преподаватель",
		IsTeacher:       true,
		AllowedClassIDs: []int64{},
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now,
		LastSeenAt:      now,
	})
}

func TestTeacherEmptyFresh_repairsToList(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-repair")
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return []stepik.Class{{ID: 82866, Title: "2025-26"}}, nil
	}
	w := doHTML(t, s, "GET", "/", "teach-repair")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after repair", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/class/82866") {
		t.Errorf("repaired index missing class card: %s", w.Body.String())
	}
	if calls != 1 {
		t.Fatalf("stepik calls = %d, want 1", calls)
	}
	got, err := store.GetSession("teach-repair")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedClassIDs) != 1 || got.AllowedClassIDs[0] != 82866 {
		t.Errorf("persisted classes = %v, want [82866]", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v after non-empty success, want zero", got.NextRetryAt)
	}
	// Second hit keeps lazy TTL: no further Stepik call.
	w2 := doHTML(t, s, "GET", "/", "teach-repair")
	if w2.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", w2.Code)
	}
	if calls != 1 {
		t.Errorf("stepik calls after second hit = %d, want 1 (lazy TTL)", calls)
	}
}

func TestTeacherEmptyFresh_genuineEmptyBackoffSingleAttempt(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-empty")
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return nil, nil
	}
	w1 := doHTML(t, s, "GET", "/", "teach-empty")
	if w1.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", w1.Code)
	}
	if strings.Contains(w1.Body.String(), "/class/") {
		t.Errorf("genuinely-empty index must not list classes: %s", w1.Body.String())
	}
	w2 := doHTML(t, s, "GET", "/", "teach-empty")
	if w2.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", w2.Code)
	}
	if calls != 1 {
		t.Errorf("stepik calls after two rapid hits = %d, want exactly 1 (NextRetryAt gate)", calls)
	}
	got, err := store.GetSession("teach-empty")
	if err != nil {
		t.Fatal(err)
	}
	if got.NextRetryAt.IsZero() || time.Now().After(got.NextRetryAt) {
		t.Errorf("NextRetryAt = %v, want future backoff after genuine-empty", got.NextRetryAt)
	}
}

func TestTeacherEmptyFresh_expiredTaxonomy(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-exp")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, &stepik.UnauthorizedError{Status: 401}
	}
	w := doHTML(t, s, "GET", "/", "teach-exp")
	if w.Code != http.StatusFound {
		t.Fatalf("expired first-visit status = %d, want 302", w.Code)
	}
	if got := nextOf(t, w.Header().Get("Location")); got != "/?relogin=1" {
		t.Errorf("next = %q, want /?relogin=1", got)
	}
	w2 := doHTML(t, s, "GET", "/?relogin=1", "teach-exp")
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expired second-visit status = %d, want 401", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), RUExpired) {
		t.Errorf("body missing RUExpired")
	}
}

func TestTeacherEmptyFresh_transientStaleTaxonomy(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putTeacherEmptyFresh(t, store, "teach-tr")
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, &stepik.TransientError{Status: 500}
	}
	w := doHTML(t, s, "GET", "/", "teach-tr")
	if w.Code != http.StatusOK {
		t.Fatalf("transient status = %d, want 200 stale", w.Code)
	}
	if !strings.Contains(w.Body.String(), RUTransient) {
		t.Errorf("stale index missing RUTransient banner")
	}
	got, err := store.GetSession("teach-tr")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedClassIDs) != 0 {
		t.Errorf("transient must not persist classes, got %v", got.AllowedClassIDs)
	}
	if got.NextRetryAt.IsZero() {
		t.Errorf("transient must arm NextRetryAt backoff")
	}
}

func TestTeacherEmptyFresh_nonEmptyKeepsLazyTTL(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "teach-full", &sessions.SessionRecord{
		StepikUserID:    baseCfg().TeacherID,
		IsTeacher:       true,
		AllowedClassIDs: []int64{82866},
		ClassTitles:     map[string]string{"82866": "2025-26"},
	})
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return []stepik.Class{{ID: 82866, Title: "2025-26"}}, nil
	}
	w := doHTML(t, s, "GET", "/", "teach-full")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if calls != 0 {
		t.Errorf("fresh non-empty teacher must not call Stepik, calls = %d", calls)
	}
}

func TestTeacherEmptyFresh_ttlExpiredEmptySingleCall(t *testing.T) {
	s, store := testServer(t, baseCfg())
	ct, nonce, err := store.EncryptToken("teacher-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSess(t, store, "teach-ttl-empty", &sessions.SessionRecord{
		StepikUserID:    baseCfg().TeacherID,
		FIO:             "Преподаватель",
		IsTeacher:       true,
		AllowedClassIDs: []int64{},
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now.Add(-7 * time.Hour),
		LastSeenAt:      now.Add(-7 * time.Hour),
	})
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return nil, nil
	}
	w := doHTML(t, s, "GET", "/", "teach-ttl-empty")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if calls != 1 {
		t.Fatalf("stepik calls = %d, want exactly 1 for TTL-expired empty teacher in a single request", calls)
	}
	got, err := store.GetSession("teach-ttl-empty")
	if err != nil {
		t.Fatal(err)
	}
	if got.NextRetryAt.IsZero() || time.Now().After(got.NextRetryAt) {
		t.Errorf("NextRetryAt = %v, want future backoff after genuinely-empty refresh", got.NextRetryAt)
	}
}

func TestTeacherEmptyFresh_gatedForceKeepsStaleBanner(t *testing.T) {
	s, store := testServer(t, baseCfg())
	ct, nonce, err := store.EncryptToken("teacher-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSess(t, store, "teach-gated", &sessions.SessionRecord{
		StepikUserID:    baseCfg().TeacherID,
		FIO:             "Преподаватель",
		IsTeacher:       true,
		AllowedClassIDs: []int64{},
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now,
		LastSeenAt:      now,
		NextRetryAt:     now.Add(5 * time.Minute),
	})
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return nil, nil
	}
	w := doHTML(t, s, "GET", "/", "teach-gated")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if calls != 0 {
		t.Fatalf("stepik calls = %d, want 0 while gated by NextRetryAt", calls)
	}
	if !strings.Contains(w.Body.String(), RUTransient) {
		t.Errorf("gated forced empty must keep stale RUTransient banner instead of flickering to fresh-empty")
	}
}

func TestTeacherEmptyFresh_studentEmptyNeverForces(t *testing.T) {
	s, store := testServer(t, baseCfg())
	putSess(t, store, "stud-empty", &sessions.SessionRecord{
		StepikUserID: 2, AllowedClassIDs: []int64{},
	})
	calls := 0
	s.checker.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		calls++
		return []stepik.Class{{ID: 82866, Title: "2025-26"}}, nil
	}
	w := doHTML(t, s, "GET", "/", "stud-empty")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if calls != 0 {
		t.Errorf("student empty must never force Stepik, calls = %d", calls)
	}
	wc := doHTML(t, s, "GET", "/class/82866", "stud-empty")
	if wc.Code != http.StatusForbidden {
		t.Fatalf("class status = %d, want 403 outsider", wc.Code)
	}
	if !strings.Contains(wc.Body.String(), RUOutsider) {
		t.Errorf("body missing RUOutsider")
	}
}
