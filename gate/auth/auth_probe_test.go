package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

// putStaleSession seeds a TTL-expired session (VerifyTTL 6h + 15m jitter max,
// so 7h ago always forces a live refresh) with an encrypted token.
func putStaleSession(t *testing.T, c *Checker, sid string, teacher bool, uid int64, classes []int64) {
	t.Helper()
	ct, nonce, err := c.Store.EncryptToken("probe-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSession(t, c.Store, sid, &sessions.SessionRecord{
		StepikUserID:    uid,
		IsTeacher:       teacher,
		AllowedClassIDs: classes,
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now.Add(-7 * time.Hour),
		LastSeenAt:      now.Add(-7 * time.Hour),
	})
}

func probeCAChecker(t *testing.T) *Checker {
	t.Helper()
	return testChecker(testStore(t))
}

func TestProbe_teacherDeadTokenEmptyExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "teach-dead", true, 1182644732, []int64{82866, 87566})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	if _, err := c.EnsureFresh(context.Background(), "teach-dead", mustGet(t, c, "teach-dead")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "teach-dead")
	if len(got.AllowedClassIDs) != 2 {
		t.Errorf("persisted classes = %v, want untouched [82866 87566] (no empty persist)", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_teacherDeadAnonMismatchExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "teach-anon", true, 1182644732, []int64{82866, 87566})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	// Live evidence: dead bearer degrades to 200-anonymous (uid 1390904444), not 401.
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	if _, err := c.EnsureFresh(context.Background(), "teach-anon", mustGet(t, c, "teach-anon")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "teach-anon")
	if len(got.AllowedClassIDs) != 2 {
		t.Errorf("persisted classes = %v, want untouched [82866 87566] (no empty persist)", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_teacherStepicsEmptyExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "teach-empty-probe", true, 1182644732, []int64{82866, 87566})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, stepik.ErrEmptyStepics
	}
	if _, err := c.EnsureFresh(context.Background(), "teach-empty-probe", mustGet(t, c, "teach-empty-probe")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "teach-empty-probe")
	if len(got.AllowedClassIDs) != 2 {
		t.Errorf("persisted classes = %v, want untouched [82866 87566] (no empty persist)", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_teacherGenuineEmptyPersistsBackoff(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "teach-gen", true, 1182644732, []int64{82866})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1182644732, nil
	}
	sess := mustGet(t, c, "teach-gen")
	stale, err := c.EnsureFresh(context.Background(), "teach-gen", sess)
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v, want (false, nil)", stale, err)
	}
	got := mustGet(t, c, "teach-gen")
	if len(got.AllowedClassIDs) != 0 {
		t.Errorf("persisted classes = %v, want []", got.AllowedClassIDs)
	}
	if got.NextRetryAt.IsZero() || time.Now().After(got.NextRetryAt) {
		t.Errorf("NextRetryAt = %v, want future backoff", got.NextRetryAt)
	}
}

func TestProbe_teacherProbeTransientStale(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "teach-tr", true, 1182644732, []int64{82866})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.TransientError{Status: 500}
	}
	sess := mustGet(t, c, "teach-tr")
	stale, err := c.EnsureFresh(context.Background(), "teach-tr", sess)
	if err != nil || !stale {
		t.Fatalf("stale = %v, err = %v, want (true, nil)", stale, err)
	}
	got := mustGet(t, c, "teach-tr")
	if len(got.AllowedClassIDs) != 1 || got.AllowedClassIDs[0] != 82866 {
		t.Errorf("persisted classes = %v, want untouched [82866]", got.AllowedClassIDs)
	}
	if got.NextRetryAt.IsZero() {
		t.Error("NextRetryAt must be armed on probe-transient stale")
	}
}

func TestProbe_studentDeadTokenEmptyExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "stud-dead", false, 1190530325, []int64{82866})
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	if _, err := c.EnsureFresh(context.Background(), "stud-dead", mustGet(t, c, "stud-dead")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "stud-dead")
	if len(got.AllowedClassIDs) != 1 {
		t.Errorf("persisted classes = %v, want untouched [82866]", got.AllowedClassIDs)
	}
}

func TestProbe_studentDeadAnonMismatchExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "stud-anon", false, 1190530325, []int64{82866})
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	if _, err := c.EnsureFresh(context.Background(), "stud-anon", mustGet(t, c, "stud-anon")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "stud-anon")
	if len(got.AllowedClassIDs) != 1 {
		t.Errorf("persisted classes = %v, want untouched [82866]", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_studentStepicsEmptyExpired(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "stud-empty-probe", false, 1190530325, []int64{82866})
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, stepik.ErrEmptyStepics
	}
	if _, err := c.EnsureFresh(context.Background(), "stud-empty-probe", mustGet(t, c, "stud-empty-probe")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	got := mustGet(t, c, "stud-empty-probe")
	if len(got.AllowedClassIDs) != 1 {
		t.Errorf("persisted classes = %v, want untouched [82866]", got.AllowedClassIDs)
	}
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_studentGenuineEmptyPersistsOutsider(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "stud-gen", false, 1190530325, []int64{82866})
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1190530325, nil
	}
	sess := mustGet(t, c, "stud-gen")
	stale, err := c.EnsureFresh(context.Background(), "stud-gen", sess)
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v, want (false, nil)", stale, err)
	}
	got := mustGet(t, c, "stud-gen")
	if len(got.AllowedClassIDs) != 0 {
		t.Errorf("persisted classes = %v, want [] (outsider downstream)", got.AllowedClassIDs)
	}
	if !Allowed(got, 82866) {
		return
	}
	t.Error("outsider session must not allow 82866 after genuine-empty persist")
}

func TestProbe_studentProbeTransientStale(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "stud-tr", false, 1190530325, []int64{82866})
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.TransientError{Status: 500}
	}
	sess := mustGet(t, c, "stud-tr")
	stale, err := c.EnsureFresh(context.Background(), "stud-tr", sess)
	if err != nil || !stale {
		t.Fatalf("stale = %v, err = %v, want (true, nil)", stale, err)
	}
	got := mustGet(t, c, "stud-tr")
	if len(got.AllowedClassIDs) != 1 {
		t.Errorf("persisted classes = %v, want untouched [82866]", got.AllowedClassIDs)
	}
	if got.NextRetryAt.IsZero() {
		t.Error("NextRetryAt must be armed on probe-transient stale")
	}
}

func TestProbe_teacherForceDeadTokenEmptyExpired(t *testing.T) {
	c := probeCAChecker(t)
	ct, nonce, err := c.Store.EncryptToken("probe-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSession(t, c.Store, "teach-force-dead", &sessions.SessionRecord{
		StepikUserID:    1182644732,
		IsTeacher:       true,
		AllowedClassIDs: []int64{},
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now,
		LastSeenAt:      now,
	})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	if _, ferr := c.ForceTeacherEmptyRefresh(context.Background(), "teach-force-dead", mustGet(t, c, "teach-force-dead")); !errors.Is(ferr, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", ferr)
	}
	got := mustGet(t, c, "teach-force-dead")
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func TestProbe_teacherForceAnonMismatchExpired(t *testing.T) {
	c := probeCAChecker(t)
	ct, nonce, err := c.Store.EncryptToken("probe-plain")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	putSession(t, c.Store, "teach-force-anon", &sessions.SessionRecord{
		StepikUserID:    1182644732,
		IsTeacher:       true,
		AllowedClassIDs: []int64{},
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		LastVerifiedAt:  now,
		LastSeenAt:      now,
	})
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		return nil, nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	if _, ferr := c.ForceTeacherEmptyRefresh(context.Background(), "teach-force-anon", mustGet(t, c, "teach-force-anon")); !errors.Is(ferr, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", ferr)
	}
	got := mustGet(t, c, "teach-force-anon")
	if !got.NextRetryAt.IsZero() {
		t.Errorf("NextRetryAt = %v, want zero (no backoff on expiry)", got.NextRetryAt)
	}
}

func mustGet(t *testing.T, c *Checker, sid string) *sessions.SessionRecord {
	t.Helper()
	sess, err := c.Store.GetSession(sid)
	if err != nil {
		t.Fatal(err)
	}
	if sess == nil {
		t.Fatalf("session %q missing", sid)
	}
	return sess
}
