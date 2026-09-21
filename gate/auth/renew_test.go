package auth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func putStaleSessionWithRefresh(t *testing.T, c *Checker, sid string, teacher bool, uid int64, classes []int64, access, refresh string) {
	t.Helper()
	ct, nonce, err := c.Store.EncryptToken(access)
	if err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-7 * time.Hour)
	rec := &sessions.SessionRecord{
		StepikUserID:    uid,
		IsTeacher:       teacher,
		AllowedClassIDs: classes,
		ClassTitles:     map[string]string{},
		TokenCiphertext: ct,
		TokenNonce:      nonce,
		TokenObtainedAt: then,
		TokenExpiresAt:  then.Add(time.Hour),
		LastVerifiedAt:  then,
		LastSeenAt:      then,
	}
	if refresh != "" {
		rct, rnonce, err := c.Store.EncryptToken(refresh)
		if err != nil {
			t.Fatal(err)
		}
		rec.RefreshCiphertext = rct
		rec.RefreshNonce = rnonce
		rec.RefreshObtainedAt = then
	}
	putSession(t, c.Store, sid, rec)
}

func storedAccess(t *testing.T, c *Checker, sid string) string {
	t.Helper()
	rec := mustGet(t, c, sid)
	plain, err := c.Store.DecryptToken(rec.TokenCiphertext, rec.TokenNonce)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func storedRefresh(t *testing.T, c *Checker, sid string) (string, bool) {
	t.Helper()
	rec := mustGet(t, c, sid)
	if len(rec.RefreshCiphertext) == 0 {
		return "", false
	}
	plain, err := c.Store.DecryptToken(rec.RefreshCiphertext, rec.RefreshNonce)
	if err != nil {
		t.Fatal(err)
	}
	return plain, true
}

func ownedClass(cid int64) stepik.Class {
	return stepik.Class{ID: cid, Title: "T", Owner: 1182644732}
}

func TestRenew_student401_renewRetrySuccess(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-stud", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	var redeems int
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		if refresh != "refresh-old" {
			t.Errorf("redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "refresh-new", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		if userToken == "access-old" {
			return nil, "B", &stepik.UnauthorizedError{Status: 401}
		}
		if userToken == "access-new" {
			return []stepik.Class{ownedClass(82866)}, "B", nil
		}
		t.Errorf("verify saw unexpected token")
		return nil, "B", &stepik.UnauthorizedError{Status: 401}
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		t.Error("probe must not run on the non-empty retry path")
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-stud", mustGet(t, c, "renew-stud"))
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v; want (false, nil)", stale, err)
	}
	if redeems != 1 {
		t.Errorf("redeems = %d, want 1", redeems)
	}
	if got := storedAccess(t, c, "renew-stud"); got != "access-new" {
		t.Errorf("stored access = %q, want access-new", got)
	}
	if got, ok := storedRefresh(t, c, "renew-stud"); !ok || got != "refresh-new" {
		t.Errorf("stored refresh = %q, %v; want refresh-new, true", got, ok)
	}
	got := mustGet(t, c, "renew-stud")
	if len(got.AllowedClassIDs) != 1 || got.AllowedClassIDs[0] != 82866 {
		t.Errorf("classes = %v, want [82866]", got.AllowedClassIDs)
	}
	if time.Since(got.LastVerifiedAt) > 5*time.Minute {
		t.Errorf("LastVerifiedAt = %v, want fresh (set by retried verify)", got.LastVerifiedAt)
	}
	if time.Since(got.TokenObtainedAt) > 5*time.Minute {
		t.Errorf("TokenObtainedAt = %v, want fresh (persisted by renew)", got.TokenObtainedAt)
	}
}

func TestRenew_student401_noRotationRetains(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-norot", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "access-new", "", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		if userToken == "access-old" {
			return nil, "B", &stepik.UnauthorizedError{Status: 401}
		}
		return []stepik.Class{ownedClass(82866)}, "B", nil
	}
	if _, err := c.EnsureFresh(context.Background(), "renew-norot", mustGet(t, c, "renew-norot")); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := storedAccess(t, c, "renew-norot"); got != "access-new" {
		t.Errorf("stored access = %q, want access-new", got)
	}
	if got, ok := storedRefresh(t, c, "renew-norot"); !ok || got != "refresh-old" {
		t.Errorf("stored refresh = %q, %v; want retained refresh-old", got, ok)
	}
}

func TestRenew_invalidGrantExpiredClearsRefresh(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-ig", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	var redeems int
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "", "", time.Time{}, &stepik.UnauthorizedError{Status: 400}
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", &stepik.UnauthorizedError{Status: 401}
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		t.Error("no probe after invalid_grant")
		return 0, &stepik.UnauthorizedError{Status: 401}
	}
	if _, err := c.EnsureFresh(context.Background(), "renew-ig", mustGet(t, c, "renew-ig")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if redeems != 1 {
		t.Errorf("redeems = %d, want 1", redeems)
	}
	if _, ok := storedRefresh(t, c, "renew-ig"); ok {
		t.Error("stored refresh must be cleared on invalid_grant")
	}
	if got := storedAccess(t, c, "renew-ig"); got != "access-old" {
		t.Errorf("stored access = %q, want untouched access-old", got)
	}
}

func TestRenew_preFeatureRowOldPath(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSession(t, c, "renew-legacy", false, 1190530325, []int64{82866})
	var redeems int
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "access-new", "refresh-new", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", &stepik.UnauthorizedError{Status: 401}
	}
	if _, err := c.EnsureFresh(context.Background(), "renew-legacy", mustGet(t, c, "renew-legacy")); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired (legacy 401 path)", err)
	}
	if redeems != 0 {
		t.Errorf("redeems = %d, want 0 (no refresh stored)", redeems)
	}
}

func TestRenew_teacher401_renewRetrySuccess(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-teach", true, 1182644732, []int64{82866}, "access-old", "refresh-old")
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		if refresh != "refresh-old" {
			t.Errorf("redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "refresh-new", time.Now().Add(time.Hour), nil
	}
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		if token == "access-old" {
			return nil, &stepik.UnauthorizedError{Status: 401}
		}
		if token == "access-new" {
			return []stepik.Class{ownedClass(87566)}, nil
		}
		t.Errorf("listOwned saw unexpected token")
		return nil, &stepik.UnauthorizedError{Status: 401}
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-teach", mustGet(t, c, "renew-teach"))
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v; want (false, nil)", stale, err)
	}
	got := mustGet(t, c, "renew-teach")
	if len(got.AllowedClassIDs) != 1 || got.AllowedClassIDs[0] != 87566 {
		t.Errorf("classes = %v, want [87566]", got.AllowedClassIDs)
	}
	tok, terr := c.Store.GetTeacherToken()
	if terr != nil || tok == nil {
		t.Fatalf("teacher record = %v, %v; want present", tok, terr)
	}
	plain, derr := c.Store.DecryptToken(tok.Ciphertext, tok.Nonce)
	if derr != nil || plain != "access-new" {
		t.Errorf("teacher record access decrypts to %q, want access-new", plain)
	}
	rplain, rerr := c.Store.DecryptToken(tok.RefreshCiphertext, tok.RefreshNonce)
	if rerr != nil || rplain != "refresh-new" {
		t.Errorf("teacher record refresh decrypts to %q, want refresh-new", rplain)
	}
}

func TestRenew_probeExpiredTriggersRenew(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-probe", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	var redeems, probes int
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "access-new", "", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		if userToken == "access-old" {
			return nil, "B", nil
		}
		return []stepik.Class{ownedClass(82866)}, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probes++
		if token == "access-old" {
			return 1390904444, nil
		}
		return 1190530325, nil
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-probe", mustGet(t, c, "renew-probe"))
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v; want (false, nil)", stale, err)
	}
	if redeems != 1 {
		t.Errorf("redeems = %d, want 1", redeems)
	}
	if probes != 1 {
		t.Errorf("probes = %d, want 1 (no second probe on non-empty retry)", probes)
	}
}

func TestRenew_probeAfterRetry(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-par", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	var redeems int
	var probeTokens []string
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "access-new", "", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", nil
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probeTokens = append(probeTokens, token)
		if token == "access-old" {
			return 1390904444, nil
		}
		return 1190530325, nil
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-par", mustGet(t, c, "renew-par"))
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v; want (false, nil) genuine-empty", stale, err)
	}
	if redeems != 1 {
		t.Errorf("redeems = %d, want 1", redeems)
	}
	if len(probeTokens) != 2 || probeTokens[0] != "access-old" || probeTokens[1] != "access-new" {
		t.Errorf("probe tokens = %v, want [access-old access-new] (probe re-runs after renew+retry)", probeTokens)
	}
	if got := mustGet(t, c, "renew-par"); len(got.AllowedClassIDs) != 0 {
		t.Errorf("classes = %v, want [] genuine-empty", got.AllowedClassIDs)
	}
}

func TestRenew_triggerMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verify401  bool
		probeMatch bool
		wantProbes int
	}{
		{"unauthorized_only", true, true, 0},
		{"mismatch_only", false, false, 1},
		{"both", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := probeCAChecker(t)
			putStaleSessionWithRefresh(t, c, "renew-mx", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
			var redeems, probes int
			c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
				redeems++
				return "access-new", "", time.Now().Add(time.Hour), nil
			}
			c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
				if userToken == "access-old" && tc.verify401 {
					return nil, "B", &stepik.UnauthorizedError{Status: 401}
				}
				if userToken == "access-old" {
					return nil, "B", nil
				}
				return []stepik.Class{ownedClass(82866)}, "B", nil
			}
			c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
				probes++
				if tc.probeMatch {
					return 1190530325, nil
				}
				return 1390904444, nil
			}
			stale, err := c.EnsureFresh(context.Background(), "renew-mx", mustGet(t, c, "renew-mx"))
			if err != nil || stale {
				t.Fatalf("stale = %v, err = %v; want (false, nil)", stale, err)
			}
			if redeems != 1 {
				t.Errorf("redeems = %d, want exactly 1", redeems)
			}
			if probes != tc.wantProbes {
				t.Errorf("probes = %d, want %d", probes, tc.wantProbes)
			}
		})
	}
}

func TestRenew_transientFallsBackToStale(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-tr", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "", "", time.Time{}, &stepik.TransientError{Status: 500}
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		return nil, "B", &stepik.UnauthorizedError{Status: 401}
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-tr", mustGet(t, c, "renew-tr"))
	if err != nil || !stale {
		t.Fatalf("stale = %v, err = %v; want (true, nil)", stale, err)
	}
	if _, ok := storedRefresh(t, c, "renew-tr"); !ok {
		t.Error("transient renew must persist nothing (refresh kept)")
	}
	if got := storedAccess(t, c, "renew-tr"); got != "access-old" {
		t.Errorf("stored access = %q, want untouched access-old", got)
	}
}

func TestRenew_concurrentSingleRedeem(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-cc", false, 1190530325, []int64{82866}, "access-old", "refresh-old")
	var redeems atomic.Int64
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems.Add(1)
		time.Sleep(200 * time.Millisecond)
		return "access-new", "refresh-new", time.Now().Add(time.Hour), nil
	}
	c.VerifyStudentFn = func(ctx context.Context, userToken, teacherToken string, teacherValid bool, uid int64) ([]stepik.Class, string, error) {
		if userToken == "access-old" {
			return nil, "B", &stepik.UnauthorizedError{Status: 401}
		}
		return []stepik.Class{ownedClass(82866)}, "B", nil
	}
	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = c.EnsureFresh(context.Background(), "renew-cc", mustGet(t, c, "renew-cc"))
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: err = %v", i, err)
		}
	}
	if got := redeems.Load(); got != 1 {
		t.Errorf("redeems = %d, want exactly 1 (coalesced)", got)
	}
	if got := storedAccess(t, c, "renew-cc"); got != "access-new" {
		t.Errorf("stored access = %q, want access-new", got)
	}
}

func TestRenew_teacherHandoffUnlockBalance(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "handoff-sid", false, 1182644732, []int64{82866}, "access-old", "refresh-old")
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		if refresh != "refresh-old" {
			t.Errorf("redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "refresh-new", time.Now().Add(time.Hour), nil
	}
	// Hold the sid lock so the renewal blocks in lock(): its pre-lock
	// snapshot sees the student record, then the promotion below makes the
	// locked re-read see a teacher record and take the handoff path that
	// used to unlock twice (explicit unlock plus deferred unlock).
	hold := c.renewMu.lock("sid:handoff-sid")
	var wg sync.WaitGroup
	var res renewResult
	var access string
	var panicked any
	wg.Go(func() {
		defer func() {
			if p := recover(); p != nil {
				panicked = p
			}
		}()
		access, res = c.tryRenewSession(t.Context(), "handoff-sid", "test_handoff")
	})
	time.Sleep(200 * time.Millisecond)
	promoted := mustGet(t, c, "handoff-sid")
	promoted.IsTeacher = true
	putSession(t, c.Store, "handoff-sid", promoted)
	hold()
	wg.Wait()
	if panicked != nil {
		t.Fatalf("tryRenewSession panicked: %v (unlock imbalance on teacher handoff)", panicked)
	}
	if res != renewOK || access != "access-new" {
		t.Fatalf("access = %q, res = %v; want (access-new, renewOK)", access, res)
	}
	c.renewMu.mu.Lock()
	n := len(c.renewMu.m)
	c.renewMu.mu.Unlock()
	if n != 0 {
		t.Errorf("renewMu holds %d keys after handoff, want 0 (refcount leak)", n)
	}
	if got := storedAccess(t, c, "handoff-sid"); got != "access-new" {
		t.Errorf("stored access = %q, want access-new", got)
	}
}

func TestRenew_teacherDualWriteTeacherPutFailureRollsBack(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	putStaleSessionWithRefresh(t, c, "dual-teach", true, 1182644732, []int64{82866}, "access-old", "refresh-old")
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	// No rotation: the previous refresh stays valid at Stepik, so the
	// session must roll back to it when the teacher put fails.
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		if refresh != "refresh-old" {
			t.Errorf("redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "", now.Add(2 * time.Hour), nil
	}
	c.PutTeacherTokenFn = func(*sessions.TeacherToken) error {
		return errors.New("teacher put boom")
	}
	_, res := c.tryRenewTeacherSession(t.Context(), "dual-teach", "test_dual_write", mustGet(t, c, "dual-teach"))
	if res != renewTransient {
		t.Fatalf("res = %v, want renewTransient (taxonomy unchanged)", res)
	}
	if got := storedAccess(t, c, "dual-teach"); got != "access-old" {
		t.Errorf("session access = %q, want rolled-back access-old", got)
	}
	if got, ok := storedRefresh(t, c, "dual-teach"); !ok || got != "refresh-old" {
		t.Errorf("session refresh = %q, %v; want rolled-back refresh-old", got, ok)
	}
	if got := teacherAccess(t, c); got != "access-old" {
		t.Errorf("teacher record access = %q, want untouched access-old", got)
	}
	// No false park: with the hook cleared the rolled-back refresh redeems
	// normally instead of parking on invalid_grant.
	c.PutTeacherTokenFn = nil
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		if token == "access-new" {
			return 1182644732, nil
		}
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		if refresh != "refresh-old" {
			t.Errorf("background redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "refresh-new", now.Add(2 * time.Hour), nil
	}
	if got := c.teacherBackgroundTick(t.Context(), now); got != "renewed" {
		t.Errorf("background tick = %q, want renewed (no false park)", got)
	}
}

func TestRenew_teacherFencingDiscard(t *testing.T) {
	c := probeCAChecker(t)
	putStaleSessionWithRefresh(t, c, "renew-fence", true, 1182644732, []int64{82866}, "access-old", "refresh-old")
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		// A re-login wins mid-flight: strictly newer record.
		rec := mustGet(t, c, "renew-fence")
		wct, wnonce, err := c.Store.EncryptToken("winner-access")
		if err != nil {
			t.Fatal(err)
		}
		wrct, wrnonce, err := c.Store.EncryptToken("winner-refresh")
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		rec.TokenCiphertext = wct
		rec.TokenNonce = wnonce
		rec.TokenObtainedAt = now
		rec.RefreshCiphertext = wrct
		rec.RefreshNonce = wrnonce
		rec.RefreshObtainedAt = now
		if err := c.Store.PutSession("renew-fence", rec); err != nil {
			t.Fatal(err)
		}
		return "redeem-access", "redeem-refresh", now.Add(time.Hour), nil
	}
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		if token == "access-old" {
			return nil, &stepik.UnauthorizedError{Status: 401}
		}
		if token == "winner-access" {
			return []stepik.Class{ownedClass(87566)}, nil
		}
		t.Errorf("listOwned saw unexpected token")
		return nil, &stepik.UnauthorizedError{Status: 401}
	}
	stale, err := c.EnsureFresh(context.Background(), "renew-fence", mustGet(t, c, "renew-fence"))
	if err != nil || stale {
		t.Fatalf("stale = %v, err = %v; want (false, nil)", stale, err)
	}
	if got := storedAccess(t, c, "renew-fence"); got != "winner-access" {
		t.Errorf("stored access = %q, want winner-access (redeem result discarded)", got)
	}
	if got, _ := storedRefresh(t, c, "renew-fence"); got != "winner-refresh" {
		t.Errorf("stored refresh = %q, want winner-refresh", got)
	}
}

func TestRefreshTeacher_StaleSidDoesNotRegressLiveRecord(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-live", "refresh-live", now.Add(-time.Hour), now.Add(9*time.Hour))
	putStaleSessionWithRefresh(t, c, "teach-stale", true, 1182644732, []int64{82866}, "access-stale", "refresh-stale")
	c.ListOwnedFn = func(ctx context.Context, token string) ([]stepik.Class, error) {
		if token != "access-stale" {
			t.Errorf("listOwned token = %q, want access-stale", token)
		}
		return []stepik.Class{ownedClass(82866)}, nil
	}
	sess := mustGet(t, c, "teach-stale")
	if _, err := c.refreshTeacher(context.Background(), "teach-stale", sess, now); err != nil {
		t.Fatalf("refreshTeacher = %v", err)
	}
	if got := teacherAccess(t, c); got != "access-live" {
		t.Errorf("shared access = %q, want access-live (no clobber by stale SID)", got)
	}
	tok, err := c.Store.GetTeacherToken()
	if err != nil || tok == nil {
		t.Fatal(err)
	}
	rplain, err := c.Store.DecryptToken(tok.RefreshCiphertext, tok.RefreshNonce)
	if err != nil {
		t.Fatal(err)
	}
	if rplain != "refresh-live" {
		t.Errorf("shared refresh = %q, want refresh-live", rplain)
	}
	if got := storedAccess(t, c, "teach-stale"); got != "access-live" {
		t.Errorf("stale SID access = %q, want access-live (adopt-live heal)", got)
	}
	if got, _ := storedRefresh(t, c, "teach-stale"); got != "refresh-live" {
		t.Errorf("stale SID refresh = %q, want refresh-live", got)
	}
}
