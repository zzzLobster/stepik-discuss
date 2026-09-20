package auth

import (
	"context"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

func seedTeacherRecord(t *testing.T, c *Checker, access, refresh string, obtained, expires time.Time) {
	t.Helper()
	ct, nonce, err := c.Store.EncryptToken(access)
	if err != nil {
		t.Fatal(err)
	}
	tok := &sessions.TeacherToken{
		Ciphertext: ct,
		Nonce:      nonce,
		ObtainedAt: obtained,
		ExpiresAt:  expires,
		ExpiresIn:  36000,
		OwnerUID:   1182644732,
	}
	if refresh != "" {
		rct, rnonce, err := c.Store.EncryptToken(refresh)
		if err != nil {
			t.Fatal(err)
		}
		tok.RefreshCiphertext = rct
		tok.RefreshNonce = rnonce
		tok.RefreshObtainedAt = obtained
	}
	if err := c.Store.PutTeacherToken(tok); err != nil {
		t.Fatal(err)
	}
}

func teacherAccess(t *testing.T, c *Checker) string {
	t.Helper()
	tok, err := c.Store.GetTeacherToken()
	if err != nil || tok == nil {
		t.Fatalf("teacher record = %v, %v", tok, err)
	}
	plain, err := c.Store.DecryptToken(tok.Ciphertext, tok.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestTeacherBackground_noRecord(t *testing.T) {
	c := probeCAChecker(t)
	var probes, redeems int
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probes++
		return 1182644732, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "a", "r", time.Now().Add(time.Hour), nil
	}
	now := time.Now()
	if got := c.teacherBackgroundTick(context.Background(), now); got != "no_record" {
		t.Errorf("tick = %q, want no_record", got)
	}
	if probes != 0 || redeems != 0 {
		t.Errorf("probes = %d, redeems = %d; want no Stepik calls", probes, redeems)
	}
	if got := c.teacherBackgroundTick(context.Background(), now.Add(time.Minute)); got != "no_record" {
		t.Errorf("second tick = %q, want no_record (parked, still no Stepik call)", got)
	}
	if probes != 0 || redeems != 0 {
		t.Errorf("after two ticks: probes = %d, redeems = %d; want no Stepik calls", probes, redeems)
	}
}

func TestTeacherBackground_expiryRenewsWithoutProbe(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(30*time.Minute))
	var probes int
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probes++
		if token != "access-new" {
			t.Errorf("confirm probe token = %q, want access-new", token)
			return 0, &stepik.UnauthorizedError{Status: 401}
		}
		return 1182644732, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		if refresh != "refresh-old" {
			t.Errorf("redeem refresh = %q, want refresh-old", refresh)
		}
		return "access-new", "refresh-new", now.Add(2 * time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "renewed" {
		t.Fatalf("tick = %q, want renewed", got)
	}
	if probes != 1 {
		t.Errorf("probes = %d, want 1 (confirm only, no expiry probe)", probes)
	}
	if got := teacherAccess(t, c); got != "access-new" {
		t.Errorf("stored access = %q, want access-new", got)
	}
}

func TestTeacherBackground_probeMismatchRenews(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	var probeTokens []string
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probeTokens = append(probeTokens, token)
		if token == "access-old" {
			return 1390904444, nil
		}
		return 1182644732, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "access-new", "", now.Add(2 * time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "renewed" {
		t.Fatalf("tick = %q, want renewed", got)
	}
	if len(probeTokens) != 2 || probeTokens[0] != "access-old" || probeTokens[1] != "access-new" {
		t.Errorf("probe tokens = %v, want [access-old access-new]", probeTokens)
	}
	tok, _ := c.Store.GetTeacherToken()
	rplain, err := c.Store.DecryptToken(tok.RefreshCiphertext, tok.RefreshNonce)
	if err != nil || rplain != "refresh-old" {
		t.Errorf("refresh = %q, %v; want retained refresh-old", rplain, err)
	}
}

func TestTeacherBackground_aliveNoop(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	var redeems int
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1182644732, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "a", "r", now.Add(time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "alive" {
		t.Errorf("tick = %q, want alive", got)
	}
	if redeems != 0 {
		t.Errorf("redeems = %d, want 0", redeems)
	}
	if got := teacherAccess(t, c); got != "access-old" {
		t.Errorf("stored access = %q, want untouched access-old", got)
	}
}

func TestTeacherBackground_transientBackoff(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	var probes, redeems int
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probes++
		return 0, &stepik.TransientError{Status: 500}
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "a", "r", now.Add(time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "transient" {
		t.Fatalf("tick1 = %q, want transient", got)
	}
	for i, want := range []string{"skip_backoff", "skip_backoff"} {
		if got := c.teacherBackgroundTick(context.Background(), now.Add(time.Duration(i+1)*15*time.Minute)); got != want {
			t.Fatalf("tick%d = %q, want %s", i+2, got, want)
		}
	}
	if probes != 1 || redeems != 0 {
		t.Fatalf("probes = %d, redeems = %d; want 1 probe, 0 redeems during backoff", probes, redeems)
	}
	if got := c.teacherBackgroundTick(context.Background(), now.Add(45*time.Minute)); got != "transient" {
		t.Errorf("tick4 = %q, want transient (backoff exhausted, probe again)", got)
	}
	if probes != 2 {
		t.Errorf("probes = %d, want 2", probes)
	}
}

func TestTeacherBackground_invalidGrantParks(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	var probes, redeems int
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		probes++
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "", "", time.Time{}, &stepik.UnauthorizedError{Status: 400}
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "parked_invalid_grant" {
		t.Fatalf("tick = %q, want parked_invalid_grant", got)
	}
	tok, _ := c.Store.GetTeacherToken()
	if len(tok.RefreshCiphertext) != 0 {
		t.Error("refresh must be cleared on invalid_grant")
	}
	if got := c.teacherBackgroundTick(context.Background(), now.Add(time.Minute)); got != "parked" {
		t.Errorf("second tick = %q, want parked", got)
	}
	if probes != 1 || redeems != 1 {
		t.Errorf("probes = %d, redeems = %d; want no Stepik calls while parked", probes, redeems)
	}
}

func TestTeacherBackground_stillDeadParks(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "access-new", "", now.Add(2 * time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "parked_still_dead" {
		t.Errorf("tick = %q, want parked_still_dead", got)
	}
}

func TestTeacherBackground_renewTransient(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "", "", time.Time{}, &stepik.TransientError{Status: 503}
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "renew_transient" {
		t.Errorf("tick = %q, want renew_transient", got)
	}
	if got := teacherAccess(t, c); got != "access-old" {
		t.Errorf("stored access = %q, want untouched access-old (persist nothing)", got)
	}
}

func TestTeacherBackground_supersede(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		if token == "winner-access" {
			return 1182644732, nil
		}
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		wct, wnonce, err := c.Store.EncryptToken("winner-access")
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := c.Store.GetTeacherToken()
		cur.Ciphertext = wct
		cur.Nonce = wnonce
		cur.ObtainedAt = now
		if err := c.Store.PutTeacherToken(cur); err != nil {
			t.Fatal(err)
		}
		return "redeem-access", "redeem-refresh", now.Add(2 * time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "renewed" {
		t.Fatalf("tick = %q, want renewed (winner reused)", got)
	}
	if got := teacherAccess(t, c); got != "winner-access" {
		t.Errorf("stored access = %q, want winner-access (redeem result discarded)", got)
	}
}

func TestTeacherBackground_parkEscape6h(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "", "", time.Time{}, &stepik.UnauthorizedError{Status: 400}
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "parked_invalid_grant" {
		t.Fatalf("tick = %q, want parked_invalid_grant", got)
	}
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1182644732, nil
	}
	later := now.Add(7 * time.Hour)
	if got := c.teacherBackgroundTick(context.Background(), later); got != "alive" {
		t.Errorf("tick after 7h = %q, want alive (false-park escape)", got)
	}
}

func TestTeacherBackground_staleRecordFresherSessionNoPark(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	// Shared record stale with a dead refresh (a demand dual-write failure
	// left the rotated chain in the session): redeeming it yields
	// invalid_grant, but the live chain in the session must not park.
	seedTeacherRecord(t, c, "access-old", "refresh-dead", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	putStaleSessionWithRefresh(t, c, "dual-sess", true, 1182644732, []int64{82866}, "access-new", "refresh-new")
	fresh := mustGet(t, c, "dual-sess")
	fresh.TokenObtainedAt = now
	putSession(t, c.Store, "dual-sess", fresh)
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		return "", "", time.Time{}, &stepik.UnauthorizedError{Status: 400}
	}
	if got := c.teacherBackgroundTick(t.Context(), now); got != "renew_transient" {
		t.Fatalf("tick = %q, want renew_transient (stale redeem must not park a live chain)", got)
	}
	if parked, _, _ := c.teacherBG.snapshot(); parked {
		t.Error("background parked after stale redeem despite fresher session")
	}
}

func TestTeacherBackground_concurrentHealNoPark(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "refresh-old", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		// An out-of-band heal wins mid-redeem (a fresh OAuth callback
		// bypassing the renewal lock): the stale redeem fails, but the
		// live chain must not park.
		wct, wnonce, err := c.Store.EncryptToken("winner-access")
		if err != nil {
			t.Fatal(err)
		}
		cur, _ := c.Store.GetTeacherToken()
		cur.Ciphertext = wct
		cur.Nonce = wnonce
		cur.ObtainedAt = now
		if err := c.Store.PutTeacherToken(cur); err != nil {
			t.Fatal(err)
		}
		return "", "", time.Time{}, &stepik.UnauthorizedError{Status: 400}
	}
	if got := c.teacherBackgroundTick(t.Context(), now); got != "renew_transient" {
		t.Fatalf("tick = %q, want renew_transient (concurrent heal must not park)", got)
	}
	if got := teacherAccess(t, c); got != "winner-access" {
		t.Errorf("teacher record access = %q, want winner-access (heal preserved, not cleared)", got)
	}
	if parked, _, _ := c.teacherBG.snapshot(); parked {
		t.Error("background parked despite concurrent heal")
	}
}

func TestTeacherBackground_noRefreshParks(t *testing.T) {
	c := probeCAChecker(t)
	now := time.Now()
	seedTeacherRecord(t, c, "access-old", "", now.Add(-2*time.Hour), now.Add(10*time.Hour))
	c.GetLoggedIDFn = func(ctx context.Context, token string) (int64, error) {
		return 1390904444, nil
	}
	var redeems int
	c.RedeemRefreshFn = func(ctx context.Context, refresh string) (string, string, time.Time, error) {
		redeems++
		return "a", "r", now.Add(time.Hour), nil
	}
	if got := c.teacherBackgroundTick(context.Background(), now); got != "parked_still_dead" {
		t.Errorf("tick = %q, want parked_still_dead (pre-feature row cannot renew)", got)
	}
	if redeems != 0 {
		t.Errorf("redeems = %d, want 0", redeems)
	}
}
