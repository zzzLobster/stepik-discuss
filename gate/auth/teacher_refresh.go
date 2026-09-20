package auth

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

// Background teacher refresh proactively renews the shared teacher token so
// student fallback verification keeps working. One tick snapshots the record
// (absent means park, no Stepik call); an access token expiring within an
// hour renews without probing, otherwise a single GetLoggedID probe decides:
// uid mismatch / empty stepics / 401 renew, transient backs off for up to two
// ticks, alive is a no-op. invalid_grant and still-dead park the loop with a
// single warning; the banner surfaces via teacherTokenValid and a six-hour
// re-check escapes false parks. All writes are ObtainedAt-fenced: a record
// that advanced mid-flight is kept and the redeem result discarded.
type teacherBGState struct {
	mu         sync.Mutex
	parked     bool
	parkedAt   time.Time
	warned     bool
	probeSkips int
}

func (s *teacherBGState) snapshot() (parked bool, parkedAt time.Time, skips int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.parked, s.parkedAt, s.probeSkips
}

func (s *teacherBGState) park(now time.Time) (warn bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parked = true
	s.parkedAt = now
	s.probeSkips = 0
	if !s.warned {
		s.warned = true
		return true
	}
	return false
}

func (s *teacherBGState) markAlive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parked = false
	s.warned = false
	s.probeSkips = 0
}

func (s *teacherBGState) addProbeSkip() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probeSkips = 2
}

func (s *teacherBGState) takeProbeSkip() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probeSkips == 0 {
		return false
	}
	s.probeSkips--
	return true
}

// StartTeacherRefresh runs the background teacher loop until stop closes: one
// jittered (5-15s) immediate check, then a 15m±3m ticker.
func (c *Checker) StartTeacherRefresh(stop <-chan struct{}) {
	go func() {
		timer := time.NewTimer(5*time.Second + time.Duration(rand.Int63n(int64(10*time.Second))))
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		c.teacherBackgroundTick(context.Background(), time.Now())
		for {
			interval := 15*time.Minute + time.Duration(rand.Int63n(int64(6*time.Minute))) - 3*time.Minute
			timer := time.NewTimer(interval)
			select {
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
				c.teacherBackgroundTick(context.Background(), time.Now())
			}
		}
	}()
}

func (c *Checker) teacherProbeOwner(snap *sessions.TeacherToken) int64 {
	if snap.OwnerUID != 0 {
		return snap.OwnerUID
	}
	return c.Cfg.TeacherID
}

func (c *Checker) teacherGetLoggedID(ctx context.Context, token string) (int64, error) {
	if c.GetLoggedIDFn != nil {
		return c.GetLoggedIDFn(ctx, token)
	}
	return c.Stepik.GetLoggedID(ctx, token)
}

// teacherBackgroundTick runs one background check at now and reports the
// transition for logs and tests.
func (c *Checker) teacherBackgroundTick(ctx context.Context, now time.Time) string {
	snap, err := c.Store.GetTeacherToken()
	if err != nil || snap == nil {
		if first := c.teacherBG.park(now); first {
			c.Log.Warn("teacher_background_parked", "reason", "no_record")
		} else {
			c.Log.Info("teacher_background_no_record")
		}
		return "no_record"
	}
	uid := c.teacherProbeOwner(snap)
	parked, parkedAt, _ := c.teacherBG.snapshot()
	if parked && now.Sub(parkedAt) < 6*time.Hour {
		return "parked"
	}
	if snap.ExpiresAt.Sub(now) < time.Hour {
		return c.teacherBackgroundRenew(ctx, snap, now, "background_expiry")
	}
	if c.teacherBG.takeProbeSkip() {
		c.Log.Info("teacher_background_transient_skip", "uid", uid)
		return "skip_backoff"
	}
	access, derr := c.Store.DecryptToken(snap.Ciphertext, snap.Nonce)
	if derr != nil {
		return c.teacherBackgroundRenew(ctx, snap, now, "background_probe")
	}
	probeUID, perr := c.teacherGetLoggedID(ctx, access)
	if perr != nil {
		if stepik.IsUnauthorized(perr) || errors.Is(perr, stepik.ErrEmptyStepics) {
			return c.teacherBackgroundRenew(ctx, snap, now, "background_probe")
		}
		c.teacherBG.addProbeSkip()
		c.Log.Warn("teacher_background_transient", "uid", uid, "status", probeStatus(perr))
		return "transient"
	}
	if probeUID != uid {
		return c.teacherBackgroundRenew(ctx, snap, now, "background_probe")
	}
	c.teacherBG.markAlive()
	c.Log.Info("teacher_background_alive", "uid", uid)
	return "alive"
}

// teacherBackgroundRenew redeems the teacher record and confirms the fresh
// token with one probe; a still-dead token parks the loop.
func (c *Checker) teacherBackgroundRenew(ctx context.Context, snap *sessions.TeacherToken, now time.Time, reason string) string {
	uid := c.teacherProbeOwner(snap)
	access, res := c.tryRenewTeacherRecord(ctx, reason)
	switch res {
	case renewOK:
		probeUID, perr := c.teacherGetLoggedID(ctx, access)
		if perr == nil && probeUID == uid {
			c.teacherBG.markAlive()
			c.Log.Info("teacher_background_renew_ok", "uid", uid, "reason", reason)
			return "renewed"
		}
		if perr != nil && !stepik.IsUnauthorized(perr) && !errors.Is(perr, stepik.ErrEmptyStepics) {
			c.Log.Warn("teacher_background_transient", "uid", uid, "reason", reason, "status", probeStatus(perr))
			return "renew_transient"
		}
		if first := c.teacherBG.park(now); first {
			c.Log.Warn("teacher_background_parked", "uid", uid, "reason", "still_dead")
		}
		return "parked_still_dead"
	case renewExpired:
		// Re-check freshness before parking: the shared record may have
		// healed concurrently (an out-of-band write advanced it past snap),
		// or a demand dual-write failure may have left a fresher rotated
		// chain in a teacher session while this record is stale. Either way
		// a stale redeem must not park a live chain; the next tick retries.
		if live, err := c.Store.GetTeacherToken(); err == nil && live != nil && !live.ObtainedAt.Equal(snap.ObtainedAt) {
			c.Log.Warn("teacher_background_transient", "uid", uid, "reason", reason)
			return "renew_transient"
		}
		if fresher, err := c.Store.HasTeacherSessionFresherThan(snap.ObtainedAt); err == nil && fresher {
			c.Log.Warn("teacher_background_transient", "uid", uid, "reason", reason)
			return "renew_transient"
		}
		if first := c.teacherBG.park(now); first {
			c.Log.Warn("teacher_background_parked", "uid", uid, "reason", "invalid_grant")
		}
		return "parked_invalid_grant"
	case renewTransient:
		c.Log.Warn("teacher_background_transient", "uid", uid, "reason", reason)
		return "renew_transient"
	default:
		if first := c.teacherBG.park(now); first {
			c.Log.Warn("teacher_background_parked", "uid", uid, "reason", "no_refresh")
		}
		return "parked_still_dead"
	}
}
