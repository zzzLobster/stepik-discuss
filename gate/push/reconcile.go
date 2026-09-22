package push

import (
	"context"
	"errors"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func ReconcilePushSubs(ctx context.Context, store *sessions.Store, checker *auth.Checker) {
	subs, err := store.SnapshotPushSubs()
	if err != nil {
		return
	}
	seen := map[string]int64{}
	for _, sub := range subs {
		if _, ok := seen[sub.SID]; ok {
			continue
		}
		seen[sub.SID] = sub.UID
	}
	for sid, uid := range seen {
		sess, err := store.GetSession(sid)
		if err != nil || sess == nil {
			continue
		}
		if time.Since(sess.LastVerifiedAt) <= checker.Cfg.VerifyTTL {
			continue
		}
		before := append([]int64(nil), sess.AllowedClassIDs...)
		_, rerr := checker.EnsureFresh(ctx, sid, sess)
		if rerr != nil {
			if errors.Is(rerr, auth.ErrExpired) {
				_ = store.DeletePushSubsForUID(uid)
				continue
			}
			continue
		}
		afterSet := map[int64]bool{}
		for _, id := range sess.AllowedClassIDs {
			afterSet[id] = true
		}
		for _, id := range before {
			if !afterSet[id] {
				_ = store.StripClassAndPrunePush(uid, id)
			}
		}
	}
}
