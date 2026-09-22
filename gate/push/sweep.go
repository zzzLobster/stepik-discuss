package push

import (
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func SweepPushSubs(store *sessions.Store, verifyTTL time.Duration) error {
	subs, err := store.SnapshotPushSubs()
	if err != nil {
		return err
	}
	now := time.Now()
	var toDelete []string
	for _, sub := range subs {
		if sub.FailCount > 10 && !sub.LastOkAt.IsZero() && now.Sub(sub.LastOkAt) > 30*24*time.Hour {
			toDelete = append(toDelete, sub.Endpoint)
			continue
		}
		best, _ := store.BestSessionForUID(sub.UID, verifyTTL)
		if best != nil {
			continue
		}
		maxT := sub.CreatedAt
		if sub.LastOkAt.After(maxT) {
			maxT = sub.LastOkAt
		}
		if maxT.IsZero() {
			continue
		}
		if now.Sub(maxT) > 24*time.Hour {
			toDelete = append(toDelete, sub.Endpoint)
		}
	}
	for _, ep := range toDelete {
		_ = store.DeletePushSub(ep)
	}
	return nil
}
