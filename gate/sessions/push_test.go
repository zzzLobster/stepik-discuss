package sessions

import (
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestSchema_v1tov2(t *testing.T) {
	key := testKey(t)
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{BucketSessions, BucketUserVersions, BucketTeacherToken, BucketMeta} {
			_, _ = tx.CreateBucketIfNotExists(b)
		}
		_ = tx.Bucket(BucketMeta).Put(KeySchemaVersion, []byte("1"))
		_ = tx.Bucket(BucketMeta).Put(KeyGlobalEpoch, []byte("0"))
		return nil
	})
	_ = db.Close()
	s, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open v1 = %v", err)
	}
	defer s.Close()
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping after migrate = %v", err)
	}
}

func TestBestSessionForUID_matrix(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	mk := func(sid string, uid int64, verified time.Time, exp time.Time, uv, epoch uint64) {
		r := &SessionRecord{StepikUserID: uid, AllowedClassIDs: []int64{1}, LastVerifiedAt: verified, ExpiresAt: exp, LastSeenAt: now, UserVersion: uv, GlobalEpoch: epoch}
		if err := s.PutSession(sid, r); err != nil {
			t.Fatal(err)
		}
	}
	mk("fresh", 7, now, now.Add(time.Hour), 0, 0)
	mk("stale", 7, now.Add(-7*time.Hour), now.Add(time.Hour), 0, 0)
	mk("expired", 7, now, now.Add(-time.Hour), 0, 0)
	best, sid := s.BestSessionForUID(7, 6*time.Hour)
	if best == nil || sid != "fresh" {
		t.Fatalf("best = %v %q, want fresh", best, sid)
	}
	if _, sid := s.BestSessionForUID(99, 6*time.Hour); sid != "" {
		t.Fatalf("unknown uid sid = %q", sid)
	}
}

func TestDeleteSessionAndPushSubs_onlyThatSid(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	_ = s.PutSession("sid-a", &SessionRecord{StepikUserID: 1, ExpiresAt: now.Add(time.Hour)})
	_ = s.PutSession("sid-b", &SessionRecord{StepikUserID: 1, ExpiresAt: now.Add(time.Hour)})
	_ = s.PutPushSub(&PushSub{UID: 1, SID: "sid-a", Endpoint: "https://fcm.googleapis.com/a", CreatedAt: now})
	_ = s.PutPushSub(&PushSub{UID: 1, SID: "sid-b", Endpoint: "https://fcm.googleapis.com/b", CreatedAt: now})
	if err := s.DeleteSessionAndPushSubs("sid-a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSession("sid-a"); got != nil {
		t.Error("sid-a session survived")
	}
	if got, _ := s.GetSession("sid-b"); got == nil {
		t.Error("sid-b session deleted")
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/a"); got != nil {
		t.Error("sid-a push survived")
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/b"); got == nil {
		t.Error("sid-b push deleted")
	}
}

func TestStripClassAndPrunePush_revokeImmediate(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	_ = s.PutSession("sid-1", &SessionRecord{StepikUserID: 5, AllowedClassIDs: []int64{100, 200}, ClassTitles: map[string]string{"100": "A", "200": "B"}, ExpiresAt: now.Add(time.Hour), LastVerifiedAt: now})
	_ = s.PutPushSub(&PushSub{UID: 5, SID: "sid-1", Endpoint: "https://fcm.googleapis.com/1", Cids: []int64{100}, CreatedAt: now})
	_ = s.PutPushSub(&PushSub{UID: 5, SID: "sid-1", Endpoint: "https://fcm.googleapis.com/all", All: true, CreatedAt: now})
	_ = s.PutPushSub(&PushSub{UID: 5, SID: "sid-1", Endpoint: "https://fcm.googleapis.com/2", Cids: []int64{100, 200}, CreatedAt: now})
	if err := s.StripClassAndPrunePush(5, 100); err != nil {
		t.Fatal(err)
	}
	rec, _ := s.GetSession("sid-1")
	for _, id := range rec.AllowedClassIDs {
		if id == 100 {
			t.Error("cid 100 still allowed")
		}
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/1"); got != nil {
		t.Error("single-cid row survived")
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/all"); got != nil {
		t.Error("all row survived")
	}
	kept, _ := s.GetPushSub("https://fcm.googleapis.com/2")
	if kept == nil || len(kept.Cids) != 1 || kept.Cids[0] != 200 {
		t.Errorf("narrowed row = %+v", kept)
	}
}

func TestBumpVersionAndPrunePush(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	_ = s.PutPushSub(&PushSub{UID: 9, SID: "x", Endpoint: "https://fcm.googleapis.com/9", CreatedAt: now})
	v, err := s.BumpVersionAndPrunePush(9)
	if err != nil || v != 1 {
		t.Fatalf("bump = %d %v", v, err)
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/9"); got != nil {
		t.Error("push survived version bump")
	}
}

func TestDeletePushSubsForUID(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	_ = s.PutPushSub(&PushSub{UID: 3, SID: "a", Endpoint: "https://fcm.googleapis.com/3a", CreatedAt: now})
	_ = s.PutPushSub(&PushSub{UID: 4, SID: "b", Endpoint: "https://fcm.googleapis.com/4b", CreatedAt: now})
	if err := s.DeletePushSubsForUID(3); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/3a"); got != nil {
		t.Error("uid 3 survived")
	}
	if got, _ := s.GetPushSub("https://fcm.googleapis.com/4b"); got == nil {
		t.Error("uid 4 deleted")
	}
}
