package push

import (
	"net/http"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func TestRetryAfterCap(t *testing.T) {
	r := &http.Response{Header: make(http.Header)}
	r.Header.Set("Retry-After", "600")
	if d := parseRetryAfter(r); d != 5*time.Minute {
		t.Errorf("cap = %v, want 5m", d)
	}
	r.Header.Set("Retry-After", "2")
	if d := parseRetryAfter(r); d != 2*time.Second {
		t.Errorf("2s = %v", d)
	}
}

func TestTitleCache(t *testing.T) {
	c := NewTitleCache()
	c.Set(100, "Math")
	if v, ok := c.Get(100); !ok || v != "Math" {
		t.Fatalf("get = %q %v", v, ok)
	}
	if _, ok := c.Get(999); ok {
		t.Error("missing hit")
	}
}

func TestSweep(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	store, err := sessions.Open(t.TempDir()+"/s.db", key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	old := time.Now().Add(-31 * 24 * time.Hour)
	_ = store.PutPushSub(&sessions.PushSub{UID: 1, SID: "a", Endpoint: "https://fcm.googleapis.com/old", CreatedAt: old.Add(-time.Hour), LastOkAt: old, FailCount: 11})
	_ = store.PutPushSub(&sessions.PushSub{UID: 2, SID: "b", Endpoint: "https://fcm.googleapis.com/recent", CreatedAt: time.Now(), FailCount: 0})
	_ = SweepPushSubs(store, 6*time.Hour)
	if got, _ := store.GetPushSub("https://fcm.googleapis.com/old"); got != nil {
		t.Error("old fail row survived")
	}
	if got, _ := store.GetPushSub("https://fcm.googleapis.com/recent"); got == nil {
		t.Error("recent row deleted")
	}
}
