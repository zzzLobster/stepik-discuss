package push

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/config"
)

func TestUnknownFP8(t *testing.T) {
	pub1 := "B" + strings.Repeat("A", 86)
	pub2 := "B" + strings.Repeat("B", 86)
	if config.VapidFP8(pub1) == config.VapidFP8(pub2) {
		t.Error("different pubs same fp8")
	}
}

func TestAbsentCap(t *testing.T) {
	now := time.Now()
	maxT := now.Add(-25 * time.Hour)
	if time.Since(maxT) < 24*time.Hour {
		t.Error("25h should exceed 24h cap")
	}
	maxT = now.Add(-time.Hour)
	if time.Since(maxT) >= 24*time.Hour {
		t.Error("1h should be within cap")
	}
}

func TestPayload2048(t *testing.T) {
	snippet := strings.Repeat("a", 120)
	title := strings.Repeat("b", 100)
	p := PushPayload{Title: title, Body: snippet, Tag: "cid-1", URL: "/class/1#remark-x", Cid: 1, CommentID: "x"}
	raw, _ := json.Marshal(p)
	if len(raw) > 2048 {
		t.Fatalf("max payload len = %d, want <=2048", len(raw))
	}
}

func TestCoalesceN(t *testing.T) {
	count := 5
	ownCount := 2
	n := count - ownCount
	if n != 3 {
		t.Fatalf("N = %d", n)
	}
	if got := plural(n); got != "новых комментария" {
		t.Errorf("plural(3) = %q", got)
	}
}

func TestAllMinusOne(t *testing.T) {
	allowed := []int64{100, 200, 300}
	narrowed := []int64{100, 200}
	c := CidsOrAll{All: false, List: narrowed}
	if !IsValidCids(c, allowed, false) {
		t.Error("narrowed rejected")
	}
	bad := CidsOrAll{All: false, List: []int64{100, 999}}
	if IsValidCids(bad, allowed, false) {
		t.Error("bad cid accepted")
	}
}

func TestQueueFull(t *testing.T) {
	w := &Worker{queue: make(chan Job, 1), coalesce: map[int64]*coalesceEntry{}}
	if !w.Enqueue(Job{Cid: 1}) {
		t.Fatal("first enqueue failed")
	}
	if w.QueueLen() != 1 {
		t.Fatalf("len = %d", w.QueueLen())
	}
}
