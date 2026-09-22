package push

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSummaryBadgeCount(t *testing.T) {
	cases := []struct {
		name         string
		windowUnique int
		ownInWindow  int
		firstAuthor  int64
		subUID       int64
		wantN        int
		wantBadge    int
		wantSend     bool
	}{
		// Third user, no own: N=2 (window 2), immediate covered 1 → badge 1.
		{"non-author gets incremental", 2, 0, 10, 20, 2, 1, true},
		// First-own edge: sub wrote first, second is new → N=1, no subtract → badge 1.
		{"first-own edge sends", 2, 1, 10, 10, 1, 1, true},
		// Second-author edge: sub wrote second, only first is new but already
		// notified via immediate → N=1, badge 0 → skip (no zero-increment push).
		{"second-author badge zero skips", 2, 1, 10, 20, 1, 0, false},
		// All own: N=0 → skip (would render "0 ..." body if sent).
		{"all-own N zero skips", 2, 2, 10, 10, 0, 0, false},
		// Stranger, all own by someone else: still new for this sub.
		{"stranger two new", 3, 0, 10, 30, 3, 2, true},
		// Floor: single-comment window would not flush, but formula floors.
		{"floor negative to zero", 1, 1, 10, 20, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := summaryN(tc.windowUnique, tc.ownInWindow); got != tc.wantN {
				t.Errorf("summaryN = %d, want %d", got, tc.wantN)
			}
			if got := summaryBadgeCount(tc.windowUnique, tc.ownInWindow, tc.firstAuthor, tc.subUID); got != tc.wantBadge {
				t.Errorf("summaryBadgeCount = %d, want %d", got, tc.wantBadge)
			}
			// Send rule mirrors sendSummary: skip when N<=0 or badge<=0.
			send := summaryN(tc.windowUnique, tc.ownInWindow) > 0 &&
				summaryBadgeCount(tc.windowUnique, tc.ownInWindow, tc.firstAuthor, tc.subUID) > 0
			if send != tc.wantSend {
				t.Errorf("send = %v, want %v", send, tc.wantSend)
			}
		})
	}
}

func TestOwnInSeen(t *testing.T) {
	seen := map[string]int64{"c1": 10, "c2": 20, "c3": 10}
	if got := ownInSeen(seen, 10); got != 2 {
		t.Errorf("ownInSeen(10) = %d, want 2", got)
	}
	if got := ownInSeen(seen, 20); got != 1 {
		t.Errorf("ownInSeen(20) = %d, want 1", got)
	}
	if got := ownInSeen(seen, 30); got != 0 {
		t.Errorf("ownInSeen(30) = %d, want 0", got)
	}
}

func TestPayloadCountMarshal(t *testing.T) {
	p := PushPayload{Title: "t", Body: "b", Tag: "cid-1", URL: "/class/1#remark-x", Cid: 1, CommentID: "x", Count: 3}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"count":3`) {
		t.Errorf("marshal missing count=3: %s", raw)
	}
	// Immediate always carries 1.
	p = PushPayload{Title: "t", Body: "b", Tag: "cid-1", URL: "/class/1#remark-x", Cid: 1, CommentID: "x", Count: 1}
	raw, _ = json.Marshal(p)
	if !strings.Contains(string(raw), `"count":1`) {
		t.Errorf("immediate marshal missing count=1: %s", raw)
	}
	// Backward compat: absent count decodes to 0 in Go; SW treats absent as 1
	// via (payload.count ?? 1).
	var back PushPayload
	if err := json.Unmarshal([]byte(`{"title":"t","body":"b","tag":"cid-1","url":"/class/1#remark-x","cid":1,"comment_id":"x"}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.Count != 0 {
		t.Errorf("absent count decodes to %d, want 0 (SW defaults to 1)", back.Count)
	}
	// Payload stays within 2KB with count present.
	big := PushPayload{Title: strings.Repeat("b", 100), Body: strings.Repeat("a", 120), Tag: "cid-1", URL: "/class/1#remark-x", Cid: 1, CommentID: "x", Count: 12}
	raw, _ = json.Marshal(big)
	if len(raw) > 2048 {
		t.Errorf("payload with count len = %d, want <=2048", len(raw))
	}
}
