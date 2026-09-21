package stepik

import (
	"context"
	"net/http"
	"testing"
)

func TestListPages_capHit(t *testing.T) {
	hits := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		hits++
		return jsonResp(200, map[string]any{
			"classes": []Class{owned(int64(hits))},
			"meta":    map[string]any{"has_next": true, "page": hits},
		}), nil
	})
	classes, err := c.ListByStudent(context.Background(), "tok", 5)
	if err != nil {
		t.Fatalf("ListByStudent err = %v", err)
	}
	if len(classes) != MaxClassPages {
		t.Errorf("len = %d, want MaxClassPages %d", len(classes), MaxClassPages)
	}
	if hits != MaxClassPages {
		t.Errorf("upstream hits = %d, want %d (11th page must never be requested)", hits, MaxClassPages)
	}
	seen := map[int64]bool{}
	for _, cl := range classes {
		seen[cl.ID] = true
	}
	for i := 1; i <= MaxClassPages; i++ {
		if !seen[int64(i)] {
			t.Errorf("missing class id %d in merged result %+v", i, classes)
		}
	}
}

func TestListPages_emptyWithHasNext(t *testing.T) {
	hits := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		hits++
		return jsonResp(200, map[string]any{
			"classes": []Class{},
			"meta":    map[string]any{"has_next": true, "page": 1},
		}), nil
	})
	classes, err := c.ListByStudent(context.Background(), "tok", 5)
	if err != nil {
		t.Fatalf("ListByStudent err = %v", err)
	}
	if len(classes) != 0 {
		t.Errorf("len = %d, want 0 (empty page with has_next stops)", len(classes))
	}
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (no follow-up after empty page)", hits)
	}
}
