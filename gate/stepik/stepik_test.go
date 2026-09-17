package stepik

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResp(status int, v any) *http.Response {
	raw, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(raw))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func testClient(t *testing.T, fn roundTripFunc) *Client {
	t.Helper()
	return &Client{
		http:      &http.Client{Transport: fn},
		out:       rate.NewLimiter(1000, 1000),
		teacherID: 1182644732,
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func classPayload(classes ...Class) map[string]any {
	return map[string]any{
		"classes": classes,
		"meta":    map[string]any{"has_next": false, "page": 1},
	}
}

func owned(cid int64) Class {
	return Class{ID: cid, Title: "T", Owner: 1182644732}
}

func foreign(cid int64) Class {
	return Class{ID: cid, Title: "F", Owner: 999}
}

func ownerless(cid int64) Class {
	return Class{ID: cid, Title: "?", Owner: 0}
}

func TestDisplayTitle(t *testing.T) {
	if got := (Class{ID: 1, Title: "T"}).DisplayTitle(); got != "T" {
		t.Errorf("title = %q", got)
	}
	if got := (Class{ID: 1, Name: "N"}).DisplayTitle(); got != "N" {
		t.Errorf("name = %q", got)
	}
	if got := (Class{ID: 42}).DisplayTitle(); got != "Класс 42" {
		t.Errorf("fallback = %q", got)
	}
}

func TestVerifyStudent_pathB_owned(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.RawQuery, "student=") {
			return jsonResp(200, classPayload(owned(82866), foreign(87566))), nil
		}
		return jsonResp(404, map[string]any{}), nil
	})
	classes, path, err := VerifyStudent(context.Background(), c, "user-tok", "", false, 1190530325)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if path != "B" {
		t.Errorf("path = %q, want B", path)
	}
	if len(classes) != 1 || classes[0].ID != 82866 {
		t.Errorf("classes = %+v, want only owned 82866 (owner==1182644732)", classes)
	}
}

func TestVerifyStudent_pathBDetail_resolvesOwner(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.Path, "/api/classes/") && r.URL.Path != "/api/classes" {
			return jsonResp(200, map[string]any{"classes": []Class{owned(82866)}}), nil
		}
		return jsonResp(200, classPayload(ownerless(82866))), nil
	})
	classes, path, err := VerifyStudent(context.Background(), c, "user-tok", "", false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if path != "B+detail" {
		t.Errorf("path = %q, want B+detail", path)
	}
	if len(classes) != 1 || classes[0].ID != 82866 {
		t.Errorf("classes = %+v", classes)
	}
}

func TestVerifyStudent_assistantOnlyDenied(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, classPayload(foreign(82866))), nil
	})
	classes, path, err := VerifyStudent(context.Background(), c, "user-tok", "", false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if path != "B" {
		t.Errorf("path = %q", path)
	}
	if len(classes) != 0 {
		t.Errorf("assistant-only class granted: %+v", classes)
	}
}

func TestVerifyStudent_transientFallsBackToA(t *testing.T) {
	calls := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		calls++
		q, _ := url.ParseQuery(r.URL.RawQuery)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "user-tok" {
			return jsonResp(500, map[string]any{}), nil
		}
		if tok == "teacher-tok" && q.Get("student") == "111" {
			return jsonResp(200, classPayload(owned(87566))), nil
		}
		return jsonResp(404, map[string]any{}), nil
	})
	classes, path, err := VerifyStudent(context.Background(), c, "user-tok", "teacher-tok", true, 111)
	if err != nil {
		t.Fatalf("err = %v (want A-fallback success)", err)
	}
	if path != "A-fallback" {
		t.Errorf("path = %q, want A-fallback", path)
	}
	if len(classes) != 1 || classes[0].ID != 87566 {
		t.Errorf("classes = %+v", classes)
	}
	if calls < 5 {
		t.Errorf("calls = %d, want user retries (4) + teacher fallback", calls)
	}
}

func TestVerifyStudent_transientNoTeacher_StaleOrDeny(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(500, map[string]any{}), nil
	})
	_, path, err := VerifyStudent(context.Background(), c, "user-tok", "", false, 1)
	if err == nil {
		t.Fatal("want transient error when teacher token invalid")
	}
	if !IsTransient(err) {
		t.Errorf("err type = %T, want TransientError", err)
	}
	if path != "A-expired" {
		t.Errorf("path = %q, want A-expired", path)
	}
}

func TestVerifyStudent_unauthorizedIsDefinitive(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(401, map[string]any{}), nil
	})
	_, _, err := VerifyStudent(context.Background(), c, "bad-tok", "teacher-tok", true, 1)
	if err == nil || !IsUnauthorized(err) {
		t.Errorf("err = %v, want UnauthorizedError (no A-fallback on 401)", err)
	}
}

func TestGet_retriesThenTransient(t *testing.T) {
	n := 0
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		n++
		return jsonResp(500, map[string]any{}), nil
	})
	_, err := c.GetLoggedID(context.Background(), "tok")
	if !IsTransient(err) {
		t.Errorf("err = %v, want transient after 4 attempts", err)
	}
	if n != 4 {
		t.Errorf("attempts = %d, want 4", n)
	}
}

func TestGet_429isTransient(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(429, map[string]any{}), nil
	})
	_, err := c.GetLoggedID(context.Background(), "tok")
	if !IsTransient(err) {
		t.Errorf("err = %v, want transient on 429", err)
	}
}

func TestGetLoggedID_ok(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, map[string]any{"stepics": []map[string]any{{"user": 1182644732}}}), nil
	})
	uid, err := c.GetLoggedID(context.Background(), "tok")
	if err != nil || uid != 1182644732 {
		t.Errorf("uid = %d, err = %v", uid, err)
	}
}

func TestGetProfile_ok(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, map[string]any{"users": []map[string]any{
			{"first_name": "Иван", "last_name": "Петров", "avatar": "https://cdn/a.png"},
		}}), nil
	})
	fio, avatar, err := c.GetProfile(context.Background(), "tok", 5)
	if err != nil {
		t.Fatal(err)
	}
	if fio != "Иван Петров" {
		t.Errorf("fio = %q", fio)
	}
	if avatar != "https://cdn/a.png" {
		t.Errorf("avatar = %q", avatar)
	}
}

func TestGetProfile_emptyFallsBackToID(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, map[string]any{"users": []map[string]any{{}}}), nil
	})
	fio, _, err := c.GetProfile(context.Background(), "tok", 77)
	if err != nil {
		t.Fatal(err)
	}
	if fio != "Stepik 77" {
		t.Errorf("fio = %q, want Stepik 77", fio)
	}
}

func TestRetryAfter_caps(t *testing.T) {
	if d := retryAfter("120"); d != 30*time.Second {
		t.Errorf("120s capped = %v", d)
	}
	if d := retryAfter("5"); d != 5*time.Second {
		t.Errorf("5s = %v", d)
	}
	if d := retryAfter("bogus"); d != 0 {
		t.Errorf("bogus = %v", d)
	}
	if d := retryAfter(""); d != 0 {
		t.Errorf("empty = %v", d)
	}
}

func TestListOwned_usesTeacherFilter(t *testing.T) {
	var gotQ url.Values
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		gotQ, _ = url.ParseQuery(r.URL.RawQuery)
		return jsonResp(200, classPayload(owned(1))), nil
	})
	classes, err := c.ListOwned(context.Background(), "tok")
	if err != nil || len(classes) != 1 {
		t.Fatalf("classes=%v err=%v", classes, err)
	}
	if gotQ.Get("owner_or_assistant") != "1182644732" {
		t.Errorf("filter = %v, want owner_or_assistant=1182644732", gotQ)
	}
}

func TestListPages_paginates(t *testing.T) {
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		q, _ := url.ParseQuery(r.URL.RawQuery)
		if q.Get("page") == "1" {
			return jsonResp(200, map[string]any{
				"classes": []Class{owned(1)},
				"meta":    map[string]any{"has_next": true, "page": 1},
			}), nil
		}
		return jsonResp(200, classPayload(owned(2))), nil
	})
	classes, err := c.ListByStudent(context.Background(), "tok", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 2 {
		t.Errorf("classes = %+v, want 2 pages merged", classes)
	}
}
