package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/zzzLobster/stepik-discuss/gate/admin"
	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
	"github.com/zzzLobster/stepik-discuss/gate/stepik"
)

// callbackRoundTripper mocks the Stepik endpoints used by the OAuth callback.
type callbackRoundTripper struct {
	teacherID int64
}

func (rt *callbackRoundTripper) jsonResp(status int, v any) *http.Response {
	body, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func (rt *callbackRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case r.URL.Path == "/token" && r.Method == http.MethodPost:
		return rt.jsonResp(http.StatusOK, map[string]any{
			"access_token":  "teacher-access",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "teacher-refresh",
		}), nil
	case r.URL.Path == "/api/stepics/1":
		return rt.jsonResp(http.StatusOK, map[string]any{
			"stepics": []map[string]any{{"user": rt.teacherID}},
		}), nil
	case strings.HasPrefix(r.URL.Path, "/api/users/"):
		return rt.jsonResp(http.StatusOK, map[string]any{
			"users": []map[string]any{{
				"first_name": "Teach",
				"last_name":  "Er",
				"avatar":     "https://example/a.png",
			}},
		}), nil
	case r.URL.Path == "/api/classes":
		return rt.jsonResp(http.StatusOK, map[string]any{
			"classes": []map[string]any{{
				"id":    82866,
				"title": "2025-26",
				"owner": rt.teacherID,
			}},
			"meta": map[string]any{"has_next": false, "page": 1},
		}), nil
	default:
		return rt.jsonResp(http.StatusNotFound, map[string]any{}), nil
	}
}

func TestCallback_teacherTokenPutFailure(t *testing.T) {
	cfg := baseCfg()
	store := testStore(t)
	log := testLogger()

	mockStep := stepik.New(cfg.TeacherID, log, stepik.WithHTTPClient(&http.Client{
		Transport: &callbackRoundTripper{teacherID: cfg.TeacherID},
	}))
	mockStep.TokenURL = "http://stepik.org/token"

	limits := ratelimit.NewStore()
	checker := &auth.Checker{
		Cfg:    cfg,
		Store:  store,
		Stepik: mockStep,
		Limits: limits,
		Log:    log,
		PutTeacherTokenFn: func(*sessions.TeacherToken) error {
			return errors.New("simulated PutTeacherToken failure")
		},
	}
	adm := &admin.Admin{Store: store, Origin: cfg.Origin, Log: log}
	s := New(cfg, store, mockStep, limits, checker, adm, log, testTemplates(t), os.DirFS("../static"))

	binder := "binder-put-fail"
	state, err := s.newState("/", binder, "1.2.3.4")
	if err != nil {
		t.Fatalf("newState: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=code1&state="+state, nil)
	r.RemoteAddr = "1.2.3.4:1"
	r.AddCookie(&http.Cookie{Name: sessions.CookieBinder, Value: binder})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on PutTeacherToken failure", w.Code)
	}
	if !strings.Contains(w.Body.String(), RUTransient) {
		t.Errorf("body missing RUTransient: %s", w.Body.String())
	}
}
