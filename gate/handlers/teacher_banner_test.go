package handlers

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func TestIndex_teacherBanner_teacherOnly(t *testing.T) {
	s, store := testServer(t, baseCfg())
	if s.teacherTokenValid() {
		t.Fatal("precondition: fresh test store must have no valid teacher token")
	}
	now := time.Now()
	putSess(t, store, "tb-student", &sessions.SessionRecord{
		StepikUserID: 2, FIO: "Ученик", IsTeacher: false,
		AllowedClassIDs: []int64{82866},
		ClassTitles:     map[string]string{"82866": "2025-26"},
	})
	putSess(t, store, "tb-student-stale", &sessions.SessionRecord{
		StepikUserID: 3, FIO: "Ученик", IsTeacher: false,
		AllowedClassIDs: []int64{82866},
		ClassTitles:     map[string]string{"82866": "2025-26"},
		LastVerifiedAt:  now.Add(-7 * time.Hour),
		NextRetryAt:     now.Add(5 * time.Minute),
	})
	putSess(t, store, "tb-teacher", &sessions.SessionRecord{
		StepikUserID: baseCfg().TeacherID, FIO: "Преподаватель", IsTeacher: true,
		AllowedClassIDs: []int64{82866},
		ClassTitles:     map[string]string{"82866": "2025-26"},
	})

	t.Run("student sees no teacher banner", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "tb-student")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		body := w.Body.String()
		if strings.Contains(body, RUTeacherBanner) {
			t.Errorf("student index must not contain teacher banner")
		}
		if strings.Contains(body, "/auth/login?next=") {
			t.Errorf("student index must not contain teacher re-login link")
		}
	})

	t.Run("student stale keeps transient banner but no teacher banner", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "tb-student-stale")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, RUTransient) {
			t.Errorf("stale student index missing StaleBanner RUTransient")
		}
		if strings.Contains(body, RUTeacherBanner) {
			t.Errorf("stale student index must not contain teacher banner")
		}
		if strings.Contains(body, "/auth/login?next=") {
			t.Errorf("stale student index must not contain teacher re-login link")
		}
	})

	t.Run("teacher sees banner with relogin link", func(t *testing.T) {
		w := doHTML(t, s, "GET", "/", "tb-teacher")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, RUTeacherBanner) {
			t.Fatalf("teacher index missing teacher banner")
		}
		if !strings.Contains(body, RULoginButton) {
			t.Errorf("teacher banner missing relogin button")
		}
		if !strings.Contains(body, "/auth/login?next=") {
			t.Errorf("teacher banner missing login link")
		}
	})
}
