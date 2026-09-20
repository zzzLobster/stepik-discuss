package handlers

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

const reloginSuffix = "?relogin=1"

const (
	htmlOutcomeAnon         = "anon"
	htmlOutcomeOK           = "ok"
	htmlOutcomeRedirect     = "redirect"
	htmlOutcomeExpiredFinal = "expired_final"
	htmlOutcomeTransient    = "transient"
	htmlOutcomeForbidden    = "forbidden"
)

type errorData struct {
	Message     string
	LoginNext   string
	LoginButton string
}

func hasReloginFlag(r *http.Request) bool {
	return r.URL.Query().Get("relogin") == "1"
}

func currentNext(r *http.Request) string {
	if r.URL.Path == "/" {
		return "/"
	}
	if m := classPathPattern.FindStringSubmatch(r.URL.Path); m != nil {
		return "/class/" + m[1]
	}
	return "/"
}

func loginURL(next string) string {
	return "/auth/login?next=" + url.QueryEscape(next)
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request, next string, withFlag bool) {
	target := next
	if withFlag {
		target += reloginSuffix
	}
	if v, ok := validNext(target); ok {
		target = v
	} else {
		target = "/"
	}
	http.Redirect(w, r, loginURL(target), http.StatusFound)
}

func (s *Server) renderExpiredFinal(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusUnauthorized, "error.html", errorData{
		Message:     RUExpired,
		LoginNext:   loginURL(currentNext(r)),
		LoginButton: RULoginButton,
	})
}

func (s *Server) renderHTMLTransient(w http.ResponseWriter) {
	s.render(w, http.StatusServiceUnavailable, "error.html", errorData{Message: RUTransient})
}

func (s *Server) renderHTMLForbidden(w http.ResponseWriter, sess *sessions.SessionRecord) {
	if len(sess.AllowedClassIDs) == 0 && !sess.IsTeacher {
		s.render(w, http.StatusForbidden, "error.html", errorData{Message: RUOutsider})
		return
	}
	s.render(w, http.StatusForbidden, "error.html", errorData{Message: RULeft})
}

// resolveHTMLSession loads the session, refreshes it via EnsureFresh, slides
// the cookie on success only, and optionally enforces class membership.
// It returns handled=true when the response was already written.
func (s *Server) resolveHTMLSession(w http.ResponseWriter, r *http.Request, cid int64, checkAllowed bool) (sess *sessions.SessionRecord, sid string, stale bool, outcome, reason string, handled bool) {
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		if errors.Is(err, auth.ErrNoSession) {
			if !checkAllowed {
				return nil, "", false, htmlOutcomeAnon, "no_session", false
			}
			s.redirectToLogin(w, r, currentNext(r), false)
			return nil, "", false, htmlOutcomeRedirect, "no_session", true
		}
		if errors.Is(err, auth.ErrExpired) {
			if hasReloginFlag(r) {
				s.renderExpiredFinal(w, r)
				return nil, "", false, htmlOutcomeExpiredFinal, "expired", true
			}
			s.redirectToLogin(w, r, currentNext(r), true)
			return nil, "", false, htmlOutcomeRedirect, "expired", true
		}
		s.renderHTMLTransient(w)
		return nil, "", false, htmlOutcomeTransient, "transient", true
	}
	stale, err = s.checker.EnsureFresh(r.Context(), sid, sess)
	if err != nil {
		if errors.Is(err, auth.ErrExpired) {
			if hasReloginFlag(r) {
				s.renderExpiredFinal(w, r)
				return nil, "", false, htmlOutcomeExpiredFinal, "expired", true
			}
			s.redirectToLogin(w, r, currentNext(r), true)
			return nil, "", false, htmlOutcomeRedirect, "expired", true
		}
		s.renderHTMLTransient(w)
		return nil, "", false, htmlOutcomeTransient, "transient", true
	}
	if auth.SlideSession(s.store, sid, sess, time.Now()) {
		sessions.SetSID(w, sid)
	}
	if checkAllowed && !auth.Allowed(sess, cid) {
		reason = "left"
		if len(sess.AllowedClassIDs) == 0 && !sess.IsTeacher {
			reason = "outsider"
		}
		s.renderHTMLForbidden(w, sess)
		return sess, sid, stale, htmlOutcomeForbidden, reason, true
	}
	if stale {
		return sess, sid, true, htmlOutcomeOK, "stale", false
	}
	return sess, sid, false, htmlOutcomeOK, "", false
}

func stripReloginSuffix(decoded string) (string, bool) {
	base, found := strings.CutSuffix(decoded, reloginSuffix)
	if !found {
		return decoded, false
	}
	if base == "" {
		return "", true
	}
	return base, true
}
