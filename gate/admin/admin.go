package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

type Admin struct {
	Store  *sessions.Store
	Origin string
	Log    *slog.Logger
}

// validSameOrigin mirrors handlers.validSameOrigin (duplicated to avoid an
// import cycle: handlers already imports admin).
func validSameOrigin(r *http.Request, origin string) bool {
	if origin == "" {
		return false
	}
	if r.Header.Get("Origin") == origin {
		return true
	}
	if r.Header.Get("Origin") != "" {
		return false
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		return false
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return false
	}
	ou, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if ru.Scheme == "" || ru.Host == "" {
		return false
	}
	return ru.Scheme == ou.Scheme && ru.Host == ou.Host
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !validSameOrigin(r, a.Origin) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sess, _, err := auth.LoadSession(a.Store, r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !sess.IsTeacher {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !sessions.VerifyHeaderCSRF(r) {
		a.Log.Warn("admin csrf mismatch", "uid", sess.StepikUserID)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	cleaned := path.Clean(r.URL.Path)
	switch cleaned {
	case "/auth/admin/logout-all":
		a.logoutAll(w, r, sess)
	case "/auth/admin/revoke-user":
		a.revokeUser(w, r, sess)
	case "/auth/admin/revoke-class":
		a.revokeClass(w, r, sess)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (a *Admin) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private,no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *Admin) logoutAll(w http.ResponseWriter, r *http.Request, sess *sessions.SessionRecord) {
	_ = r
	epoch, err := a.Store.BumpGlobalEpoch()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "transient"})
		return
	}
	a.Log.Info("admin logout-all", "uid", sess.StepikUserID, "epoch", epoch)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "global_epoch": epoch})
}

func (a *Admin) revokeUser(w http.ResponseWriter, r *http.Request, sess *sessions.SessionRecord) {
	uid, err := strconv.ParseInt(r.FormValue("uid"), 10, 64)
	if err != nil || uid <= 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_uid"})
		return
	}
	v, err := a.Store.BumpUserVersion(uid)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "transient"})
		return
	}
	a.Log.Info("admin revoke-user", "uid", sess.StepikUserID, "target", uid)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_version": v})
}

func (a *Admin) revokeClass(w http.ResponseWriter, r *http.Request, sess *sessions.SessionRecord) {
	uid, err := strconv.ParseInt(r.FormValue("uid"), 10, 64)
	if err != nil || uid <= 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_uid"})
		return
	}
	cid, err := strconv.ParseInt(r.FormValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_cid"})
		return
	}
	n, err := a.Store.StripClass(uid, cid)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "transient"})
		return
	}
	a.Log.Info("admin revoke-class", "uid", sess.StepikUserID, "target", uid, "cid", cid)
	a.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stripped": n})
}
