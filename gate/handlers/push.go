package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/config"
	"github.com/zzzLobster/stepik-discuss/gate/push"
	"github.com/zzzLobster/stepik-discuss/gate/ratelimit"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

func (s *Server) writePushJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private,no-store")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writePushError(w http.ResponseWriter, status int, code string) {
	s.writePushJSON(w, status, map[string]string{"error": code})
}

func (s *Server) checkPushIP(w http.ResponseWriter, r *http.Request) bool {
	ip := ratelimit.ClientIP(r)
	ok, retryAfter := s.limits.AllowPushByIP(ip)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private,no-store")
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate_limited"})
		return false
	}
	return true
}

func (s *Server) checkPushSID(w http.ResponseWriter, sid string) bool {
	ok, retryAfter := s.limits.AllowPush(sid)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private,no-store")
		w.Header().Set("X-Robots-Tag", "noindex")
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate_limited"})
		return false
	}
	return true
}

func canonicalOriginExact(r *http.Request, origin string) bool {
	if origin == "" {
		return false
	}
	got := r.Header.Get("Origin")
	if got == "" {
		return false
	}
	if got == "null" {
		return false
	}
	return got == origin
}

func pushHash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

func sanitizePushStr(v string, max int) string {
	v = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, v)
	r := []rune(v)
	if len(r) > max {
		r = r[:max]
	}
	return string(r)
}

func (s *Server) cacheTitlesFromSession(sess *sessions.SessionRecord) {
	if sess == nil || len(sess.ClassTitles) == 0 {
		return
	}
	for k, title := range sess.ClassTitles {
		if title == "" {
			continue
		}
		cid, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			continue
		}
		if cur, ok := s.titles.Get(cid); ok && cur == title {
			continue
		}
		s.titles.Set(cid, title)
	}
}

func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	raw, err := fs.ReadFile(s.staticFS, "offline.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public,max-age=3600")
	_, _ = w.Write(raw)
}

func (s *Server) handleVapidKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.checkPushIP(w, r) {
		return
	}
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		s.writePushError(w, http.StatusUnauthorized, "auth_required")
		return
	}
	_ = sess
	if !s.checkPushSID(w, sid) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(push.VapidKeyResp{
		Key: s.cfg.VapidPublicKey,
		FP:  config.VapidFP8(s.cfg.VapidPublicKey),
	})
}

func (s *Server) handlePushSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.checkPushIP(w, r) {
		return
	}
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		s.writePushError(w, http.StatusUnauthorized, "auth_required")
		return
	}
	if !validSameOrigin(r, s.cfg.Origin) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !sessions.VerifyHeaderCSRF(r) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkPushSID(w, sid) {
		return
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req push.SubscribeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !push.IsValidEndpoint(req.Endpoint) {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !push.IsValidKeys(req.Keys.P256dh, req.Keys.Auth) {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !push.IsValidCids(req.Cids, sess.AllowedClassIDs, sess.IsTeacher) {
		if len(req.Cids.List) == 0 && !req.Cids.All {
			s.writePushError(w, http.StatusBadRequest, "bad_request")
			return
		}
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	ua := sanitizePushStr(req.Device.UA, 256)
	name := sanitizePushStr(req.Device.Name, 64)
	_ = name
	now := time.Now()
	existing, _ := s.store.GetPushSub(req.Endpoint)
	created := now
	if existing != nil {
		created = existing.CreatedAt
		if created.IsZero() {
			created = now
		}
	}
	sub := &sessions.PushSub{
		UID:        sess.StepikUserID,
		SID:        sid,
		Endpoint:   req.Endpoint,
		P256dh:     req.Keys.P256dh,
		Auth:       req.Keys.Auth,
		Cids:       req.Cids.List,
		All:        req.Cids.All,
		UA:         ua,
		KeyVersion: config.VapidFP8(s.cfg.VapidPublicKey),
		CreatedAt:  created,
		FailCount:  0,
	}
	if existing != nil {
		sub.LastOkAt = existing.LastOkAt
	}
	if err := s.store.PutPushSub(sub); err != nil {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	s.cacheTitlesFromSession(sess)
	s.writePushJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePushUnsubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.checkPushIP(w, r) {
		return
	}
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		s.writePushError(w, http.StatusUnauthorized, "auth_required")
		return
	}
	if !validSameOrigin(r, s.cfg.Origin) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !sessions.VerifyHeaderCSRF(r) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkPushSID(w, sid) {
		return
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req push.UnsubscribeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Endpoint == "" {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	row, err := s.store.GetPushSub(req.Endpoint)
	if err != nil {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if row == nil {
		s.writePushJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if row.UID == sess.StepikUserID {
		_ = s.store.DeletePushSub(req.Endpoint)
		s.writePushJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	best, _ := s.store.BestSessionForUID(row.UID, s.cfg.VerifyTTL)
	if best != nil {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	_ = s.store.DeletePushSub(req.Endpoint)
	s.writePushJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePushResubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.checkPushIP(w, r) {
		return
	}
	sess, sid, err := auth.LoadSession(s.store, r)
	if err != nil {
		s.writePushError(w, http.StatusUnauthorized, "auth_required")
		return
	}
	if !canonicalOriginExact(r, s.cfg.CanonicalOrigin()) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkPushSID(w, sid) {
		return
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req push.ResubscribeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if req.OldEndpoint == "" {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	old, err := s.store.GetPushSub(req.OldEndpoint)
	if err != nil || old == nil || old.UID != sess.StepikUserID {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !push.IsValidEndpoint(req.Endpoint) {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !push.IsValidKeys(req.Keys.P256dh, req.Keys.Auth) {
		s.writePushError(w, http.StatusBadRequest, "bad_request")
		return
	}
	copied := push.CidsOrAll{All: old.All, List: old.Cids}
	if !push.IsValidCids(copied, sess.AllowedClassIDs, sess.IsTeacher) {
		s.writePushError(w, http.StatusForbidden, "forbidden")
		return
	}
	ua := sanitizePushStr(req.Device.UA, 256)
	now := time.Now()
	created := old.CreatedAt
	if created.IsZero() {
		created = now
	}
	_ = s.store.DeletePushSub(req.OldEndpoint)
	sub := &sessions.PushSub{
		UID:        sess.StepikUserID,
		SID:        sid,
		Endpoint:   req.Endpoint,
		P256dh:     req.Keys.P256dh,
		Auth:       req.Keys.Auth,
		Cids:       old.Cids,
		All:        old.All,
		UA:         ua,
		KeyVersion: config.VapidFP8(s.cfg.VapidPublicKey),
		CreatedAt:  created,
		LastOkAt:   old.LastOkAt,
		FailCount:  0,
	}
	_ = s.store.PutPushSub(sub)
	s.writePushJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePushWebhook(w http.ResponseWriter, r *http.Request) {
	if !push.VerifyWebhook(r, s.cfg.PushWebhookSecret) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		remote := r.RemoteAddr
		s.log.Warn("push_webhook_bad_body", "remote_hash8", pushHash8(remote), "bytes", 0, "reason", "read")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	var req push.WebhookReq
	if err := json.Unmarshal(raw, &req); err != nil {
		s.log.Warn("push_webhook_bad_body", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw), "reason", "parse")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	cid, err := auth.ExtractCIDWithConfig("", req.PageURL, s.cfg.ClassBase(), s.cfg.EmbedHost())
	if err != nil {
		s.log.Warn("push_webhook_bad_url", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	if req.Site != s.cfg.Site {
		s.log.Warn("push_webhook_bad_site", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	var authorUID int64
	if strings.HasPrefix(req.Comment.UserID, "stepik_") {
		if n, perr := strconv.ParseInt(strings.TrimPrefix(req.Comment.UserID, "stepik_"), 10, 64); perr == nil {
			authorUID = n
		} else {
			s.log.Warn("push_webhook_bad_author", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw))
		}
	} else {
		s.log.Warn("push_webhook_bad_author", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw))
	}
	if !push.IsValidCommentID(req.Comment.ID) {
		s.log.Warn("push_webhook_bad_id", "remote_hash8", pushHash8(r.RemoteAddr), "bytes", len(raw))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	snippet := push.Snippet(req.Comment.TextOrig, req.Comment.TextHTML)
	ok := s.worker.Enqueue(push.Job{Cid: cid, CommentID: req.Comment.ID, AuthorUID: authorUID, AuthorName: req.Comment.UserName, Snippet: snippet})
	subs, _ := s.store.PushSubsCount()
	if !ok {
		s.log.Warn("push_queue_drop", "cid", cid)
	}
	s.log.Info("push_webhook", "cid", cid, "comment_id", req.Comment.ID, "author_hash8", pushHash8(strconv.FormatInt(authorUID, 10)), "sub_count", subs)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) handlePushHealth(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("deep") == "1" {
		if !auth.Guard(r, s.cfg.GateToken) {
			http.NotFound(w, r)
			return
		}
		subs, _ := s.store.PushSubsCount()
		q := 0
		if s.worker != nil {
			q = s.worker.QueueLen()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "subs": subs, "queue": q})
		return
	}
	if !s.checkPushIP(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}
