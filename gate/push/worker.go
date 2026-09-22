package push

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/microcosm-cc/bluemonday"
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/zzzLobster/stepik-discuss/gate/auth"
	"github.com/zzzLobster/stepik-discuss/gate/config"
	"github.com/zzzLobster/stepik-discuss/gate/sessions"
)

type Job struct {
	Cid        int64
	CommentID  string
	AuthorUID  int64
	AuthorName string
	Snippet    string
	Attempt    int
}

type coalesceEntry struct {
	count      int
	latestID   string
	authorUIDs []int64
	timer      *time.Timer
}

type Sender func(ctx context.Context, payload []byte, sub *sessions.PushSub, opts *webpush.Options) (*http.Response, error)

func defaultSender(ctx context.Context, payload []byte, sub *sessions.PushSub, opts *webpush.Options) (*http.Response, error) {
	s := &webpush.Subscription{Endpoint: sub.Endpoint, Keys: webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth}}
	return webpush.SendNotificationWithContext(ctx, payload, s, opts)
}

type Worker struct {
	cfg    config.Config
	store  *sessions.Store
	check  *auth.Checker
	log    *slog.Logger
	queue  chan Job
	titles *TitleCache
	send   Sender

	mu       sync.Mutex
	coalesce map[int64]*coalesceEntry
}

func NewWorker(cfg config.Config, store *sessions.Store, check *auth.Checker, log *slog.Logger, titles *TitleCache) *Worker {
	if titles == nil {
		titles = NewTitleCache()
	}
	w := &Worker{
		cfg:      cfg,
		store:    store,
		check:    check,
		log:      log,
		queue:    make(chan Job, 512),
		titles:   titles,
		send:     defaultSender,
		coalesce: map[int64]*coalesceEntry{},
	}
	for range 4 {
		go w.loop()
	}
	return w
}

func (w *Worker) QueueLen() int {
	return len(w.queue)
}

func (w *Worker) Enqueue(j Job) bool {
	select {
	case w.queue <- j:
		return true
	default:
		w.log.Warn("push_queue_drop", "cid", j.Cid)
		return false
	}
}

func (w *Worker) loop() {
	for j := range w.queue {
		w.handleJob(j)
	}
}

func (w *Worker) handleJob(j Job) {
	w.mu.Lock()
	e, ok := w.coalesce[j.Cid]
	if !ok {
		e = &coalesceEntry{count: 1, latestID: j.CommentID, authorUIDs: []int64{j.AuthorUID}}
		e.timer = time.AfterFunc(30*time.Second, func() { w.flush(j.Cid) })
		w.coalesce[j.Cid] = e
		w.mu.Unlock()
		w.sendImmediate(j)
		return
	}
	e.count++
	e.latestID = j.CommentID
	found := false
	for _, id := range e.authorUIDs {
		if id == j.AuthorUID {
			found = true
			break
		}
	}
	if !found {
		e.authorUIDs = append(e.authorUIDs, j.AuthorUID)
	}
	count := e.count
	latest := e.latestID
	authors := append([]int64(nil), e.authorUIDs...)
	w.mu.Unlock()
	_ = count
	_ = latest
	_ = authors
}

func (w *Worker) flush(cid int64) {
	w.mu.Lock()
	e, ok := w.coalesce[cid]
	if !ok {
		w.mu.Unlock()
		return
	}
	delete(w.coalesce, cid)
	count := e.count
	latest := e.latestID
	authors := e.authorUIDs
	w.mu.Unlock()
	if count <= 1 {
		return
	}
	w.sendSummary(cid, count, latest, authors)
}

func (w *Worker) titleFor(cid int64) string {
	if t, ok := w.titles.Get(cid); ok && t != "" {
		return truncateRunes(t, 100)
	}
	return "Класс " + strconv.FormatInt(cid, 10)
}

func (w *Worker) sendImmediate(j Job) {
	subs, err := w.store.SnapshotPushSubs()
	if err != nil {
		return
	}
	title := w.titleFor(j.Cid) + " — новый комментарий"
	author := j.AuthorName
	if author == "" {
		if rec, _ := w.store.BestSessionForUID(j.AuthorUID, w.cfg.VerifyTTL); rec != nil {
			author = rec.FIO
		}
	}
	body := j.Snippet
	if author != "" && body != "" {
		body = author + ": " + body
	} else if author != "" {
		body = author
	}
	if body == "" {
		body = "Новый комментарий"
	}
	for _, sub := range subs {
		w.sendToSub(sub, j.Cid, title, body, j.CommentID, j.AuthorUID, j.Attempt)
	}
}

func (w *Worker) sendSummary(cid int64, count int, latestID string, authorUIDs []int64) {
	subs, err := w.store.SnapshotPushSubs()
	if err != nil {
		return
	}
	title := w.titleFor(cid)
	ownSet := map[int64]bool{}
	for _, id := range authorUIDs {
		ownSet[id] = true
	}
	_ = ownSet
	for _, sub := range subs {
		ownCount := 0
		for _, id := range authorUIDs {
			if id == sub.UID {
				ownCount++
			}
		}
		n := count - ownCount
		if n <= 0 {
			continue
		}
		body := strconv.Itoa(n) + " " + plural(n)
		w.sendToSub(sub, cid, title, body, latestID, 0, 0)
	}
}

func (w *Worker) sendToSub(sub sessions.PushSub, cid int64, title, body, commentID string, authorUID int64, attempt int) {
	if authorUID != 0 && sub.UID == authorUID {
		return
	}
	best, _ := w.store.BestSessionForUID(sub.UID, w.cfg.VerifyTTL)
	if best != nil {
		allowed := false
		if best.IsTeacher {
			allowed = true
		} else {
			for _, id := range best.AllowedClassIDs {
				if id == cid {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			w.log.Info("push_skip_revoked", "cid", cid)
			return
		}
	} else {
		if sub.All {
			return
		}
		found := false
		for _, id := range sub.Cids {
			if id == cid {
				found = true
				break
			}
		}
		if !found {
			return
		}
		maxT := sub.CreatedAt
		if sub.LastOkAt.After(maxT) {
			maxT = sub.LastOkAt
		}
		if time.Since(maxT) >= 24*time.Hour {
			return
		}
	}
	priv := w.cfg.VapidPrivateKey
	pub := w.cfg.VapidPublicKey
	if sub.KeyVersion != "" && sub.KeyVersion != config.VapidFP8(pub) {
		if w.cfg.VapidPublicKeyOld != "" && sub.KeyVersion == config.VapidFP8(w.cfg.VapidPublicKeyOld) {
			priv = ""
		} else {
			w.log.Info("push_skip_unknown_key", "cid", cid)
			return
		}
		if priv == "" {
			w.log.Info("push_skip_unknown_key", "cid", cid)
			return
		}
	}
	_ = pub
	url := "/class/" + strconv.FormatInt(cid, 10) + "#remark-" + commentID
	if !strings.HasPrefix(url, "/class/") {
		return
	}
	if !IsValidCommentID(commentID) {
		return
	}
	payload := PushPayload{Title: truncateRunes(title, 100), Body: body, Tag: "cid-" + strconv.FormatInt(cid, 10), URL: url, Cid: cid, CommentID: commentID}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for len(raw) > 2048 && len(body) > 0 {
		body = truncateRunes(body, len([]rune(body))-10)
		payload.Body = body
		raw, err = json.Marshal(payload)
		if err != nil {
			return
		}
	}
	if len(raw) > 2048 {
		return
	}
	if err := checkRebind(sub.Endpoint); err != nil {
		w.log.Info("push_skip_ssrf_rebind", "cid", cid)
		_ = w.store.DeletePushSub(sub.Endpoint)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := w.send(ctx, raw, &sub, &webpush.Options{
		Subscriber:      w.cfg.VapidSubject,
		VAPIDPublicKey:  w.cfg.VapidPublicKey,
		VAPIDPrivateKey: priv,
		TTL:             86400,
		Topic:           "class-" + strconv.FormatInt(cid, 10),
		Urgency:         webpush.UrgencyNormal,
	})
	lat := time.Since(start).Milliseconds()
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	uidHash := hash8(strconv.FormatInt(sub.UID, 10))
	epHash := hash8(sub.Endpoint)
	if err != nil {
		w.log.Info("push_send", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", "transient", "latency_ms", lat)
		w.retryOrPark(sub, Job{Cid: cid, CommentID: commentID, Attempt: attempt}, 0)
		return
	}
	switch {
	case status == 404 || status == 410:
		w.log.Info("push_prune", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", status)
		_ = w.store.DeletePushSub(sub.Endpoint)
		return
	case status == 400 || status == 413 || status == 415:
		w.log.Info("push_prune", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", status)
		_ = w.store.DeletePushSub(sub.Endpoint)
		return
	case status == 403:
		w.log.Info("push_403_key_mismatch", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash)
		return
	case status == 429 || (status >= 500 && status <= 599):
		retryAfter := parseRetryAfter(resp)
		w.log.Info("push_send", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", status, "latency_ms", lat)
		w.retryOrPark(sub, Job{Cid: cid, CommentID: commentID, Attempt: attempt}, retryAfter)
		return
	case status >= 200 && status < 300:
		w.log.Info("push_send", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", status, "latency_ms", lat)
		if best != nil {
			cur, err := w.store.GetPushSub(sub.Endpoint)
			if err == nil && cur != nil {
				cur.LastOkAt = time.Now()
				cur.FailCount = 0
				_ = w.store.PutPushSub(cur)
			}
		}
		return
	default:
		w.log.Info("push_send", "uid_hash8", uidHash, "cid", cid, "endpoint_hash8", epHash, "status", status, "latency_ms", lat)
		return
	}
}

func (w *Worker) retryOrPark(sub sessions.PushSub, j Job, retryAfter time.Duration) {
	cur, err := w.store.GetPushSub(sub.Endpoint)
	if err != nil || cur == nil {
		return
	}
	if cur.FailCount >= 3 || j.Attempt >= 3 {
		return
	}
	cur.FailCount++
	_ = w.store.PutPushSub(cur)
	delays := []time.Duration{time.Second, 30 * time.Second, 5 * time.Minute}
	d := delays[j.Attempt%len(delays)]
	if retryAfter > 0 {
		if retryAfter > 5*time.Minute {
			retryAfter = 5 * time.Minute
		}
		d = retryAfter
	}
	j.Attempt++
	time.AfterFunc(d, func() {
		best, _ := w.store.BestSessionForUID(sub.UID, w.cfg.VerifyTTL)
		_ = best
		row, err := w.store.GetPushSub(sub.Endpoint)
		if err != nil || row == nil {
			return
		}
		if row.FailCount > 3 {
			return
		}
		select {
		case w.queue <- j:
		default:
			w.log.Warn("push_queue_drop", "cid", j.Cid)
		}
	})
}

func parseRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
		if n < 0 {
			return 0
		}
		d := time.Duration(n) * time.Second
		if d > 5*time.Minute {
			d = 5 * time.Minute
		}
		return d
	}
	return 0
}

func Snippet(orig, html string) string {
	s := strings.TrimSpace(orig)
	if s == "" {
		p := bluemonday.StrictPolicy()
		s = p.Sanitize(html)
	}
	s = stripControls(s)
	s = collapseWS(s)
	s = truncateRunes(s, 120)
	if s == "" {
		return "Новый комментарий"
	}
	return s
}

func stripControls(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func hash8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

func checkRebind(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return errBadHost()
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return errBadHost()
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return errBadHost()
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return errBadHost()
		}
	}
	return nil
}

func errBadHost() error {
	return errRebind
}

var errRebind = errString("bad host")

type errString string

func (e errString) Error() string { return string(e) }
