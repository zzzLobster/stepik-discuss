package push

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"
)

// VapidKeyResp is GET /push/vapid-key → 200.
type VapidKeyResp struct {
	Key string `json:"key"`
	FP  string `json:"fp"`
}

// CidsOrAll is JSON array of int64 OR string "all". Missing/null/empty → Unmarshal error.
type CidsOrAll struct {
	All  bool
	List []int64
}

func (c *CidsOrAll) UnmarshalJSON(b []byte) error {
	if string(b) == `"all"` {
		c.All = true
		c.List = nil
		return nil
	}
	var arr []int64
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	if len(arr) == 0 {
		return errEmptyCids()
	}
	c.All = false
	c.List = arr
	return nil
}

func (c CidsOrAll) MarshalJSON() ([]byte, error) {
	if c.All {
		return []byte(`"all"`), nil
	}
	return json.Marshal(c.List)
}

func errEmptyCids() error {
	return errCidsEmpty
}

var errCidsEmpty = jsonErr("cids must be non-empty array or \"all\"")

type jsonErr string

func (e jsonErr) Error() string { return string(e) }

// SubscribeReq is POST /push/subscribe.
type SubscribeReq struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	Device struct {
		UA   string `json:"ua"`
		Name string `json:"name,omitempty"`
	} `json:"device"`
	Cids CidsOrAll `json:"cids"`
}

// UnsubscribeReq is POST /push/unsubscribe.
type UnsubscribeReq struct {
	Endpoint string `json:"endpoint"`
}

// ResubscribeReq is POST /push/resubscribe (no cids — copied from old row).
type ResubscribeReq struct {
	OldEndpoint string `json:"old_endpoint"`
	Endpoint    string `json:"endpoint"`
	Keys        struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	Device struct {
		UA string `json:"ua"`
	} `json:"device"`
}

// WebhookReq is POST /push/webhook (from remark42 template §7.1).
type WebhookReq struct {
	Site    string `json:"site"`
	PageURL string `json:"page_url"`
	Comment struct {
		ID          string `json:"id"`
		ParentID    string `json:"parent_id"`
		UserID      string `json:"user_id"`
		UserName    string `json:"user_name"`
		TextHTML    string `json:"text_html"`
		TextOrig    string `json:"text_orig"`
		CreatedUnix int64  `json:"created_unix"`
		Score       int    `json:"score"`
	} `json:"comment"`
}

// PushPayload is Gate → push service payload (≤2048B after marshal).
type PushPayload struct {
	Title     string `json:"title"`
	Body      string `json:"body"`
	Tag       string `json:"tag"`
	URL       string `json:"url"`
	Cid       int64  `json:"cid"`
	CommentID string `json:"comment_id"`
}

func plural(n int) string {
	if n%10 == 1 && n%100 != 11 {
		return "новый комментарий"
	}
	if n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14) {
		return "новых комментария"
	}
	return "новых комментариев"
}

var commentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func IsValidCommentID(id string) bool {
	return commentIDPattern.MatchString(id)
}

func IsValidKeys(p256dh, auth string) bool {
	if len(p256dh) < 87 || len(p256dh) > 88 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(p256dh)
	if err != nil {
		return false
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return false
	}
	if len(auth) < 22 || len(auth) > 24 {
		return false
	}
	araw, err := base64.RawURLEncoding.DecodeString(auth)
	if err != nil {
		return false
	}
	if len(araw) != 16 {
		return false
	}
	return true
}

func IsValidCids(c CidsOrAll, allowed []int64, isTeacher bool) bool {
	if c.All {
		return true
	}
	if len(c.List) == 0 {
		return false
	}
	if isTeacher {
		return true
	}
	set := make(map[int64]bool, len(allowed))
	for _, id := range allowed {
		set[id] = true
	}
	for _, id := range c.List {
		if !set[id] {
			return false
		}
	}
	return true
}

func IsValidEndpoint(endpoint string) bool {
	if len(endpoint) == 0 || len(endpoint) >= 2048 {
		return false
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	if u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if host != strings.ToLower(host) {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	port := u.Port()
	if port != "" && port != "443" {
		return false
	}
	normalized := strings.ToLower(strings.TrimSuffix(host, "."))
	ascii, err := idna.ToASCII(normalized)
	if err != nil || ascii == "" {
		return false
	}
	allowed := isAllowedPushHost(ascii)
	if !allowed {
		return false
	}
	if ip := net.ParseIP(ascii); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
		return true
	}
	ips, err := net.LookupIP(ascii)
	if err != nil {
		return false
	}
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
	}
	return true
}

func isAllowedPushHost(host string) bool {
	if host == "fcm.googleapis.com" {
		return true
	}
	if host == "updates.push.services.mozilla.com" {
		return true
	}
	if host == "web.push.apple.com" {
		return true
	}
	if host == "push.apple.com" {
		return false
	}
	if strings.HasSuffix(host, ".push.apple.com") {
		return true
	}
	if strings.HasSuffix(host, ".notify.windows.com") {
		return true
	}
	return false
}

// VerifyWebhook validates internal webhook guard per §4/D25.
// Returns true if request may proceed; caller must return 404 empty body on false.
func VerifyWebhook(r *http.Request, secret string) bool {
	if r.Method != http.MethodPost {
		return false
	}
	if secret == "" {
		return false
	}
	if len(secret) != 64 {
		return false
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	if !(ip.IsLoopback() || ip.IsPrivate()) {
		return false
	}
	for _, h := range []string{
		"X-Forwarded-Uri", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host",
		"Forwarded", "Via",
		"CF-Ray", "CF-Connecting-IP", "CF-Visitor", "CF-IPCountry",
		"X-Gate-Auth",
	} {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	ct := r.Header.Get("Content-Type")
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	if mt != "application/json" {
		return false
	}
	got := r.Header.Get("X-Push-Webhook-Secret")
	if got == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return false
	}
	return true
}

// TitleCache is in-memory cid → title mutex map.
type TitleCache struct {
	mu sync.Mutex
	m  map[int64]string
}

func NewTitleCache() *TitleCache {
	return &TitleCache{m: map[int64]string{}}
}

func (t *TitleCache) Set(cid int64, title string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[int64]string{}
	}
	t.m[cid] = title
}

func (t *TitleCache) Get(cid int64) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[cid]
	return v, ok
}
