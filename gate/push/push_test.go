package push

import (
	"net/http"
	"strings"
	"testing"
)

func TestCidsOrAll(t *testing.T) {
	var c CidsOrAll
	if err := c.UnmarshalJSON([]byte(`"all"`)); err != nil || !c.All {
		t.Fatalf("all parse = %v %+v", err, c)
	}
	if err := c.UnmarshalJSON([]byte(`[82866,87566]`)); err != nil || c.All || len(c.List) != 2 {
		t.Fatalf("array parse = %v %+v", err, c)
	}
	for _, bad := range []string{`[]`, `null`, `{}`, `[1,2`, `""`} {
		var x CidsOrAll
		if err := x.UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("bad %s accepted", bad)
		}
	}
}

func TestPlural(t *testing.T) {
	cases := map[int]string{
		1: "новый комментарий", 21: "новый комментарий", 101: "новый комментарий",
		2: "новых комментария", 3: "новых комментария", 4: "новых комментария", 22: "новых комментария",
		5: "новых комментариев", 0: "новых комментариев", 11: "новых комментариев", 12: "новых комментариев", 13: "новых комментариев", 14: "новых комментариев", 111: "новых комментариев",
	}
	for n, want := range cases {
		if got := plural(n); got != want {
			t.Errorf("plural(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCommentID(t *testing.T) {
	for _, ok := range []string{"abc123", "A-_0", "x", strings.Repeat("a", 64)} {
		if !IsValidCommentID(ok) {
			t.Errorf("valid %q rejected", ok)
		}
	}
	for _, bad := range []string{"", "../../", "<img>", "a b", "a/b", strings.Repeat("a", 65), "a<b", "a b"} {
		if IsValidCommentID(bad) {
			t.Errorf("bad %q accepted", bad)
		}
	}
}

func TestKeys(t *testing.T) {
	validP := "B" + strings.Repeat("A", 86)
	validA := strings.Repeat("A", 22)
	if !IsValidKeys(validP, validA) {
		t.Fatal("valid keys rejected")
	}
	if IsValidKeys("short", validA) {
		t.Error("short p256dh accepted")
	}
	if IsValidKeys(validP, "short") {
		t.Error("short auth accepted")
	}
}

func TestEndpoint(t *testing.T) {
	for _, bad := range []string{
		"http://fcm.googleapis.com/fcm/send/x",
		"https://169.254.169.254/x",
		"http://gate:8081/x",
		"https://FCM.GOOGLEAPIS.COM/x",
		"https://fcm.googleapis.com./x",
		"https://fcm.googleapis.com:8443/x",
		"https://evil.example/x",
	} {
		if IsValidEndpoint(bad) {
			t.Errorf("bad %q accepted", bad)
		}
	}
}

func TestVerifyWebhook(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	mk := func(method, remote, ct, sec string, headers map[string]string) *http.Request {
		r, _ := http.NewRequest(method, "/push/webhook", nil)
		r.RemoteAddr = remote
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if sec != "" {
			r.Header.Set("X-Push-Webhook-Secret", sec)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	if VerifyWebhook(mk("GET", "127.0.0.1:1", "application/json", secret, nil), secret) {
		t.Error("GET accepted")
	}
	if VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json", secret, nil), "") {
		t.Error("empty secret accepted")
	}
	if VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json", secret, nil), "short") {
		t.Error("short secret accepted")
	}
	if VerifyWebhook(mk("POST", "9.9.9.9:1", "application/json", secret, nil), secret) {
		t.Error("public peer accepted")
	}
	if VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json", secret, map[string]string{"X-Forwarded-For": "1.1.1.1"}), secret) {
		t.Error("XFF spoof accepted")
	}
	for _, h := range []string{"X-Forwarded-Uri", "Forwarded", "Via", "CF-Ray", "CF-Visitor", "X-Gate-Auth"} {
		if VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json", secret, map[string]string{h: "x"}), secret) {
			t.Errorf("header %s accepted", h)
		}
	}
	if !VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json; charset=utf-8", secret, nil), secret) {
		t.Error("charset CT rejected")
	}
	if VerifyWebhook(mk("POST", "127.0.0.1:1", "text/plain", secret, nil), secret) {
		t.Error("non-JSON CT accepted")
	}
	if !VerifyWebhook(mk("POST", "127.0.0.1:1", "application/json", secret, nil), secret) {
		t.Error("valid rejected")
	}
	if !VerifyWebhook(mk("POST", "10.0.0.1:1", "application/json", secret, nil), secret) {
		t.Error("private peer rejected")
	}
}

func TestSnippet(t *testing.T) {
	if got := Snippet("hello **world**", "<p>ignored</p>"); got != "hello **world**" {
		t.Errorf("orig primary = %q", got)
	}
	if got := Snippet("", "<p>hi <b>there</b></p>"); got != "hi there" {
		t.Errorf("html strip = %q", got)
	}
	if got := Snippet("", ""); got != "Новый комментарий" {
		t.Errorf("empty = %q", got)
	}
	long := strings.Repeat("a", 200)
	if got := Snippet(long, ""); len([]rune(got)) != 120 {
		t.Errorf("truncate len = %d", len([]rune(got)))
	}
}
