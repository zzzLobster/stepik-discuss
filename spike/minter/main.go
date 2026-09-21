package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	gatejwt "github.com/zzzLobster/stepik-discuss/gate/jwt"
)

type userInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	Admin   bool   `json:"admin"`
}

func call(client *http.Client, method, url, jwt, xsrf string, body any) (int, []byte) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(2)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(2)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if jwt != "" {
		req.Header.Set("X-JWT", jwt)
	}
	if xsrf != "" {
		req.Header.Set("X-XSRF-TOKEN", xsrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "do:", err)
		os.Exit(2)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw
}

func main() {
	secret := flag.String("secret", os.Getenv("REMARK_JWT_SECRET"), "shared remark42 SECRET")
	base := flag.String("base", "http://127.0.0.1:8080/discuss", "remark42 base URL behind spike caddy")
	site := flag.String("site", "stepik-discuss", "remark42 site id (JWT aud)")
	flag.Parse()
	if *secret == "" {
		fmt.Fprintln(os.Stderr, "missing -secret / REMARK_JWT_SECRET")
		os.Exit(2)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	// remark42 matchSiteID requires explicit ?site= matching token aud on all
	// protected routes (bundled frontend always sends it); omit => 403.
	userURL := *base + "/api/v1/user?site=" + *site
	commentURL := *base + "/api/v1/comment?site=" + *site

	teacherJWT, teacherJTI, err := gatejwt.Mint(*secret, *site, 1182644732, "Михаил Гаврилов", "", true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint teacher:", err)
		os.Exit(2)
	}
	studentJWT, studentJTI, err := gatejwt.Mint(*secret, *site, 1190530325, "Spike Student", "", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint student:", err)
		os.Exit(2)
	}
	expiredJWT, expiredJTI, err := gatejwt.MintWithTTL(*secret, *site, 1190530325, "Spike Student", "", -time.Minute, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint expired:", err)
		os.Exit(2)
	}
	tampered := tamperPayload(studentJWT)

	type verdict struct {
		name   string
		status int
		want   int
		body   []byte
	}
	var results []verdict

	st, body := call(client, http.MethodGet, userURL, teacherJWT, teacherJTI, nil)
	results = append(results, verdict{"valid teacher GET /user", st, 200, body})
	var teacher userInfo
	_ = json.Unmarshal(body, &teacher)

	st, body = call(client, http.MethodGet, userURL, studentJWT, studentJTI, nil)
	results = append(results, verdict{"valid student GET /user", st, 200, body})

	st, body = call(client, http.MethodGet, userURL, tampered, studentJTI, nil)
	results = append(results, verdict{"tampered GET /user", st, 401, body})

	st, body = call(client, http.MethodGet, userURL, expiredJWT, expiredJTI, nil)
	results = append(results, verdict{"expired GET /user", st, 401, body})

	st, body = call(client, http.MethodGet, userURL, "", "", nil)
	results = append(results, verdict{"no-cookie GET /user", st, 401, body})

	pageURL := "https://stepik.study67.fyi/class/82866"
	comment := map[string]any{
		"text":    "spike teacher probe",
		"locator": map[string]string{"site": *site, "url": pageURL},
	}
	st, body = call(client, http.MethodPost, commentURL, teacherJWT, teacherJTI, comment)
	teacherPost := st == http.StatusCreated || st == http.StatusOK
	fmt.Printf("teacher POST /comment -> %d\n", st)
	comment["text"] = "spike student probe"
	time.Sleep(3 * time.Second) // stay under remark42 update limiter (0.5/s default)
	st, body = call(client, http.MethodPost, commentURL, studentJWT, studentJTI, comment)
	studentPost := st == http.StatusCreated || st == http.StatusOK
	fmt.Printf("student POST /comment -> %d\n", st)

	// functional admin probe: teacher must reach admin API, student must not.
	// (/user admin flag alone is display-only; AdminOnly middleware is authoritative.)
	adminURL := *base + "/api/v1/admin/blocked?site=" + *site
	st, body = call(client, http.MethodGet, adminURL, teacherJWT, teacherJTI, nil)
	results = append(results, verdict{"teacher GET /admin/blocked", st, 200, body})
	st, body = call(client, http.MethodGet, adminURL, studentJWT, studentJTI, nil)
	results = append(results, verdict{"student GET /admin/blocked", st, 403, body})

	ok := true
	for _, r := range results {
		mark := "PASS"
		if r.status != r.want {
			mark = "FAIL"
			ok = false
		}
		fmt.Printf("[%s] %s -> %d (want %d) body=%.200s\n", mark, r.name, r.status, r.want, strings.TrimSpace(string(r.body)))
	}
	for _, want := range []struct {
		name string
		got  bool
	}{{"teacher post attributed", teacherPost}, {"student post attributed", studentPost}} {
		mark := "PASS"
		if !want.got {
			mark = "FAIL"
			ok = false
		}
		fmt.Printf("[%s] %s\n", mark, want.name)
	}
	adminMark := "PASS"
	if !teacher.Admin {
		adminMark = "FAIL"
		ok = false
	}
	fmt.Printf("[%s] admin mapping stepik_1182644732 (admin=%v)\n", adminMark, teacher.Admin)
	if !ok {
		os.Exit(1)
	}
	fmt.Println("SPIKE VERDICT: JWT shape (b) works with stock remark42.")
}

// tamperPayload flips a character in the JWT payload segment so the signature
// no longer matches the content. Flipping the last character of the token is
// unreliable because it is often base64 padding ('=') and remains valid.
func tamperPayload(signed string) string {
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		return signed
	}
	payload := parts[1]
	if len(payload) == 0 {
		return signed
	}
	flip := "a"
	if payload[0] == 'a' {
		flip = "b"
	}
	parts[1] = flip + payload[1:]
	return strings.Join(parts, ".")
}
