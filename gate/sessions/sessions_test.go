package sessions

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "gate.db"), testKey(t))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestEncryptToken_roundtrip(t *testing.T) {
	s := openTest(t)
	ct, nonce, err := s.EncryptToken("stepik-access-token-abc")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, []byte("stepik-access-token-abc")) {
		t.Fatal("ciphertext equals plaintext")
	}
	plain, err := s.DecryptToken(ct, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "stepik-access-token-abc" {
		t.Errorf("roundtrip = %q", plain)
	}
}

func TestEncryptToken_nonceUnique(t *testing.T) {
	s := openTest(t)
	_, n1, _ := s.EncryptToken("same")
	_, n2, _ := s.EncryptToken("same")
	if bytes.Equal(n1, n2) {
		t.Fatal("nonces reused")
	}
}

func TestDecryptToken_wrongKeyFails(t *testing.T) {
	s := openTest(t)
	ct, nonce, err := s.EncryptToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Open(filepath.Join(t.TempDir(), "other.db"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.DecryptToken(ct, nonce); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
}

func TestDecryptToken_tamperedFails(t *testing.T) {
	s := openTest(t)
	ct, nonce, err := s.EncryptToken("secret")
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	if _, err := s.DecryptToken(ct, nonce); err == nil {
		t.Fatal("decrypt of tampered ciphertext succeeded")
	}
}

func TestOpen_badKeyLength(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "x.db"), []byte("short")); err == nil {
		t.Fatal("Open with short key succeeded")
	}
}

func TestNewSID_unique64hex(t *testing.T) {
	a, err := NewSID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("duplicate SID")
	}
	if len(a) != 64 {
		t.Errorf("SID len = %d, want 64 (32B hex)", len(a))
	}
}

func TestNewBinder_16B(t *testing.T) {
	v, err := NewBinder()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 32 {
		t.Errorf("binder len = %d, want 32 (16B hex)", len(v))
	}
}

func TestSetSID_cookieAttrs(t *testing.T) {
	w := httptest.NewRecorder()
	SetSID(w, "abc")
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-sid" {
		t.Errorf("name = %q, want __Host-sid", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want / (__Host- requires Path=/)", c.Path)
	}
	if !c.Secure || !c.HttpOnly {
		t.Errorf("Secure=%v HttpOnly=%v, want both true", c.Secure, c.HttpOnly)
	}
	if c.SameSite != 2 { // SameSiteLaxMode
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != SIDMaxAgeSeconds {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, SIDMaxAgeSeconds)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, want empty (__Host- forbids Domain)", c.Domain)
	}
}

func TestClearSID_expires(t *testing.T) {
	w2 := httptest.NewRecorder()
	ClearSID(w2)
	c := w2.Result().Cookies()[0]
	if c.Name != "__Host-sid" || c.Path != "/" {
		t.Errorf("clear cookie = %v %v", c.Name, c.Path)
	}
	if c.MaxAge >= 0 {
		t.Errorf("clear MaxAge = %d, want negative", c.MaxAge)
	}
}

func TestSetBinder_cookieAttrs_pathSlash(t *testing.T) {
	w := httptest.NewRecorder()
	SetBinder(w, "binder")
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-oa" {
		t.Errorf("name = %q, want __Host-oa", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want / (__Host- cookies with Path=/auth are rejected by browsers)", c.Path)
	}
	if !c.Secure || !c.HttpOnly {
		t.Errorf("Secure=%v HttpOnly=%v, want both true", c.Secure, c.HttpOnly)
	}
	if c.MaxAge != BinderMaxAgeSeconds {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, BinderMaxAgeSeconds)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, want empty (__Host- forbids Domain)", c.Domain)
	}
}

func TestSession_putGetDelete(t *testing.T) {
	s := openTest(t)
	rec := &SessionRecord{StepikUserID: 42, FIO: "N", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.PutSession("sid1", rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession("sid1")
	if err != nil || got == nil {
		t.Fatalf("GetSession = %v, %v", got, err)
	}
	if got.StepikUserID != 42 {
		t.Errorf("uid = %d", got.StepikUserID)
	}
	if err := s.DeleteSession("sid1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetSession("sid1")
	if err != nil || got != nil {
		t.Errorf("after delete: got=%v err=%v, want nil,nil", got, err)
	}
}

func TestUserVersion_bumpInvalidates(t *testing.T) {
	s := openTest(t)
	v0, _ := s.GetUserVersion(7)
	if v0 != 0 {
		t.Fatalf("initial version = %d, want 0", v0)
	}
	v1, err := s.BumpUserVersion(7)
	if err != nil || v1 != 1 {
		t.Fatalf("bump = %d, %v; want 1", v1, err)
	}
	v2, _ := s.GetUserVersion(7)
	if v2 != 1 {
		t.Errorf("version = %d, want 1", v2)
	}
}

func TestGlobalEpoch_bump(t *testing.T) {
	s := openTest(t)
	e0, _ := s.GetGlobalEpoch()
	if e0 != 0 {
		t.Fatalf("initial epoch = %d, want 0", e0)
	}
	e1, err := s.BumpGlobalEpoch()
	if err != nil || e1 != 1 {
		t.Fatalf("bump = %d, %v; want 1", e1, err)
	}
}

func TestTeacherToken_putGet(t *testing.T) {
	s := openTest(t)
	tok, err := s.GetTeacherToken()
	if err != nil || tok != nil {
		t.Fatalf("initial teacher token = %v, %v; want nil", tok, err)
	}
	ct, nonce, _ := s.EncryptToken("teacher-plain")
	in := &TeacherToken{Ciphertext: ct, Nonce: nonce, OwnerUID: 1182644732, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.PutTeacherToken(in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTeacherToken()
	if err != nil || got == nil {
		t.Fatal("teacher token missing after put")
	}
	if got.OwnerUID != 1182644732 {
		t.Errorf("owner = %d", got.OwnerUID)
	}
	plain, err := s.DecryptToken(got.Ciphertext, got.Nonce)
	if err != nil || plain != "teacher-plain" {
		t.Errorf("decrypt = %q, %v", plain, err)
	}
}

func TestStripClass_onlyTargetUser(t *testing.T) {
	s := openTest(t)
	mk := func(uid int64, cids []int64) {
		r := &SessionRecord{StepikUserID: uid, AllowedClassIDs: cids, ClassTitles: map[string]string{}, ExpiresAt: time.Now().Add(time.Hour)}
		for _, c := range cids {
			r.ClassTitles["cid"] = "t"
			_ = c
		}
		if err := s.PutSession("sid-"+string(rune('0'+uid)), r); err != nil {
			t.Fatal(err)
		}
	}
	mk(1, []int64{100, 200})
	mk(2, []int64{100, 300})
	n, err := s.StripClass(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("stripped = %d, want 1", n)
	}
	got1, _ := s.GetSession("sid-1")
	for _, id := range got1.AllowedClassIDs {
		if id == 100 {
			t.Error("cid 100 still in uid=1 session")
		}
	}
	got2, _ := s.GetSession("sid-2")
	found := false
	for _, id := range got2.AllowedClassIDs {
		if id == 100 {
			found = true
		}
	}
	if !found {
		t.Error("cid 100 removed from uid=2 session, want untouched")
	}
}

func TestSweep_deletesOnlyExpired7d(t *testing.T) {
	s := openTest(t)
	old := &SessionRecord{StepikUserID: 1, ExpiresAt: time.Now().Add(-8 * 24 * time.Hour)}
	fresh := &SessionRecord{StepikUserID: 2, ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.PutSession("old", old); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSession("fresh", fresh); err != nil {
		t.Fatal(err)
	}
	if err := s.sweep(); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSession("old"); got != nil {
		t.Error("expired-8d session survived sweep")
	}
	if got, _ := s.GetSession("fresh"); got == nil {
		t.Error("fresh session deleted by sweep")
	}
}

func TestPing_ok(t *testing.T) {
	s := openTest(t)
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping = %v", err)
	}
}

func TestNewCSRFToken_64hex_unique(t *testing.T) {
	a, err := NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("duplicate CSRF token")
	}
	if len(a) != 64 {
		t.Errorf("len = %d, want 64 (32B hex)", len(a))
	}
}

func TestSetCSRF_cookieAttrs(t *testing.T) {
	w := httptest.NewRecorder()
	SetCSRF(w, "tok")
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-csrf" {
		t.Errorf("name = %q, want __Host-csrf", c.Name)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want /", c.Path)
	}
	if !c.Secure {
		t.Error("Secure = false, want true")
	}
	if c.HttpOnly {
		t.Error("HttpOnly = true, want false so JS can read the cookie")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.MaxAge != CSRFMaxAgeSeconds {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, CSRFMaxAgeSeconds)
	}
	if c.Domain != "" {
		t.Errorf("Domain = %q, want empty (__Host- forbids Domain)", c.Domain)
	}
}

func TestClearCSRF_expires(t *testing.T) {
	w := httptest.NewRecorder()
	ClearCSRF(w)
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-csrf" || c.Path != "/" {
		t.Errorf("clear cookie = %v %v", c.Name, c.Path)
	}
	if c.MaxAge >= 0 {
		t.Errorf("clear MaxAge = %d, want negative", c.MaxAge)
	}
}

func TestVerifyFormCSRF(t *testing.T) {
	// No cookie: deny.
	r := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	if VerifyFormCSRF(r) {
		t.Error("accepted with no cookie")
	}

	// Cookie present but form value mismatches.
	body := strings.NewReader("csrf_token=tok")
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "other"})
	if VerifyFormCSRF(r) {
		t.Error("accepted mismatched form token")
	}

	// Matching cookie and form value.
	body = strings.NewReader("csrf_token=tok")
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "tok"})
	if !VerifyFormCSRF(r) {
		t.Error("rejected matching form token")
	}

	// Token supplied only in the query string must be rejected.
	r = httptest.NewRequest(http.MethodPost, "/auth/logout?csrf_token=tok", nil)
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "tok"})
	if VerifyFormCSRF(r) {
		t.Error("accepted csrf_token from URL query string")
	}
}

func TestVerifyHeaderCSRF(t *testing.T) {
	// No cookie: deny.
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/logout-all", nil)
	if VerifyHeaderCSRF(r) {
		t.Error("accepted with no cookie")
	}

	// Cookie present but header mismatches.
	r = httptest.NewRequest(http.MethodPost, "/auth/admin/logout-all", nil)
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "tok"})
	r.Header.Set("X-CSRF-Token", "other")
	if VerifyHeaderCSRF(r) {
		t.Error("accepted mismatched header")
	}

	// Matching cookie and header.
	r = httptest.NewRequest(http.MethodPost, "/auth/admin/logout-all", nil)
	r.AddCookie(&http.Cookie{Name: CookieCSRF, Value: "tok"})
	r.Header.Set("X-CSRF-Token", "tok")
	if !VerifyHeaderCSRF(r) {
		t.Error("rejected matching header")
	}
}
