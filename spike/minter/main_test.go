package main

import (
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	gatejwt "github.com/zzzLobster/stepik-discuss/gate/jwt"
)

func mustMint(t *testing.T, secret, site string, uid int64, name string) (string, string) {
	t.Helper()
	signed, jti, err := gatejwt.Mint(secret, site, uid, name, "")
	if err != nil {
		t.Fatalf("mint uid=%d: %v", uid, err)
	}
	return signed, jti
}

func verify(t *testing.T, secret, site, signed string) gatejwt.Claims {
	t.Helper()
	tok, err := jwtlib.ParseWithClaims(signed, &gatejwt.Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte(secret), nil
	}, jwtlib.WithAudience(site), jwtlib.WithIssuer("remark42"))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	claims, ok := tok.Claims.(*gatejwt.Claims)
	if !ok || !tok.Valid {
		t.Fatal("token invalid")
	}
	return *claims
}

func verifyFails(t *testing.T, secret, site, signed string) {
	t.Helper()
	_, err := jwtlib.ParseWithClaims(signed, &gatejwt.Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte(secret), nil
	}, jwtlib.WithAudience(site), jwtlib.WithIssuer("remark42"))
	if err == nil {
		t.Fatal("expected verification failure, token verified")
	}
}

// TestSpikeMatrix mirrors spike/README.md expected matrix at contract level
// (no docker here): 200/200/401/401 shapes + attribution + admin mapping.
func TestSpikeMatrix(t *testing.T) {
	const secret = "spike-test-secret"
	const site = "stepik-discuss"

	teacherJWT, _ := mustMint(t, secret, site, 1182644732, "Teacher")
	studentJWT, _ := mustMint(t, secret, site, 1190530325, "Spike Student")

	expiredJWT, _, err := gatejwt.MintWithTTL(secret, site, 1190530325, "Spike Student", "", -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tampered := studentJWT[:len(studentJWT)-1] + flipLast(studentJWT[len(studentJWT)-1:])

	teacher := verify(t, secret, site, teacherJWT)
	if teacher.User.ID != "stepik_1182644732" {
		t.Errorf("teacher attribution = %q", teacher.User.ID)
	}
	student := verify(t, secret, site, studentJWT)
	if student.User.ID != "stepik_1190530325" {
		t.Errorf("student attribution = %q", student.User.ID)
	}
	if teacher.ExpiresAt == nil || student.ExpiresAt == nil {
		t.Fatal("missing exp")
	}

	verifyFails(t, secret, site, tampered)
	verifyFails(t, secret, site, expiredJWT)
	verifyFails(t, secret, site, "")
}

func TestSpikeAdminMapping(t *testing.T) {
	const adminSharedID = "stepik_1182644732"
	teacherJWT, _ := mustMint(t, "s", "stepik-discuss", 1182644732, "Teacher")
	claims := verify(t, "s", "stepik-discuss", teacherJWT)
	if claims.User.ID != adminSharedID {
		t.Errorf("teacher user.id = %q, ADMIN_SHARED_ID = %q: admin mapping broken", claims.User.ID, adminSharedID)
	}
	studentJWT, _ := mustMint(t, "s", "stepik-discuss", 1190530325, "Spike Student")
	student := verify(t, "s", "stepik-discuss", studentJWT)
	if student.User.ID == adminSharedID {
		t.Error("student maps to admin id")
	}
}

func TestFlipLast(t *testing.T) {
	if flipLast("a") != "b" {
		t.Errorf("flipLast(a) = %q", flipLast("a"))
	}
	if flipLast("x") != "a" {
		t.Errorf("flipLast(x) = %q", flipLast("x"))
	}
	for _, s := range []string{"a", "b", "Z", "9"} {
		if !strings.HasSuffix("tok"+flipLast(s), flipLast(s)) {
			t.Errorf("flipLast(%q) broken", s)
		}
	}
}
