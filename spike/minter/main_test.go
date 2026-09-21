package main

import (
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	gatejwt "github.com/zzzLobster/stepik-discuss/gate/jwt"
)

func mustMint(t *testing.T, secret, site string, uid int64, name string, admin bool) (string, string) {
	t.Helper()
	signed, jti, err := gatejwt.Mint(secret, site, uid, name, "", admin)
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

	teacherJWT, _ := mustMint(t, secret, site, 1182644732, "Teacher", true)
	studentJWT, _ := mustMint(t, secret, site, 1190530325, "Spike Student", false)

	expiredJWT, _, err := gatejwt.MintWithTTL(secret, site, 1190530325, "Spike Student", "", -time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamperPayload(studentJWT)

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
	teacherJWT, _ := mustMint(t, "s", "stepik-discuss", 1182644732, "Teacher", true)
	claims := verify(t, "s", "stepik-discuss", teacherJWT)
	if claims.User.ID != adminSharedID {
		t.Errorf("teacher user.id = %q, ADMIN_SHARED_ID = %q: admin mapping broken", claims.User.ID, adminSharedID)
	}
	if claims.User.Attributes["admin"] != true {
		t.Errorf("teacher attrs = %v, want admin:true for AdminOnly middleware", claims.User.Attributes)
	}
	studentJWT, _ := mustMint(t, "s", "stepik-discuss", 1190530325, "Spike Student", false)
	student := verify(t, "s", "stepik-discuss", studentJWT)
	if student.User.ID == adminSharedID {
		t.Error("student maps to admin id")
	}
}

func TestTamperPayload(t *testing.T) {
	signed, _, err := gatejwt.Mint("s", "stepik-discuss", 1, "N", "", false)
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamperPayload(signed)
	if tampered == signed {
		t.Fatal("tamperPayload did not change token")
	}
	if len(strings.Split(tampered, ".")) != 3 {
		t.Fatalf("tampered token malformed: %q", tampered)
	}
}
