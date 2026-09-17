package jwt

import (
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

func parse(t *testing.T, secret, audience, signed string) *Claims {
	t.Helper()
	tok, err := jwtlib.ParseWithClaims(signed, &Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte(secret), nil
	}, jwtlib.WithAudience(audience), jwtlib.WithIssuer("remark42"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		t.Fatalf("token invalid: ok=%v valid=%v", ok, tok.Valid)
	}
	return claims
}

func TestMint_shape(t *testing.T) {
	signed, jti, err := Mint("test-secret-0123456789", "stepik-discuss", 1182644732, "Teacher Name", "https://cdn/avatar.png", true)
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}
	if len(jti) != 32 {
		t.Fatalf("jti must be 16B hex (32 chars), got %q", jti)
	}
	claims := parse(t, "test-secret-0123456789", "stepik-discuss", signed)
	if claims.Issuer != "remark42" {
		t.Errorf("iss = %q, want remark42", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "stepik-discuss" {
		t.Errorf("aud = %v, want [stepik-discuss]", claims.Audience)
	}
	if claims.User.ID != "stepik_1182644732" {
		t.Errorf("user.id = %q, want stepik_1182644732", claims.User.ID)
	}
	if claims.User.Name != "Teacher Name" {
		t.Errorf("user.name = %q", claims.User.Name)
	}
	if claims.ID != jti {
		t.Errorf("jti claim %q != returned jti %q", claims.ID, jti)
	}
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Errorf("exp ttl = %v, want ~5m (300s)", ttl)
	}
	if tok, _ := jwtlib.Parse(signed, func(*jwtlib.Token) (any, error) { return []byte("x"), nil }); tok == nil {
		t.Fatal("token unparseable")
	} else if _, ok := tok.Method.(*jwtlib.SigningMethodHMAC); !ok {
		t.Errorf("signing method = %T, want HS256 HMAC", tok.Method)
	}
	if !strings.HasPrefix(signed, "eyJ") {
		t.Errorf("token does not look like compact JWT: %q", signed[:10])
	}
}

func TestMint_studentAttribution(t *testing.T) {
	signed, _, err := Mint("s", "stepik-discuss", 1190530325, "Spike Student", "", false)
	if err != nil {
		t.Fatal(err)
	}
	claims := parse(t, "s", "stepik-discuss", signed)
	if claims.User.ID != "stepik_1190530325" {
		t.Errorf("user.id = %q, want stepik_1190530325", claims.User.ID)
	}
}

func TestMint_adminAttr(t *testing.T) {
	teacher, _, err := Mint("s", "stepik-discuss", 1182644732, "Teacher", "", true)
	if err != nil {
		t.Fatal(err)
	}
	tc := parse(t, "s", "stepik-discuss", teacher)
	if tc.User.Attributes["admin"] != true {
		t.Errorf("teacher attrs = %v, want map[admin:true]", tc.User.Attributes)
	}
	student, _, err := Mint("s", "stepik-discuss", 1190530325, "Student", "", false)
	if err != nil {
		t.Fatal(err)
	}
	sc := parse(t, "s", "stepik-discuss", student)
	if len(sc.User.Attributes) != 0 {
		t.Errorf("student attrs = %v, want empty", sc.User.Attributes)
	}
}

func TestMint_neverSubEmail(t *testing.T) {
	signed, _, err := Mint("s", "stepik-discuss", 1, "N", "", false)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(signed)
	_ = lower
	parser := jwtlib.NewParser()
	tok, _, err := parser.ParseUnverified(signed, &Claims{})
	if err != nil {
		t.Fatal(err)
	}
	raw := tok.Claims.(*Claims)
	if raw.Subject != "" {
		t.Errorf("sub must be empty, got %q", raw.Subject)
	}
}

func TestMint_tamperedRejected(t *testing.T) {
	signed, jti, err := Mint("s", "stepik-discuss", 1190530325, "Spike Student", "", false)
	if err != nil {
		t.Fatal(err)
	}
	last := signed[len(signed)-1:]
	flip := "a"
	if strings.HasSuffix(signed, "a") {
		flip = "b"
	}
	_ = last
	tampered := signed[:len(signed)-1] + flip
	_, err = jwtlib.ParseWithClaims(tampered, &Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte("s"), nil
	}, jwtlib.WithAudience("stepik-discuss"), jwtlib.WithIssuer("remark42"))
	if err == nil {
		t.Fatalf("tampered token verified (jti=%s)", jti)
	}
}

func TestMint_expiredRejected(t *testing.T) {
	signed, _, err := MintWithTTL("s", "stepik-discuss", 1190530325, "Spike Student", "", -time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtlib.ParseWithClaims(signed, &Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte("s"), nil
	}, jwtlib.WithAudience("stepik-discuss"), jwtlib.WithIssuer("remark42"))
	if err == nil {
		t.Fatal("expired token verified")
	}
}

func TestMint_wrongSecretRejected(t *testing.T) {
	signed, _, err := Mint("correct", "stepik-discuss", 1, "N", "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtlib.ParseWithClaims(signed, &Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte("wrong"), nil
	}, jwtlib.WithAudience("stepik-discuss"), jwtlib.WithIssuer("remark42"))
	if err == nil {
		t.Fatal("wrong-secret token verified")
	}
}

func TestMint_wrongAudienceRejected(t *testing.T) {
	signed, _, err := Mint("s", "stepik-discuss", 1, "N", "", false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtlib.ParseWithClaims(signed, &Claims{}, func(tok *jwtlib.Token) (any, error) {
		return []byte("s"), nil
	}, jwtlib.WithAudience("other-site"), jwtlib.WithIssuer("remark42"))
	if err == nil {
		t.Fatal("wrong-audience token verified")
	}
}

func TestMint_jtiUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 10 {
		_, jti, err := Mint("s", "stepik-discuss", 1, "N", "", false)
		if err != nil {
			t.Fatal(err)
		}
		if seen[jti] {
			t.Fatal("duplicate jti")
		}
		seen[jti] = true
	}
}
