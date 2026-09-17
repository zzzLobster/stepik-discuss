package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type RemarkUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type Claims struct {
	jwtlib.RegisteredClaims
	User RemarkUser `json:"user"`
}

func Mint(secret, audience string, uid int64, name, picture string) (string, string, error) {
	return MintWithTTL(secret, audience, uid, name, picture, 5*time.Minute)
}

func MintWithTTL(secret, audience string, uid int64, name, picture string, ttl time.Duration) (string, string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	jti := hex.EncodeToString(raw)
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    "remark42",
			Audience:  jwtlib.ClaimStrings{audience},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(now),
			ID:        jti,
		},
		User: RemarkUser{
			ID:      "stepik_" + strconv.FormatInt(uid, 10),
			Name:    name,
			Picture: picture,
		},
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}
