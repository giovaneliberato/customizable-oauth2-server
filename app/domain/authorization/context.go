package authorization

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/spf13/viper"
)

type ContextClaims struct {
	ClientID          string
	State             string
	ResponseType      string
	Scope             []string
	RedirectURI       string
	AuthorizationCode string
}
type TokenSigner interface {
	SignAndEncode(claims ContextClaims) (string, error)
	VerifyAndDecode(token string) (ContextClaims, error)
}

type tokenSigner struct {
	signingKey        string
	tokenIssuer       string
	expirationSeconds time.Duration
	timeProvider      func() time.Time
}

func NewTokenSignerWith(key string, issuer string, exp time.Duration) TokenSigner {
	return &tokenSigner{
		signingKey:        key,
		tokenIssuer:       issuer,
		expirationSeconds: exp,
	}
}

func NewTokenSigner() TokenSigner {
	exp := time.Second * time.Duration(viper.GetInt("jwt.expiration-seconds"))
	return &tokenSigner{
		signingKey:        viper.GetString("jwt.signing-key"),
		tokenIssuer:       viper.GetString("jwt.issuer"),
		expirationSeconds: exp,
	}
}

func (t *tokenSigner) SignAndEncode(claims ContextClaims) (string, error) {
	now := jwt.TimeFunc()

	mapClaims := jwt.MapClaims{
		"iss":           t.tokenIssuer,
		"iat":           now.Unix(),
		"exp":           now.Add(t.expirationSeconds).Unix(),
		"client_id":     claims.ClientID,
		"redirect_uri":  claims.RedirectURI,
		"scope":         claims.Scope,
		"response_type": claims.ResponseType,
	}

	if claims.State != "" {
		mapClaims["state"] = claims.State
	}

	if claims.AuthorizationCode != "" {
		mapClaims["authorization_code"] = claims.AuthorizationCode
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString([]byte(t.signingKey))
}

func (t *tokenSigner) VerifyAndDecode(token string) (ContextClaims, error) {
	var parsedClaims jwt.MapClaims
	_, err := jwt.ParseWithClaims(token, &parsedClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.signingKey), nil
	})

	if err != nil {
		return ContextClaims{}, err
	}

	claims := ContextClaims{
		ClientID:          parsedClaims["client_id"].(string),
		Scope:             toStringSlice(parsedClaims["scope"]),
		State:             valueOrEmpty(parsedClaims, "state"),
		AuthorizationCode: valueOrEmpty(parsedClaims, "authorization_code"),
		RedirectURI:       parsedClaims["redirect_uri"].(string),
		ResponseType:      parsedClaims["response_type"].(string),
	}

	return claims, nil
}

func valueOrEmpty(claims jwt.MapClaims, key string) string {
	if claims[key] == nil {
		return ""
	}

	return claims[key].(string)
}

func toStringSlice(i interface{}) []string {
	arr := i.([]interface{})
	var converted []string
	for _, e := range arr {
		converted = append(converted, e.(string))
	}
	return converted
}
