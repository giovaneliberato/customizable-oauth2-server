package authorization

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/spf13/viper"
)

type Context struct {
	ClientID          string
	State             string
	ResponseType      string
	Scope             []string
	RedirectURI       string
	AuthorizationCode string
}

type TokenSigner interface {
	SignAndEncode(Context Context) (string, error)
	VerifyAndDecode(token string) (Context, error)
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

func (t *tokenSigner) SignAndEncode(Context Context) (string, error) {
	now := jwt.TimeFunc()

	mapContext := jwt.MapClaims{
		"iss":           t.tokenIssuer,
		"iat":           now.Unix(),
		"exp":           now.Add(t.expirationSeconds).Unix(),
		"client_id":     Context.ClientID,
		"redirect_uri":  Context.RedirectURI,
		"scope":         Context.Scope,
		"response_type": Context.ResponseType,
	}

	if Context.State != "" {
		mapContext["state"] = Context.State
	}

	if Context.AuthorizationCode != "" {
		mapContext["authorization_code"] = Context.AuthorizationCode
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapContext)
	return token.SignedString([]byte(t.signingKey))
}

func (t *tokenSigner) VerifyAndDecode(token string) (Context, error) {
	var parsedContext jwt.MapClaims
	_, err := jwt.ParseWithClaims(token, &parsedContext, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.signingKey), nil
	})

	if err != nil {
		return Context{}, err
	}

	Context := Context{
		ClientID:          parsedContext["client_id"].(string),
		Scope:             toStringSlice(parsedContext["scope"]),
		State:             valueOrEmpty(parsedContext, "state"),
		AuthorizationCode: valueOrEmpty(parsedContext, "authorization_code"),
		RedirectURI:       parsedContext["redirect_uri"].(string),
		ResponseType:      parsedContext["response_type"].(string),
	}

	return Context, nil
}

func valueOrEmpty(Context jwt.MapClaims, key string) string {
	if Context[key] == nil {
		return ""
	}

	return Context[key].(string)
}

func toStringSlice(i interface{}) []string {
	arr := i.([]interface{})
	var converted []string
	for _, e := range arr {
		converted = append(converted, e.(string))
	}
	return converted
}
