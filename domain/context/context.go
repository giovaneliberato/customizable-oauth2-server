package context

import (
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/spf13/viper"
)

type Context struct {
	ClientID          string
	State             string
	ResponseType      []string
	Scope             []string
	RedirectURI       string
	AuthorizationCode string
}

type Signer interface {
	SignAndEncode(Context Context) (string, error)
	VerifyAndDecode(context string) (Context, error)
}

type contextSigner struct {
	signingKey        string
	contextIssuer     string
	expirationSeconds time.Duration
	timeProvider      func() time.Time
}

func NewContextSignerWith(key string, issuer string, exp time.Duration) Signer {
	return &contextSigner{
		signingKey:        key,
		contextIssuer:     issuer,
		expirationSeconds: exp,
	}
}

func NewContextSigner() Signer {
	exp := time.Second * time.Duration(viper.GetInt("jwt.expiration-seconds"))
	return &contextSigner{
		signingKey:        viper.GetString("jwt.signing-key"),
		contextIssuer:     viper.GetString("jwt.issuer"),
		expirationSeconds: exp,
	}
}

func (t *contextSigner) SignAndEncode(context Context) (string, error) {
	now := jwt.TimeFunc()

	mapContext := jwt.MapClaims{
		"iss":           t.contextIssuer,
		"iat":           now.Unix(),
		"exp":           now.Add(t.expirationSeconds).Unix(),
		"client_id":     context.ClientID,
		"redirect_uri":  context.RedirectURI,
		"scope":         context.Scope,
		"response_type": context.ResponseType,
	}

	if context.State != "" {
		mapContext["state"] = context.State
	}

	if context.AuthorizationCode != "" {
		mapContext["authorization_code"] = context.AuthorizationCode
	}

	contextClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, mapContext)
	return contextClaims.SignedString([]byte(t.signingKey))
}

func (t *contextSigner) VerifyAndDecode(signedContext string) (Context, error) {
	var parsedContext jwt.MapClaims
	_, err := jwt.ParseWithClaims(signedContext, &parsedContext, func(context *jwt.Token) (interface{}, error) {
		return []byte(t.signingKey), nil
	})

	if err != nil {
		return Context{}, err
	}

	context := Context{
		ClientID:          parsedContext["client_id"].(string),
		Scope:             toStringSlice(parsedContext["scope"]),
		State:             valueOrEmpty(parsedContext, "state"),
		AuthorizationCode: valueOrEmpty(parsedContext, "authorization_code"),
		RedirectURI:       parsedContext["redirect_uri"].(string),
		ResponseType:      toStringSlice(parsedContext["response_type"]),
	}

	return context, nil
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
