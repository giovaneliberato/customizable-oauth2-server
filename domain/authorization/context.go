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

type ContextSigner interface {
	SignAndEncode(Context Context) (string, error)
	VerifyAndDecode(context string) (Context, error)
}

type contextSigner struct {
	signingKey        string
	contextIssuer     string
	expirationSeconds time.Duration
	timeProvider      func() time.Time
}

func NewContextSignerWith(key string, issuer string, exp time.Duration) ContextSigner {
	return &contextSigner{
		signingKey:        key,
		contextIssuer:     issuer,
		expirationSeconds: exp,
	}
}

func NewContextSigner() ContextSigner {
	exp := time.Second * time.Duration(viper.GetInt("jwt.expiration-seconds"))
	return &contextSigner{
		signingKey:        viper.GetString("jwt.signing-key"),
		contextIssuer:     viper.GetString("jwt.issuer"),
		expirationSeconds: exp,
	}
}

func (t *contextSigner) SignAndEncode(Context Context) (string, error) {
	now := jwt.TimeFunc()

	mapContext := jwt.MapClaims{
		"iss":           t.contextIssuer,
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

	context := jwt.NewWithClaims(jwt.SigningMethodHS256, mapContext)
	return context.SignedString([]byte(t.signingKey))
}

func (t *contextSigner) VerifyAndDecode(context string) (Context, error) {
	var parsedContext jwt.MapClaims
	_, err := jwt.ParseWithClaims(context, &parsedContext, func(context *jwt.Token) (interface{}, error) {
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
