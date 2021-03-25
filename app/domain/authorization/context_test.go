package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

const TEST_KEY = "86088fd3028e486cc7adea8a1450a41e36529a23"
const DURATION = time.Second * 60

func TestSignAndEncode(t *testing.T) {
	tokenSigner := authorization.NewTokenSignerWith(TEST_KEY, "app", DURATION)

	Context := authorization.Context{
		ClientID:    "test-client",
		State:       "xpto",
		Scope:       []string{"profile", "messages"},
		RedirectURI: "https://my.app/oauth2-callback",
	}

	token, err := tokenSigner.SignAndEncode(Context)

	assert.Nil(t, err)
	var parsedContext jwt.MapClaims
	parsedToken, err := jwt.ParseWithClaims(token, &parsedContext, func(token *jwt.Token) (interface{}, error) {
		return []byte(TEST_KEY), nil
	})

	assert.True(t, parsedToken.Valid)
}

func TestRejectInvalidToken(t *testing.T) {
	tokenSigner := authorization.NewTokenSignerWith(TEST_KEY, "app", 1)

	_, err := tokenSigner.VerifyAndDecode("not even a token")
	assert.NotNil(t, err)
}

func TestRejectInvalidSignature(t *testing.T) {
	tokenSigner := authorization.NewTokenSignerWith(TEST_KEY, "app", 1)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6MTYxNjUzMTkzOSwiaWF0IjoxNjE2NTMxODc5LCJpc3MiOiJhcHAiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL215LmFwcC9vYXV0aDItY2FsbGJhY2siLCJzY29wZXMiOiJwcm9maWxlIG1lc3NhZ2VzIiwic3RhdGUiOiJ4cHRvIn0.4i4ex4Hj63bot0DHg7AZwAaACJhPImessed"

	_, err := tokenSigner.VerifyAndDecode(token)
	assert.NotNil(t, err)
}

func TestRejectExpiredTokens(t *testing.T) {
	tokenSigner := authorization.NewTokenSignerWith(TEST_KEY, "app", 1)

	token, err := tokenSigner.SignAndEncode(authorization.Context{})
	assert.Nil(t, err)
	time.Sleep(1)

	_, err = tokenSigner.VerifyAndDecode(token)
	assert.NotNil(t, err)
}

func TestVerifySuccess(t *testing.T) {
	tokenSigner := authorization.NewTokenSignerWith(TEST_KEY, "app", DURATION)

	Context := authorization.Context{
		ClientID:    "test-client",
		State:       "xpto",
		Scope:       []string{"profile", "messages"},
		RedirectURI: "https://my.app/oauth2-callback",
	}

	token, err := tokenSigner.SignAndEncode(Context)

	verifiedContext, err := tokenSigner.VerifyAndDecode(token)
	assert.Nil(t, err)

	assert.Equal(t, "test-client", verifiedContext.ClientID)
	assert.Equal(t, "xpto", verifiedContext.State)
	assert.Equal(t, []string{"profile", "messages"}, verifiedContext.Scope)
	assert.Equal(t, "https://my.app/oauth2-callback", verifiedContext.RedirectURI)
}
