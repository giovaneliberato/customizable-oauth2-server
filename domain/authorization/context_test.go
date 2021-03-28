package authorization_test

import (
	"oauth2-server/domain/authorization"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

const TEST_KEY = "86088fd3028e486cc7adea8a1450a41e36529a23"
const DURATION = time.Second * 60

func TestSignAndEncode(t *testing.T) {
	contextSigner := authorization.NewContextSignerWith(TEST_KEY, "app", DURATION)

	Context := authorization.Context{
		ClientID:    "test-client",
		State:       "xpto",
		Scope:       []string{"profile", "messages"},
		RedirectURI: "https://my.app/oauth2-callback",
	}

	signedContext, err := contextSigner.SignAndEncode(Context)

	assert.Nil(t, err)
	var parsedContext jwt.MapClaims
	parsedToken, err := jwt.ParseWithClaims(signedContext, &parsedContext, func(token *jwt.Token) (interface{}, error) {
		return []byte(TEST_KEY), nil
	})

	assert.True(t, parsedToken.Valid)
}

func TestRejectInvalidContext(t *testing.T) {
	contextSigner := authorization.NewContextSignerWith(TEST_KEY, "app", 1)

	_, err := contextSigner.VerifyAndDecode("not even a context")
	assert.NotNil(t, err)
}

func TestRejectInvalidSignature(t *testing.T) {
	contextSigner := authorization.NewContextSignerWith(TEST_KEY, "app", 1)
	context := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJ0ZXN0LWNsaWVudCIsImV4cCI6MTYxNjUzMTkzOSwiaWF0IjoxNjE2NTMxODc5LCJpc3MiOiJhcHAiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL215LmFwcC9vYXV0aDItY2FsbGJhY2siLCJzY29wZXMiOiJwcm9maWxlIG1lc3NhZ2VzIiwic3RhdGUiOiJ4cHRvIn0.4i4ex4Hj63bot0DHg7AZwAaACJhPImessed"

	_, err := contextSigner.VerifyAndDecode(context)
	assert.NotNil(t, err)
}

func TestRejectExpiredTokens(t *testing.T) {
	contextSigner := authorization.NewContextSignerWith(TEST_KEY, "app", 1)

	context, err := contextSigner.SignAndEncode(authorization.Context{})
	assert.Nil(t, err)
	time.Sleep(1)

	_, err = contextSigner.VerifyAndDecode(context)
	assert.NotNil(t, err)
}

func TestVerifySuccess(t *testing.T) {
	contextSigner := authorization.NewContextSignerWith(TEST_KEY, "app", DURATION)

	Context := authorization.Context{
		ClientID:    "test-client",
		State:       "xpto",
		Scope:       []string{"profile", "messages"},
		RedirectURI: "https://my.app/oauth2-callback",
	}

	context, err := contextSigner.SignAndEncode(Context)

	verifiedContext, err := contextSigner.VerifyAndDecode(context)
	assert.Nil(t, err)

	assert.Equal(t, "test-client", verifiedContext.ClientID)
	assert.Equal(t, "xpto", verifiedContext.State)
	assert.Equal(t, []string{"profile", "messages"}, verifiedContext.Scope)
	assert.Equal(t, "https://my.app/oauth2-callback", verifiedContext.RedirectURI)
}
