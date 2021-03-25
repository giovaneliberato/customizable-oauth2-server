package token_test

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/token"
	"goauth-extension/app/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrantTypeNotMatch(t *testing.T) {
	test.ConfigureTestScenario()

	ctx := authorization.ContextClaims{
		AuthorizationCode: "xpto",
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
	}

	signed, _ := authorization.NewTokenSigner().SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		GrantType:               "implicit",
		SignedAuthorizationCode: signed,
	}

	err := token.ValidateContext(req, ctx)
	assert.NotNil(t, err)
	assert.Equal(t, domain.UnsupportedResponseTypeError, err)
}

func TestClientSecretDoNotMatch(t *testing.T) {
	test.ConfigureTestScenario()

	req := token.AuthorizationCodeRequest{
		ClientID:     test.TestClient.ID,
		ClientSecret: test.TestClient.RawSecret,
		GrantType:    "code",
	}

	err := token.ValidateClient(req, test.TestClient)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidClientError, err)
}
