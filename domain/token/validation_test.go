package token_test

import (
	"oauth2-server/domain"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"
	"oauth2-server/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIDDoNotMatch(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID:     "not-the-same-id",
		ClientSecret: test.TestClient.RawSecret,
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req.ClientID, req.ClientSecret, test.TestClient)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidClientError, err)
}

func TestRequestURLDoNotMatch(t *testing.T) {
	ctx := context.Context{
		ClientID:    test.TestClient.ID,
		RedirectURI: test.TestClient.AllowedRedirectUrls[0],
	}

	req := token.AuthorizationCodeRequest{
		ClientID:    test.TestClient.ID,
		RedirectURL: "http://invalid.url",
	}

	err := token.ValidateContext(req, ctx)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidAuthorizationCodeRequestError, err)
}

func TestClientSecretDoNotMatch(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID: test.TestClient.ID,

		ClientSecret: "not-the-same-secret",
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req.ClientID, req.ClientSecret, test.TestClient)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidClientError, err)
}

func TestClientValidationSuccess(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID:     test.TestClient.ID,
		ClientSecret: test.TestClient.RawSecret,
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req.ClientID, req.ClientSecret, test.TestClient)
	assert.Nil(t, err)
}
