package token_test

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/token"
	"goauth-extension/app/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIDDoNotMatch(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID:     "not-the-same-id",
		ClientSecret: test.TestClient.RawSecret,
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req, test.TestClient)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidClientError, err)
}

func TestClientSecretDoNotMatch(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID:     test.TestClient.ID,
		ClientSecret: "not-the-same-secret",
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req, test.TestClient)
	assert.NotNil(t, err)
	assert.Equal(t, domain.InvalidClientError, err)
}

func TestClientValidationSuccess(t *testing.T) {
	req := token.AuthorizationCodeRequest{
		ClientID:     test.TestClient.ID,
		ClientSecret: test.TestClient.RawSecret,
		GrantType:    "authorization_code",
	}

	err := token.ValidateClient(req, test.TestClient)
	assert.Nil(t, err)
}
