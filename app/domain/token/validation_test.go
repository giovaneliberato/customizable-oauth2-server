package token_test

import (
	"oauth2-server/app/domain"
	"oauth2-server/app/domain/token"
	"oauth2-server/app/test"
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
