package token_test

import (
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"
	"oauth2-server/test"
	"testing"

	"github.com/golobby/container/v2"
	"github.com/stretchr/testify/assert"
)

func TestInvalidSignedAuthorizationCode(t *testing.T) {
	contextSigner := getContextSigner()
	service := buildTestService()

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := contextSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		GrantType:               "authorization_code",
		SignedAuthorizationCode: signedAuthCode + "tampered",
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestInvalidClient(t *testing.T) {
	contextSigner := getContextSigner()
	service := buildTestService()

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      []string{"code"},
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := contextSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                "another-client-id",
		ClientSecret:            test.TestClient.RawSecret,
		GrantType:               "authorization_code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestInvalidExternalError(t *testing.T) {
	contextSigner := getContextSigner()
	service := token.NewService(
		&test.ClientServiceMock{},
		getContextSigner(),
		&test.ExternalServiceClientMock{
			ReturnError: true,
		})

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      []string{"code"},
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := contextSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		GrantType:               "authorization_code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestExchangeSuccess(t *testing.T) {
	contextSigner := getContextSigner()
	service := buildTestService()

	ctx := context.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      []string{"code"},
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := contextSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		RedirectURL:             ctx.RedirectURI,
		GrantType:               "authorization_code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.Nil(t, err)
	assert.NotEmpty(t, accessToken.AccessToken)
	assert.NotEmpty(t, accessToken.RefreshToken)
	assert.Equal(t, ctx.Scope, accessToken.Scope)
}

func getContextSigner() context.Signer {
	test.ConfigureTestScenario()

	var contextSigner context.Signer
	container.Make(&contextSigner)
	return contextSigner
}

func buildTestService() token.Service {
	return token.NewService(
		&test.ClientServiceMock{
			Return: test.TestClient,
		},
		getContextSigner(),
		&test.ExternalServiceClientMock{})
}
