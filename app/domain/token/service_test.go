package token_test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/token"
	"goauth-extension/app/test"
	"testing"

	"github.com/golobby/container/v2"
	"github.com/stretchr/testify/assert"
)

func TestInvalidSignedAuthorizationCode(t *testing.T) {
	tokenSigner := getTokenSigner()
	service := buildTestService()

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := tokenSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		ResponseType:            "code",
		SignedAuthorizationCode: signedAuthCode + "tampered",
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestInvalidContext(t *testing.T) {
	tokenSigner := getTokenSigner()
	service := buildTestService()

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := tokenSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		ResponseType:            "another-response-type",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestInvalidClient(t *testing.T) {
	tokenSigner := getTokenSigner()
	service := buildTestService()

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := tokenSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                "another-client-id",
		ClientSecret:            test.TestClient.RawSecret,
		ResponseType:            "code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestInvalidExternalError(t *testing.T) {
	tokenSigner := getTokenSigner()
	service := token.NewService(
		&test.ClientServiceMock{},
		getTokenSigner(),
		&test.ExternalServiceClientMock{
			ReturnError: true,
		})

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := tokenSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		ResponseType:            "code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.NotNil(t, err)
	assert.Empty(t, accessToken.AccessToken)
}

func TestExchangeSuccess(t *testing.T) {
	tokenSigner := getTokenSigner()
	service := buildTestService()

	ctx := authorization.Context{
		ClientID:          test.TestClient.ID,
		ResponseType:      "code",
		Scope:             test.TestClient.AllowedScopes,
		RedirectURI:       test.TestClient.AllowedRedirectUrls[0],
		AuthorizationCode: "some-authorization-code",
	}

	signedAuthCode, _ := tokenSigner.SignAndEncode(ctx)

	req := token.AuthorizationCodeRequest{
		ClientID:                test.TestClient.ID,
		ClientSecret:            test.TestClient.RawSecret,
		ResponseType:            "code",
		SignedAuthorizationCode: signedAuthCode,
	}

	accessToken, err := service.Exchange(req)

	assert.Nil(t, err)
	assert.NotEmpty(t, accessToken.AccessToken)
	assert.NotEmpty(t, accessToken.RefreshToken)
	assert.Equal(t, ctx.Scope, accessToken.Scope)
}

func getTokenSigner() authorization.TokenSigner {
	test.ConfigureTestScenario()

	var tokenSigner authorization.TokenSigner
	container.Make(&tokenSigner)
	return tokenSigner
}

func buildTestService() token.Service {
	return token.NewService(
		&test.ClientServiceMock{
			Return: test.TestClient,
		},
		getTokenSigner(),
		&test.ExternalServiceClientMock{})
}
