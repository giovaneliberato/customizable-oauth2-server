package authorization_test

import (
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"
	"oauth2-server/test"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildAuthorizationContextIfValidationFails(t *testing.T) {
	test.LoadConfig()
	service := buildTestService()

	ctx, err := service.Authorize(authorization.Authorization{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildAuthorizationContext(t *testing.T) {
	test.LoadConfig()

	service := buildTestService()

	auth := authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: []string{"code"},
		State:        "client-state",
		Scope:        []string{"profile"},
	}

	ctx, err := service.Authorize(auth)

	assert.Nil(t, err)
	assert.Equal(t, auth.ClientID, ctx.ClientID)
	assert.Equal(t, ctx.ClientName, test.TestClient.Name)
	assert.Equal(t, auth.Scope, ctx.RequestedScopes)
	assert.Equal(t, viper.GetString("authorization.consent-url"), ctx.AuthorizationURL)
	assert.NotEmpty(t, ctx.SignedAuthorizationContext)
}

func TestAuthorizationWithTokenResponseType(t *testing.T) {
	test.LoadConfig()

	service := buildTestService()

	auth := authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: []string{"token"},
		State:        "client-state",
		Scope:        []string{"profile"},
	}
	ctx, err := service.Authorize(auth)

	approval := authorization.AuthorizationApproval{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approval)

	assert.Nil(t, err)
	assert.Equal(t, auth.ClientID, ctx.ClientID)
	assert.Equal(t, auth.Scope, auth.Scope)
	assert.Equal(t, auth.RedirectURI, resp.RedirectURI)
	assert.Empty(t, resp.SignedAuthorizationCode)
	assert.NotEmpty(t, resp.AccessToken.AccessToken)
}

func TestAuthorizationWithHybridResponseType(t *testing.T) {
	test.LoadConfig()

	service := buildTestService()

	auth := authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: []string{"token", "code"},
		State:        "client-state",
		Scope:        []string{"profile"},
	}
	ctx, err := service.Authorize(auth)

	approval := authorization.AuthorizationApproval{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approval)

	assert.Nil(t, err)
	assert.Equal(t, auth.ClientID, ctx.ClientID)
	assert.Equal(t, auth.Scope, auth.Scope)
	assert.Equal(t, auth.RedirectURI, resp.RedirectURI)
	assert.NotEmpty(t, resp.SignedAuthorizationCode)
	assert.NotEmpty(t, resp.AccessToken.AccessToken)
}

func TestRejectApproveAuthorizationIfSignatureIsInvalid(t *testing.T) {
	test.LoadConfig()
	service := buildTestService()

	ctx, _ := service.Authorize(buildAuthorization())

	approval := authorization.AuthorizationApproval{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext + "tampered",
	}

	_, err := service.ApproveAuthorization(approval)
	assert.NotNil(t, err)
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
}

func TestDeniedAuthorization(t *testing.T) {
	test.LoadConfig()
	service := buildTestService()

	auth := buildAuthorization()
	ctx, _ := service.Authorize(auth)

	approval := authorization.AuthorizationApproval{
		ApprovedByUser:             false,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approval)
	assert.NotNil(t, err)
	assert.False(t, err.Abort)
	assert.Equal(t, "access_denied", err.Err)
	assert.Equal(t, auth.RedirectURI, resp.RedirectURI)
	assert.Equal(t, auth.State, resp.State)
	assert.Empty(t, resp.SignedAuthorizationCode)
}

func TestSuccessfulAuthorization(t *testing.T) {
	test.LoadConfig()
	service := buildTestService()
	authorizationSigner := context.NewContextSigner()

	auth := buildAuthorization()
	ctx, _ := service.Authorize(auth)

	approval := authorization.AuthorizationApproval{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approval)
	assert.Nil(t, err)
	assert.Equal(t, auth.RedirectURI, resp.RedirectURI)
	assert.Equal(t, auth.State, resp.State)

	context, _ := authorizationSigner.VerifyAndDecode(resp.SignedAuthorizationCode)
	assert.Equal(t, approval.AuthorizationCode, context.AuthorizationCode)
	assert.Equal(t, auth.RedirectURI, context.RedirectURI)
	assert.Equal(t, test.TestClient.ID, context.ClientID)
	assert.Equal(t, auth.Scope, context.Scope)
}

func buildTestService() authorization.Service {
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	contextSigner := context.NewContextSigner()

	tokenService := token.NewService(clientServiceMock, contextSigner, &test.ExternalServiceClientMock{})

	return authorization.NewService(clientServiceMock, contextSigner, tokenService)
}

func buildAuthorization() authorization.Authorization {
	return authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: test.TestClient.AllowedResponseTypes,
		State:        "client-state",
		Scope:        []string{"profile"},
	}

}
