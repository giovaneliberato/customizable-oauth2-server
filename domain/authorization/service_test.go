package authorization_test

import (
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/client"
	"oauth2-server/domain/context"
	"oauth2-server/test"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildAuthorizationContextIfValidationFails(t *testing.T) {
	test.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = client.Client{}

	service := authorization.NewService(clientServiceMock, context.NewContextSigner())

	ctx, err := service.Authorize(authorization.Authorization{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildAuthorizationContext(t *testing.T) {
	test.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient

	service := authorization.NewService(clientServiceMock, context.NewContextSigner())

	auth := authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: "code",
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

func TestRejectApproveAuthorizationIfSignatureIsInvalid(t *testing.T) {
	test.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, context.NewContextSigner())

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
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, context.NewContextSigner())

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
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, context.NewContextSigner())
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

	Context, _ := authorizationSigner.VerifyAndDecode(resp.SignedAuthorizationCode)
	assert.Equal(t, approval.AuthorizationCode, Context.AuthorizationCode)
	assert.Equal(t, auth.RedirectURI, Context.RedirectURI)
	assert.Equal(t, test.TestClient.ID, Context.ClientID)
	assert.Equal(t, auth.Scope, Context.Scope)
}

func buildAuthorization() authorization.Authorization {
	return authorization.Authorization{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: test.TestClient.AllowedResponseTypes[0],
		State:        "client-state",
		Scope:        []string{"profile"},
	}

}
