package authorization_test

import (
	"oauth2-server/cmd/domain/authorization"
	"oauth2-server/cmd/domain/client"
	"oauth2-server/cmd/infra"
	"oauth2-server/cmd/test"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildAuthorizationContextIfValidationFails(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = client.Client{}

	service := authorization.NewService(clientServiceMock, authorization.NewContextSigner())

	ctx, err := service.Authorize(authorization.AuthorizationRequest{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildAuthorizationContext(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient

	service := authorization.NewService(clientServiceMock, authorization.NewContextSigner())

	req := authorization.AuthorizationRequest{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: "code",
		State:        "client-state",
		Scope:        []string{"profile"},
	}

	ctx, err := service.Authorize(req)

	assert.Nil(t, err)
	assert.Equal(t, req.ClientID, ctx.ClientID)
	assert.Equal(t, ctx.ClientName, test.TestClient.Name)
	assert.Equal(t, req.Scope, ctx.RequestedScopes)
	assert.Equal(t, viper.GetString("authorization.consent-url"), ctx.AuthorizationURL)
	assert.NotEmpty(t, ctx.SignedAuthorizationContext)
}

func TestRejectApproveAuthorizationIfSignatureIsInvalid(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, authorization.NewContextSigner())

	ctx, _ := service.Authorize(buildAuthorizationRequest())

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext + "tampered",
	}

	_, err := service.ApproveAuthorization(approveReq)
	assert.NotNil(t, err)
	assert.True(t, err.Abort)
	assert.Equal(t, "invalid_request", err.Err)
}

func TestDeniedAuthorization(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, authorization.NewContextSigner())

	req := buildAuthorizationRequest()
	ctx, _ := service.Authorize(req)

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             false,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approveReq)
	assert.NotNil(t, err)
	assert.False(t, err.Abort)
	assert.Equal(t, "access_denied", err.Err)
	assert.Equal(t, req.RedirectURI, resp.RedirectURI)
	assert.Equal(t, req.State, resp.State)
	assert.Empty(t, resp.SignedAuthorizationCode)
}

func TestSuccessfulAuthorization(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, authorization.NewContextSigner())
	authorizationSigner := authorization.NewContextSigner()

	req := buildAuthorizationRequest()
	ctx, _ := service.Authorize(req)

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationContext,
	}

	resp, err := service.ApproveAuthorization(approveReq)
	assert.Nil(t, err)
	assert.Equal(t, req.RedirectURI, resp.RedirectURI)
	assert.Equal(t, req.State, resp.State)

	Context, _ := authorizationSigner.VerifyAndDecode(resp.SignedAuthorizationCode)
	assert.Equal(t, approveReq.AuthorizationCode, Context.AuthorizationCode)
	assert.Equal(t, req.RedirectURI, Context.RedirectURI)
	assert.Equal(t, test.TestClient.ID, Context.ClientID)
	assert.Equal(t, req.Scope, Context.Scope)
}

func buildAuthorizationRequest() authorization.AuthorizationRequest {
	return authorization.AuthorizationRequest{
		ClientID:     test.TestClient.ID,
		RedirectURI:  test.TestClient.AllowedRedirectUrls[0],
		ResponseType: test.TestClient.AllowedResponseTypes[0],
		State:        "client-state",
		Scope:        []string{"profile"},
	}

}
