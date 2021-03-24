package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"goauth-extension/app/test"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildConsentContextIfValidationFails(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = client.Client{}

	service := authorization.NewService(clientServiceMock, authorization.NewTokenSigner())

	ctx, err := service.Authorize(authorization.AuthorizationRequest{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildAuthorizationContext(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient

	service := authorization.NewService(clientServiceMock, authorization.NewTokenSigner())

	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		State:       "client-state",
		Scope:       []string{"profile"},
	}

	ctx, err := service.Authorize(req)

	assert.Nil(t, err)
	assert.Equal(t, req.ClientID, ctx.ClientID)
	assert.Equal(t, req.Scope, ctx.RequestedScopes)
	assert.Equal(t, viper.GetString("authorization.consent-url"), ctx.AuthorizationURL)
	assert.NotEmpty(t, ctx.SignedAuthorizationRequest)
}

func TestRejectApproveAuthorizationIfSignatureIsInvalid(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock, authorization.NewTokenSigner())

	ctx, _ := service.Authorize(buildAuthorizationRequest())

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationRequest + "tampered",
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
	service := authorization.NewService(clientServiceMock, authorization.NewTokenSigner())

	req := buildAuthorizationRequest()
	ctx, _ := service.Authorize(req)

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             false,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationRequest,
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
	service := authorization.NewService(clientServiceMock, authorization.NewTokenSigner())
	authorizationSigner := authorization.NewTokenSigner()

	req := buildAuthorizationRequest()
	ctx, _ := service.Authorize(req)

	approveReq := authorization.ApproveAuthorizationRequest{
		ApprovedByUser:             true,
		AuthorizationCode:          "authorization-code",
		SignedAuthorizationRequest: ctx.SignedAuthorizationRequest,
	}

	resp, err := service.ApproveAuthorization(approveReq)
	assert.Nil(t, err)
	assert.Equal(t, req.RedirectURI, resp.RedirectURI)
	assert.Equal(t, req.State, resp.State)

	claims, _ := authorizationSigner.VerifyAndDecode(resp.SignedAuthorizationCode)
	assert.Equal(t, approveReq.AuthorizationCode, claims.AuthorizationCode)
	assert.Equal(t, req.RedirectURI, claims.RedirectURI)
	assert.Equal(t, test.TestClient.ID, claims.ClientID)
	assert.Equal(t, req.Scope, claims.Scope)
}

func buildAuthorizationRequest() authorization.AuthorizationRequest {
	return authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		State:       "client-state",
		Scope:       []string{"profile"},
	}

}
