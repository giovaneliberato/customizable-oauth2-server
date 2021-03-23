package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/client"
	"goauth-extension/app/infra"
	"goauth-extension/app/test"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNotBuildConsentContextIfValidationFails(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = client.Client{}

	service := authorization.NewService(clientServiceMock)

	ctx, err := service.Authorize(authorization.AuthorizationRequest{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildConsentContext(t *testing.T) {
	infra.LoadConfig()
	clientServiceMock := new(test.ClientServiceMock)
	clientServiceMock.Return = test.TestClient
	service := authorization.NewService(clientServiceMock)

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
	assert.NotEmpty(t, ctx.SignedAuthorizationRequest)
}
