package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/infra"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/golobby/container/v2"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildConsentContextIfValidationFails(t *testing.T) {
	infra.InitializeComponents()
	var service authorization.Service
	container.Make(&service)
	ctx, err := service.Authorize(authorization.AuthorizationRequest{})

	assert.NotNil(t, err)
	assert.Empty(t, ctx)
}

func TestBuildConsentContext(t *testing.T) {
	req := authorization.AuthorizationRequest{
		ClientID:    "test-id",
		RedirectURI: "https://test.client/oauth2-callback",
		GrantType:   "authorization_code",
		Scope:       []string{"profile"},
	}

	infra.InitializeComponents()
	var service authorization.Service
	err := container.Make(&service)
	ctx, err := service.Authorize(authorization.AuthorizationRequest{})

	assert.Nil(t, err)
	assert.Equal(t, req.ClientID, ctx.ClientID)
	assert.Equal(t, req.Scope, ctx.RequestedScopes)

	decodedJWT, _ := jwt.Parse(ctx.SignedAuthorizationRequest, nil)
	assert.NotEmpty(t, decodedJWT.Claims)
}
