package authorization_test

import (
	"goauth-extension/app/domain/authorization"
	"testing"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/stretchr/testify/assert"
)

func TestNotBuildConsentContextIfValidationFails(t *testing.T) {
	ctx, err := authorization.Do(authorization.AuthorizationRequest{})

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

	ctx, err := authorization.Do(req)

	assert.Nil(t, err)
	assert.Equal(t, req.ClientID, ctx.ClientID)
	assert.Equal(t, req.Scope, ctx.RequestedScopes)

	decodedJWT, _ := jwt.Parse(ctx.SignedAuthorizationRequest, nil)
	assert.NotEmpty(t, decodedJWT.Claims)
}
