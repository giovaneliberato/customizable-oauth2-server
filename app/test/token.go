package test

import (
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/token"

	"github.com/google/uuid"
)

type ExternalServiceClientMock struct{}

func (c *ExternalServiceClientMock) GetAccessToken(ctx authorization.ContextClaims) token.AccessTokenResponse {
	return token.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}
}
