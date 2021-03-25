package test

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"
	"goauth-extension/app/domain/token"

	"github.com/google/uuid"
)

type ExternalServiceClientMock struct {
	ReturnError bool
}

func (c *ExternalServiceClientMock) GetAccessToken(ctx authorization.ContextClaims) (token.AccessTokenResponse, *domain.OAuthError) {
	if c.ReturnError {
		return token.AccessTokenResponse{}, &domain.OAuthError{}
	}
	return token.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}, nil
}
