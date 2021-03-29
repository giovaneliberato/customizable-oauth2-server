package test

import (
	"oauth2-server/domain"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/context"

	"github.com/google/uuid"
)

type ExternalServiceClientMock struct {
	ReturnError bool
}

func (c *ExternalServiceClientMock) GetAccessToken(ctx context.Context) (authorization.AccessTokenResponse, *domain.OAuthError) {
	if c.ReturnError {
		return authorization.AccessTokenResponse{}, &domain.OAuthError{}
	}
	return authorization.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}, nil
}

func (c *ExternalServiceClientMock) RefreshAccessToken(refreshToken string) (authorization.AccessTokenResponse, *domain.OAuthError) {
	if c.ReturnError {
		return authorization.AccessTokenResponse{}, &domain.OAuthError{}
	}
	return authorization.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
	}, nil
}
