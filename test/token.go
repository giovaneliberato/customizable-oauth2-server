package test

import (
	"oauth2-server/domain"
	"oauth2-server/domain/context"
	"oauth2-server/domain/token"

	"github.com/google/uuid"
)

type ExternalServiceClientMock struct {
	ReturnError bool
}

func (c *ExternalServiceClientMock) GetAccessToken(ctx context.Context) (token.AccessTokenResponse, *domain.OAuthError) {
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

func (c *ExternalServiceClientMock) RefreshAccessToken(refreshToken string) (token.AccessTokenResponse, *domain.OAuthError) {
	if c.ReturnError {
		return token.AccessTokenResponse{}, &domain.OAuthError{}
	}
	return token.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
	}, nil
}
