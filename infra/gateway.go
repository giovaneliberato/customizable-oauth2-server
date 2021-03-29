package infra

import (
	"oauth2-server/domain"
	"oauth2-server/domain/authorization"
	"oauth2-server/domain/context"

	"github.com/google/uuid"
)

type ExternalServiceClient interface {
	GetAccessToken(context.Context) (authorization.AccessTokenResponse, *domain.OAuthError)
	RefreshAccessToken(string) (authorization.AccessTokenResponse, *domain.OAuthError)
}

type externalServiceClient struct {
}

func NewExternalServiceClient() ExternalServiceClient {
	return &externalServiceClient{}
}

func (c *externalServiceClient) GetAccessToken(ctx context.Context) (authorization.AccessTokenResponse, *domain.OAuthError) {
	return authorization.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}, nil
}

func (c *externalServiceClient) RefreshAccessToken(string) (authorization.AccessTokenResponse, *domain.OAuthError) {
	return authorization.AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
	}, nil
}
