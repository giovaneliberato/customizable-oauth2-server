package token

import (
	"oauth2-server/domain"
	"oauth2-server/domain/context"

	"github.com/google/uuid"
)

type ExternalServiceClient interface {
	GetAccessToken(context.Context) (AccessTokenResponse, *domain.OAuthError)
	RefreshAccessToken(string) (AccessTokenResponse, *domain.OAuthError)
}

type externalServiceClient struct {
}

func NewExternalServiceClient() ExternalServiceClient {
	return &externalServiceClient{}
}

func (c *externalServiceClient) GetAccessToken(ctx context.Context) (AccessTokenResponse, *domain.OAuthError) {
	return AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}, nil
}

func (c *externalServiceClient) RefreshAccessToken(string) (AccessTokenResponse, *domain.OAuthError) {
	return AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
	}, nil
}
