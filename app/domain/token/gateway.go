package token

import (
	"goauth-extension/app/domain"
	"goauth-extension/app/domain/authorization"

	"github.com/google/uuid"
)

type ExternalServiceClient interface {
	GetAccessToken(authorization.Context) (AccessTokenResponse, *domain.OAuthError)
}

type externalServiceClient struct {
}

func NewExternalServiceClient() ExternalServiceClient {
	return &externalServiceClient{}
}

func (c *externalServiceClient) GetAccessToken(ctx authorization.Context) (AccessTokenResponse, *domain.OAuthError) {
	return AccessTokenResponse{
		AccessToken:  uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "bearer",
		ExpiresIn:    36000,
		Scope:        ctx.Scope,
	}, nil
}
