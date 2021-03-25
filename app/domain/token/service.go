package token

import (
	"goauth-extension/app/domain/authorization"
)

type Service interface {
	Exchange(AuthorizationCodeRequest) (AccessTokenResponse, error)
}

type service struct {
	externalServiceClient ExternalServiceClient
	tokenSigner           authorization.TokenSigner
}

func NewService(tokenSigner authorization.TokenSigner, client ExternalServiceClient) Service {
	return &service{
		tokenSigner:           tokenSigner,
		externalServiceClient: client,
	}
}

func (s *service) Exchange(req AuthorizationCodeRequest) (AccessTokenResponse, error) {
	return AccessTokenResponse{}, nil
}
